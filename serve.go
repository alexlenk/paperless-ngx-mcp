package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// Serve mode exposes the same MCP server over Streamable HTTP, for clients
// that reach it over the network (for example through a Cloudflare Tunnel).
// It is stricter than stdio: Cloudflare Access must vouch for every request,
// the policy filter must be on, and tools that touch the server's own disk
// are not offered.

const (
	envHTTPAddr      = "PAPERLESS_MCP_HTTP_ADDR"
	defaultHTTPAddr  = ":8080"
	mcpEndpointPath  = "/mcp"
	healthPath       = "/healthz"
	maxRequestBody   = 16 << 20 // JSON-RPC requests are small; this only caps abuse
	shutdownTimeout  = 10 * time.Second
	healthcheckLimit = 5 * time.Second
)

// remoteInstructions is appended to the server instructions in serve mode.
const remoteInstructions = `

## Remote (HTTP) Mode
This server runs over HTTP. document_download returns file content inline only (no disk downloads, no dest_dir, no cleanup_downloads), and document_upload is not available. The policy filter is on: documents outside the full tier show metadata only, and blocked calls return errors starting with "policy:".`

func serveCmd() *cobra.Command {
	var downloadConcurrency int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start MCP server over Streamable HTTP (requires Cloudflare Access and the policy filter)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if downloadConcurrency < 1 {
				return fmt.Errorf(`invalid argument "%d" for "--download-concurrency" flag: must be at least 1`, downloadConcurrency)
			}
			cmd.SilenceUsage = true

			baseURL := os.Getenv("PAPERLESS_URL")
			if baseURL == "" {
				return fmt.Errorf("PAPERLESS_URL environment variable is required")
			}
			token := os.Getenv("PAPERLESS_TOKEN")
			if token == "" {
				return fmt.Errorf("PAPERLESS_TOKEN environment variable is required")
			}
			access, err := loadAccessConfig(os.Getenv)
			if err != nil {
				return err
			}
			policyCfg, err := loadPolicyConfig(os.Getenv)
			if err != nil {
				return err
			}
			if !policyCfg.Enabled {
				return fmt.Errorf("serve requires the policy filter: set %s=true and configure its tags", envPolicyEnabled)
			}
			addr := strings.TrimSpace(os.Getenv(envHTTPAddr))
			if addr == "" {
				addr = defaultHTTPAddr
			}

			signal.Ignore(syscall.SIGPIPE)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer stop()
			context.AfterFunc(ctx, stop)

			clientOpts, err := configurePolicy(ctx, os.Getenv, baseURL, token, http.DefaultTransport, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if len(clientOpts) == 0 {
				// configurePolicy returns no options only when the filter is off,
				// which was ruled out above. Never serve without it.
				return fmt.Errorf("serve requires the policy filter, but it was not installed")
			}

			logger := slog.New(slog.NewJSONHandler(cmd.OutOrStdout(), nil))
			client := NewClient(baseURL, token, clientOpts...)
			handler := newServeHandler(ctx, client, downloadConcurrency, access, logger)

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", addr, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "serve: listening on %s, MCP endpoint %s, Access issuer %s, %d allowed email(s)\n",
				ln.Addr(), mcpEndpointPath, access.Issuer, len(access.AllowedEmails))
			return runHTTPServer(ctx, ln, handler)
		},
	}

	cmd.Flags().IntVar(&downloadConcurrency, "download-concurrency", 5, "Max parallel document downloads")
	return cmd
}

// newServeHandler builds the HTTP handler for serve mode: an unauthenticated
// health endpoint, and the MCP endpoint behind the Access check.
func newServeHandler(ctx context.Context, client *Client, downloadConcurrency int, access accessConfig, logger *slog.Logger) http.Handler {
	srv := newRemoteMCPServer(client, downloadConcurrency, logger)
	streamable := server.NewStreamableHTTPServer(srv,
		server.WithEndpointPath(mcpEndpointPath),
		server.WithStateLess(true),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.Handle(mcpEndpointPath, requireAccess(newAccessVerifier(ctx, access), logger,
		http.MaxBytesHandler(streamable, maxRequestBody)))
	return mux
}

// newRemoteMCPServer is NewServer for serve mode: the same tools, minus the
// ones that read or write the server's own disk, with an audit log of every
// tool call.
func newRemoteMCPServer(client *Client, downloadConcurrency int, logger *slog.Logger) *server.MCPServer {
	// Inline downloads only use the concurrency limit; no directory is created,
	// so the container's root filesystem can stay read-only.
	dl := &Downloader{concurrency: downloadConcurrency, files: map[string]struct{}{}}
	srv := NewServer(client, dl,
		server.WithInstructions(serverInstructions+remoteInstructions),
		server.WithToolHandlerMiddleware(auditMiddleware(logger)),
	)

	// document_upload would read a path on the server (in a container that
	// includes /proc/self/environ, which holds PAPERLESS_TOKEN). Disk downloads
	// land where no remote client can read them.
	srv.DeleteTools("document_upload", "cleanup_downloads", "document_download")
	inline := handleDocumentDownload(client, dl)
	srv.AddTool(
		mcp.NewTool("document_download",
			mcp.WithDescription("Download one or more document files and return their content inline: image files come back as viewable MCP image content blocks, other types as base64 JSON."),
			mcp.WithString("ids", mcp.Description("JSON array of document IDs to download"), mcp.Required()),
			mcp.WithString("variant", mcp.Description("File variant: archived (default, OCR'd PDF/A), original (as uploaded), or thumbnail")),
		),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := map[string]any{}
			for k, v := range request.GetArguments() {
				if k != "dest_dir" {
					args[k] = v
				}
			}
			args["content"] = true
			request.Params.Arguments = args
			return inline(ctx, request)
		},
	)
	return srv
}

// runHTTPServer serves handler on ln until ctx is cancelled, then shuts down
// gracefully. A shutdown on request is a success.
func runHTTPServer(ctx context.Context, ln net.Listener, handler http.Handler) error {
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// healthcheckCmd checks a running serve instance in the same container, for
// Docker's HEALTHCHECK (the image has no shell or curl).
func healthcheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Check that a local serve instance answers on its health endpoint",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			target, err := healthURL(os.Getenv(envHTTPAddr))
			if err != nil {
				return err
			}
			// This client only calls the local health endpoint, never Paperless.
			hc := &http.Client{Timeout: healthcheckLimit}
			resp, err := hc.Get(target)
			if err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("health check failed: status %d", resp.StatusCode)
			}
			return nil
		},
	}
}

// healthURL derives the local health endpoint from the listen address. A
// wildcard or empty host means the loopback address.
func healthURL(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = defaultHTTPAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", envHTTPAddr, addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + healthPath, nil
}

// --- Audit log ---

// auditRecord collects what happens during one tool call. The policy
// transport adds to it, so the log can tell a policy refusal from an error.
type auditRecord struct {
	mu           sync.Mutex
	policyBlocks int
}

type auditKey struct{}

// notePolicyBlock records a blocked request on the tool call in ctx, if any.
func notePolicyBlock(ctx context.Context) {
	if rec, ok := ctx.Value(auditKey{}).(*auditRecord); ok {
		rec.mu.Lock()
		rec.policyBlocks++
		rec.mu.Unlock()
	}
}

// auditMiddleware logs one line per tool call: email, tool, document IDs from
// the arguments, result and duration. It never logs argument values other
// than document IDs, nor any part of the result.
func auditMiddleware(logger *slog.Logger) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			rec := &auditRecord{}
			start := time.Now()
			result, err := next(context.WithValue(ctx, auditKey{}, rec), request)

			rec.mu.Lock()
			blocks := rec.policyBlocks
			rec.mu.Unlock()
			outcome := "ok"
			switch {
			case blocks > 0:
				outcome = "refused_by_policy"
			case err != nil || result == nil || result.IsError:
				outcome = "error"
			}
			logger.Info("tool call",
				"email", identityFrom(ctx),
				"tool", request.Params.Name,
				"documents", auditDocumentIDs(request.Params.Name, request.GetArguments()),
				"result", outcome,
				"policy_blocks", blocks,
				"duration_ms", time.Since(start).Milliseconds(),
			)
			return result, err
		}
	}
}

// maxAuditIDs caps the document IDs logged per call.
const maxAuditIDs = 100

// auditDocumentIDs extracts document IDs from tool arguments: the parameters
// that name documents in every tool, plus "id" on document_* tools (other
// than document_type_*, whose id is a document type).
func auditDocumentIDs(tool string, args map[string]any) []int {
	keys := []string{"ids", "documents", "document", "document_id", "more_like_id"}
	if strings.HasPrefix(tool, "document_") && !strings.HasPrefix(tool, "document_type_") {
		keys = append(keys, "id")
	}
	var ids []int
	seen := map[int]bool{}
	add := func(id int) {
		if !seen[id] && len(ids) < maxAuditIDs {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, key := range keys {
		switch v := args[key].(type) {
		case float64:
			add(int(v))
		case json.Number:
			if n, err := strconv.Atoi(v.String()); err == nil {
				add(n)
			}
		case string:
			s := strings.TrimSpace(v)
			if n, err := strconv.Atoi(s); err == nil {
				add(n)
				continue
			}
			var list []int
			if json.Unmarshal([]byte(s), &list) == nil {
				for _, n := range list {
					add(n)
				}
			}
		case []any:
			for _, item := range v {
				if n, ok := asInt(item); ok {
					add(n)
				}
			}
		}
	}
	return ids
}
