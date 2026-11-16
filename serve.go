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
	envTools         = "PAPERLESS_MCP_TOOLS"
	envHTTPAddr      = "PAPERLESS_MCP_HTTP_ADDR"
	defaultHTTPAddr  = ":8080"
	mcpEndpointPath  = "/mcp"
	healthPath       = "/healthz"
	maxRequestBody   = 16 << 20 // JSON-RPC requests are small; this only caps abuse
	healthcheckLimit = 5 * time.Second
)

// shutdownTimeout is how long a shutdown waits for requests in flight before
// closing their connections. A variable so tests can shorten it.
var shutdownTimeout = 10 * time.Second

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
			tools := splitPolicyNames(os.Getenv(envTools))
			if err := checkRemoteTools(tools); err != nil {
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
			handler, err := newServeHandler(ctx, client, downloadConcurrency, tools, access, logger)
			if err != nil {
				return err
			}

			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen on %s: %w", addr, err)
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "serve: listening on %s, MCP endpoint %s, Access issuer %s, %d allowed email(s), %d tool(s): %s\n",
				ln.Addr(), mcpEndpointPath, access.Issuer, len(access.AllowedEmails), len(tools), strings.Join(tools, ","))
			return runHTTPServer(ctx, ln, handler)
		},
	}

	cmd.Flags().IntVar(&downloadConcurrency, "download-concurrency", 5, "Max parallel document downloads")
	return cmd
}

// newServeHandler builds the HTTP handler for serve mode: an unauthenticated
// health endpoint, and the MCP endpoint behind the Access check.
func newServeHandler(ctx context.Context, client *Client, downloadConcurrency int, tools []string, access accessConfig, logger *slog.Logger) (http.Handler, error) {
	srv, err := newRemoteMCPServer(client, downloadConcurrency, tools, logger)
	if err != nil {
		return nil, err
	}
	streamable := server.NewStreamableHTTPServer(srv,
		server.WithEndpointPath(mcpEndpointPath),
		server.WithStateLess(true),
		// mcp-go refuses requests that arrive on a loopback address with a
		// non-loopback Host header, to stop DNS rebinding against
		// unauthenticated local servers. Here every request needs a signed
		// Access JWT, which a rebinding page cannot produce, and the check
		// would break a tunnel connector that reaches serve via localhost
		// (it forwards the public hostname as Host).
		server.WithDisableLocalhostProtection(true),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	// The key set outlives the signal context, so keys can still be fetched
	// while requests drain during shutdown.
	verifier := newAccessVerifier(context.WithoutCancel(ctx), access)
	mux.Handle(mcpEndpointPath, requireAccess(verifier, logger,
		postOnly(http.MaxBytesHandler(streamable, maxRequestBody))))
	return mux, nil
}

// postOnly lets only POST through to the MCP endpoint. Sessions are
// stateless and no tool sends server-initiated messages, so the optional GET
// stream is not offered (the MCP spec allows 405 for it). In mcp-go a GET
// would register a long-lived session that later stateless requests join,
// and its open stream would hold up shutdown.
func postOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newRemoteMCPServer is the MCP server for serve mode: remoteToolSet reduced
// to the tools in allowed. Every name must be a tool serve offers, so a typo
// or a tool that is not available over HTTP stops serve from starting; an
// empty list is refused too.
func newRemoteMCPServer(client *Client, downloadConcurrency int, allowed []string, logger *slog.Logger) (*server.MCPServer, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("serve requires %s: a comma-separated list of the tools to offer", envTools)
	}
	srv := remoteToolSet(client, downloadConcurrency, logger)
	offered := srv.ListTools()
	keep := map[string]bool{}
	var unknown []string
	for _, name := range allowed {
		if _, ok := offered[name]; !ok {
			unknown = append(unknown, name)
		}
		keep[name] = true
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%s names tools serve does not offer: %s (document_upload and cleanup_downloads are not available over HTTP)",
			envTools, strings.Join(unknown, ", "))
	}
	var drop []string
	for name := range offered {
		if !keep[name] {
			drop = append(drop, name)
		}
	}
	srv.DeleteTools(drop...)
	return srv, nil
}

// checkRemoteTools validates a tool allowlist without contacting Paperless,
// so a bad list fails before any network call. The tool handlers are never
// invoked here, so the client is an empty placeholder.
func checkRemoteTools(allowed []string) error {
	_, err := newRemoteMCPServer(&Client{}, 1, allowed, slog.New(slog.DiscardHandler))
	return err
}

// remoteToolSet is NewServer for serve mode: the same tools, minus the ones
// that read or write the server's own disk, with an audit log of every tool
// call.
func remoteToolSet(client *Client, downloadConcurrency int, logger *slog.Logger) *server.MCPServer {
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
		ReadTimeout:       time.Minute, // request bodies are small JSON-RPC messages
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: an inline download of a large document can take a
		// while to stream out.
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
			// Requests still running after the grace period are cut off. The
			// shutdown was requested, so this is still a clean exit.
			_ = httpSrv.Close()
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
			docs := auditDocumentIDs(request)
			failed := err != nil || result == nil || result.IsError
			outcome := "ok"
			switch {
			case blocks > 0 && (failed || blocks >= len(docs)):
				outcome = "refused_by_policy"
			case blocks > 0:
				// Some requests were blocked and the rest succeeded, as in a
				// download of several documents of which some are refused.
				outcome = "partly_refused_by_policy"
			case failed:
				outcome = "error"
			}
			logger.Info("tool call",
				"email", identityFrom(ctx),
				"tool", request.Params.Name,
				"documents", docs,
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

// auditDocumentIDs extracts the document IDs a tool call names, parsed the
// way the tool handlers parse them (numbers via GetFloat, truncated to int;
// ID lists as JSON arrays of integers). Only parameters that hold document
// IDs count: on document_* tools (not document_type_*) "id", "ids",
// "documents" and "more_like_id"; elsewhere the named document parameters
// of share_link_create, storage_path_test and trash_action.
func auditDocumentIDs(request mcp.CallToolRequest) []int {
	tool := request.Params.Name
	var scalars, lists []string
	switch {
	case strings.HasPrefix(tool, "document_") && !strings.HasPrefix(tool, "document_type_"):
		scalars = []string{"id", "more_like_id"}
		lists = []string{"ids", "documents"}
	case tool == "share_link_create":
		scalars = []string{"document"}
	case tool == "storage_path_test":
		scalars = []string{"document_id"}
	case tool == "trash_action":
		lists = []string{"documents"}
	}

	args := request.GetArguments()
	var ids []int
	seen := map[int]bool{}
	add := func(id int) {
		if !seen[id] && len(ids) < maxAuditIDs {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, key := range scalars {
		if _, ok := args[key]; ok {
			add(int(request.GetFloat(key, 0)))
		}
	}
	for _, key := range lists {
		s, ok := args[key].(string)
		if !ok {
			continue
		}
		// Floats as well: bulk tools pass the list to Paperless as given.
		var list []float64
		if json.Unmarshal([]byte(s), &list) == nil {
			for _, n := range list {
				add(int(n))
			}
		}
	}
	return ids
}
