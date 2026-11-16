package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// serveFixture runs serve mode's HTTP handler against the fake Paperless,
// with the policy filter on and a fake Cloudflare Access.
type serveFixture struct {
	fp     *fakePaperless
	access *accessFixture
	srv    *httptest.Server
	logs   *lockedBuffer
}

func newServeFixture(t *testing.T) *serveFixture {
	t.Helper()
	fp := newFakePaperless(t)
	access := newAccessFixture(t)
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	client := fp.policyClient(t)
	srv := httptest.NewServer(newServeHandler(context.Background(), client, 2, access.config, logger))
	t.Cleanup(srv.Close)
	return &serveFixture{fp: fp, access: access, srv: srv, logs: logs}
}

// rpc sends one JSON-RPC request to /mcp with the given Access JWT ("" for
// none) and returns the HTTP status and the JSON-RPC response (from a JSON
// or an SSE body).
func (f *serveFixture) rpc(t *testing.T, token, method string, params any) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+mcpEndpointPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set(accessJWTHeader, token)
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, map[string]any{"raw": string(raw)}
	}
	payload := raw
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
				payload = []byte(strings.TrimSpace(data))
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("%s: response is not JSON-RPC: %s\n%s", method, err, raw)
	}
	return resp.StatusCode, out
}

func (f *serveFixture) call(t *testing.T, tool string, args map[string]any) (map[string]any, []byte) {
	t.Helper()
	status, out := f.rpc(t, f.access.token(t, nil), "tools/call", map[string]any{"name": tool, "arguments": args})
	if status != http.StatusOK {
		t.Fatalf("tools/call %s: status %d: %v", tool, status, out)
	}
	raw, _ := json.Marshal(out)
	return out, raw
}

// auditLines returns the "tool call" log entries.
func (f *serveFixture) auditLines(t *testing.T) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(f.logs.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) == nil && entry["msg"] == "tool call" {
			lines = append(lines, entry)
		}
	}
	return lines
}

func TestServeRejectsRequestsWithoutAccess(t *testing.T) {
	f := newServeFixture(t)
	expired := f.access.token(t, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
	for name, token := range map[string]string{"no token": "", "expired": expired} {
		status, out := f.rpc(t, token, "tools/call", map[string]any{"name": "document_get", "arguments": map[string]any{"id": docFull}})
		if status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401 (%v)", name, status, out)
		}
	}
	f.fp.mu.Lock()
	defer f.fp.mu.Unlock()
	if len(f.fp.log) != 0 {
		t.Errorf("unauthenticated requests reached Paperless: %v", f.fp.log)
	}
}

func TestServeHealthNeedsNoAuth(t *testing.T) {
	f := newServeFixture(t)
	resp, err := http.Get(f.srv.URL + healthPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("health: %d %q", resp.StatusCode, body)
	}
	// Anything else is not served.
	resp, err = http.Get(f.srv.URL + "/api/documents/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("other path: status %d, want 404", resp.StatusCode)
	}
}

func TestServeToolSet(t *testing.T) {
	f := newServeFixture(t)
	status, out := f.rpc(t, f.access.token(t, nil), "tools/list", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("tools/list: %d %v", status, out)
	}
	result := out["result"].(map[string]any)
	tools := map[string]map[string]any{}
	for _, tool := range result["tools"].([]any) {
		m := tool.(map[string]any)
		tools[m["name"].(string)] = m
	}
	for _, gone := range []string{"document_upload", "cleanup_downloads"} {
		if _, ok := tools[gone]; ok {
			t.Errorf("%s is offered in serve mode", gone)
		}
	}
	dl, ok := tools["document_download"]
	if !ok {
		t.Fatal("document_download missing")
	}
	props := dl["inputSchema"].(map[string]any)["properties"].(map[string]any)
	if got := slices.Sorted(maps.Keys(props)); !slices.Equal(got, []string{"ids", "variant"}) {
		t.Errorf("document_download parameters = %v, want ids and variant", got)
	}
	for _, kept := range []string{"document_get", "document_list", "document_page_image", "document_update", "tag_list"} {
		if _, ok := tools[kept]; !ok {
			t.Errorf("%s missing in serve mode", kept)
		}
	}
	if len(tools) < 100 {
		t.Errorf("only %d tools in serve mode", len(tools))
	}
}

func TestServeInstructionsMentionRemoteMode(t *testing.T) {
	f := newServeFixture(t)
	status, out := f.rpc(t, f.access.token(t, nil), "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "1"},
	})
	if status != http.StatusOK {
		t.Fatalf("initialize: %d %v", status, out)
	}
	instructions, _ := out["result"].(map[string]any)["instructions"].(string)
	if !strings.Contains(instructions, "## Remote (HTTP) Mode") || !strings.Contains(instructions, "## Tool Categories") {
		t.Errorf("instructions lack the remote note or the base text:\n%s", instructions)
	}
}

func TestServePolicyAndAuditLog(t *testing.T) {
	f := newServeFixture(t)

	_, raw := f.call(t, "document_get", map[string]any{"id": docMetadata})
	if bytes.Contains(raw, []byte(secretMarker)) || !bytes.Contains(raw, []byte("Tax assessment")) {
		t.Errorf("document_get over HTTP: %s", raw)
	}
	_, raw = f.call(t, "document_download", map[string]any{"ids": fmt.Sprintf("[%d]", docMetadata), "dest_dir": "x"})
	if bytes.Contains(raw, []byte(secretMarker)) || !bytes.Contains(raw, []byte("full text is not available for document 2")) {
		t.Errorf("document_download over HTTP: %s", raw)
	}
	_, raw = f.call(t, "document_download", map[string]any{"ids": fmt.Sprintf("[%d]", docFull)})
	if !bytes.Contains(raw, []byte(`"content"`)) || bytes.Contains(raw, []byte(`"path"`)) {
		t.Errorf("full-tier download over HTTP was not inline: %s", raw)
	}
	f.call(t, "tag_get", map[string]any{"id": tagInvoice})
	f.call(t, "document_get", map[string]any{"id": 999})

	lines := f.auditLines(t)
	if len(lines) != 5 {
		t.Fatalf("got %d audit lines, want 5:\n%s", len(lines), f.logs.String())
	}
	want := []struct {
		tool, result string
		docs         []float64
	}{
		{"document_get", "ok", []float64{docMetadata}},
		{"document_download", "refused_by_policy", []float64{docMetadata}},
		{"document_download", "ok", []float64{docFull}},
		{"tag_get", "ok", nil},
		{"document_get", "error", []float64{999}},
	}
	for i, w := range want {
		line := lines[i]
		if line["email"] != testEmail || line["tool"] != w.tool || line["result"] != w.result {
			t.Errorf("audit line %d = %v, want email %s, tool %s, result %s", i, line, testEmail, w.tool, w.result)
		}
		var docs []float64
		if list, ok := line["documents"].([]any); ok {
			for _, d := range list {
				docs = append(docs, d.(float64))
			}
		}
		if !slices.Equal(docs, w.docs) {
			t.Errorf("audit line %d documents = %v, want %v", i, docs, w.docs)
		}
	}
	for _, marker := range []string{secretMarker, publicMarker, "Tax assessment", "Electricity"} {
		if strings.Contains(f.logs.String(), marker) {
			t.Errorf("audit log contains document data %q", marker)
		}
	}
}

// TestServeNoLeakThroughAnyTool repeats the all-tools leak test over HTTP
// against the tool set serve mode offers.
func TestServeNoLeakThroughAnyTool(t *testing.T) {
	f := newServeFixture(t)
	status, out := f.rpc(t, f.access.token(t, nil), "tools/list", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("tools/list: %d", status)
	}
	upload := filepath.Join(t.TempDir(), "scan.pdf")
	os.WriteFile(upload, []byte("%PDF-1.4"), 0o600)

	var calls []leakCall
	for _, tool := range out["result"].(map[string]any)["tools"].([]any) {
		m := tool.(map[string]any)
		schemaJSON, _ := json.Marshal(m["inputSchema"])
		var parsed struct {
			Required   []string       `json:"required"`
			Properties map[string]any `json:"properties"`
		}
		json.Unmarshal(schemaJSON, &parsed)
		args := map[string]any{}
		for _, name := range parsed.Required {
			args[name] = leakArgValue(name, parsed.Properties[name], docMetadata, upload)
		}
		calls = append(calls, leakCall{m["name"].(string), args})
	}
	calls = append(calls, extraLeakCalls(docMetadata)...)

	found := map[string]bool{}
	for _, c := range calls {
		_, raw := f.call(t, c.tool, c.args)
		if leakScan(raw, secretMarker)[secretMarker] {
			found[c.tool] = true
		}
	}
	if len(found) > 0 {
		t.Errorf("secret marker leaked over HTTP through: %v", slices.Sorted(maps.Keys(found)))
	}

	// Liveness: the full-tier document's text does come through.
	_, raw := f.call(t, "document_get", map[string]any{"id": docFull})
	if !bytes.Contains(raw, []byte(publicMarker)) {
		t.Error("full-tier text did not come through over HTTP")
	}
}

// leakArgValue is leakArgs for a single parameter given its JSON schema.
func leakArgValue(name string, schema any, doc int, upload string) any {
	m, _ := schema.(map[string]any)
	switch name {
	case "ids", "documents":
		return fmt.Sprintf("[%d]", doc)
	case "objects", "tasks":
		return "[1]"
	case "parameters", "body":
		return "{}"
	case "file_path":
		return upload
	case "to":
		return "someone@example.com"
	case "object_type":
		return "tags"
	case "operation":
		return "delete"
	case "method":
		return "set_correspondent"
	case "action":
		return "restore"
	case "data_type":
		return "string"
	case "path":
		return "{{ document.content }}"
	case "term", "query":
		return "tax"
	}
	if enum, ok := m["enum"].([]any); ok && len(enum) > 0 {
		return enum[0]
	}
	switch t := m["type"].(type) {
	case string:
		switch t {
		case "boolean":
			return false
		case "number", "integer":
			return doc
		}
		return "x"
	}
	return doc
}

func TestServeRefusesToStart(t *testing.T) {
	fp := newFakePaperless(t)
	access := map[string]string{
		envAccessTeamDomain: "example-team.cloudflareaccess.com",
		envAccessAUD:        testAccessAUD,
		envAllowedEmails:    testEmail,
	}
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"policy filter off", access, "serve requires the policy filter: set PAPERLESS_MCP_POLICY_ENABLED=true"},
		{"no Access team domain", merge(testPolicyEnv(), access, map[string]string{envAccessTeamDomain: ""}), "serve requires PAPERLESS_MCP_ACCESS_TEAM_DOMAIN"},
		{"no Access AUD", merge(testPolicyEnv(), access, map[string]string{envAccessAUD: ""}), "serve requires PAPERLESS_MCP_ACCESS_AUD"},
		{"no allowed emails", merge(testPolicyEnv(), access, map[string]string{envAllowedEmails: ""}), "serve requires PAPERLESS_MCP_ALLOWED_EMAILS"},
		{"policy misconfigured", merge(testPolicyEnv(), access, map[string]string{envPolicyFullTags: ""}), "PAPERLESS_MCP_POLICY_FULL_TAGS must name at least one tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{envPolicyEnabled, envPolicyFullTags, envPolicyMetadataTags, envPolicyRestrictedTags,
				envPolicyProtectedTags, envPolicyProtectedCustomFields, envAccessTeamDomain, envAccessAUD, envAllowedEmails} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			t.Setenv("PAPERLESS_URL", fp.srv.URL)
			t.Setenv("PAPERLESS_TOKEN", "test-token")
			t.Setenv(envHTTPAddr, "127.0.0.1:0")

			var stderr bytes.Buffer
			cmd := rootCmd()
			cmd.SetArgs([]string{"serve"})
			cmd.SetOut(&stderr)
			cmd.SetErr(&stderr)
			if err := cmd.ExecuteContext(context.Background()); err == nil {
				t.Fatal("serve started, want it to refuse")
			}
			if !strings.HasPrefix(stderr.String(), "Error: ") || !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want %q", stderr.String(), tc.wantErr)
			}
			if strings.Contains(stderr.String(), "Usage:") || strings.Contains(stderr.String(), "test-token") {
				t.Errorf("stderr has usage or the token:\n%s", stderr.String())
			}
		})
	}
}

func merge(maps_ ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps_ {
		maps.Copy(out, m)
	}
	return out
}

func TestServeStartsAndStopsCleanly(t *testing.T) {
	fp := newFakePaperless(t)
	env := merge(testPolicyEnv(), map[string]string{
		envAccessTeamDomain: "example-team.cloudflareaccess.com",
		envAccessAUD:        testAccessAUD,
		envAllowedEmails:    testEmail,
		"PAPERLESS_URL":     fp.srv.URL,
		"PAPERLESS_TOKEN":   "test-token",
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	env[envHTTPAddr] = addr
	for k, v := range env {
		t.Setenv(k, v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stderr lockedBuffer
	done := make(chan error, 1)
	go func() {
		cmd := rootCmd()
		cmd.SetArgs([]string{"serve"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(&stderr)
		done <- cmd.ExecuteContext(ctx)
	}()

	// Wait until the health endpoint answers, then use the healthcheck command.
	deadline := time.Now().Add(10 * time.Second)
	for {
		hc := rootCmd()
		hc.SetArgs([]string{"healthcheck"})
		hc.SetOut(io.Discard)
		hc.SetErr(io.Discard)
		if hc.Execute() == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("serve never became healthy:\n%s", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stderr.String(), "policy filter: enabled") || !strings.Contains(stderr.String(), "serve: listening on "+addr) {
		t.Errorf("startup log:\n%s", stderr.String())
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v after shutdown, want nil", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop")
	}

	// With the server gone, the healthcheck fails.
	hc := rootCmd()
	hc.SetArgs([]string{"healthcheck"})
	hc.SetOut(io.Discard)
	hc.SetErr(io.Discard)
	if hc.Execute() == nil {
		t.Error("healthcheck succeeded with no server running")
	}
}

func TestHealthURL(t *testing.T) {
	for in, want := range map[string]string{
		"":               "http://127.0.0.1:8080/healthz",
		":9000":          "http://127.0.0.1:9000/healthz",
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://127.0.0.1:8080/healthz",
		"10.1.2.3:8080":  "http://10.1.2.3:8080/healthz",
		"localhost:8081": "http://localhost:8081/healthz",
	} {
		if got, err := healthURL(in); err != nil || got != want {
			t.Errorf("healthURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := healthURL("no-port"); err == nil {
		t.Error("healthURL accepted an address without a port")
	}
}

func TestAuditDocumentIDs(t *testing.T) {
	for _, tc := range []struct {
		tool string
		args map[string]any
		want []int
	}{
		{"document_get", map[string]any{"id": float64(616)}, []int{616}},
		{"document_get", map[string]any{"id": "616"}, []int{616}},
		{"document_download", map[string]any{"ids": "[1, 2, 2]"}, []int{1, 2}},
		{"document_bulk_edit", map[string]any{"documents": "[3]", "method": "add_tag"}, []int{3}},
		{"document_list", map[string]any{"more_like_id": float64(9), "query": "tax"}, []int{9}},
		{"share_link_create", map[string]any{"document": float64(5)}, []int{5}},
		{"storage_path_test", map[string]any{"document_id": float64(7), "path": "x"}, []int{7}},
		{"document_type_get", map[string]any{"id": float64(4)}, nil},
		{"tag_get", map[string]any{"id": float64(10)}, nil},
	} {
		if got := auditDocumentIDs(tc.tool, tc.args); !slices.Equal(got, tc.want) {
			t.Errorf("auditDocumentIDs(%s, %v) = %v, want %v", tc.tool, tc.args, got, tc.want)
		}
	}
}
