package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// Markers placed in document text and files. The metadata-tier marker must
// never reach a tool result; the full-tier marker must, which proves the
// checks look at live data.
const (
	secretMarker = "SECRET-7f3a"
	publicMarker = "PUBLIC-c9d2"
)

// Document IDs served by the fake Paperless.
const (
	docFull     = 1 // dp:internal
	docMetadata = 2 // dp:confidential
	docTrashed  = 3 // dp:confidential, in the trash
	docUntagged = 4 // no tier tag
)

// --- Fake Paperless ---

type fakeTag struct {
	Name   string
	Parent int // 0: none
}

type fakeDoc struct {
	ID           int
	Title        string
	Tags         []int
	Content      string
	CustomFields []map[string]any
	Deleted      bool
}

// fakePaperless is an in-memory Paperless-ngx API with enough behaviour for
// every tool: documents with text, files, history and suggestions that carry
// the markers, tag and custom field lookups, search, trash and the bulk
// endpoints.
type fakePaperless struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	docs   map[int]*fakeDoc
	tags   map[int]fakeTag
	fields map[int]string
	log    []string // "METHOD /path?query" of every request received
}

func newFakePaperless(t *testing.T) *fakePaperless {
	t.Helper()
	fp := &fakePaperless{
		t: t,
		docs: map[int]*fakeDoc{
			docFull: {ID: docFull, Title: "Electricity bill", Tags: []int{tagInternal, tagInvoice},
				Content: "Electricity bill " + publicMarker + " amount due 42 EUR",
				CustomFields: []map[string]any{
					{"field": fieldSummary, "value": "Electricity bill for May"},
					{"field": fieldPrivacyClass, "value": "internal"},
				}},
			docMetadata: {ID: docMetadata, Title: "Tax assessment", Tags: []int{tagConfidential, tagInvoice},
				Content: "Tax assessment " + secretMarker + " IBAN DE00 0000",
				CustomFields: []map[string]any{
					{"field": fieldSummary, "value": "Tax assessment 2025, refund expected"},
					{"field": fieldPrivacyClass, "value": "confidential"},
					{"field": fieldTriggers, "value": "own-iban"},
				}},
			docTrashed: {ID: docTrashed, Title: "Old payslip", Tags: []int{tagConfidential},
				Content: "Payslip " + secretMarker, Deleted: true},
			docUntagged: {ID: docUntagged, Title: "Unclassified letter", Tags: []int{tagInvoice},
				Content: "Unclassified " + secretMarker},
		},
		tags: map[int]fakeTag{
			tagPublic: {Name: "dp:public"}, tagInternal: {Name: "dp:internal"},
			tagConfidential: {Name: "dp:confidential"}, tagReview: {Name: "dp:manual-review"},
			tagRestricted: {Name: "dp:restricted"},
			tagReprocess:  {Name: "gpt-reprocess"}, tagReset: {Name: "gpt-reset"},
			tagInvoice: {Name: "invoice"},
		},
		fields: map[int]string{
			fieldPrivacyClass: "AI privacy class", fieldTriggers: "Privacy triggers", fieldSummary: "Summary",
		},
	}
	fp.srv = httptest.NewServer(fp)
	t.Cleanup(fp.srv.Close)
	return fp
}

// policyClient returns a client for fp with the policy filter enabled and
// configured from testPolicyEnv, resolving names against fp.
func (fp *fakePaperless) policyClient(t *testing.T) *Client {
	t.Helper()
	opts, err := configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), fp.srv.URL, "test-token", http.DefaultTransport, io.Discard)
	if err != nil {
		t.Fatalf("configurePolicy: %s", err)
	}
	fp.resetLog()
	return NewClient(fp.srv.URL, "test-token", opts...)
}

func (fp *fakePaperless) resetLog() {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.log = nil
}

// received reports whether a request with this method and exact path reached
// the fake (lookups use other paths or carry a fields= query).
func (fp *fakePaperless) received(method, path string) bool {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for _, entry := range fp.log {
		m, rest, _ := strings.Cut(entry, " ")
		p, query, _ := strings.Cut(rest, "?")
		if m == method && p == path && !strings.Contains(query, "fields=id%2Ctags") {
			return true
		}
	}
	return false
}

func (fp *fakePaperless) setTags(id int, tags ...int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.docs[id].Tags = tags
}

func (fp *fakePaperless) setTagParent(id, parent int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	tag := fp.tags[id]
	tag.Parent = parent
	fp.tags[id] = tag
}

func (fp *fakePaperless) addTag(id int, name string, parent int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.tags[id] = fakeTag{Name: name, Parent: parent}
}

func (fp *fakePaperless) docJSON(d *fakeDoc, fields string) map[string]any {
	m := map[string]any{
		"id": d.ID, "title": d.Title, "tags": d.Tags, "content": d.Content,
		"custom_fields": d.CustomFields, "correspondent": nil, "document_type": nil,
		"notes": []any{map[string]any{"id": 1, "note": "called the office"}},
	}
	if d.CustomFields == nil {
		m["custom_fields"] = []any{}
	}
	if d.Deleted {
		m["deleted_at"] = "2026-11-01T00:00:00Z"
	}
	if fields != "" {
		keep := strings.Split(fields, ",")
		for k := range m {
			if !slices.Contains(keep, k) {
				delete(m, k)
			}
		}
	}
	return m
}

func (fp *fakePaperless) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

var fakeDocPath = regexp.MustCompile(`^/api/documents/(\d+)/(?:([a-z_]+)/)?$`)

func (fp *fakePaperless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Token test-token" {
		fp.t.Errorf("fake Paperless: %s %s with Authorization %q", r.Method, r.URL.Path, got)
	}
	fp.mu.Lock()
	fp.log = append(fp.log, r.Method+" "+r.URL.RequestURI())
	fp.mu.Unlock()

	q := r.URL.Query()
	path := r.URL.Path

	if m := fakeDocPath.FindStringSubmatch(path); m != nil {
		id, _ := strconv.Atoi(m[1])
		fp.mu.Lock()
		d, ok := fp.docs[id]
		fp.mu.Unlock()
		// Like Paperless, the document endpoints hide trashed documents.
		if !ok || (d.Deleted && m[2] == "") {
			fp.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "No Document matches the given query."})
			return
		}
		fp.serveDocument(w, r, d, m[2])
		return
	}

	switch {
	case path == "/api/tags/" && r.Method == http.MethodGet:
		fp.serveTags(w, q)
	case path == "/api/custom_fields/" && r.Method == http.MethodGet:
		var results []map[string]any
		for _, id := range sortedKeys(boolKeys(fp.fields)) {
			if n := q.Get("name__iexact"); n == "" || strings.EqualFold(n, fp.fields[id]) {
				results = append(results, map[string]any{"id": id, "name": fp.fields[id], "data_type": "string"})
			}
		}
		fp.writeJSON(w, http.StatusOK, paginatedResponse(results, len(results)))
	case path == "/api/documents/" && r.Method == http.MethodGet:
		fp.serveDocumentList(w, q)
	case path == "/api/search/":
		var docs []map[string]any
		for _, d := range fp.liveDocs() {
			docs = append(docs, fp.docJSON(d, ""))
		}
		fp.writeJSON(w, http.StatusOK, map[string]any{"total": len(docs), "documents": docs, "tags": []any{}, "correspondents": []any{}})
	case path == "/api/search/autocomplete/":
		// Paperless suggests whole words from the text index, lowercased.
		// That autocomplete can reveal words of metadata-tier documents is a
		// documented, accepted residual risk (README, "Policy filter").
		term := strings.ToLower(q.Get("term"))
		words := []string{}
		for _, d := range fp.liveDocs() {
			for _, w := range regexp.MustCompile(`[a-z0-9]+`).FindAllString(strings.ToLower(d.Content), -1) {
				if strings.HasPrefix(w, term) && !slices.Contains(words, w) {
					words = append(words, w)
				}
			}
		}
		fp.writeJSON(w, http.StatusOK, words)
	case path == "/api/trash/" && r.Method == http.MethodGet:
		var docs []map[string]any
		for _, id := range sortedKeys(boolKeys(fp.docs)) {
			if d := fp.docs[id]; d.Deleted {
				docs = append(docs, fp.docJSON(d, ""))
			}
		}
		fp.writeJSON(w, http.StatusOK, paginatedResponse(docs, len(docs)))
	case path == "/api/storage_paths/test/":
		// Paperless renders the template with the document, content included.
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Document int `json:"document"`
		}
		json.Unmarshal(body, &req)
		content := ""
		if d, ok := fp.docs[req.Document]; ok {
			content = d.Content
		}
		fp.writeJSON(w, http.StatusOK, "archive/"+content)
	case path == "/api/documents/bulk_download/":
		w.Header().Set("Content-Type", "application/zip")
		for _, d := range fp.docs {
			io.WriteString(w, d.Content)
		}
	case path == "/api/documents/chat/":
		w.Header().Set("Content-Type", "text/event-stream")
		for _, d := range fp.docs {
			io.WriteString(w, "data: "+d.Content+"\n\n")
		}
	case path == "/api/documents/next_asn/":
		fp.writeJSON(w, http.StatusOK, 7)
	case path == "/api/documents/post_document/":
		fp.writeJSON(w, http.StatusOK, "6f1e1d4a-task")
	case path == "/api/documents/selection_data/":
		fp.writeJSON(w, http.StatusOK, map[string]any{"documents": []any{}, "selected_tags": []any{}})
	case path == "/api/tasks/" || path == "/api/logs/":
		fp.writeJSON(w, http.StatusOK, []any{})
	case strings.HasPrefix(path, "/api/logs/"):
		fp.writeJSON(w, http.StatusOK, []string{"[2026-11-14] INFO started"})
	case r.Method == http.MethodGet && strings.Count(path, "/") == 3:
		fp.writeJSON(w, http.StatusOK, paginatedResponse([]any{}, 0))
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		fp.writeJSON(w, http.StatusOK, map[string]any{"id": 1, "result": "OK"})
	}
}

func boolKeys[V any](m map[int]V) map[int]bool {
	out := make(map[int]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func (fp *fakePaperless) liveDocs() []*fakeDoc {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	var docs []*fakeDoc
	for _, id := range sortedKeys(boolKeys(fp.docs)) {
		if d := fp.docs[id]; !d.Deleted {
			docs = append(docs, d)
		}
	}
	return docs
}

func (fp *fakePaperless) serveTags(w http.ResponseWriter, q url.Values) {
	fp.mu.Lock()
	ids := sortedKeys(boolKeys(fp.tags))
	tags := maps.Clone(fp.tags)
	fp.mu.Unlock()

	var all []map[string]any
	for _, id := range ids {
		tag := tags[id]
		if n := q.Get("name__iexact"); n != "" && !strings.EqualFold(n, tag.Name) {
			continue
		}
		var parent any
		if tag.Parent != 0 {
			parent = tag.Parent
		}
		all = append(all, map[string]any{"id": id, "name": tag.Name, "parent": parent})
	}
	// Serve two tags per page so the hierarchy lookup has to page.
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	size := 2
	if q.Get("name__iexact") != "" {
		size = len(all) + 1
	}
	start := min((page-1)*size, len(all))
	end := min(start+size, len(all))
	resp := paginatedResponse(all[start:end], len(all))
	if end < len(all) {
		resp["next"] = fmt.Sprintf("%s/api/tags/?page=%d", fp.srv.URL, page+1)
	}
	fp.writeJSON(w, http.StatusOK, resp)
}

func (fp *fakePaperless) serveDocumentList(w http.ResponseWriter, q url.Values) {
	var ids []int
	if in := q.Get("id__in"); in != "" {
		for s := range strings.SplitSeq(in, ",") {
			id, _ := strconv.Atoi(s)
			ids = append(ids, id)
		}
	}
	more, _ := strconv.Atoi(q.Get("more_like_id"))
	var results []map[string]any
	for _, d := range fp.liveDocs() {
		if ids != nil && !slices.Contains(ids, d.ID) {
			continue
		}
		if more != 0 && d.ID == more {
			continue
		}
		doc := fp.docJSON(d, q.Get("fields"))
		if q.Get("query") != "" {
			doc["__search_hit__"] = map[string]any{
				"score": 1.5, "rank": 1,
				"highlights":      "…<span>" + d.Content + "</span>…",
				"note_highlights": "called the <span>office</span>",
			}
		}
		results = append(results, doc)
	}
	resp := paginatedResponse(results, len(results))
	resp["all"] = []int{docFull, docMetadata, docUntagged}
	fp.writeJSON(w, http.StatusOK, resp)
}

func (fp *fakePaperless) serveDocument(w http.ResponseWriter, r *http.Request, d *fakeDoc, action string) {
	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			fp.writeJSON(w, http.StatusOK, fp.docJSON(d, r.URL.Query().Get("fields")))
		case http.MethodPatch, http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var patch map[string]any
			if err := json.Unmarshal(body, &patch); err != nil {
				fp.writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "bad json"})
				return
			}
			fp.mu.Lock()
			if v, ok := patch["title"].(string); ok {
				d.Title = v
			}
			if v, ok := patch["tags"].([]any); ok {
				d.Tags = nil
				for _, t := range v {
					d.Tags = append(d.Tags, int(t.(float64)))
				}
			}
			fp.mu.Unlock()
			fp.writeJSON(w, http.StatusOK, fp.docJSON(d, ""))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	case "download", "preview":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="doc-%d.txt"`, d.ID))
		io.WriteString(w, "FILE "+d.Content)
	case "thumb":
		w.Header().Set("Content-Type", "image/webp")
		io.WriteString(w, "RIFF-THUMB "+d.Content)
	case "history":
		fp.writeJSON(w, http.StatusOK, []any{map[string]any{
			"id": 9, "action": "update", "changes": map[string]any{"content": []string{"", d.Content}},
		}})
	case "suggestions", "ai_suggestions":
		fp.writeJSON(w, http.StatusOK, map[string]any{"title": d.Content, "tags": []int{}})
	case "metadata":
		fp.writeJSON(w, http.StatusOK, map[string]any{"original_checksum": "abc", "original_mime_type": "application/pdf"})
	case "notes":
		fp.writeJSON(w, http.StatusOK, []any{map[string]any{"id": 1, "note": "called the office"}})
	case "share_links":
		fp.writeJSON(w, http.StatusOK, []any{})
	case "root":
		fp.writeJSON(w, http.StatusOK, map[string]any{"root_id": d.ID})
	default:
		// Unknown action: answer with text, as a future content endpoint might.
		fp.writeJSON(w, http.StatusOK, map[string]any{"text": d.Content})
	}
}

// --- Request helpers ---

// send performs a request through the client (so through the policy filter)
// and returns the status and body. body may be a []byte (sent as is with
// contentType) or any value to encode as JSON.
func send(t *testing.T, c *Client, method, path string, body any, contentType string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
		contentType = "application/json"
	}
	req, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.doWithAccept(req, "application/json; version="+apiVersion+", */*")
	if err != nil {
		t.Fatalf("%s %s: %s", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(data)) {
		t.Errorf("%s %s: Content-Length %s, body %d bytes", method, path, cl, len(data))
	}
	return resp.StatusCode, data
}

// assertBlocked checks a synthetic policy response and that the request did
// not reach Paperless.
func assertBlocked(t *testing.T, fp *fakePaperless, status int, body []byte, method, path, wantReason string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s %s: status %d, want 403 (body %s)", method, path, status, body)
	}
	var detail struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &detail); err != nil || !strings.HasPrefix(detail.Detail, "policy: ") {
		t.Fatalf("%s %s: body %s, want {\"detail\": \"policy: …\"}", method, path, body)
	}
	if !strings.Contains(detail.Detail, wantReason) {
		t.Errorf("%s %s: reason %q, want it to contain %q", method, path, detail.Detail, wantReason)
	}
	if strings.Contains(string(body), "test-token") || strings.Contains(string(body), secretMarker) {
		t.Errorf("%s %s: blocked response leaks the token or document text: %s", method, path, body)
	}
	if fp.received(method, path) {
		t.Errorf("%s %s: blocked request reached Paperless", method, path)
	}
}

func assertPassed(t *testing.T, fp *fakePaperless, status int, body []byte, method, path string) {
	t.Helper()
	if status == http.StatusForbidden {
		t.Fatalf("%s %s: blocked, want it to pass: %s", method, path, body)
	}
	if !fp.received(method, path) {
		t.Errorf("%s %s: request did not reach Paperless", method, path)
	}
}

func multipartBody(t *testing.T, fields map[string][]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		for _, v := range fields[k] {
			mw.WriteField(k, v)
		}
	}
	part, _ := mw.CreateFormFile("document", "scan.pdf")
	part.Write([]byte("%PDF-1.4"))
	mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

// --- Rule 1: single-document requests (section 6.2) ---

func TestPolicySingleDocumentRules(t *testing.T) {
	for _, tc := range []struct {
		method, action string
		query          string
		fullPasses     bool
		metadataPasses bool
	}{
		{"GET", "", "", true, true},
		{"GET", "download", "", true, false},
		{"GET", "download", "original=true", true, false},
		{"GET", "preview", "", true, false},
		{"GET", "thumb", "", true, false},
		{"GET", "history", "", true, false},
		{"GET", "suggestions", "", true, false},
		{"GET", "ai_suggestions", "", true, false},
		{"GET", "metadata", "", true, true},
		{"GET", "notes", "", true, true},
		{"POST", "notes", "", true, true},
		{"DELETE", "notes", "id=1", true, true},
		{"GET", "share_links", "", true, true},
		{"GET", "root", "", true, false},
		{"GET", "foo", "", true, false},
		{"POST", "update_version", "", true, false},
	} {
		for _, doc := range []int{docFull, docMetadata} {
			name := fmt.Sprintf("%s %s doc %d", tc.method, tc.action, doc)
			t.Run(name, func(t *testing.T) {
				fp := newFakePaperless(t)
				c := fp.policyClient(t)
				path := fmt.Sprintf("/api/documents/%d/", doc)
				if tc.action != "" {
					path += tc.action + "/"
				}
				target := path
				if tc.query != "" {
					target += "?" + tc.query
				}
				var body any
				if tc.method == "POST" {
					body = map[string]string{"note": "hello"}
				}
				status, data := send(t, c, tc.method, target, body, "")
				passes := tc.metadataPasses
				if doc == docFull {
					passes = tc.fullPasses
				}
				if passes {
					assertPassed(t, fp, status, data, tc.method, path)
				} else {
					assertBlocked(t, fp, status, data, tc.method, path, fmt.Sprintf("full text is not available for document %d (tier: metadata)", doc))
				}
			})
		}
	}
}

func TestPolicyDocumentEmailAlwaysBlocked(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "POST", "/api/documents/1/email/", map[string]any{"addresses": "a@example.com"}, "")
	assertBlocked(t, fp, status, data, "POST", "/api/documents/1/email/", "emailing documents is not allowed")
}

func TestPolicyLookupNotFoundPassesThrough(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	// Trashed documents and unknown IDs (including version IDs, which the
	// document endpoints do not list) are not found by the tier lookup.
	for _, id := range []int{docTrashed, 999} {
		path := fmt.Sprintf("/api/documents/%d/download/", id)
		status, data := send(t, c, "GET", path, nil, "")
		if status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404 (body %s)", path, status, data)
		}
		if fp.received("GET", path) {
			t.Errorf("GET %s reached Paperless after the lookup returned 404", path)
		}
	}
}

func TestPolicyRestrictedAndUntaggedDocuments(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "GET", "/api/documents/4/download/", nil, "")
	assertBlocked(t, fp, status, data, "GET", "/api/documents/4/download/", "document 4 (tier: metadata)")

	fp.setTags(docFull, tagPublic, tagRestricted)
	status, data = send(t, c, "GET", "/api/documents/1/download/", nil, "")
	assertBlocked(t, fp, status, data, "GET", "/api/documents/1/download/", "document 1 (tier: restricted)")
}

// --- Rule 1: responses (section 6.3) ---

func decodeBody(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("response is not JSON: %s\n%s", err, data)
	}
	return v
}

func docsByID(t *testing.T, v any) map[int]map[string]any {
	t.Helper()
	out := map[int]map[string]any{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if id, ok := x["id"].(float64); ok {
				if _, has := x["title"]; has {
					out[int(id)] = x
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

func TestPolicyResponseFilterList(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "GET", "/api/documents/?page_size=25", nil, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, data)
	}
	docs := docsByID(t, decodeBody(t, data))
	if docs[docFull]["content"] == nil || !strings.Contains(docs[docFull]["content"].(string), publicMarker) {
		t.Errorf("full-tier document lost its content: %v", docs[docFull])
	}
	for _, id := range []int{docMetadata, docUntagged} {
		if _, has := docs[id]["content"]; has {
			t.Errorf("document %d still has content", id)
		}
		if docs[id]["title"] == nil || docs[id]["custom_fields"] == nil || docs[id]["notes"] == nil {
			t.Errorf("document %d lost metadata: %v", id, docs[id])
		}
	}
	if bytes.Contains(data, []byte(secretMarker)) {
		t.Errorf("list response contains the secret marker")
	}
}

func TestPolicyResponseFilterGetAndPatch(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)

	status, data := send(t, c, "GET", "/api/documents/2/", nil, "")
	if status != http.StatusOK || bytes.Contains(data, []byte(secretMarker)) {
		t.Fatalf("GET metadata document: status %d, body %s", status, data)
	}
	doc := decodeBody(t, data).(map[string]any)
	if _, has := doc["content"]; has || doc["title"] != "Tax assessment" {
		t.Errorf("GET metadata document = %v, want title without content", doc)
	}

	status, data = send(t, c, "PATCH", "/api/documents/2/", map[string]any{"title": "Tax assessment 2025"}, "")
	if status != http.StatusOK || bytes.Contains(data, []byte(secretMarker)) {
		t.Fatalf("PATCH metadata document: status %d, body %s", status, data)
	}
	if doc := decodeBody(t, data).(map[string]any); doc["title"] != "Tax assessment 2025" {
		t.Errorf("PATCH response = %v", doc)
	}

	status, data = send(t, c, "GET", "/api/documents/1/", nil, "")
	if status != http.StatusOK || !bytes.Contains(data, []byte(publicMarker)) {
		t.Errorf("GET full document: status %d, body %s", status, data)
	}
}

func TestPolicyResponseFilterSearchHits(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "GET", "/api/documents/?query=tax", nil, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, data)
	}
	if bytes.Contains(data, []byte(secretMarker)) {
		t.Fatalf("search response contains the secret marker: %s", data)
	}
	docs := docsByID(t, decodeBody(t, data))
	hit := docs[docMetadata]["__search_hit__"].(map[string]any)
	if _, has := hit["highlights"]; has {
		t.Errorf("metadata hit kept highlights: %v", hit)
	}
	for _, key := range []string{"score", "rank", "note_highlights"} {
		if _, has := hit[key]; !has {
			t.Errorf("metadata hit lost %s: %v", key, hit)
		}
	}
	full := docs[docFull]["__search_hit__"].(map[string]any)
	if !strings.Contains(full["highlights"].(string), publicMarker) {
		t.Errorf("full hit lost highlights: %v", full)
	}
}

func TestPolicyResponseFilterGlobalSearchAndTrash(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	for _, path := range []string{"/api/search/?query=tax", "/api/trash/"} {
		status, data := send(t, c, "GET", path, nil, "")
		if status != http.StatusOK || bytes.Contains(data, []byte(secretMarker)) {
			t.Errorf("GET %s: status %d, body %s", path, status, data)
		}
	}
	_, data := send(t, c, "GET", "/api/search/?query=bill", nil, "")
	if !bytes.Contains(data, []byte(publicMarker)) {
		t.Errorf("global search lost full-tier content: %s", data)
	}
}

func TestPolicyResponseFilterFieldsWithoutTags(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)

	status, data := send(t, c, "GET", "/api/documents/?fields=id,title,content", nil, "")
	if status != http.StatusOK || bytes.Contains(data, []byte(secretMarker)) {
		t.Fatalf("status %d, body %s", status, data)
	}
	if !bytes.Contains(data, []byte(publicMarker)) {
		t.Errorf("full-tier content was removed: %s", data)
	}
	if !fp.received("GET", "/api/documents/") {
		t.Error("request did not reach Paperless")
	}
	// The tags came from a batch lookup.
	fp.mu.Lock()
	lookedUp := slices.ContainsFunc(fp.log, func(e string) bool { return strings.Contains(e, "id__in=") })
	fp.mu.Unlock()
	if !lookedUp {
		t.Error("no batch tag lookup for documents without tags")
	}

	status, data = send(t, c, "GET", "/api/documents/2/?fields=id,content", nil, "")
	if status != http.StatusOK || bytes.Contains(data, []byte(secretMarker)) {
		t.Errorf("single document with fields=: status %d, body %s", status, data)
	}
}

func TestPolicyResponseFilterLeavesOtherResponsesAlone(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	// A response without documents passes byte for byte.
	status, data := send(t, c, "GET", "/api/documents/2/notes/", nil, "")
	if status != http.StatusOK || string(data) != `[{"id":1,"note":"called the office"}]`+"\n" {
		t.Errorf("notes response changed: %d %q", status, data)
	}
	// Full-tier files pass unchanged.
	status, data = send(t, c, "GET", "/api/documents/1/download/", nil, "")
	if status != http.StatusOK || string(data) != "FILE "+fp.docs[docFull].Content {
		t.Errorf("download changed: %d %q", status, data)
	}
}

// --- Freshness ---

func TestPolicyTierChangeIsImmediate(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "GET", "/api/documents/1/download/", nil, "")
	assertPassed(t, fp, status, data, "GET", "/api/documents/1/download/")

	fp.setTags(docFull, tagConfidential)
	fp.resetLog()
	status, data = send(t, c, "GET", "/api/documents/1/download/", nil, "")
	assertBlocked(t, fp, status, data, "GET", "/api/documents/1/download/", "tier: metadata")
}

// --- Multi-document requests (section 6.4 and the agreed additions) ---

func TestPolicyMultiDocumentRules(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		body       any
		wantReason string // empty: passes
	}{
		{"email", "/api/documents/email/", map[string]any{"documents": []int{1}, "addresses": "a@example.com"}, "emailing documents is not allowed"},
		{"chat", "/api/documents/chat/", map[string]any{"q": "what is due?"}, "document chat is not allowed"},
		{"merge", "/api/documents/merge/", map[string]any{"documents": []int{1, 2}}, "merge is not allowed"},
		{"edit_pdf", "/api/documents/edit_pdf/", map[string]any{"documents": []int{1}}, "edit_pdf is not allowed"},
		{"remove_password", "/api/documents/remove_password/", map[string]any{"documents": []int{1}}, "remove_password is not allowed"},
		{"merge_as_versions", "/api/documents/merge_as_versions/", map[string]any{"documents": []int{1, 2}}, "merge_as_versions is not allowed"},
		{"bulk_download full", "/api/documents/bulk_download/", map[string]any{"documents": []int{1}}, ""},
		{"bulk_download mixed", "/api/documents/bulk_download/", map[string]any{"documents": []int{1, 2}}, "document 2 (tier: metadata)"},
		{"bulk_download trashed", "/api/documents/bulk_download/", map[string]any{"documents": []int{3}}, "document 3 (tier: metadata)"},
		{"bulk_download all", "/api/documents/bulk_download/", map[string]any{"all": true, "filters": map[string]any{}}, "explicit list of documents"},
		{"bulk_download empty", "/api/documents/bulk_download/", map[string]any{"documents": []int{}}, "explicit list of documents"},
		{"rotate", "/api/documents/rotate/", map[string]any{"documents": []int{2}, "degrees": 90}, ""},
		{"reprocess", "/api/documents/reprocess/", map[string]any{"documents": []int{2}}, ""},
		{"delete", "/api/documents/delete/", map[string]any{"documents": []int{2}}, ""},
		{"selection_data", "/api/documents/selection_data/", map[string]any{"documents": []int{2}}, ""},
		{"storage path test", "/api/storage_paths/test/", map[string]any{"document": 2, "path": "{{ document.content }}"}, "testing storage paths is not allowed"},
		{"share link bundle create", "/api/share_link_bundles/", map[string]any{"documents": []int{2}}, "share link bundles is not allowed"},
		{"share link bundle rebuild", "/api/share_link_bundles/5/rebuild/", nil, "share link bundles is not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp := newFakePaperless(t)
			c := fp.policyClient(t)
			status, data := send(t, c, "POST", tc.path, tc.body, "")
			if tc.wantReason == "" {
				assertPassed(t, fp, status, data, "POST", tc.path)
			} else {
				assertBlocked(t, fp, status, data, "POST", tc.path, tc.wantReason)
			}
		})
	}
}

func TestPolicyShareLinkBundleReadsPass(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	status, data := send(t, c, "GET", "/api/share_link_bundles/", nil, "")
	assertPassed(t, fp, status, data, "GET", "/api/share_link_bundles/")
	status, data = send(t, c, "DELETE", "/api/share_link_bundles/5/", nil, "")
	assertBlocked(t, fp, status, data, "DELETE", "/api/share_link_bundles/5/", "share link bundles is not allowed")
}

// --- Rule 2: the classification is read-only (section 7) ---

func TestPolicyClassificationRules(t *testing.T) {
	cf := func(fields ...map[string]any) []map[string]any { return fields }
	field := func(id int, value any) map[string]any { return map[string]any{"field": id, "value": value} }
	docMetadataFields := cf(
		field(fieldSummary, "Tax assessment 2025, refund expected"),
		field(fieldPrivacyClass, "confidential"),
		field(fieldTriggers, "own-iban"),
	)

	for _, tc := range []struct {
		name       string
		method     string
		path       string
		body       any
		wantReason string // empty: passes
	}{
		// PATCH tags
		{"patch adds ordinary tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagInvoice, 999}}, ""},
		{"patch resends current tags", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagInvoice, tagConfidential}}, ""},
		{"patch removes tier tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagInvoice}}, "protected tag 103 (dp:confidential) may not be removed"},
		{"patch adds full tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagInvoice, tagPublic}}, "protected tag 101 (dp:public) may not be added"},
		{"patch adds pipeline tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagInvoice, tagReprocess}}, "protected tag 106 (gpt-reprocess) may not be added"},
		{"put removes tier tag", "PUT", "/api/documents/2/", map[string]any{"title": "x", "tags": []int{}}, "may not be removed"},
		{"patch tags not a list", "PATCH", "/api/documents/2/", map[string]any{"tags": "103"}, "tags must be a list"},

		// PATCH custom fields
		{"patch changes ordinary field", "PATCH", "/api/documents/2/", map[string]any{"custom_fields": cf(
			field(fieldSummary, "Refund received"), field(fieldPrivacyClass, "confidential"), field(fieldTriggers, "own-iban"))}, ""},
		{"patch resends fields unchanged", "PATCH", "/api/documents/2/", map[string]any{"custom_fields": docMetadataFields}, ""},
		{"patch changes protected field", "PATCH", "/api/documents/2/", map[string]any{"custom_fields": cf(
			field(fieldSummary, "x"), field(fieldPrivacyClass, "public"), field(fieldTriggers, "own-iban"))}, "protected custom field 201 (AI privacy class) of document 2 may not be changed"},
		{"patch drops protected field", "PATCH", "/api/documents/2/", map[string]any{"custom_fields": cf(
			field(fieldSummary, "x"), field(fieldPrivacyClass, "confidential"))}, "protected custom field 202 (Privacy triggers) may not be removed"},
		{"patch adds protected field", "PATCH", "/api/documents/1/", map[string]any{"custom_fields": cf(
			field(fieldSummary, "Electricity bill for May"), field(fieldPrivacyClass, "internal"), field(fieldTriggers, "none"))}, "protected custom field 202 (Privacy triggers) may not be added"},
		{"patch custom_fields not a list", "PATCH", "/api/documents/2/", map[string]any{"custom_fields": map[string]any{"201": "public"}}, "custom_fields must be a list"},

		// PATCH owner, permissions, inbox tags
		{"patch owner", "PATCH", "/api/documents/2/", map[string]any{"owner": nil}, "changing the owner"},
		{"patch set_permissions", "PATCH", "/api/documents/2/", map[string]any{"set_permissions": map[string]any{}}, "changing the permissions"},
		{"patch remove_inbox_tags", "PATCH", "/api/documents/2/", map[string]any{"remove_inbox_tags": true}, "remove_inbox_tags is not allowed"},
		{"patch remove_inbox_tags false", "PATCH", "/api/documents/2/", map[string]any{"remove_inbox_tags": false, "title": "x"}, ""},

		// bulk_edit
		{"bulk add ordinary tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "add_tag", "parameters": map[string]any{"tag": tagInvoice}}, ""},
		{"bulk add protected tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "add_tag", "parameters": map[string]any{"tag": tagPublic}}, "protected tag 101 (dp:public) may not be added"},
		{"bulk add protected tag as string", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "add_tag", "parameters": map[string]any{"tag": "106"}}, "protected tag 106 (gpt-reprocess)"},
		{"bulk remove ordinary tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "remove_tag", "parameters": map[string]any{"tag": tagInvoice}}, ""},
		{"bulk remove protected tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "remove_tag", "parameters": map[string]any{"tag": tagConfidential}}, "protected tag 103 (dp:confidential) may not be removed"},
		{"bulk modify ordinary tags", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_tags", "parameters": map[string]any{"add_tags": []int{tagInvoice}, "remove_tags": []int{}}}, ""},
		{"bulk modify adds protected", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_tags", "parameters": map[string]any{"add_tags": []int{tagReset}, "remove_tags": []int{}}}, "protected tag 107 (gpt-reset) may not be added"},
		{"bulk modify removes protected", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_tags", "parameters": map[string]any{"add_tags": []int{}, "remove_tags": []int{tagReview}}}, "protected tag 104 (dp:manual-review) may not be removed"},
		{"bulk custom fields ordinary", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_custom_fields", "parameters": map[string]any{"add_custom_fields": map[string]any{"203": "x"}, "remove_custom_fields": []int{}}}, ""},
		{"bulk custom fields add protected (object)", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_custom_fields", "parameters": map[string]any{"add_custom_fields": map[string]any{"201": "public"}, "remove_custom_fields": []int{}}}, "custom field 201 (AI privacy class) is protected"},
		{"bulk custom fields add protected (list)", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_custom_fields", "parameters": map[string]any{"add_custom_fields": []int{202}, "remove_custom_fields": []int{}}}, "custom field 202 (Privacy triggers) is protected"},
		{"bulk custom fields remove protected", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_custom_fields", "parameters": map[string]any{"add_custom_fields": []int{}, "remove_custom_fields": []int{201}}}, "custom field 201 (AI privacy class) is protected"},
		{"bulk set_permissions", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "set_permissions", "parameters": map[string]any{}}, "set_permissions is not allowed"},
		{"bulk run_workflow", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "run_workflow", "parameters": map[string]any{"workflow": 1}}, "run_workflow is not allowed"},
		{"bulk set_correspondent", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "set_correspondent", "parameters": map[string]any{"correspondent": 1}}, ""},
		{"bulk rotate", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "rotate", "parameters": map[string]any{"degrees": 90}}, ""},
		{"bulk reprocess", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "reprocess", "parameters": map[string]any{}}, ""},
		{"bulk delete", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "delete", "parameters": map[string]any{}}, ""},
		{"bulk merge", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{1, 2}, "method": "merge", "parameters": map[string]any{}}, "merge is not allowed"},
		{"bulk split", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "split", "parameters": map[string]any{}}, "split is not allowed"},
		{"bulk delete_pages", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "delete_pages", "parameters": map[string]any{}}, "delete_pages is not allowed"},
		{"bulk edit_pdf", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "edit_pdf", "parameters": map[string]any{}}, "edit_pdf is not allowed"},
		{"bulk remove_password", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "remove_password", "parameters": map[string]any{}}, "remove_password is not allowed"},
		{"bulk unknown method", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "make_public", "parameters": map[string]any{}}, `bulk_edit method "make_public" is not allowed`},
		{"bulk unparseable JSON", "POST", "/api/documents/bulk_edit/", []byte(`{"method": "add_tag",`), "the request body must be a JSON object"},

		// tags and custom fields
		{"patch ordinary tag", "PATCH", "/api/tags/110/", map[string]any{"name": "invoices"}, ""},
		{"patch protected tag", "PATCH", "/api/tags/103/", map[string]any{"name": "dp:open"}, "tag 103 (dp:confidential) is protected"},
		{"put protected tag", "PUT", "/api/tags/106/", map[string]any{"name": "x", "matching_algorithm": 1}, "tag 106 (gpt-reprocess) is protected"},
		{"delete ordinary tag", "DELETE", "/api/tags/110/", nil, ""},
		{"delete protected tag", "DELETE", "/api/tags/101/", nil, "tag 101 (dp:public) is protected"},
		{"patch ordinary field", "PATCH", "/api/custom_fields/203/", map[string]any{"name": "Abstract"}, ""},
		{"patch protected field", "PATCH", "/api/custom_fields/201/", map[string]any{"extra_data": map[string]any{}}, "custom field 201 (AI privacy class) is protected"},
		{"delete protected field", "DELETE", "/api/custom_fields/202/", nil, "custom field 202 (Privacy triggers) is protected"},

		// bulk_edit_objects
		{"objects delete ordinary tag", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "tags", "objects": []int{110}, "operation": "delete"}, ""},
		{"objects delete protected tag", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "tags", "objects": []int{110, 105}, "operation": "delete"}, "tag 105 (dp:restricted) is protected"},
		{"objects delete all tags", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "tags", "all": true, "operation": "delete"}, "explicit list of tags"},
		{"objects set_permissions", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "correspondents", "objects": []int{1}, "operation": "set_permissions"}, "changing permissions is not allowed"},
		{"objects delete correspondents", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "correspondents", "objects": []int{1}, "operation": "delete"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp := newFakePaperless(t)
			c := fp.policyClient(t)
			status, data := send(t, c, tc.method, tc.path, tc.body, "application/json")
			if tc.wantReason == "" {
				assertPassed(t, fp, status, data, tc.method, tc.path)
			} else {
				assertBlocked(t, fp, status, data, tc.method, tc.path, tc.wantReason)
			}
		})
	}
}

func TestPolicyUploadRules(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fields     map[string][]string
		wantReason string
	}{
		{"ordinary tags", map[string][]string{"title": {"Scan"}, "tags": {"110"}}, ""},
		{"no tags", map[string][]string{"title": {"Scan"}}, ""},
		{"protected tag", map[string][]string{"tags": {"110", "101"}}, "protected tag 101 (dp:public) may not be added"},
		{"ordinary custom field", map[string][]string{"custom_fields": {`{"203": "x"}`}}, ""},
		{"protected custom field (object)", map[string][]string{"custom_fields": {`{"201": "public"}`}}, "custom field 201 (AI privacy class) is protected"},
		{"protected custom field (list)", map[string][]string{"custom_fields": {`[202]`}}, "custom field 202 (Privacy triggers) is protected"},
		{"protected custom field (single)", map[string][]string{"custom_fields": {`201`}}, "custom field 201 (AI privacy class) is protected"},
		{"tag not an ID", map[string][]string{"tags": {"dp:public"}}, "upload tags must be tag IDs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp := newFakePaperless(t)
			c := fp.policyClient(t)
			body, ct := multipartBody(t, tc.fields)
			status, data := send(t, c, "POST", "/api/documents/post_document/", body, ct)
			if tc.wantReason == "" {
				assertPassed(t, fp, status, data, "POST", "/api/documents/post_document/")
			} else {
				assertBlocked(t, fp, status, data, "POST", "/api/documents/post_document/", tc.wantReason)
			}
		})
	}

	t.Run("not multipart", func(t *testing.T) {
		fp := newFakePaperless(t)
		c := fp.policyClient(t)
		status, data := send(t, c, "POST", "/api/documents/post_document/", map[string]any{"tags": []int{101}}, "")
		assertBlocked(t, fp, status, data, "POST", "/api/documents/post_document/", "must be multipart/form-data")
	})
}

// --- Rule 2: the tag hierarchy ---

func TestPolicyTagHierarchyRules(t *testing.T) {
	const (
		tagUnderReprocess = 120 // child of gpt-reprocess
		tagGrandchild     = 121 // child of 120
		tagPrivacyParent  = 122 // parent of dp:confidential
		tagOther          = 123 // ordinary, no relations
	)
	setup := func(t *testing.T) (*fakePaperless, *Client) {
		fp := newFakePaperless(t)
		fp.addTag(tagUnderReprocess, "auto-sub", tagReprocess)
		fp.addTag(tagGrandchild, "auto-sub-sub", tagUnderReprocess)
		fp.addTag(tagPrivacyParent, "privacy", 0)
		fp.addTag(tagOther, "misc", 0)
		fp.setTagParent(tagConfidential, tagPrivacyParent)
		fp.setTags(docMetadata, tagConfidential, tagPrivacyParent, tagInvoice)
		return fp, fp.policyClient(t)
	}

	for _, tc := range []struct {
		name       string
		method     string
		path       string
		body       any
		wantReason string
	}{
		{"patch adds a tag under a protected tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagPrivacyParent, tagInvoice, tagGrandchild}}, "protected tag 106 (gpt-reprocess) may not be added"},
		{"patch removes the parent of a protected tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagInvoice}}, "protected tag 103 (dp:confidential) may not be removed"},
		{"patch adds an unrelated tag", "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagConfidential, tagPrivacyParent, tagInvoice, tagOther}}, ""},
		{"bulk add_tag under a protected tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "add_tag", "parameters": map[string]any{"tag": tagUnderReprocess}}, "protected tag 106 (gpt-reprocess) may not be added"},
		{"bulk remove_tag of a protected tag's parent", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "remove_tag", "parameters": map[string]any{"tag": tagPrivacyParent}}, "protected tag 103 (dp:confidential) may not be removed"},
		{"bulk modify_tags under a protected tag", "POST", "/api/documents/bulk_edit/", map[string]any{"documents": []int{2}, "method": "modify_tags", "parameters": map[string]any{"add_tags": []int{tagGrandchild}, "remove_tags": []int{}}}, "protected tag 106 (gpt-reprocess) may not be added"},
		{"create tag under a protected tag", "POST", "/api/tags/", map[string]any{"name": "sneaky", "parent": tagReprocess}, "tags may not be placed under protected tag 106 (gpt-reprocess)"},
		{"create tag under a protected tag's child", "POST", "/api/tags/", map[string]any{"name": "sneaky", "parent": tagUnderReprocess}, "tags may not be placed under protected tag 106 (gpt-reprocess)"},
		{"create tag under an ordinary tag", "POST", "/api/tags/", map[string]any{"name": "fine", "parent": tagOther}, ""},
		{"create tag without parent", "POST", "/api/tags/", map[string]any{"name": "fine"}, ""},
		{"move a tag under a protected tag", "PATCH", "/api/tags/123/", map[string]any{"parent": tagReset}, "tags may not be placed under protected tag 107 (gpt-reset)"},
		{"rename the parent of a protected tag", "PATCH", "/api/tags/122/", map[string]any{"name": "private"}, "tag 122 is a parent of a protected tag"},
		{"delete the parent of a protected tag", "DELETE", "/api/tags/122/", nil, "tag 122 is a parent of a protected tag"},
		{"objects delete the parent of a protected tag", "POST", "/api/bulk_edit_objects/", map[string]any{"object_type": "tags", "objects": []int{tagPrivacyParent}, "operation": "delete"}, "tag 122 is a parent of a protected tag"},
		{"rename a child of a protected tag", "PATCH", "/api/tags/120/", map[string]any{"name": "renamed"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, c := setup(t)
			status, data := send(t, c, tc.method, tc.path, tc.body, "application/json")
			if tc.wantReason == "" {
				assertPassed(t, fp, status, data, tc.method, tc.path)
			} else {
				assertBlocked(t, fp, status, data, tc.method, tc.path, tc.wantReason)
			}
		})
	}

	t.Run("upload with a tag under a protected tag", func(t *testing.T) {
		fp, c := setup(t)
		body, ct := multipartBody(t, map[string][]string{"tags": {strconv.Itoa(tagGrandchild)}})
		status, data := send(t, c, "POST", "/api/documents/post_document/", body, ct)
		assertBlocked(t, fp, status, data, "POST", "/api/documents/post_document/", "protected tag 106 (gpt-reprocess) may not be added")
	})
}

// --- Routing and fail-closed ---

func TestPolicyRouting(t *testing.T) {
	fp := newFakePaperless(t)
	c := fp.policyClient(t)
	for _, tc := range []struct {
		name, target, wantReason string
	}{
		{"dot segments", "/api/logs/../documents/2/download/", "malformed"},
		{"encoded slash", "/api/documents/2%2Fdownload/", "characters the policy filter does not accept"},
		{"format suffix", "/api/documents/2.json", "malformed"},
		{"outside the API", "/share/abc/", "only the Paperless REST API"},
		{"double slash", "/api//documents/2/download/", "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", c.baseURL+tc.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(data), tc.wantReason) {
				t.Errorf("GET %s: %d %s, want 403 with %q", tc.target, resp.StatusCode, data, tc.wantReason)
			}
		})
	}
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if len(fp.log) != 0 {
		t.Errorf("malformed requests reached Paperless: %v", fp.log)
	}
}

func TestPolicyBlocksRedirectToAnotherHost(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request reached another host: %s", r.URL)
	}))
	t.Cleanup(other.Close)
	fp := newFakePaperless(t)
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/download/") {
			http.Redirect(w, r, other.URL+"/api/documents/1/download/", http.StatusFound)
			return
		}
		fp.ServeHTTP(w, r)
	}))
	t.Cleanup(redirecting.Close)

	opts, err := configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), redirecting.URL, "test-token", http.DefaultTransport, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(redirecting.URL, "test-token", opts...)
	status, data := send(t, c, "GET", "/api/documents/1/download/", nil, "")
	if status != http.StatusForbidden || !strings.Contains(string(data), "may only go to the Paperless instance") {
		t.Errorf("redirect to another host: %d %s", status, data)
	}
}

func TestPolicyUnparseableJSONResponseBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id": 2, "content": "`+secretMarker)
	}))
	t.Cleanup(srv.Close)
	rt, err := newPolicyTransport(testPolicy(), http.DefaultTransport, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(srv.URL, "test-token", WithTransport(rt))
	req, _ := http.NewRequest("GET", srv.URL+"/api/documents/", nil)
	resp, err := c.do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || bytes.Contains(data, []byte(secretMarker)) {
		t.Errorf("unparseable JSON: %d %s", resp.StatusCode, data)
	}
}

func TestPolicyLookupFailureBlocks(t *testing.T) {
	// The tier lookup is refused (403), so the download must not go through.
	fp := newFakePaperless(t)
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "fields=id%2Ctags") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fp.ServeHTTP(w, r)
	}))
	t.Cleanup(failing.Close)
	opts, err := configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), failing.URL, "test-token", http.DefaultTransport, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(failing.URL, "test-token", opts...)
	status, data := send(t, c, "GET", "/api/documents/1/download/", nil, "")
	assertBlocked(t, fp, status, data, "GET", "/api/documents/1/download/", "could not determine the tier of document 1 (lookup status 403)")
}

// --- No bypass ---

func TestPolicyNoHTTPClientBypass(t *testing.T) {
	forbidden := regexp.MustCompile(`http\.(Get|Head|Post|PostForm)\(|http\.DefaultClient|http\.Client\{`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			m := forbidden.FindString(line)
			if m == "" {
				continue
			}
			// client.go builds the one http.Client all traffic goes through.
			if f == "client.go" && m == "http.Client{" {
				continue
			}
			t.Errorf("%s:%d: %q bypasses Client and the policy filter", f, i+1, strings.TrimSpace(line))
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no Go files checked")
	}
}

// --- Upstream behaviour when disabled ---

func TestPolicyDisabledIsUpstreamBehaviour(t *testing.T) {
	fp := newFakePaperless(t)
	opts, err := configurePolicy(context.Background(), getenvFrom(map[string]string{envPolicyEnabled: "false"}), fp.srv.URL, "test-token", http.DefaultTransport, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(fp.srv.URL, "test-token", opts...)
	if c.httpClient.Transport != nil {
		t.Fatalf("transport = %T, want none", c.httpClient.Transport)
	}

	for _, path := range []string{"/api/documents/2/", "/api/documents/2/download/", "/api/documents/?query=tax"} {
		// Through the client and straight from the fake, byte for byte.
		_, viaClient := send(t, c, "GET", path, nil, "")
		resp, err := http.DefaultTransport.RoundTrip(mustRequest(t, fp.srv.URL+path))
		if err != nil {
			t.Fatal(err)
		}
		direct, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Equal(viaClient, direct) {
			t.Errorf("GET %s differs from upstream:\n%s\nvs\n%s", path, viaClient, direct)
		}
		if !bytes.Contains(viaClient, []byte(secretMarker)) {
			t.Errorf("GET %s: disabled filter removed content", path)
		}
	}
	// Writes the filter would block go through.
	status, data := send(t, c, "PATCH", "/api/documents/2/", map[string]any{"tags": []int{tagPublic}}, "")
	if status != http.StatusOK {
		t.Errorf("PATCH with filter disabled: %d %s", status, data)
	}
}

func mustRequest(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Token test-token")
	req.Header.Set("Accept", "application/json; version="+apiVersion+", */*")
	return req
}

// --- Leak test across all tools (acceptance test 3) ---

// leakArgs returns plausible arguments for a tool, aimed at document doc.
// Required parameters are filled from their names and types, so tools added
// later are called too without changes here.
func leakArgs(tool mcp.Tool, doc int, uploadFile string) map[string]any {
	args := map[string]any{}
	for _, name := range tool.InputSchema.Required {
		schema, _ := tool.InputSchema.Properties[name].(map[string]any)
		if enum, ok := schema["enum"].([]string); ok && len(enum) > 0 {
			args[name] = enum[0]
			continue
		}
		switch name {
		case "ids", "documents":
			args[name] = fmt.Sprintf("[%d]", doc)
			continue
		case "objects", "tasks":
			args[name] = "[1]"
			continue
		case "parameters", "body":
			args[name] = "{}"
			continue
		case "file_path":
			args[name] = uploadFile
			continue
		case "to":
			args[name] = "someone@example.com"
			continue
		case "object_type":
			args[name] = "tags"
			continue
		case "operation":
			args[name] = "delete"
			continue
		case "method":
			args[name] = "set_correspondent"
			continue
		case "action":
			args[name] = "restore"
			continue
		case "data_type":
			args[name] = "string"
			continue
		case "path":
			args[name] = "{{ document.content }}"
			continue
		case "term", "query":
			args[name] = "tax"
			continue
		}
		switch t := schema["type"].(type) {
		case string:
			switch t {
			case "boolean":
				args[name] = false
			case "number", "integer":
				args[name] = doc
			default:
				args[name] = "x"
			}
		default: // withNumber: ["integer", "string"]
			args[name] = doc
		}
	}
	return args
}

// leakCall is one tool call of the leak test.
type leakCall struct {
	tool string
	args map[string]any
}

// extraLeakCalls adds variants beyond the required arguments: the ones that
// reach text through optional parameters.
func extraLeakCalls(doc int) []leakCall {
	ids := fmt.Sprintf("[%d]", doc)
	return []leakCall{
		{"document_list", map[string]any{"full_content": true, "include_notes": true}},
		{"document_list", map[string]any{"query": "tax", "full_content": true}},
		{"document_list", map[string]any{"more_like_id": doc, "full_content": true}},
		{"document_list", map[string]any{"content": "assessment", "content_snippet_bytes": 0}},
		{"search_global", map[string]any{"query": "tax", "full_content": true}},
		{"search_autocomplete", map[string]any{"term": "secret"}},
		{"search_autocomplete", map[string]any{"term": "7f"}},
		{"document_download", map[string]any{"ids": ids, "content": true}},
		{"document_download", map[string]any{"ids": ids, "content": true, "variant": "original"}},
		{"document_download", map[string]any{"ids": ids, "content": true, "variant": "thumbnail"}},
		{"document_download", map[string]any{"ids": ids, "variant": "original"}},
		{"document_download", map[string]any{"ids": ids, "variant": "thumbnail"}},
		{"document_page_image", map[string]any{"id": doc, "region": "[0,0,0.5,0.5]"}},
		{"document_update", map[string]any{"id": doc, "title": "Renamed"}},
		{"document_bulk_edit", map[string]any{"documents": ids, "method": "merge", "parameters": "{}"}},
		{"document_bulk_edit", map[string]any{"documents": ids, "method": "add_tag", "parameters": fmt.Sprintf(`{"tag": %d}`, tagPublic)}},
		{"document_email", map[string]any{"documents": ids, "subject": "s", "body": "b", "to": "x@example.com"}},
		{"storage_path_test", map[string]any{"path": "{{ document.content }}", "document_id": doc}},
		{"trash_list", map[string]any{}},
	}
}

// leakScan returns the markers found in v: in any string, in any string that
// is valid base64 (inline file content), or in image data.
func leakScan(data []byte, markers ...string) map[string]bool {
	found := map[string]bool{}
	check := func(s string) {
		for _, m := range markers {
			if strings.Contains(s, m) {
				found[m] = true
			}
		}
	}
	check(string(data))
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			check(x)
			if dec, err := base64.StdEncoding.DecodeString(x); err == nil {
				check(string(dec))
			}
			// Tool results nest JSON in text content.
			var inner any
			if json.Unmarshal([]byte(x), &inner) == nil {
				walk(inner)
			}
		case map[string]any:
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	var v any
	if json.Unmarshal(data, &v) == nil {
		walk(v)
	}
	return found
}

// scanDir returns the markers found in the files under dir.
func scanDir(t *testing.T, dir string, markers ...string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range markers {
			if bytes.Contains(data, []byte(m)) {
				found[m] = true
			}
		}
		return nil
	})
	return found
}

func TestPolicyNoLeakThroughAnyTool(t *testing.T) {
	fp := newFakePaperless(t)
	client := fp.policyClient(t)
	downloads := t.TempDir()
	dl, err := NewDownloader(2, downloads)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(client, dl)
	upload := filepath.Join(t.TempDir(), "scan.pdf")
	if err := os.WriteFile(upload, []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatal(err)
	}

	tools := srv.ListTools()
	if len(tools) < 100 {
		t.Fatalf("only %d tools registered", len(tools))
	}
	names := slices.Sorted(maps.Keys(tools))

	callAll := func(doc int) map[string]map[string]bool {
		calls := make([]leakCall, 0, len(names))
		for _, name := range names {
			calls = append(calls, leakCall{name, leakArgs(tools[name].Tool, doc, upload)})
		}
		calls = append(calls, extraLeakCalls(doc)...)
		found := map[string]map[string]bool{}
		for i, call := range calls {
			msg, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
				"params": map[string]any{"name": call.tool, "arguments": call.args},
			})
			resp := srv.HandleMessage(context.Background(), msg)
			out, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("%s: marshal response: %s", call.tool, err)
			}
			for m := range leakScan(out, secretMarker, publicMarker) {
				if found[m] == nil {
					found[m] = map[string]bool{}
				}
				found[m][call.tool] = true
			}
		}
		return found
	}

	// The metadata-tier document: the secret marker must appear nowhere,
	// neither in tool results nor in downloaded files.
	found := callAll(docMetadata)
	if tools := found[secretMarker]; len(tools) > 0 {
		t.Errorf("secret marker leaked through: %v", slices.Sorted(maps.Keys(tools)))
	}
	if files := scanDir(t, downloads, secretMarker); files[secretMarker] {
		t.Error("secret marker leaked into a downloaded file")
	}

	// The full-tier document: its marker must come through, proving the
	// calls above reached live data.
	found = callAll(docFull)
	for _, tool := range []string{"document_get", "document_list", "document_download", "search_global", "document_history"} {
		if !found[publicMarker][tool] {
			t.Errorf("full-tier text did not come through %s; is the leak test live?", tool)
		}
	}
	if files := scanDir(t, downloads, publicMarker); !files[publicMarker] {
		t.Error("full-tier file was not downloaded to disk")
	}
	if tools := found[secretMarker]; len(tools) > 0 {
		t.Errorf("secret marker (other documents) leaked while working on the full-tier document: %v", slices.Sorted(maps.Keys(tools)))
	}
}
