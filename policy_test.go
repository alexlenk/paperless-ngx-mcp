package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// Test IDs. They deliberately differ from any real instance's IDs.
const (
	tagPublic       = 101
	tagInternal     = 102
	tagConfidential = 103
	tagReview       = 104
	tagRestricted   = 105
	tagReprocess    = 106
	tagReset        = 107
	tagInvoice      = 110 // an ordinary tag

	fieldPrivacyClass = 201
	fieldTriggers     = 202
	fieldSummary      = 203 // an ordinary custom field
)

// testPolicyEnv is a complete, valid policy configuration for the fake
// Paperless in newFakePaperless.
func testPolicyEnv() map[string]string {
	return map[string]string{
		envPolicyEnabled:               "true",
		envPolicyFullTags:              "dp:public, dp:internal",
		envPolicyMetadataTags:          "dp:confidential,dp:manual-review",
		envPolicyRestrictedTags:        "dp:restricted",
		envPolicyProtectedTags:         "gpt-reprocess,gpt-reset",
		envPolicyProtectedCustomFields: "AI privacy class,Privacy triggers",
	}
}

func getenvFrom(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

// testPolicy is the resolved form of testPolicyEnv.
func testPolicy() *policy {
	return newPolicy(
		[]namedID{{"dp:public", tagPublic}, {"dp:internal", tagInternal}},
		[]namedID{{"dp:confidential", tagConfidential}, {"dp:manual-review", tagReview}},
		[]namedID{{"dp:restricted", tagRestricted}},
		[]namedID{{"gpt-reprocess", tagReprocess}, {"gpt-reset", tagReset}},
		[]namedID{{"AI privacy class", fieldPrivacyClass}, {"Privacy triggers", fieldTriggers}},
	)
}

func TestLoadPolicyConfigDisabled(t *testing.T) {
	for _, value := range []string{"", "false", " false "} {
		env := testPolicyEnv()
		env[envPolicyEnabled] = value
		// With the filter off, the other variables are ignored, even invalid ones.
		env[envPolicyFullTags] = ""
		cfg, err := loadPolicyConfig(getenvFrom(env))
		if err != nil {
			t.Fatalf("ENABLED=%q: unexpected error: %s", value, err)
		}
		if cfg.Enabled {
			t.Errorf("ENABLED=%q: filter enabled, want disabled", value)
		}
	}
}

func TestLoadPolicyConfigEnabled(t *testing.T) {
	cfg, err := loadPolicyConfig(getenvFrom(testPolicyEnv()))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !cfg.Enabled {
		t.Fatal("filter disabled, want enabled")
	}
	if want := []string{"dp:public", "dp:internal"}; !slices.Equal(cfg.FullTags, want) {
		t.Errorf("FullTags = %q, want %q (trimmed)", cfg.FullTags, want)
	}
	if want := []string{"AI privacy class", "Privacy triggers"}; !slices.Equal(cfg.ProtectedCustomFields, want) {
		t.Errorf("ProtectedCustomFields = %q, want %q", cfg.ProtectedCustomFields, want)
	}
}

func TestLoadPolicyConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  map[string]string
		wantErr string
	}{
		{"enabled value not true/false", map[string]string{envPolicyEnabled: "yes"}, "PAPERLESS_MCP_POLICY_ENABLED must be true or false"},
		{"enabled value TRUE", map[string]string{envPolicyEnabled: "TRUE"}, "must be true or false"},
		{"unsubstituted enabled template", map[string]string{envPolicyEnabled: "${user_config.policy_enabled}"}, "must be true or false"},
		{"empty full tags", map[string]string{envPolicyFullTags: ""}, "PAPERLESS_MCP_POLICY_FULL_TAGS must name at least one tag"},
		{"only commas in full tags", map[string]string{envPolicyFullTags: " , ,"}, "PAPERLESS_MCP_POLICY_FULL_TAGS must name at least one tag"},
		{"empty metadata tags", map[string]string{envPolicyMetadataTags: ""}, "PAPERLESS_MCP_POLICY_METADATA_TAGS must name at least one tag"},
		{"unsubstituted metadata template", map[string]string{envPolicyMetadataTags: "${user_config.policy_metadata_tags}"}, "PAPERLESS_MCP_POLICY_METADATA_TAGS must name at least one tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testPolicyEnv()
			for k, v := range tc.change {
				env[k] = v
			}
			_, err := loadPolicyConfig(getenvFrom(env))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestSplitPolicyNames(t *testing.T) {
	if got := splitPolicyNames(" a , b,,c ,"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("got %q", got)
	}
	if got := splitPolicyNames("${user_config.policy_protected_tags}"); got != nil {
		t.Errorf("unsubstituted template = %q, want none", got)
	}
}

func TestTierOf(t *testing.T) {
	p := testPolicy()
	for _, tc := range []struct {
		name string
		tags []int
		want tier
	}{
		{"restricted", []int{tagRestricted}, tierRestricted},
		{"restricted beats full", []int{tagPublic, tagRestricted}, tierRestricted},
		{"restricted beats metadata", []int{tagConfidential, tagRestricted}, tierRestricted},
		{"metadata", []int{tagConfidential}, tierMetadata},
		{"manual review is metadata", []int{tagReview, tagInvoice}, tierMetadata},
		{"full", []int{tagPublic}, tierFull},
		{"full internal with other tags", []int{tagInvoice, tagInternal}, tierFull},
		{"deny wins: internal + confidential", []int{tagInternal, tagConfidential}, tierMetadata},
		{"no tier tag", []int{tagInvoice}, tierMetadata},
		{"no tags at all", nil, tierMetadata},
		{"only protected pipeline tags", []int{tagReprocess}, tierMetadata},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.tierOf(tc.tags); got != tc.want {
				t.Errorf("tierOf(%v) = %s, want %s", tc.tags, got, tc.want)
			}
		})
	}
}

func TestPolicyProtectedSets(t *testing.T) {
	p := testPolicy()
	for _, id := range []int{tagPublic, tagInternal, tagConfidential, tagReview, tagRestricted, tagReprocess, tagReset} {
		if !p.protectedTags[id] {
			t.Errorf("tag %d not protected", id)
		}
	}
	if p.protectedTags[tagInvoice] {
		t.Error("ordinary tag is protected")
	}
	if !p.protectedFields[fieldPrivacyClass] || !p.protectedFields[fieldTriggers] || p.protectedFields[fieldSummary] {
		t.Errorf("protected fields = %v", p.protectedFields)
	}
}

func TestTagHierarchy(t *testing.T) {
	// 1 ─ 2 ─ 3
	//      └─ 4
	// 5 (root)
	h := newTagHierarchy(map[int]int{2: 1, 3: 2, 4: 2})
	if got := sortedKeys(h.withAncestors([]int{3})); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("withAncestors(3) = %v", got)
	}
	if got := sortedKeys(h.withDescendants([]int{2})); !slices.Equal(got, []int{2, 3, 4}) {
		t.Errorf("withDescendants(2) = %v", got)
	}
	if got := sortedKeys(h.withAncestors([]int{5})); !slices.Equal(got, []int{5}) {
		t.Errorf("withAncestors(5) = %v", got)
	}

	// A cycle must not hang.
	cyc := newTagHierarchy(map[int]int{1: 2, 2: 1})
	if got := sortedKeys(cyc.withAncestors([]int{1})); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("cycle withAncestors = %v", got)
	}
	if got := sortedKeys(cyc.withDescendants([]int{1})); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("cycle withDescendants = %v", got)
	}
}

func TestTagHierarchyFinalTags(t *testing.T) {
	h := newTagHierarchy(map[int]int{2: 1, 3: 2})
	for _, tc := range []struct {
		name                string
		previous, requested []int
		want                []int
	}{
		{"adding a child adds its ancestors", []int{9}, []int{9, 3}, []int{1, 2, 3, 9}},
		{"removing a parent removes its children", []int{1, 2, 3}, []int{9}, []int{9}},
		{"unchanged", []int{1, 2, 3}, []int{1, 2, 3}, []int{1, 2, 3}},
		{"a newly required tag wins over a removed one", []int{2}, []int{3}, []int{1, 2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sortedKeys(h.finalTags(tc.previous, tc.requested)); !slices.Equal(got, tc.want) {
				t.Errorf("finalTags(%v, %v) = %v, want %v", tc.previous, tc.requested, got, tc.want)
			}
		})
	}
}

func TestCustomFieldIDs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []int
		ok   bool
	}{
		{`5`, []int{5}, true},
		{`[5, "6"]`, []int{5, 6}, true},
		{`{"5": "x", "6": null}`, []int{5, 6}, true},
		{`[{"field": 7, "value": "x"}]`, []int{7}, true},
		{`null`, nil, true},
		{`["x"]`, nil, false},
		{`{"x": 1}`, nil, false},
		{`true`, nil, false},
	} {
		v, err := decodeJSON([]byte(tc.in))
		if err != nil {
			t.Fatalf("decode %s: %s", tc.in, err)
		}
		got, ok := customFieldIDs(v)
		slices.Sort(got)
		if ok != tc.ok || (ok && !slices.Equal(got, tc.want)) {
			t.Errorf("customFieldIDs(%s) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestJSONEqual(t *testing.T) {
	dec := func(s string) any {
		v, err := decodeJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if !jsonEqual(dec(`{"a":1,"b":[1,2]}`), dec(`{"b":[1,2],"a":1.0}`)) {
		t.Error("equal values compare unequal")
	}
	if jsonEqual(dec(`"confidential"`), dec(`"public"`)) {
		t.Error("different values compare equal")
	}
}

// --- Startup resolution ---

// resolveServer serves /api/tags/ and /api/custom_fields/ name lookups from
// the given objects, honouring name__iexact like Paperless.
func resolveServer(t *testing.T, tags, fields []namedID) *httptest.Server {
	t.Helper()
	serve := func(objs []namedID) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Token test-token" {
				t.Errorf("lookup Authorization = %q", got)
			}
			name := r.URL.Query().Get("name__iexact")
			results := []map[string]any{}
			for _, o := range objs {
				if strings.EqualFold(o.Name, name) {
					results = append(results, map[string]any{"id": o.ID, "name": o.Name})
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(paginatedResponse(results, len(results)))
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/api/tags/", serve(tags))
	mux.Handle("/api/custom_fields/", serve(fields))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func defaultResolveTags() []namedID {
	return []namedID{
		{"dp:public", tagPublic}, {"dp:internal", tagInternal},
		{"dp:confidential", tagConfidential}, {"dp:manual-review", tagReview},
		{"dp:restricted", tagRestricted},
		{"gpt-reprocess", tagReprocess}, {"gpt-reset", tagReset},
		{"invoice", tagInvoice},
	}
}

func defaultResolveFields() []namedID {
	return []namedID{
		{"AI privacy class", fieldPrivacyClass}, {"Privacy triggers", fieldTriggers}, {"Summary", fieldSummary},
	}
}

func TestConfigurePolicyEnabledInstallsTransport(t *testing.T) {
	srv := resolveServer(t, defaultResolveTags(), defaultResolveFields())
	var log bytes.Buffer
	opts, err := configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), srv.URL, "test-token", http.DefaultTransport, &log)
	if err != nil {
		t.Fatalf("configurePolicy: %s", err)
	}

	client := NewClient(srv.URL, "test-token", opts...)
	pt, ok := client.httpClient.Transport.(*policyTransport)
	if !ok {
		t.Fatalf("client transport = %T, want *policyTransport", client.httpClient.Transport)
	}
	if pt.base != http.DefaultTransport {
		t.Errorf("policy transport base = %T, want http.DefaultTransport", pt.base)
	}
	if pt.pol.tierOf([]int{tagPublic}) != tierFull || pt.pol.tierOf([]int{tagConfidential}) != tierMetadata {
		t.Error("resolved policy has the wrong tiers")
	}
	if !pt.pol.protectedFields[fieldTriggers] {
		t.Error("resolved policy misses a protected custom field")
	}

	want := "policy filter: enabled\n" +
		"policy filter: full tags: dp:public=101, dp:internal=102\n" +
		"policy filter: metadata tags: dp:confidential=103, dp:manual-review=104\n" +
		"policy filter: restricted tags: dp:restricted=105\n" +
		"policy filter: protected tags: gpt-reprocess=106, gpt-reset=107\n" +
		"policy filter: protected custom fields: AI privacy class=201, Privacy triggers=202\n"
	if log.String() != want {
		t.Errorf("startup log =\n%s\nwant\n%s", log.String(), want)
	}
	if strings.Contains(log.String(), "test-token") {
		t.Error("startup log contains the token")
	}
}

func TestConfigurePolicyDisabledLeavesClientAlone(t *testing.T) {
	var log bytes.Buffer
	// No Paperless is reachable at this URL: disabled, nothing is looked up.
	opts, err := configurePolicy(context.Background(), getenvFrom(map[string]string{}), "http://127.0.0.1:9", "test-token", http.DefaultTransport, &log)
	if err != nil {
		t.Fatalf("configurePolicy: %s", err)
	}
	if len(opts) != 0 {
		t.Errorf("got %d client options, want none", len(opts))
	}
	if log.String() != policyDisabledLine {
		t.Errorf("log = %q, want %q", log.String(), policyDisabledLine)
	}
	if client := NewClient("http://127.0.0.1:9", "test-token", opts...); client.httpClient.Transport != nil {
		t.Errorf("transport = %T, want nil (net/http default, as upstream)", client.httpClient.Transport)
	}
}

func TestConfigurePolicyResolutionErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tags    []namedID
		fields  []namedID
		env     map[string]string
		wantErr string
	}{
		{
			name:    "tag not found",
			tags:    slices.DeleteFunc(defaultResolveTags(), func(n namedID) bool { return n.Name == "dp:internal" }),
			fields:  defaultResolveFields(),
			wantErr: `policy: tag "dp:internal" not found`,
		},
		{
			name:    "tag name is ambiguous",
			tags:    append(defaultResolveTags(), namedID{"gpt-reset", 999}),
			fields:  defaultResolveFields(),
			wantErr: `policy: tag name "gpt-reset" is ambiguous: it matches 2 objects (IDs 107, 999)`,
		},
		{
			name:    "case must match exactly",
			tags:    append(slices.DeleteFunc(defaultResolveTags(), func(n namedID) bool { return n.Name == "dp:public" }), namedID{"DP:Public", tagPublic}),
			fields:  defaultResolveFields(),
			wantErr: `policy: tag "dp:public" not found`,
		},
		{
			name:    "custom field not found",
			tags:    defaultResolveTags(),
			fields:  defaultResolveFields()[1:],
			wantErr: `policy: custom field "AI privacy class" not found`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := resolveServer(t, tc.tags, tc.fields)
			env := testPolicyEnv()
			var log bytes.Buffer
			_, err := configurePolicy(context.Background(), getenvFrom(env), srv.URL, "test-token", http.DefaultTransport, &log)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "test-token") {
				t.Errorf("error contains the token: %s", err)
			}
		})
	}
}

func TestConfigurePolicyLookupFailures(t *testing.T) {
	// Paperless rejects the token.
	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"Invalid token. secret-body-text"}`))
	}))
	t.Cleanup(unauthorized.Close)
	_, err := configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), unauthorized.URL, "test-token", http.DefaultTransport, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "Paperless answered with status 401") {
		t.Fatalf("error = %v, want status 401", err)
	}
	if strings.Contains(err.Error(), "secret-body-text") || strings.Contains(err.Error(), "test-token") {
		t.Errorf("error leaks a response body or the token: %s", err)
	}

	// Paperless is unreachable.
	_, err = configurePolicy(context.Background(), getenvFrom(testPolicyEnv()), "http://127.0.0.1:9", "test-token", http.DefaultTransport, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `policy: resolve tag "dp:public": request failed`) {
		t.Fatalf("error = %v, want a request failure", err)
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Errorf("error contains the token: %s", err)
	}
}

// TestMCPExitsOnPolicyErrors runs the mcp command with broken policy
// settings and checks it refuses to start with a clear error that does not
// contain the token.
func TestMCPExitsOnPolicyErrors(t *testing.T) {
	srv := resolveServer(t, defaultResolveTags(), defaultResolveFields())
	for _, tc := range []struct {
		name    string
		change  map[string]string
		wantErr string
	}{
		{"invalid enabled value", map[string]string{envPolicyEnabled: "on"}, "PAPERLESS_MCP_POLICY_ENABLED must be true or false"},
		{"empty full tags", map[string]string{envPolicyFullTags: ""}, "PAPERLESS_MCP_POLICY_FULL_TAGS must name at least one tag"},
		{"empty metadata tags", map[string]string{envPolicyMetadataTags: ""}, "PAPERLESS_MCP_POLICY_METADATA_TAGS must name at least one tag"},
		{"unknown tag name", map[string]string{envPolicyProtectedTags: "no-such-tag"}, `policy: tag "no-such-tag" not found`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testPolicyEnv()
			for k, v := range tc.change {
				env[k] = v
			}
			for k, v := range env {
				t.Setenv(k, v)
			}
			t.Setenv("PAPERLESS_URL", srv.URL)
			t.Setenv("PAPERLESS_TOKEN", "test-token")
			t.Setenv("PAPERLESS_MCP_DOWNLOAD_DIR", "")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stderr bytes.Buffer
			cmd := rootCmd()
			cmd.SetArgs([]string{"mcp"})
			cmd.SetOut(&stderr)
			cmd.SetErr(&stderr)
			cmd.SetIn(strings.NewReader(""))
			if err := cmd.ExecuteContext(ctx); err == nil {
				t.Fatal("mcp started, want it to refuse")
			}
			if !strings.HasPrefix(stderr.String(), "Error: ") || !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want an error line containing %q", stderr.String(), tc.wantErr)
			}
			if strings.Contains(stderr.String(), "Usage:") {
				t.Errorf("stderr contains usage for a configuration error:\n%s", stderr.String())
			}
			if strings.Contains(stderr.String(), "test-token") {
				t.Errorf("stderr contains the token:\n%s", stderr.String())
			}
		})
	}
}
