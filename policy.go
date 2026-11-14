package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The policy filter is an opt-in barrier between the MCP tools and
// Paperless-ngx. It sorts documents into tiers by their tags: documents in
// the full tier expose text and files, all others expose metadata only.
// It also keeps the agent from changing the tags and custom fields that make
// up the classification. See policy_transport.go for where it is enforced.

// Environment variables that configure the policy filter.
const (
	envPolicyEnabled               = "PAPERLESS_MCP_POLICY_ENABLED"
	envPolicyFullTags              = "PAPERLESS_MCP_POLICY_FULL_TAGS"
	envPolicyMetadataTags          = "PAPERLESS_MCP_POLICY_METADATA_TAGS"
	envPolicyRestrictedTags        = "PAPERLESS_MCP_POLICY_RESTRICTED_TAGS"
	envPolicyProtectedTags         = "PAPERLESS_MCP_POLICY_PROTECTED_TAGS"
	envPolicyProtectedCustomFields = "PAPERLESS_MCP_POLICY_PROTECTED_CUSTOM_FIELDS"
)

// policyDisabledLine is what the server logs at startup when the filter is off.
const policyDisabledLine = "policy filter: disabled\n"

// policyLookupTimeout bounds each startup name lookup.
const policyLookupTimeout = 30 * time.Second

// tier is the access level of a document under the policy.
type tier int

const (
	// tierMetadata exposes metadata only. It is the zero value, so anything
	// that fails to compute a tier falls back to it.
	tierMetadata tier = iota
	tierFull
	tierRestricted
)

func (t tier) String() string {
	switch t {
	case tierFull:
		return "full"
	case tierRestricted:
		return "restricted"
	default:
		return "metadata"
	}
}

// policyConfig is the policy configuration as read from the environment,
// with names not yet resolved to IDs.
type policyConfig struct {
	Enabled               bool
	FullTags              []string
	MetadataTags          []string
	RestrictedTags        []string
	ProtectedTags         []string
	ProtectedCustomFields []string
}

// loadPolicyConfig reads the PAPERLESS_MCP_POLICY_* variables. With the filter
// disabled, the other variables are ignored. Enabled, the full and metadata
// tag lists must both be non-empty, so a half-configured filter fails closed.
func loadPolicyConfig(getenv func(string) string) (policyConfig, error) {
	var cfg policyConfig
	switch v := strings.TrimSpace(getenv(envPolicyEnabled)); v {
	case "", "false":
		return cfg, nil
	case "true":
		cfg.Enabled = true
	default:
		return cfg, fmt.Errorf("%s must be true or false, got %q", envPolicyEnabled, v)
	}

	cfg.FullTags = splitPolicyNames(getenv(envPolicyFullTags))
	cfg.MetadataTags = splitPolicyNames(getenv(envPolicyMetadataTags))
	cfg.RestrictedTags = splitPolicyNames(getenv(envPolicyRestrictedTags))
	cfg.ProtectedTags = splitPolicyNames(getenv(envPolicyProtectedTags))
	cfg.ProtectedCustomFields = splitPolicyNames(getenv(envPolicyProtectedCustomFields))

	if len(cfg.FullTags) == 0 {
		return cfg, fmt.Errorf("%s is true, so %s must name at least one tag", envPolicyEnabled, envPolicyFullTags)
	}
	if len(cfg.MetadataTags) == 0 {
		return cfg, fmt.Errorf("%s is true, so %s must name at least one tag", envPolicyEnabled, envPolicyMetadataTags)
	}
	return cfg, nil
}

// splitPolicyNames splits a comma-separated list of names and trims each one.
// Empty entries are dropped. MCPB hosts can pass an unsubstituted
// "${user_config.…}" template for a blank optional setting (see
// downloadDirFromEnv); such a value counts as empty.
func splitPolicyNames(value string) []string {
	if strings.Contains(value, "${") {
		return nil
	}
	var names []string
	for part := range strings.SplitSeq(value, ",") {
		if name := strings.TrimSpace(part); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// namedID is a configured name and the ID it resolved to.
type namedID struct {
	Name string
	ID   int
}

// policy is the resolved policy: configured names mapped to Paperless IDs.
type policy struct {
	full       map[int]bool
	metadata   map[int]bool
	restricted map[int]bool
	// protectedTags is the union of the tier tags and the further protected tags.
	protectedTags   map[int]bool
	protectedFields map[int]bool
	// names maps tag and custom field IDs to their configured names, for messages.
	tagNames   map[int]string
	fieldNames map[int]string
}

// newPolicy builds a policy from resolved tag and custom field IDs.
func newPolicy(full, metadata, restricted, protected, fields []namedID) *policy {
	p := &policy{
		full:            map[int]bool{},
		metadata:        map[int]bool{},
		restricted:      map[int]bool{},
		protectedTags:   map[int]bool{},
		protectedFields: map[int]bool{},
		tagNames:        map[int]string{},
		fieldNames:      map[int]string{},
	}
	add := func(set map[int]bool, ids []namedID) {
		for _, n := range ids {
			set[n.ID] = true
			p.protectedTags[n.ID] = true
			p.tagNames[n.ID] = n.Name
		}
	}
	add(p.full, full)
	add(p.metadata, metadata)
	add(p.restricted, restricted)
	add(map[int]bool{}, protected)
	for _, n := range fields {
		p.protectedFields[n.ID] = true
		p.fieldNames[n.ID] = n.Name
	}
	return p
}

// tierOf computes a document's tier from its tag IDs. Deny wins: a restricted
// or metadata tag beats a full tag, and a document without any tier tag is
// metadata.
func (p *policy) tierOf(tagIDs []int) tier {
	var hasMetadata, hasFull bool
	for _, id := range tagIDs {
		switch {
		case p.restricted[id]:
			return tierRestricted
		case p.metadata[id]:
			hasMetadata = true
		case p.full[id]:
			hasFull = true
		}
	}
	if hasFull && !hasMetadata {
		return tierFull
	}
	return tierMetadata
}

// tagLabel names a tag in a policy message: its configured name when it has
// one, else just its ID.
func (p *policy) tagLabel(id int) string {
	if name, ok := p.tagNames[id]; ok {
		return fmt.Sprintf("%d (%s)", id, name)
	}
	return strconv.Itoa(id)
}

// fieldLabel names a custom field in a policy message.
func (p *policy) fieldLabel(id int) string {
	if name, ok := p.fieldNames[id]; ok {
		return fmt.Sprintf("%d (%s)", id, name)
	}
	return strconv.Itoa(id)
}

// --- Tag hierarchy ---

// tagHierarchy is a snapshot of the parent links between tags. Paperless adds
// a tag's ancestors when the tag is added to a document, removes a tag's
// descendants when the tag is removed, and deletes a tag's descendants when
// the tag is deleted. So a tag that is not protected itself can still change
// protected tags through the hierarchy.
type tagHierarchy struct {
	parent   map[int]int // child -> parent, only for tags that have one
	children map[int][]int
}

func newTagHierarchy(parents map[int]int) *tagHierarchy {
	h := &tagHierarchy{parent: parents, children: map[int][]int{}}
	for child, parent := range parents {
		h.children[parent] = append(h.children[parent], child)
	}
	return h
}

// ancestors returns the ancestors of id, not including id itself.
func (h *tagHierarchy) ancestors(id int) []int {
	var result []int
	seen := map[int]bool{id: true}
	for {
		parent, ok := h.parent[id]
		if !ok || seen[parent] {
			return result
		}
		seen[parent] = true
		result = append(result, parent)
		id = parent
	}
}

// withAncestors returns ids plus all their ancestors.
func (h *tagHierarchy) withAncestors(ids []int) map[int]bool {
	result := map[int]bool{}
	for _, id := range ids {
		result[id] = true
		for _, a := range h.ancestors(id) {
			result[a] = true
		}
	}
	return result
}

// withDescendants returns ids plus all their descendants.
func (h *tagHierarchy) withDescendants(ids []int) map[int]bool {
	result := map[int]bool{}
	pending := slices.Clone(ids)
	for _, id := range ids {
		result[id] = true
	}
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, child := range h.children[id] {
			if !result[child] {
				result[child] = true
				pending = append(pending, child)
			}
		}
	}
	return result
}

// finalTags reproduces how Paperless 3.x computes a document's tags when a
// PATCH or PUT sets them (DocumentSerializer.update): newly requested tags
// bring their ancestors, removed tags take their descendants along, and a
// tag that is still required wins over one that is removed.
func (h *tagHierarchy) finalTags(previous, requested []int) map[int]bool {
	prevSet := setOf(previous)
	reqSet := setOf(requested)
	var added, removed []int
	for id := range reqSet {
		if !prevSet[id] {
			added = append(added, id)
		}
	}
	for id := range prevSet {
		if !reqSet[id] {
			removed = append(removed, id)
		}
	}
	required := h.withAncestors(added)
	blocked := h.withDescendants(removed)
	final := h.withAncestors(requested)
	for id := range blocked {
		if !required[id] {
			delete(final, id)
		}
	}
	return final
}

// protectedAncestors returns the tags that are ancestors of a protected tag.
// Changing or deleting one of them changes the protected tags below it.
func (p *policy) protectedAncestors(h *tagHierarchy) map[int]bool {
	result := map[int]bool{}
	for id := range p.protectedTags {
		for _, a := range h.ancestors(id) {
			result[a] = true
		}
	}
	return result
}

// firstProtected returns the lowest protected ID in set, if there is one.
func firstProtected(set map[int]bool, protected map[int]bool) (int, bool) {
	var ids []int
	for id := range set {
		if protected[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, false
	}
	return slices.Min(ids), true
}

func setOf(ids []int) map[int]bool {
	set := make(map[int]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// --- Startup: resolve names to IDs ---

// configurePolicy reads the policy settings and, when the filter is enabled,
// resolves the configured names against Paperless and returns the client
// option that installs the filter. Disabled, it returns no options, so the
// client is built exactly as upstream builds it. It logs one summary to logw.
// base is the transport that carries all Paperless traffic, including the
// startup lookups.
func configurePolicy(ctx context.Context, getenv func(string) string, baseURL, token string, base http.RoundTripper, logw io.Writer) ([]ClientOption, error) {
	cfg, err := loadPolicyConfig(getenv)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		fmt.Fprint(logw, policyDisabledLine)
		return nil, nil
	}

	r := &policyResolver{base: base, baseURL: strings.TrimRight(baseURL, "/"), token: token}
	var full, metadata, restricted, protected, fields []namedID
	for _, step := range []struct {
		names []string
		kind  string
		out   *[]namedID
	}{
		{cfg.FullTags, "tag", &full},
		{cfg.MetadataTags, "tag", &metadata},
		{cfg.RestrictedTags, "tag", &restricted},
		{cfg.ProtectedTags, "tag", &protected},
		{cfg.ProtectedCustomFields, "custom field", &fields},
	} {
		for _, name := range step.names {
			id, err := r.resolve(ctx, step.kind, name)
			if err != nil {
				return nil, err
			}
			*step.out = append(*step.out, namedID{Name: name, ID: id})
		}
	}

	fmt.Fprintln(logw, "policy filter: enabled")
	for _, line := range []struct {
		label string
		ids   []namedID
	}{
		{"full tags", full},
		{"metadata tags", metadata},
		{"restricted tags", restricted},
		{"protected tags", protected},
		{"protected custom fields", fields},
	} {
		fmt.Fprintf(logw, "policy filter: %s: %s\n", line.label, formatNamedIDs(line.ids))
	}

	pol := newPolicy(full, metadata, restricted, protected, fields)
	rt, err := newPolicyTransport(pol, base, baseURL)
	if err != nil {
		return nil, err
	}
	return []ClientOption{WithTransport(rt)}, nil
}

func formatNamedIDs(ids []namedID) string {
	if len(ids) == 0 {
		return "(none)"
	}
	parts := make([]string, len(ids))
	for i, n := range ids {
		parts[i] = fmt.Sprintf("%s=%d", n.Name, n.ID)
	}
	return strings.Join(parts, ", ")
}

// policyResolver looks up tag and custom field IDs by name at startup.
type policyResolver struct {
	base    http.RoundTripper
	baseURL string
	token   string
}

// resolve returns the ID of the one tag or custom field named name. The
// lookup is case-insensitive in Paperless (name__iexact); the match is then
// narrowed to the exact, case-sensitive name. Anything but exactly one match
// is an error. Errors name the object and the HTTP status, never the token or
// a response body.
func (r *policyResolver) resolve(ctx context.Context, kind, name string) (int, error) {
	path := "/api/tags/"
	if kind == "custom field" {
		path = "/api/custom_fields/"
	}
	params := url.Values{"name__iexact": {name}, "page_size": {"100"}}

	ctx, cancel := context.WithTimeout(ctx, policyLookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path+"?"+params.Encode(), nil)
	if err != nil {
		return 0, fmt.Errorf("policy: resolve %s %q: %w", kind, name, err)
	}
	req.Header.Set("Authorization", "Token "+r.token)
	req.Header.Set("Accept", "application/json; version="+apiVersion)
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return 0, fmt.Errorf("policy: resolve %s %q: request failed: %s", kind, name, redactURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("policy: resolve %s %q: read response: %w", kind, name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("policy: resolve %s %q: Paperless answered with status %d", kind, name, resp.StatusCode)
	}

	var page struct {
		Results []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("policy: resolve %s %q: unexpected response format", kind, name)
	}
	var ids []int
	for _, obj := range page.Results {
		if obj.Name == name {
			ids = append(ids, obj.ID)
		}
	}
	switch len(ids) {
	case 1:
		return ids[0], nil
	case 0:
		return 0, fmt.Errorf("policy: %s %q not found (the name must match exactly, including case, and be visible to the API user)", kind, name)
	default:
		return 0, fmt.Errorf("policy: %s name %q is ambiguous: it matches %d objects (IDs %s)", kind, name, len(ids), joinInts(ids))
	}
}

// redactURLError strips the URL from a *url.Error so a lookup failure does
// not echo the request line.
func redactURLError(err error) string {
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		return uerr.Err.Error()
	}
	return err.Error()
}

func joinInts(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ", ")
}

// --- JSON helpers shared by the rules ---

// decodeJSON decodes data keeping numbers as json.Number, so values that pass
// through unchanged keep their exact form.
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after JSON value")
	}
	return v, nil
}

// encodeJSON encodes v without HTML escaping and without a trailing newline.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// asInt converts a decoded JSON value to an int. Paperless accepts IDs as
// numbers or as numeric strings, so both count.
func asInt(v any) (int, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.Atoi(x.String())
		return n, err == nil
	case float64:
		n := int(x)
		return n, float64(n) == x
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		return n, err == nil
	}
	return 0, false
}

// asIntList converts a decoded JSON array of IDs to ints.
func asIntList(v any) ([]int, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	ids := make([]int, 0, len(arr))
	for _, item := range arr {
		id, ok := asInt(item)
		if !ok {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// customFieldIDs extracts custom field IDs from the forms Paperless accepts
// in bulk edits and uploads: a single ID, a list of IDs, a list of
// {"field": id, ...} objects, or an object keyed by ID.
func customFieldIDs(v any) ([]int, bool) {
	switch x := v.(type) {
	case nil:
		return nil, true
	case map[string]any:
		ids := make([]int, 0, len(x))
		for key := range x {
			id, err := strconv.Atoi(strings.TrimSpace(key))
			if err != nil {
				return nil, false
			}
			ids = append(ids, id)
		}
		return ids, true
	case []any:
		ids := make([]int, 0, len(x))
		for _, item := range x {
			if obj, ok := item.(map[string]any); ok {
				id, ok := asInt(obj["field"])
				if !ok {
					return nil, false
				}
				ids = append(ids, id)
				continue
			}
			id, ok := asInt(item)
			if !ok {
				return nil, false
			}
			ids = append(ids, id)
		}
		return ids, true
	default:
		id, ok := asInt(x)
		if !ok {
			return nil, false
		}
		return []int{id}, true
	}
}

// customFieldValues maps field ID to value for a document's custom_fields
// array ([{"field": id, "value": …}, …]).
func customFieldValues(v any) (map[int]any, bool) {
	if v == nil {
		return map[int]any{}, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	values := make(map[int]any, len(arr))
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		id, ok := asInt(obj["field"])
		if !ok {
			return nil, false
		}
		values[id] = obj["value"]
	}
	return values, true
}

// jsonEqual compares two decoded JSON values by their canonical encoding,
// so 1 and 1.0 or reordered object keys count as equal.
func jsonEqual(a, b any) bool {
	ca, errA := canonicalJSON(a)
	cb, errB := canonicalJSON(b)
	return errA == nil && errB == nil && bytes.Equal(ca, cb)
}

func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}
