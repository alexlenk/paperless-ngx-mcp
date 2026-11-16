package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// policyTransport is the http.RoundTripper that enforces the policy filter.
// It sits under Client.httpClient, so every Paperless request passes through
// it. Rules run before a request is forwarded (a blocked request is never
// sent) and after the response returns (document text is removed from JSON
// bodies of documents outside the full tier).
//
// Lookups the rules need (a document's tags, the tag hierarchy) go straight
// to the base transport. They are never cached, so a tag change is effective
// on the next request.
type policyTransport struct {
	pol     *policy
	base    http.RoundTripper
	baseURL string // PAPERLESS_URL without a trailing slash
	scheme  string
	host    string
	prefix  string // path of PAPERLESS_URL, e.g. "" or "/paperless"
}

// lookupChunkSize bounds the number of IDs in one batch tier lookup, keeping
// the query string short.
const lookupChunkSize = 100

// newPolicyTransport returns the policy transport for the Paperless instance
// at baseURL, forwarding allowed requests to base.
func newPolicyTransport(pol *policy, base http.RoundTripper, baseURL string) (*policyTransport, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("policy: PAPERLESS_URL must be an absolute URL such as https://paperless.example.com")
	}
	return &policyTransport{
		pol:     pol,
		base:    base,
		baseURL: trimmed,
		scheme:  strings.ToLower(u.Scheme),
		host:    strings.ToLower(u.Host),
		prefix:  strings.TrimRight(u.EscapedPath(), "/"),
	}, nil
}

// RoundTrip implements http.RoundTripper.
func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	segs, reason := t.route(req)
	if reason != "" {
		if req.Body != nil {
			req.Body.Close()
		}
		return t.block(req, "%s", reason), nil
	}

	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("policy: read request body: %w", err)
		}
		body = b
	}

	resp, err := t.checkRequest(req, segs, body)
	if err != nil || resp != nil {
		return resp, err
	}

	out := req.Clone(req.Context())
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		out.ContentLength = int64(len(body))
	}
	resp, err = t.base.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	return t.filterResponse(req, resp)
}

// route checks that req goes to the configured Paperless API and returns its
// path segments below /api/. Anything else is refused: another host (for
// example after a redirect), a path outside /api/, or a path with encoded
// characters or dot segments that the server might resolve differently than
// the rules below read it.
func (t *policyTransport) route(req *http.Request) ([]string, string) {
	if req.URL.Opaque != "" || !strings.EqualFold(req.URL.Scheme, t.scheme) || !strings.EqualFold(req.URL.Host, t.host) {
		return nil, "requests may only go to the Paperless instance in PAPERLESS_URL"
	}
	path := req.URL.EscapedPath()
	if strings.ContainsAny(path, "%\\") {
		return nil, "the request path contains characters the policy filter does not accept"
	}
	rest, ok := strings.CutPrefix(path, t.prefix+"/api/")
	if !ok {
		return nil, "only the Paperless REST API under /api/ is reachable"
	}
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return nil, ""
	}
	segs := strings.Split(rest, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, "the request path is malformed"
		}
	}
	return segs, ""
}

// checkRequest applies the request rules. It returns a response when the
// request must not be forwarded (blocked, or a 404 from a tier lookup), or
// nil to forward it.
func (t *policyTransport) checkRequest(req *http.Request, segs []string, body []byte) (*http.Response, error) {
	if len(segs) == 0 {
		return nil, nil
	}
	write := isWriteMethod(req.Method)
	switch segs[0] {
	case "documents":
		return t.checkDocuments(req, segs[1:], body)
	case "tags":
		switch {
		case len(segs) == 1 && req.Method == http.MethodPost:
			return t.checkTagWrite(req, 0, body)
		case len(segs) >= 2 && write:
			id, ok := parseID(segs[1])
			if !ok {
				return nil, nil
			}
			return t.checkTagWrite(req, id, body)
		}
	case "custom_fields":
		if len(segs) >= 2 && write {
			if id, ok := parseID(segs[1]); ok && t.pol.protectedFields[id] {
				return t.block(req, "custom field %s is protected and may not be changed or deleted", t.pol.fieldLabel(id)), nil
			}
		}
	case "bulk_edit_objects":
		if write {
			return t.checkBulkEditObjects(req, body)
		}
	case "storage_paths":
		if len(segs) >= 2 && segs[1] == "test" {
			return t.block(req, "testing storage paths is not allowed: the template can read document content"), nil
		}
	case "share_link_bundles":
		if write {
			return t.block(req, "creating or changing share link bundles is not allowed"), nil
		}
	}
	return nil, nil
}

// checkDocuments applies the rules for /api/documents/….
func (t *policyTransport) checkDocuments(req *http.Request, rest []string, body []byte) (*http.Response, error) {
	if len(rest) == 0 {
		return nil, nil
	}
	for _, s := range rest {
		// DRF format suffixes ("616.json") would otherwise slip past the
		// numeric document ID match.
		if strings.Contains(s, ".") {
			return t.block(req, "the request path is malformed"), nil
		}
	}

	id, isDoc := parseID(rest[0])
	if !isDoc {
		switch rest[0] {
		case "email":
			return t.block(req, "emailing documents is not allowed"), nil
		case "chat":
			return t.block(req, "the document chat is not allowed: it answers from document text"), nil
		case "merge", "edit_pdf", "remove_password", "merge_as_versions":
			return t.block(req, "%s is not allowed: it can move file content between documents", rest[0]), nil
		case "bulk_download":
			return t.checkBulkDownload(req, body)
		case "bulk_edit":
			return t.checkBulkEdit(req, body)
		case "post_document":
			return t.checkUpload(req, body)
		}
		return nil, nil
	}

	if len(rest) == 1 {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodDelete:
			// GET responses are filtered by their own tags; deleting moves the
			// document to the trash and returns no text.
			return nil, nil
		case http.MethodPatch, http.MethodPut:
			return t.checkDocumentWrite(req, id, body)
		default:
			return t.block(req, "%s on a document is not allowed", req.Method), nil
		}
	}

	switch rest[1] {
	case "metadata", "notes", "share_links":
		return nil, nil
	case "email":
		return t.block(req, "emailing documents is not allowed"), nil
	}
	// download, preview, thumb, history, suggestions, ai_suggestions and any
	// action not named above: only the full tier.
	state, resp, err := t.lookupDocument(req, id, false)
	if err != nil || resp != nil {
		return resp, err
	}
	if tr := t.pol.tierOf(state.tags); tr != tierFull {
		return t.block(req, "full text is not available for document %d (tier: %s)", id, tr), nil
	}
	return nil, nil
}

// checkDocumentWrite applies rule 2 to PATCH and PUT on a document.
func (t *policyTransport) checkDocumentWrite(req *http.Request, id int, body []byte) (*http.Response, error) {
	obj, ok := t.jsonObject(req, body)
	if !ok {
		return t.block(req, "the request body must be a JSON object"), nil
	}
	if _, has := obj["owner"]; has {
		return t.block(req, "changing the owner of a document is not allowed"), nil
	}
	if _, has := obj["set_permissions"]; has {
		return t.block(req, "changing the permissions of a document is not allowed"), nil
	}
	if v, has := obj["remove_inbox_tags"]; has && v != nil && v != false {
		return t.block(req, "remove_inbox_tags is not allowed: send the new tags instead"), nil
	}
	newTags, hasTags := obj["tags"]
	newFields, hasFields := obj["custom_fields"]
	if !hasTags && !hasFields {
		return nil, nil
	}

	state, resp, err := t.lookupDocument(req, id, hasFields)
	if err != nil || resp != nil {
		return resp, err
	}

	if hasTags {
		requested, ok := asIntList(newTags)
		if !ok {
			return t.block(req, "tags must be a list of tag IDs"), nil
		}
		h, resp, err := t.lookupHierarchy(req)
		if err != nil || resp != nil {
			return resp, err
		}
		current := setOf(state.tags)
		final := h.finalTags(state.tags, requested)
		for _, p := range sortedKeys(t.pol.protectedTags) {
			switch {
			case current[p] && !final[p]:
				return t.block(req, "protected tag %s may not be removed from document %d (send the document's current protected tags unchanged)", t.pol.tagLabel(p), id), nil
			case !current[p] && final[p]:
				return t.block(req, "protected tag %s may not be added to document %d (directly or as the parent of an added tag)", t.pol.tagLabel(p), id), nil
			}
		}
	}

	if hasFields {
		incoming, ok := customFieldValues(newFields)
		if !ok {
			return t.block(req, "custom_fields must be a list of {\"field\": id, \"value\": …} objects"), nil
		}
		current, ok := customFieldValues(state.customFields)
		if !ok {
			return t.block(req, "could not read the current custom fields of document %d", id), nil
		}
		for _, f := range sortedKeys(t.pol.protectedFields) {
			cur, hasCur := current[f]
			inc, hasInc := incoming[f]
			switch {
			case hasCur && !hasInc:
				return t.block(req, "protected custom field %s may not be removed from document %d (custom_fields replaces all of a document's fields: include it with its current value)", t.pol.fieldLabel(f), id), nil
			case !hasCur && hasInc:
				return t.block(req, "protected custom field %s may not be added to document %d", t.pol.fieldLabel(f), id), nil
			case hasCur && !jsonEqual(cur, inc):
				return t.block(req, "protected custom field %s of document %d may not be changed", t.pol.fieldLabel(f), id), nil
			}
		}
	}
	return nil, nil
}

// checkBulkEdit applies the rules for POST /api/documents/bulk_edit/.
// Methods not named here are blocked, so methods added by later Paperless
// versions fail closed.
func (t *policyTransport) checkBulkEdit(req *http.Request, body []byte) (*http.Response, error) {
	obj, ok := t.jsonObject(req, body)
	if !ok {
		return t.block(req, "the request body must be a JSON object"), nil
	}
	method, _ := obj["method"].(string)
	params := map[string]any{}
	if p, has := obj["parameters"]; has && p != nil {
		if params, ok = p.(map[string]any); !ok {
			return t.block(req, "bulk_edit parameters must be a JSON object"), nil
		}
	}

	switch method {
	case "set_correspondent", "set_document_type", "set_storage_path", "rotate", "reprocess", "delete":
		return nil, nil
	case "set_permissions", "run_workflow":
		return t.block(req, "bulk_edit method %s is not allowed", method), nil
	case "merge", "split", "delete_pages", "edit_pdf", "remove_password":
		return t.block(req, "bulk_edit method %s is not allowed: it can move file content between documents", method), nil
	case "add_tag", "remove_tag":
		tag, ok := asInt(params["tag"])
		if !ok {
			return t.block(req, "bulk_edit %s needs parameters.tag as a tag ID", method), nil
		}
		if method == "add_tag" {
			return t.checkTagsAdded(req, []int{tag})
		}
		return t.checkTagsRemoved(req, []int{tag})
	case "modify_tags":
		add, okAdd := optionalIntList(params["add_tags"])
		remove, okRemove := optionalIntList(params["remove_tags"])
		if !okAdd || !okRemove {
			return t.block(req, "bulk_edit modify_tags needs add_tags and remove_tags as lists of tag IDs"), nil
		}
		if resp, err := t.checkTagsAdded(req, add); err != nil || resp != nil {
			return resp, err
		}
		return t.checkTagsRemoved(req, remove)
	case "modify_custom_fields":
		for _, key := range []string{"add_custom_fields", "remove_custom_fields"} {
			ids, ok := customFieldIDs(params[key])
			if !ok {
				return t.block(req, "bulk_edit modify_custom_fields: %s is not a list or object of custom field IDs", key), nil
			}
			for _, id := range ids {
				if t.pol.protectedFields[id] {
					return t.block(req, "custom field %s is protected and may not be set or removed", t.pol.fieldLabel(id)), nil
				}
			}
		}
		return nil, nil
	}
	return t.block(req, "bulk_edit method %q is not allowed by the policy filter", method), nil
}

// checkTagsAdded blocks adding tags that are protected or that would bring a
// protected ancestor along.
func (t *policyTransport) checkTagsAdded(req *http.Request, tags []int) (*http.Response, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	h, resp, err := t.lookupHierarchy(req)
	if err != nil || resp != nil {
		return resp, err
	}
	if p, found := firstProtected(h.withAncestors(tags), t.pol.protectedTags); found {
		return t.block(req, "protected tag %s may not be added (directly or as the parent of an added tag)", t.pol.tagLabel(p)), nil
	}
	return nil, nil
}

// checkTagsRemoved blocks removing tags that are protected or that would take
// a protected descendant along.
func (t *policyTransport) checkTagsRemoved(req *http.Request, tags []int) (*http.Response, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	h, resp, err := t.lookupHierarchy(req)
	if err != nil || resp != nil {
		return resp, err
	}
	if p, found := firstProtected(h.withDescendants(tags), t.pol.protectedTags); found {
		return t.block(req, "protected tag %s may not be removed (directly or as the child of a removed tag)", t.pol.tagLabel(p)), nil
	}
	return nil, nil
}

// checkUpload applies rule 2 to POST /api/documents/post_document/: the
// upload may not set protected tags (or tags below them) or protected
// custom fields.
func (t *policyTransport) checkUpload(req *http.Request, body []byte) (*http.Response, error) {
	mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return t.block(req, "document uploads must be multipart/form-data"), nil
	}
	var tags []int
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return t.block(req, "the upload form could not be read"), nil
		}
		name := part.FormName()
		if name != "tags" && name != "custom_fields" {
			part.Close()
			continue
		}
		value, err := io.ReadAll(part)
		part.Close()
		if err != nil {
			return t.block(req, "the upload form could not be read"), nil
		}
		if name == "tags" {
			id, err := strconv.Atoi(strings.TrimSpace(string(value)))
			if err != nil {
				return t.block(req, "upload tags must be tag IDs"), nil
			}
			tags = append(tags, id)
			continue
		}
		v, err := decodeJSON(value)
		if err != nil {
			return t.block(req, "upload custom_fields must be JSON"), nil
		}
		ids, ok := customFieldIDs(v)
		if !ok {
			return t.block(req, "upload custom_fields must reference custom fields by ID"), nil
		}
		for _, id := range ids {
			if t.pol.protectedFields[id] {
				return t.block(req, "custom field %s is protected and may not be set on upload", t.pol.fieldLabel(id)), nil
			}
		}
	}
	return t.checkTagsAdded(req, tags)
}

// checkBulkDownload lets a bulk download through only when it names its
// documents explicitly and every one of them is in the full tier.
func (t *policyTransport) checkBulkDownload(req *http.Request, body []byte) (*http.Response, error) {
	obj, ok := t.jsonObject(req, body)
	if !ok {
		return t.block(req, "the request body must be a JSON object"), nil
	}
	if all, has := obj["all"]; has && all != nil && all != false {
		return t.block(req, "bulk_download needs an explicit list of documents"), nil
	}
	ids, ok := asIntList(obj["documents"])
	if !ok || len(ids) == 0 {
		return t.block(req, "bulk_download needs an explicit list of documents"), nil
	}
	tiers, resp, err := t.lookupTiers(req, ids)
	if err != nil || resp != nil {
		return resp, err
	}
	for _, id := range ids {
		if tr := tiers[id]; tr != tierFull {
			return t.block(req, "full text is not available for document %d (tier: %s)", id, tr), nil
		}
	}
	return nil, nil
}

// checkTagWrite applies the rules to creating (id 0), changing or deleting a
// tag: protected tags and the parents of protected tags may not be changed or
// deleted, and no tag may be placed under a protected tag.
func (t *policyTransport) checkTagWrite(req *http.Request, id int, body []byte) (*http.Response, error) {
	if id != 0 && t.pol.protectedTags[id] {
		return t.block(req, "tag %s is protected and may not be changed or deleted", t.pol.tagLabel(id)), nil
	}

	parent, hasParent := 0, false
	if req.Method != http.MethodDelete {
		obj, ok := t.jsonObject(req, body)
		if !ok {
			return t.block(req, "the request body must be a JSON object"), nil
		}
		if v, has := obj["parent"]; has && v != nil {
			if parent, ok = asInt(v); !ok {
				return t.block(req, "parent must be a tag ID"), nil
			}
			hasParent = true
		}
	}
	if id == 0 && !hasParent {
		return nil, nil
	}

	h, resp, err := t.lookupHierarchy(req)
	if err != nil || resp != nil {
		return resp, err
	}
	if id != 0 && t.pol.protectedAncestors(h)[id] {
		return t.block(req, "tag %d is a parent of a protected tag and may not be changed or deleted", id), nil
	}
	if hasParent {
		if p, found := firstProtected(h.withAncestors([]int{parent}), t.pol.protectedTags); found {
			return t.block(req, "tags may not be placed under protected tag %s", t.pol.tagLabel(p)), nil
		}
	}
	return nil, nil
}

// checkBulkEditObjects applies the rules to POST /api/bulk_edit_objects/:
// no permission changes, and no deleting protected tags or their parents.
func (t *policyTransport) checkBulkEditObjects(req *http.Request, body []byte) (*http.Response, error) {
	obj, ok := t.jsonObject(req, body)
	if !ok {
		return t.block(req, "the request body must be a JSON object"), nil
	}
	if op, _ := obj["operation"].(string); op == "set_permissions" {
		return t.block(req, "changing permissions is not allowed"), nil
	}
	if objectType, _ := obj["object_type"].(string); objectType != "tags" {
		return nil, nil
	}
	if all, has := obj["all"]; has && all != nil && all != false {
		return t.block(req, "bulk edits of tags need an explicit list of tags"), nil
	}
	ids, ok := asIntList(obj["objects"])
	if !ok {
		return t.block(req, "objects must be a list of tag IDs"), nil
	}
	h, resp, err := t.lookupHierarchy(req)
	if err != nil || resp != nil {
		return resp, err
	}
	ancestors := t.pol.protectedAncestors(h)
	for _, id := range ids {
		if t.pol.protectedTags[id] {
			return t.block(req, "tag %s is protected and may not be changed or deleted", t.pol.tagLabel(id)), nil
		}
		if ancestors[id] {
			return t.block(req, "tag %d is a parent of a protected tag and may not be changed or deleted", id), nil
		}
	}
	return nil, nil
}

// --- Response rules ---

// filterResponse removes document text from 2xx JSON responses: for every
// document outside the full tier, the "content" key and the search
// highlights built from content. Other responses pass unchanged.
func (t *policyTransport) filterResponse(req *http.Request, resp *http.Response) (*http.Response, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !isJSONContentType(resp.Header.Get("Content-Type")) {
		return resp, nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("policy: read response body: %w", err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}
	v, err := decodeJSON(body)
	if err != nil {
		return t.block(req, "the response from Paperless could not be checked"), nil
	}

	docs := collectDocuments(v, nil)
	if len(docs) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	tiers := make([]tier, len(docs))
	var missing []int
	for i, doc := range docs {
		if raw, has := doc["tags"]; has {
			tags, _ := asIntList(raw) // unreadable tags leave the metadata tier
			tiers[i] = t.pol.tierOf(tags)
			continue
		}
		id, _ := asInt(doc["id"])
		missing = append(missing, id)
	}
	if len(missing) > 0 {
		looked, blocked, err := t.lookupTiers(req, missing)
		if err != nil || blocked != nil {
			return blocked, err
		}
		for i, doc := range docs {
			if _, has := doc["tags"]; !has {
				id, _ := asInt(doc["id"])
				tiers[i] = looked[id] // not found: the zero value, metadata
			}
		}
	}

	changed := false
	for i, doc := range docs {
		if tiers[i] == tierFull {
			continue
		}
		if _, has := doc["content"]; has {
			delete(doc, "content")
			changed = true
		}
		if hit, ok := doc["__search_hit__"].(map[string]any); ok {
			if _, has := hit["highlights"]; has {
				delete(hit, "highlights")
				changed = true
			}
		}
	}
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	}

	filtered, err := encodeJSON(v)
	if err != nil {
		return nil, fmt.Errorf("policy: encode filtered response: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(filtered))
	resp.ContentLength = int64(len(filtered))
	resp.Header.Set("Content-Length", strconv.Itoa(len(filtered)))
	return resp, nil
}

// collectDocuments walks a decoded JSON value and returns every object that
// looks like a document: an integer "id" plus a "content" or
// "__search_hit__" key.
func collectDocuments(v any, docs []map[string]any) []map[string]any {
	switch x := v.(type) {
	case map[string]any:
		if n, ok := x["id"].(json.Number); ok {
			if _, err := strconv.Atoi(n.String()); err == nil {
				_, hasContent := x["content"]
				_, hasHit := x["__search_hit__"]
				if hasContent || hasHit {
					docs = append(docs, x)
				}
			}
		}
		for _, child := range x {
			docs = collectDocuments(child, docs)
		}
	case []any:
		for _, child := range x {
			docs = collectDocuments(child, docs)
		}
	}
	return docs
}

// --- Lookups through the base transport ---

// documentState is what a single-document lookup returns.
type documentState struct {
	tags         []int
	customFields any
}

// lookupDocument fetches a document's tags (and custom fields when asked)
// with the caller's credentials. A 404 is returned as a response to pass
// through; any other failure to read the tags blocks the request.
func (t *policyTransport) lookupDocument(req *http.Request, id int, withCustomFields bool) (*documentState, *http.Response, error) {
	fields := "id,tags"
	if withCustomFields {
		fields += ",custom_fields"
	}
	status, header, body, err := t.get(req, fmt.Sprintf("/api/documents/%d/", id), url.Values{"fields": {fields}})
	if err != nil {
		return nil, nil, err
	}
	if status == http.StatusNotFound {
		return nil, passThrough(req, status, header, body), nil
	}
	if status != http.StatusOK {
		return nil, t.block(req, "could not determine the tier of document %d (lookup status %d)", id, status), nil
	}
	v, err := decodeJSON(body)
	obj, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, t.block(req, "could not determine the tier of document %d", id), nil
	}
	tags, ok := asIntList(obj["tags"])
	if !ok {
		return nil, t.block(req, "could not determine the tier of document %d", id), nil
	}
	return &documentState{tags: tags, customFields: obj["custom_fields"]}, nil, nil
}

// lookupTiers fetches the tiers of several documents in batches. Documents
// the lookup does not return are absent from the map, which callers read as
// the metadata tier.
func (t *policyTransport) lookupTiers(req *http.Request, ids []int) (map[int]tier, *http.Response, error) {
	tiers := map[int]tier{}
	unique := slices.Compact(slices.Sorted(slices.Values(ids)))
	for chunk := range slices.Chunk(unique, lookupChunkSize) {
		params := url.Values{
			"id__in":    {joinIntsComma(chunk)},
			"fields":    {"id,tags"},
			"page_size": {strconv.Itoa(len(chunk))},
		}
		status, _, body, err := t.get(req, "/api/documents/", params)
		if err != nil {
			return nil, nil, err
		}
		if status != http.StatusOK {
			return nil, t.block(req, "could not determine the tier of documents in the response (lookup status %d)", status), nil
		}
		var page struct {
			Results []struct {
				ID   int   `json:"id"`
				Tags []int `json:"tags"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, t.block(req, "could not determine the tier of documents in the response"), nil
		}
		for _, r := range page.Results {
			tiers[r.ID] = t.pol.tierOf(r.Tags)
		}
	}
	return tiers, nil, nil
}

// maxTagPages bounds the tag hierarchy lookup.
const maxTagPages = 1000

// lookupHierarchy fetches the parent link of every tag visible to the user.
func (t *policyTransport) lookupHierarchy(req *http.Request) (*tagHierarchy, *http.Response, error) {
	parents := map[int]int{}
	for page := 1; page <= maxTagPages; page++ {
		params := url.Values{"page": {strconv.Itoa(page)}, "page_size": {"1000"}}
		status, _, body, err := t.get(req, "/api/tags/", params)
		if err != nil {
			return nil, nil, err
		}
		if status != http.StatusOK {
			return nil, t.block(req, "could not read the tag hierarchy (lookup status %d)", status), nil
		}
		var resp struct {
			Next    *string `json:"next"`
			Results []struct {
				ID     int  `json:"id"`
				Parent *int `json:"parent"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, t.block(req, "could not read the tag hierarchy"), nil
		}
		for _, r := range resp.Results {
			if r.Parent != nil {
				parents[r.ID] = *r.Parent
			}
		}
		if resp.Next == nil || len(resp.Results) == 0 {
			return newTagHierarchy(parents), nil, nil
		}
	}
	return nil, t.block(req, "could not read the tag hierarchy (too many tags)"), nil
}

// get performs a lookup GET through the base transport, with the
// Authorization header of the request being checked.
func (t *policyTransport) get(req *http.Request, path string, params url.Values) (int, http.Header, []byte, error) {
	u := t.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	lr, err := http.NewRequestWithContext(req.Context(), http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("policy: build lookup: %w", err)
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		lr.Header.Set("Authorization", auth)
	}
	lr.Header.Set("Accept", "application/json; version="+apiVersion)
	resp, err := t.base.RoundTrip(lr)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("policy: lookup failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("policy: read lookup response: %w", err)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// --- Helpers ---

// block returns the synthetic response for a blocked request: status 403 and
// {"detail": "policy: <reason>"}. The reason names the rule; it never holds
// credentials, headers or a Paperless response body.
func (t *policyTransport) block(req *http.Request, format string, args ...any) *http.Response {
	notePolicyBlock(req.Context())
	body, _ := encodeJSON(map[string]string{"detail": "policy: " + fmt.Sprintf(format, args...)})
	return syntheticResponse(req, http.StatusForbidden, http.Header{"Content-Type": {"application/json"}}, body)
}

// passThrough returns a lookup's response (a 404) in place of the request.
func passThrough(req *http.Request, status int, header http.Header, body []byte) *http.Response {
	h := http.Header{}
	if ct := header.Get("Content-Type"); ct != "" {
		h.Set("Content-Type", ct)
	}
	return syntheticResponse(req, status, h, body)
}

func syntheticResponse(req *http.Request, status int, header http.Header, body []byte) *http.Response {
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// jsonObject decodes a JSON request body as an object. An empty body is an
// empty object.
func (t *policyTransport) jsonObject(req *http.Request, body []byte) (map[string]any, bool) {
	if len(bytes.TrimSpace(body)) == 0 {
		return map[string]any{}, true
	}
	if !isJSONContentType(req.Header.Get("Content-Type")) {
		return nil, false
	}
	v, err := decodeJSON(body)
	if err != nil {
		return nil, false
	}
	obj, ok := v.(map[string]any)
	return obj, ok
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// parseID parses a path segment as a document, tag or field ID.
func parseID(s string) (int, bool) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// optionalIntList is asIntList that accepts a missing value as empty.
func optionalIntList(v any) ([]int, bool) {
	if v == nil {
		return nil, true
	}
	return asIntList(v)
}

func joinIntsComma(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}

func sortedKeys(set map[int]bool) []int {
	keys := make([]int, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
