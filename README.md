# paperless-ngx-mcp

MCP server for [Paperless-ngx](https://docs.paperless-ngx.com/) document management. Enables AI agents (Claude Code, CoWork) to search, browse, and manage documents and metadata in a Paperless-ngx instance.

## Features

- **100+ MCP tools** covering the full Paperless-ngx REST API v9
- **Document management** — list, search, get, update, delete, upload, download, email
- **Metadata CRUD** — tags, correspondents, document types, storage paths, custom fields
- **Full-text search** with tag filtering, date ranges, and custom field queries
- **Bulk operations** — batch edit, reprocess, merge, split, rotate, delete
- **Notes** — add, list, and delete notes on documents
- **Saved views, share links, mail, workflows** — full admin toolset
- **User & group management** — CRUD, profile, TOTP deactivation
- **System tools** — status, tasks, logs, config, trash management
- **In-memory caching** of metadata lists (tags, correspondents, document types, storage paths, custom fields) with automatic invalidation

## Installation

### CoWork / Claude Desktop (MCPB bundle)

Download the `.mcpb` bundle for your platform from the [latest release](https://github.com/alexlenk/paperless-ngx-mcp/releases/latest) and install it as an extension. You'll be prompted for your Paperless-ngx URL and API token.

### Claude Code (CLI)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "paperless": {
      "command": "/path/to/paperless-ngx-mcp",
      "args": ["mcp"],
      "env": {
        "PAPERLESS_URL": "http://localhost:8000",
        "PAPERLESS_TOKEN": "your-api-token"
      }
    }
  }
}
```

### Docker

```bash
docker run --rm -i \
  -e PAPERLESS_URL=http://localhost:8000 \
  -e PAPERLESS_TOKEN=your-api-token \
  ghcr.io/alexlenk/paperless-ngx-mcp:latest mcp
```

### From source

```bash
git clone https://github.com/alexlenk/paperless-ngx-mcp
cd paperless-ngx-mcp
make install   # installs to ~/.local/bin; set INSTALL_DIR to change
```

This is a fork of [freeformz/paperless-ngx-mcp](https://github.com/freeformz/paperless-ngx-mcp) that adds the [policy filter](#policy-filter). Its Go module path is still `github.com/freeformz/paperless-ngx-mcp`.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `PAPERLESS_URL` | yes | Base URL of the Paperless-ngx instance |
| `PAPERLESS_TOKEN` | yes | API authentication token |
| `PAPERLESS_MCP_DOWNLOAD_DIR` | no | Directory for document downloads. When set, files are saved here (or in a `dest_dir` subdirectory) with their real filenames and are left alone by `cleanup_downloads`. When unset, a per-instance temp directory (`paperless-ngx-mcp-*` in the system temp dir) is used and deleted with its contents when the server shuts down: on stdin EOF, SIGINT, SIGTERM or SIGHUP, or when the MCP host exits mid-call. A server killed with SIGKILL, or by a second signal during shutdown, can't clean up and leaves that directory behind. |

| `PAPERLESS_MCP_POLICY_*` | no | Optional policy filter, off by default. See [Policy filter](#policy-filter). |

Generate an API token in Paperless-ngx under **Settings > Administration > Auth Tokens**.

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--download-concurrency` | 5 | Max parallel document downloads (at least 1) |

### Exit Status

| Status | When |
|--------|------|
| 0 | Graceful shutdown: the MCP host closed stdin, or sent a first SIGINT, SIGTERM or SIGHUP. The shutdown doesn't print an error or usage, though a response that can't be written because the host has gone is still logged to stderr. |
| 1 | An error, printed to stderr as `Error: <message>`, such as an unset `PAPERLESS_URL` or `PAPERLESS_TOKEN`, or a [policy filter](#policy-filter) setting that is invalid or names a tag or custom field that doesn't resolve to exactly one object. Only flag errors, such as an unknown flag or a `--download-concurrency` below 1, also print usage. |
| 128 + signal number | A second signal ended a stalled shutdown: shells and Docker report 130 for SIGINT, 143 for SIGTERM and 129 for SIGHUP. The temp download directory is left behind. |

## Policy filter

Paperless-ngx permissions work per document, not per field: a user who can see a document can read its full text, notes and files. The policy filter adds what Paperless can't express: an agent that may find, read and change the **metadata** of every document its Paperless user can see, but may read the **text and files** only of documents with certain tags. It also keeps the agent from changing the classification that decides this.

The filter is **off by default**. Switched off, the server behaves exactly like it does without this feature and logs `policy filter: disabled` to stderr at startup.

**The filter is the only barrier protecting the text of documents outside the full tier.** The agent's Paperless user can read all of it through the API; only this server, when the filter is on, holds it back. Anything else that uses the same token sees everything.

### Tiers

Each document gets a tier from its tags, computed fresh on every request:

| Tags on the document | Tier | The agent gets |
|---|---|---|
| any restricted tag | restricted | metadata only (such documents should not be visible to the user at all) |
| any metadata tag | metadata | metadata only |
| a full tag, and none of the above | full | metadata, text and files |
| no tier tag | metadata | metadata only |

A metadata tag wins over a full tag: a document tagged both `dp:internal` and `dp:confidential` is metadata.

Metadata is everything except the text: title, correspondent, document type, tags, dates, ASN, custom fields, notes, file metadata (`document_metadata`) and share links. For documents outside the full tier, the filter:

- removes `content` and the search highlights built from it from every JSON response (`document_list`, `document_get`, `document_update`, full-text search, `more_like_id`, `search_global`, `trash_list`, and any other response that carries documents);
- blocks `document_download` (all variants, including thumbnails), `document_page_image`, `document_history` (the audit log holds old and new text) and `document_suggestions`, and any other per-document endpoint not known to be metadata only.

Files of trashed documents, and files requested by the ID of an older document version, are blocked in every tier: the tier lookup can't see those documents, so the request gets Paperless's 404.

Regardless of tier it blocks `document_email`, `storage_path_test` (storage path templates can read the text), the file operations that move content between documents (`merge`, `split`, `delete_pages`, `edit_pdf`, `remove_password`, merging as versions), Paperless's built-in AI chat, bulk downloads that are not an explicit list of full-tier documents, and creating or changing share link bundles.

### The classification is read-only

The tier tags, the further protected tags and the protected custom fields can't be changed by the agent:

- `document_update`, `document_bulk_edit` and `document_upload` may not add or remove a protected tag, or set, change or remove a protected custom field. Re-sending a document's current protected tags and fields unchanged is fine. `custom_fields` in `document_update` replaces all of a document's custom fields, so protected fields must be included with their current values.
- Protected tags and custom fields may not be renamed, re-matched or deleted (`tag_update`, `tag_delete`, `custom_field_update`, `custom_field_delete`, `bulk_edit_objects`).
- Nested tags count: Paperless adds a tag's parents along with it, removes a tag's children along with it, and deletes a tag's children along with it. So the agent may not add a tag that sits below a protected tag, remove a tag that has a protected tag below it, create or move a tag below a protected tag, or change or delete a parent of a protected tag.
- `document_update` may not change a document's owner or permissions or use `remove_inbox_tags`, and `document_bulk_edit` may not use `set_permissions` or `run_workflow`. `bulk_edit_objects` may not set permissions.
- `document_bulk_edit` methods the filter doesn't know are blocked, so methods added by later Paperless versions fail closed.

A blocked request is never sent to Paperless. The tool returns status 403 with a reason, for example `policy: full text is not available for document 616 (tier: metadata)`.

### What the filter does not stop

- **Search matches the text.** Full-text search (`document_list` with `query`, `search_global`), `more_like_id` and the `content` filter of `document_list` match the text of metadata-tier documents; only the text itself is removed from the results. Repeated `content` filter queries can confirm a guessed phrase. This is intended: finding the right document is allowed.
- **Autocomplete returns words from the text.** `search_autocomplete` suggests words from the full-text index of every document the user can see, including words from metadata-tier documents.
- **Custom field values and notes are not filtered.** Keeping sensitive values out of them (for example out of an AI-written summary) is up to whatever writes them.
- **Workflows, storage paths, mail rules, share links, users, groups and app config are not filtered.** Paperless's own permissions must keep the agent from changing them (see below).

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PAPERLESS_MCP_POLICY_ENABLED` | `false` | `true` switches the filter on. Any value other than `true` or `false` stops the server with an error. |
| `PAPERLESS_MCP_POLICY_FULL_TAGS` | empty | Comma-separated tag names whose documents may expose text and files. Required when enabled. |
| `PAPERLESS_MCP_POLICY_METADATA_TAGS` | empty | Comma-separated tag names whose documents expose metadata only. Required when enabled. |
| `PAPERLESS_MCP_POLICY_RESTRICTED_TAGS` | empty | Comma-separated tag names of documents that should never be visible to the user (listed so they are protected). |
| `PAPERLESS_MCP_POLICY_PROTECTED_TAGS` | empty | Further tag names the agent may never add, remove, rename, re-match or delete, such as tags that trigger re-classification. The tier tags are always protected. |
| `PAPERLESS_MCP_POLICY_PROTECTED_CUSTOM_FIELDS` | empty | Custom field names the agent may never set, change, remove, rename or delete. |

Names are trimmed and must match exactly, including case. At startup the server looks up every name in Paperless and stops with an error if a name matches no object or more than one, or if Paperless can't be reached. It then logs the resolved IDs, one line per list:

```
policy filter: enabled
policy filter: full tags: dp:public=8, dp:internal=9
…
```

Example for Claude Desktop or `.mcp.json`:

```json
"env": {
  "PAPERLESS_URL": "https://paperless.example.com",
  "PAPERLESS_TOKEN": "your-api-token",
  "PAPERLESS_MCP_POLICY_ENABLED": "true",
  "PAPERLESS_MCP_POLICY_FULL_TAGS": "dp:public,dp:internal",
  "PAPERLESS_MCP_POLICY_METADATA_TAGS": "dp:confidential,dp:manual-review",
  "PAPERLESS_MCP_POLICY_RESTRICTED_TAGS": "dp:restricted",
  "PAPERLESS_MCP_POLICY_PROTECTED_TAGS": "gpt-reprocess,gpt-reset,paperless-gpt-auto,paperless-gpt-ocr-auto",
  "PAPERLESS_MCP_POLICY_PROTECTED_CUSTOM_FIELDS": "AI privacy class,Privacy triggers"
}
```

The MCPB bundle has the same settings in its configuration dialog.

### Prerequisites in Paperless

The filter relies on Paperless permissions for everything it doesn't filter. Set these up by hand **before** pointing the agent at a server with the filter on:

1. The agent's Paperless user is **not** a superuser or staff.
2. Global permissions: view, add and change on tags, correspondents, document types, custom fields and saved views; view and change on documents; view on workflows, storage paths and mail rules. **No** add, change or delete on workflows, workflow triggers, workflow actions, storage paths, mail rules or mail accounts. **No** permissions on users, groups, app config (`paperless.applicationconfiguration`), the audit log (`auditlog.logentry`) or share links.
3. Grant view (and change) on documents per document, for example with workflows that assign them by tier tag. Documents with a restricted tag should never be visible to the user.
4. Remove the workflow rights first. A user who can create workflows can make documents unowned with a "remove owners" action, and unowned documents are visible to every user.

Keep the server's binary and configuration where the agent can't edit them; otherwise the agent could switch the filter off.

The rules were checked against Paperless-ngx 3.4.2. Re-check them when upgrading Paperless.

## Tools

Responses are shaped to stay compact for MCP clients: document `content` in list/search results is truncated to a snippet — default 500 bytes, adjustable per call with `content_snippet_bytes` (0 disables); `full_content: true` opts out and `document_get` returns full text — document `notes` in list/search results are replaced with a `notes_count` field (`include_notes: true` keeps them; `document_note_list` returns full notes), the unbounded `all` ID array is stripped from paginated lists (`include_all_ids: true` on `document_list` re-includes it), `task_list` is paginated client-side, `log_get` returns only the last `tail` lines (default 100), `document_selection_data` omits zero-count objects, `user_list` omits `inherited_permissions` unless `include_permissions: true`, and `profile_get` redacts the API auth token.

### Documents
`document_list`, `document_get`, `document_update`, `document_delete`, `document_upload`, `document_download`, `document_metadata`, `document_suggestions`, `document_next_asn`, `document_share_links`, `document_history`, `document_email`

### Document Notes
`document_note_list`, `document_note_add`, `document_note_delete`

### Downloads & Page Images
`document_download` (disk or inline; images come back as viewable MCP image content), `document_page_image` (render a PDF page or region as an image the model can see — for handwriting and bad scans where OCR fails), `cleanup_downloads`

PDF rendering happens in-process via [go-pdfium](https://github.com/klippa-app/go-pdfium)'s WebAssembly runtime (PDFium compiled to wasm, executed by [wazero](https://wazero.io)) — pure Go, no cgo, no external binaries to install.

### Tags
`tag_list`, `tag_get`, `tag_create`, `tag_update`, `tag_delete`

### Correspondents
`correspondent_list`, `correspondent_get`, `correspondent_create`, `correspondent_update`, `correspondent_delete`

### Document Types
`document_type_list`, `document_type_get`, `document_type_create`, `document_type_update`, `document_type_delete`

### Storage Paths
`storage_path_list`, `storage_path_get`, `storage_path_create`, `storage_path_update`, `storage_path_delete`, `storage_path_test`

### Custom Fields
`custom_field_list`, `custom_field_get`, `custom_field_create`, `custom_field_update`, `custom_field_delete`

### Search & Statistics
`search_autocomplete`, `search_global`, `statistics`

### Bulk Operations
`document_bulk_edit`, `document_selection_data`, `bulk_edit_objects`

### Saved Views
`saved_view_list`, `saved_view_get`, `saved_view_create`, `saved_view_update`, `saved_view_delete`

### Share Links
`share_link_list`, `share_link_get`, `share_link_create`, `share_link_update`, `share_link_delete`

### Users & Groups
`user_list`, `user_get`, `user_create`, `user_update`, `user_delete`, `user_deactivate_totp`, `group_list`, `group_get`, `group_create`, `group_update`, `group_delete`, `profile_get`, `profile_update`

### Mail
`mail_account_list`, `mail_account_get`, `mail_account_create`, `mail_account_update`, `mail_account_delete`, `mail_account_test`, `mail_account_process`, `mail_rule_list`, `mail_rule_get`, `mail_rule_create`, `mail_rule_update`, `mail_rule_delete`, `processed_mail_list`, `processed_mail_get`, `processed_mail_bulk_delete`

### Workflows
`workflow_list`, `workflow_get`, `workflow_create`, `workflow_update`, `workflow_delete`, `workflow_trigger_list`, `workflow_trigger_get`, `workflow_trigger_create`, `workflow_trigger_update`, `workflow_trigger_delete`, `workflow_action_list`, `workflow_action_get`, `workflow_action_create`, `workflow_action_update`, `workflow_action_delete`

### System
`system_status`, `remote_version`, `ui_settings_get`, `config_list`, `config_get`, `config_update`, `task_list`, `task_get`, `task_acknowledge`, `task_run`, `log_list`, `log_get`, `trash_list`, `trash_action`

## Development

```bash
make build          # build binary
make test           # run tests
make test-coverage  # tests with coverage report
make lint           # vet + staticcheck + test
```

## License

MIT
