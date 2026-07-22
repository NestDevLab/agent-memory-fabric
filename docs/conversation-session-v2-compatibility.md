# Conversation session v2 compatibility view

The public v2 session REST routes and MCP session tools may use an injected
`conversationSessionReader` backed by Conversation Archive v1 tables. This is
a compatibility view, not a second session store.

## Scope and identity

The view accepts only `ccon_` conversation identifiers. Its public session id
is the conversation id. It does not infer a legacy session alias, owner, or
native-runtime identifier. Exact legacy-id aliases are a separate M4 backfill
artifact.

The reader is independently injected. If it is not configured, public v2 and
MCP session reads return `session_reader_unconfigured` with status 503 and do
not call the legacy reader. The internal extractor remains on the legacy
`sessionReader`; it does not receive archive-wide access through this view.
The public status field and MCP capability named `sessionReader` describe this
public compatibility reader only; they do not report the internal extractor's
legacy reader state.

## Runtime selection

Production composition is explicit and defaults to disabled. Set
`AMF_CONVERSATION_READER_MODE` to one of:

- `disabled`: construct no archive reader and leave the public compatibility
  surface unconfigured;
- `shadow`: serve the legacy reader unchanged while bounded background work
  compares complete legacy and v3 results;
- `active`: serve the v3 archive-backed compatibility view.

Shadow comparison maps deterministic legacy session and event identifiers to
their v3 identifiers, ignores intentional presentation differences, and never
delays or fails the primary response. Partial cursor pages are inconclusive.
The public status reports only counters for matches, mismatches, unavailable or
inconclusive comparisons, skipped work, and work currently pending. It contains
no identifiers, queries, or content.

Shadow and active modes require exactly one archive target:
`AMF_CONVERSATION_ARCHIVE_SQLITE_PATH` or
`AMF_CONVERSATION_ARCHIVE_POSTGRES_URL`. PostgreSQL TLS defaults to
`verify-full`; `require` and `disable` are explicit alternatives for controlled
environments. Connection URLs with query parameters or fragments are rejected
so they cannot override the dedicated TLS or read-only settings.
`AMF_CONVERSATION_READER_CURSOR_KEY_PATH` must name an owner-only regular file
containing one canonical base64-encoded 32-byte key. The optional
`AMF_CONVERSATION_READER_SCAN_LIMIT` is bounded from 1 through 500.

On Linux, SQLite anchors the configured regular file and opens that descriptor
read-only; it never creates an archive. Startup checks the required archive
columns before listening. PostgreSQL performs an equivalent zero-row schema
query and requests read-only sessions; deployments must also use a database role
limited to read-only grants. Configuration, schema, or connectivity failure
prevents startup with a content-free error.

## Authorization and content

The existing v2 route, purpose, context-token, and session-route checks run
before the reader result is exposed. The reader also requires a non-empty
context and verifies `exactContextIntersection` before it yields a candidate.
Only then does it set `ownerSelf: true`, so the existing server authorization
still performs its second check. A null-context global search is rejected.

`view=original` returns `session_original_unavailable` with status 410 before
RAW permission checks, decrypt-intent audit, or a reader call. This view never
reads or decrypts legacy RAW rows. Transcript items contain only normalized
v3 `visibleText`, mapped to the existing redacted text shape and truncated at
4096 Unicode code points.

## Visibility and metadata

The view uses the archive's active visibility relation. Conflicts, expired
events, tombstones, and replacement targets are not returned. Replacement and
tombstone hiding remains effective after the hiding event expires, so a target
cannot reappear.

Only visible user and assistant events are transcript candidates. Their
archive ordering is `sourceOccurredAt` instant, source sequence, then event
id; returned item time is the event `occurredAt`. Metadata is derived from the
complete visible event set, independently of query and time filters:

- `id` is `conversationId`; `runtime` is `conversation-v3`; `title` is empty.
- `scope` is an empty placeholder for the existing route exposure layer.
- first and last times use the archive ordering key; event count is visible
  event count.
- conversation kind and context tags come from that set.

The reader rejects a conversation rather than merging it when visible events
disagree on source instance, conversation kind, or authorization context tags.

Time windows accept calendar-valid RFC3339 timestamps with an explicit UTC
offset. They are normalized to UTC milliseconds and compared inclusively. A
queryless search includes a conversation when its visible interval intersects
the requested window; a text search requires a matching visible event within
that window.

## Bounded search and cursors

Search scans a fixed, deterministic candidate window. Per-conversation
metadata is an aggregate, and transcript pages are keyset queries with
`limit + 1`; a conversation is not rejected because it has many visible
events. It uses parameterized SQLite and PostgreSQL queries. Query matching
is literal and is performed against the same 4096-code-point redacted text
that can be returned; no wildcard SQL matching or hidden text is used. ASCII
letters match case-insensitively. Non-ASCII characters are exact literals so
SQLite and PostgreSQL do not depend on different locale rules.

When a scan window ends before a requested page can be filled, the response
contains a keyset continuation after the last scanned candidate. Cursors are
HMAC-protected, at most 512 characters, and bind the operation, context
digest, request filters, requested limit, and strict keyset state. They are
not portable across query or context changes. A page can contain fewer items
than requested when candidates in its fixed scan window fail the context or
metadata checks; clients follow `nextCursor` to continue the bounded search.

The reader never closes an injected archive database or PostgreSQL pool. The
caller that constructed those shared resources owns their lifecycle.
