# Conversation event v3 source rules

This contract filters source records before v3 construction. It does not change
native transcripts or the v2 archive.

## Supported transcript sources

| Source adapter | Include | Exclude |
|---|---|---|
| Codex JSON Lines | Only `type: "response_item"` records with `payload.type: "message"`, `payload.role` of `user` or `assistant`, a native session and message identifier, a valid source timestamp, and a non-empty `payload.content` array. A user message permits only `input_text` parts; an assistant message permits only `output_text` parts. Every permitted part has a string `text`. | `session_meta`, `event_msg`, `turn_context`, compaction, status, mirror user or agent messages, reasoning, function or custom tool calls and outputs, usage or token records, task status, telemetry, unknown records, strings or structured content, non-text parts, missing identifiers, and invalid timestamps. |
| Claude JSON Lines | Only records where top-level `type` and `message.role` are both `user` or both `assistant`, with a native session and message identifier and a valid source timestamp. `message.content` is either a string or a non-empty array of `type: "text"` blocks with string `text`; every array block must be text. | System, summary, queue, file-history, progress, unknown records, mismatched roles, tool or non-text blocks, mixed arrays, structured content, missing identifiers, and invalid timestamps. |

No other transcript adapter is currently supported by this repository. A new
source requires a versioned rule-table update and conformance fixtures before
it can produce v3 events.

## Deterministic construction

1. Normalize only eligible visible text without retaining the native row. For an
   eligible content array, preserve native part order, replace CRLF and CR with
   LF in every text value, and join parts with one LF. For an eligible string,
   apply the same line-ending normalization. Exclude the row if the resulting
   text contains no non-whitespace character. Preserve eligible whitespace;
   do not trim it. This prevents a mirror or status row from becoming a second
   event for the same visible message.
2. Assign stable opaque event, conversation, source-instance, and optional
   thread identifiers from the adapter identity registry. Never use a local
   path, display name, message text, timestamp, or binary body as identity.
3. Require and preserve the source occurrence timestamp. Exclude a record when
   its source timestamp is absent or invalid; do not invent one. Set
   `occurredAt` to the normalized event occurrence time. Both timestamps are
   UTC RFC 3339.
4. Order events by `sourceOccurredAt`, then `ordering.sourceSequence`, then
   lexical `eventId`. Producers must assign a non-negative sequence within one
   source instance; consumers use all three fields as the deterministic key.
5. Map a user-originated eligible message to `inbound` and an assistant-originated
   eligible message to `outbound`. The adapter assigns the conversation kind.
6. Emit `authorizationContextTags` as a typed opaque-tag map. `conversation`
   is required; `actor`, `sender`, `room`, `person`, `relationship`, and
   `thread` are bounded optional tag kinds. Literal identities, room names,
   paths, access tokens, and secret-bearing metadata are forbidden.

## Revisions, conflicts, and tombstones

- `active` is revision 1 and has visible text.
- `edited` and `replacement` have visible text, a revision of at least 2, and
  `replacesEventId`. They preserve prior events rather than overwriting them.
- `tombstone` has `tombstonesEventId`, no visible text, and no attachments. It
  makes the target unavailable to ordinary conversation reads without carrying
  the removed content.
- `conflict` carries a visible competing event and one or more
  `conflictsWithEventIds`. A consumer must expose the conflict instead of
  silently selecting a winner.
- Every `replacesEventId`, `tombstonesEventId`, and `conflictsWithEventIds`
  target must resolve to an event with the same `conversationId` and
  `sourceInstanceId`. The archive rejects a cross-conversation or cross-source
  reference before it can replace, hide, or quarantine any event.
- `logicalDigest` is `sha256:` plus the lowercase SHA-256 of a domain-separated
  canonical JSON tuple: `["amf.conversation-event/v3/logical", conversationId,
  threadId-or-null, role, state, visibleText-or-null, attachment-reference
  metadata-or-empty-array, replacesEventId-or-null, tombstonesEventId-or-null,
  conflictsWithEventIds-or-empty-array, revision]`. Tombstones therefore use
  `null` for absent text; conflicts include their visible text and conflict
  targets. It is used for idempotency and conflict detection, not as an
  authorization tag.

## Attachments and integrity

An attachment is only an opaque reference identifier, allowlisted media type,
byte length, optional visible caption, and optional SHA-256. URLs, local paths,
filenames, binary bodies, executable content, and arbitrary metadata are not
part of this transport.

The `integrity` member is an HTTPS delivery envelope. Its `payloadDigest` is
the SHA-256 of canonical JSON for the event with `integrity` omitted. Its
signature is an HMAC-SHA-256 over the domain-separated canonical JSON tuple
`["amf.conversation-event/v3/integrity", payloadDigest, keyId, sentAt, nonce]`,
encoded as unpadded base64url. Receivers must require TLS, authenticate the key
by `keyId`, reject invalid signatures, bind the nonce to the delivery window,
and reject replayed nonces. This contract carries no key material or
credentials.
