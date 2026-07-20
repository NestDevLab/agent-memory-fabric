# Conversation archive interface v1

`config/contracts/amf.conversation-archive-v1.schema.json` validates the
content-free conformance manifest. It does not validate or replace the stored
event payload. The adapter boundary is normative:

```text
append(event: amf.conversation-event/v3, idempotencyKey: cai_...) -> ArchiveResult
tombstone(event: amf.conversation-event/v3, idempotencyKey: cai_...) -> ArchiveResult
list(conversationId, limit, includeTombstones, cursor?) -> ArchiveResult
applyRetention(cutoff, limit, idempotencyKey: cai_...) -> ArchiveResult
```

Before any archive transaction, an adapter MUST validate the complete `event`
against the committed `amf.conversation-event/v3` schema, including its
integrity envelope. It MUST store that complete validated event atomically; it
MUST NOT construct storage from the conformance manifest's `eventReference`.
`eventReference` is only a content-free public result and fixture projection.
The shared conformance manifest applies every scenario unchanged to each listed
adapter label; labels are test harness selectors, never public result fields.
The `tombstone` method accepts only a complete v3 event whose state is
`tombstone`. `applyRetention` accepts an explicit UTC cutoff and a batch limit
from 1 through 1000; it never accepts an event projection as its command.

## Identity, retries, and transactions

The v3 `eventId` is stable source identity. `logicalDigest` remains the logical
identity. `integrity.payloadDigest` is the full payload binding. An exact retry
requires the same idempotency key, `eventId`, and full payload digest and
returns `duplicate`. The same `eventId` with any different full payload digest
returns `conflict_visible`, even when `logicalDigest` is unchanged. Conflict
metadata exposes only `eventId`, `logicalDigest`, and existing/received payload
digests; it never exposes hidden content.

`append`, `tombstone`, and `applyRetention` are state-changing operations.
Their state change and append-only committed audit row are one transaction.
`stored` and `retention_expired` change state and require `audit.recorded`.
`transaction_rolled_back` changes neither state nor committed audit row and
therefore has `audit.absent`. If audit is unavailable, the mutation fails
closed as `audit_unavailable`, with no state change and no committed audit row.
Failed-attempt telemetry is outside this contract.

## Reads, cursors, tombstones, and retention

`list(conversationId, limit, includeTombstones, cursor?)` is bounded to a limit
of 1 through 100. Its stable ordering version is
`conversation-archive-order/v1`; ascending order is
`(sourceOccurredAt, sourceSequence, eventId)`. A cursor is bound structurally
to conversation identifier, tombstone visibility, ordering version, and page
limit. Any malformed or mismatched cursor returns `cursor_binding_invalid`.

A v3 tombstone hides its target from ordinary reads. With
`includeTombstones=true`, the tombstone projection is visible but removed
content is not. Retention uses a separate `expiresAt` eligibility timestamp:
an event is expired when `expiresAt <= cutoff`; it is retained only when
`expiresAt > cutoff`. `sourceOccurredAt` is ordering metadata, never retention
eligibility.

PostgreSQL and SQLite are alternative adapters selected one at a time. They
never dual-write or fall back. Adapter names never appear in agent-facing
requests, results, item projections, cursors, conflicts, or audit records.
