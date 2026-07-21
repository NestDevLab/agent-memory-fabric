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
Exact `duplicate` replays for both write and retention operations also append a
new `audit.recorded` row in their replay transaction. If that audit insert is
unavailable, the replay fails closed as `audit_unavailable` and does not commit
a replay audit row.
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

Edited and replacement events are immutable. A replacement hides its referenced
target from every archive list, including after the replacement itself expires;
chains therefore expose only their current visible projection and never
resurrect superseded content. An injected archive remains caller-owned by
default: server shutdown does not close it unless the server explicitly created
and owns that archive instance.

PostgreSQL and SQLite are alternative adapters selected one at a time. They
never dual-write or fall back. Adapter names never appear in agent-facing
requests, results, item projections, cursors, conflicts, or audit records.

The v3 HTTP route accepts `Idempotency-Key: cevt_...` and deterministically
derives the archive-only `cai_...` key by replacing the prefix. Archive retries
remain exact only for that same internal key, event ID, and payload digest; the
derived key never appears in the HTTP acknowledgement.

`POST /v3/ingest/conversation-events` is gated by bearer permission
`conversation:ingest` before the server reads the request body. The injected
endpoint then enforces an exact JSON content type, a bounded byte length and
read timeout, an optional request HMAC when configured, event integrity and
replay verification, source-instance authorization, and exact event-ID
idempotency. The default endpoint bounds are 256 KiB and 10 seconds; callers
may select only validated bounds when constructing the handler.

Successful writes return a content-free acknowledgement with the event ID,
payload digest, and `stored` or `duplicate` status. Authorization, validation,
timeout, storage, audit, and conflict failures never return visible text,
signatures, nonces, archive-only keys, adapter names, or stored evidence. A
visible conflict is limited to the event ID and the three contract digests.

## Executable conformance

`npm run test:conversation-archive` always executes the shared scenarios against
SQLite. It reports PostgreSQL as skipped unless a real disposable PostgreSQL
database is supplied explicitly:

```sh
AMF_ARCHIVE_POSTGRES_TEST_URL=postgresql://user:password@127.0.0.1:5432/archive_test npm run test:conversation-archive
```

The test uses fixed archive-only schema tables and truncates those tables before
the PostgreSQL scenario run. Use an isolated test database only.

PostgreSQL writes serialize stable event and idempotency keys with transaction
advisory locks. If a commit acknowledgement is ambiguous, the adapter re-reads
the idempotency record: a durably recorded exact write returns `duplicate`, and
a durably recorded changed-payload write returns its content-free
`conflict_visible` projection. It never retries a changed payload as a new
write.
