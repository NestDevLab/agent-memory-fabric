# RAW projection v2 conformance

The executable authority is `validateProjectionV2`; the matching portable JSON
Schema is `config/raw-event-projection-v2.schema.json`, and
`scripts/fixtures/raw-projection-v2.conformance.json` is the adapter fixture.
Adapters must not invent reduced variants.

## Identifiers and tags

- `eventId`: `evt_` plus the SHA-256 returned by `deriveEventIdV2`.
- `sessionId`: `ses_` plus the SHA-256 returned by `deriveSessionIdV2`.
- `logicalMessageId`: `lmsg_` plus the HMAC returned by
  `deriveLogicalMessageIds`; active historical key versions appear in
  `logicalMessageAliases` as `{keyVersion,logicalMessageId}`.
- Every `contextTags` value is a non-empty array. Every element is
  `hmac-sha256:<keyVersion>:<64 lowercase hex>`; literal actor, room, thread,
  person, sender or platform identifiers are forbidden.

Codex uses the native rollout/session id from `session_meta` as
`nativeSessionId`. OpenClaw uses the authoritative JSONL session key (including
the owning agent/profile when that is part of the native key). Neither adapter
uses a file path, timestamp, display name or message text as a session identity.
When a runtime has no native session identifier, it may derive a session from
the already-keyed conversation tag. Native message ids are preferred for
`eventId`; byte fallback identifies one observation only and never proves two
cross-source messages are the same.

Logical-message derivation requires either the native platform message tuple or
a durable delivery correlation id. Timestamp, role and content similarity are
never accepted as strong coalescing evidence.

## Session binding

`contextTags` is event metadata, not a session-wide identity tuple. The persisted
v2 session binding is the exact normalized subset `conversation`, `room` and
`thread`; `conversation` is required and the other two keys are optional. Runtime
and `conversationKind` are also invariant. A change to any present binding key is
rejected fail-closed as `raw_session_binding_conflict`.

`actor`, `sender`, `person` and `relationship` are deliberately excluded. They can
change across `session_meta`, system, user, tool and assistant observations in the
same native session. Their opaque values remain on the individual event projection.

## Readiness contract

`GET /v2/status` returns the capability at exactly:

```json
{
  "data": {
    "fabricStore": {
      "rawProjectionV2Ready": true,
      "rawProjectionV2ReadinessReason": null,
      "legacyV1WritesEnabled": false
    }
  }
}
```

Adapters and rollout automation must read that path. Readiness is false until
v1 writes are disabled and the production PostgreSQL catalog has persisted a
schema-v7 migration proof containing v1/v2/alias counts, zero orphan aliases,
zero forbidden legacy fields, and a database-side scan proving that every
context value is an opaque HMAC tag. Every v2 session binding is also parsed and
validated before readiness can become true. Memory and SQLite catalogs remain useful
for tests but deliberately report `production_postgres_required`; validating
an in-memory JSON object is never production readiness. General service health
does not override this gate.
