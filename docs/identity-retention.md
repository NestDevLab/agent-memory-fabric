# Identity and retention operations

This tranche adds internal, policy-gated operations. It does not enable a
deployment, automatic merge, or physical RAW deletion.

## Identity safety contract

- Identity keys, evidence, issuers, and claims are encrypted in RAW storage.
- Catalog rows contain only keyed opaque tags, record ids, state, revision, and
  encrypted evidence references.
- Identity state transitions are append-only events with optimistic revision.
- `merge` changes only the source identity to `merged`; `split` reverses that
  link and creates a new event. Neither operation rewrites history.
- Automatic merge is disabled by default. It requires both
  `allowAutomaticStrongMerge: true` and a server-recognized strong evidence
  type. Callers cannot declare evidence strong.
- Evidence is a closed schema: verified accounts require provider/account/
  verification ids; cryptographic bindings require algorithm, fingerprint,
  challenge hash and signature; operator attestations require ticket and
  assertion; weak observations require the observation itself.
- Source and target must have the same identity kind and opaque scope. Missing,
  cross-kind, cross-scope, and unauthorized records return
  `identity_not_found`.
- Evidence timestamps accept real RFC3339 UTC values only. Merge/split retries
  return the immutable response stored with the original event, even if later
  events changed the identity again.

Internal REST routes use the normal bearer authentication, current scope ACL,
no-store response headers, and audit writer:

- `POST /v2/internal/identities`
- `GET /v2/internal/identities/:id`
- `POST /v2/internal/identities/:id/merge`
- `POST /v2/internal/identities/:id/split`

Writes require an `Idempotency-Key` header and `identity:write`; reads require
`identity:read`.

## Retention safety contract

- Default expiry is three calendar years from the original timestamp. A leap
  day expires on the last valid day of the target month.
- Per-scope day overrides are explicit FabricStore policy.
- Planning and applying are separate authenticated operations.
- Apply requires `Idempotency-Key`. Its response is stored atomically with the
  lifecycle transition, so retries and ambiguous commit reconciliation return
  the same response.
- Apply atomically changes catalog lifecycle and inserts a tombstone preserving
  checksum, original timestamp, expiry, and an opaque native-source pointer.
- A GC candidate is emitted only from the same catalog transaction that proves
  no live proposal reference exists.
- Fabric never calls `rawStore.remove`; `physicalRawDeletionEnabled` is always
  false in this tranche. A future gated collector must re-prove references in
  its own transaction immediately before any deletion.
- `revoked` and `forgotten` use the same versioned tombstone path and therefore
  cannot bypass catalog or scope checks.
- Search results are filtered again after the semantic backend. Explicit
  proposal, content, and identity references that are revoked, expired,
  forgotten, merged, unknown, or cross-scope are removed together with their
  counts before a response is composed.

Routes require `retention:manage`:

- `POST /v2/internal/retention/plan`
- `POST /v2/internal/retention/apply`

PostgreSQL schema version 3 and SQLite use equivalent identity-event,
retention-metadata, and tombstone structures. Real PostgreSQL execution remains
an isolated integration test and is not run against production by this work.
