# PostgreSQL catalog operations

The PostgreSQL catalog is an explicit production option. It stores catalog
metadata only; encrypted RAW bodies remain in the configured RAW object store.
Do not point it at the legacy Mem0/OpenMemory database or reuse a Mem0 vector
collection. Provision a dedicated database and role for Agent Memory Fabric.

## Configuration

```bash
AMF_CATALOG_KIND=postgres
AMF_CATALOG_DATABASE_URL=postgresql://agent_memory_fabric:<password>@<host>/agent_memory_fabric
AMF_CATALOG_SSL_MODE=verify-full
AMF_CATALOG_SSL_CA_PATH=/run/secrets/postgres-ca.pem
AMF_CATALOG_POOL_MAX=10
AMF_CATALOG_CONNECT_TIMEOUT_MS=5000
AMF_CATALOG_QUERY_TIMEOUT_MS=15000
AMF_CATALOG_STATEMENT_TIMEOUT_MS=10000
```

`AMF_CATALOG_SSL_MODE` accepts `verify-full` (default), `require`, or `disable`.
Use `require` only where certificate verification is intentionally delegated to
a trusted private network layer. Keep the connection URL in a protected runtime
environment file or secret injection mechanism.

Selecting `postgres` without a URL, with an invalid SSL mode, or with an invalid
pool size fails closed. There is no automatic fallback to SQLite. Server startup
waits for schema initialization before listening.

Connection acquisition, client queries and PostgreSQL statements all have finite,
validated timeouts. Transactions set a local `statement_timeout`; client queries
also carry the driver query timeout and an abort signal. A timed-out transactional
client is discarded instead of being returned to the pool.

Audit is fail-closed: if the catalog cannot durably record an audit event within
`AMF_AUDIT_TIMEOUT_MS` (default 2000 ms), the request returns controlled `503`
instead of reporting success without accountability. Status health probes are
bounded separately by `AMF_CATALOG_HEALTH_TIMEOUT_MS` (default 3000 ms).
RAW ingestion commits its event row, session aggregate and audit row in the same
transaction, so none can become visible without the others.

A timeout or connection loss after `COMMIT` was sent is ambiguous, so the Fabric
first reconciles by owner/idempotency key. All proposal failures and conflicts,
including proven pre-COMMIT rollback, conservatively retain content-addressed
encrypted RAW: a blob locally reported as newly created may already be referenced
by another proposal, owner, key or process. Orphan deletion is therefore excluded
from request handling. A separate approved GC/reconciliation job may delete only
with a catalog-coordinated, transaction-safe proof that no reference exists; a
racy check-then-delete is forbidden.

### RAW projection v2 cutover

Projection v2 writes only opaque keyed context tags and supports Codex, Claude,
Hermes, OpenClaw and Principia observations. The catalog keeps v1 event/session
tables readable during migration and writes new v2 observations to separate
tables. Logical-message aliases join observations across HMAC key rotation;
preferred observation, payload conflict and authoritative tombstone state are
recomputed transactionally.

`AMF_RAW_V2_CUTOVER=true` disables new v1 writes. The status capability
`rawProjectionV2Ready` remains false until cutover is enabled and every stored v2
projection passes the strict literal-routing scan. A false capability is a hard
stop for fleet rollout, even when ordinary health checks remain green.

## Schema and privacy boundary

The adapter owns the fixed `agent_memory_fabric` schema. Migration version 7 is
idempotent and protected by a PostgreSQL advisory transaction lock. A database
whose migration version is newer than the running binary is rejected. Projection
v2 and logical-message selection are introduced by migration version 4.

The schema contains:

- encrypted RAW object metadata and storage references;
- RAW event metadata with only an allowlisted projection and stable keyed digest;
- session aggregates bound to runtime, conversation kind and the opaque
  `conversation`/`room`/`thread` routing subset; actor, sender and source tags on
  v2 event rows are event-scoped, while literals remain only inside authenticated
  ciphertext;
- proposal state with a unique opaque owner/idempotency pair;
- versioned identity metadata using opaque tags;
- encrypted ingestion cursor values;
- audit events containing allowlisted operational metadata;
- retention tombstones containing checksums and opaque source pointers.

Schema version 3 adds `identity_records_v2`, append-only `identity_events_v2`
with an opaque `response_json` snapshot for stable replay,
`raw_retention_v2`, `retention_tombstones_v2`, and
`retention_operations_v2` for atomic idempotency and ambiguous-commit
reconciliation. See `identity-retention.md` for the mutation and
deletion-safety contract.

Schema version 7 adds `raw_sessions_v1.session_binding_json`. Startup backfills
it idempotently from the existing `context_tags_json`, selecting only
`conversation`, `room` and `thread`. The former full JSON is retained as
compatibility metadata; it is not consulted for v2 binding. Missing or malformed
v2 bindings fail readiness and subsequent writes closed.

It does not contain proposal bodies, claims, transcripts, bearer tokens, people
names, room names, or unencrypted cursor values. All runtime DML is parameterized.

## Migration and rollout

The v7 session-binding migration supports existing SQLite and PostgreSQL v2
session rows in place. It does not migrate legacy Mem0 data. Take a consistent
catalog backup before starting a v7 binary and verify the backfilled binding count
against the v2 session count before enabling writers.

1. Provision an empty, isolated PostgreSQL database and least-privilege role.
2. Back up the SQLite catalog and encrypted RAW root.
3. Run the optional integration test against a separate disposable test database:

   ```bash
   AMF_TEST_POSTGRES_URL=postgresql://.../agent_memory_fabric_test \
   AMF_TEST_POSTGRES_ALLOW_MUTATION=true \
   node --test scripts/test-postgres-catalog-integration.mjs
   ```

4. Start a shadow instance with Mem0 still disabled and verify `memory_status`,
   proposal retries, audit persistence, pool health, and outage behavior.
5. Start the v7 binary with writers stopped; verify `session_binding_json` for
   every v2 session and confirm `rawProjectionV2Ready` before enabling ingest.
6. Change the production catalog kind and restart only after the deployment gate.

## Rollback

Stop writers before rollback. The v7 column and backfill are additive and retain
the prior `context_tags_json`; do not drop or rewrite either column. An older
binary can ignore the new column, but it will again reject multi-role session
events, so replay must remain paused. For exact pre-upgrade semantics, restore the
consistent catalog backup and its matching RAW snapshot, then restart. Do not
simply switch back to an older SQLite
file after PostgreSQL has accepted writes: replay the durable outbox or an approved
export first, otherwise catalog events will be missing. Retain the PostgreSQL
database for investigation until checksums, proposal counts, and audit continuity
are reconciled. Schema downgrade and automatic destructive cleanup are unsupported.
