# Agent Memory Fabric

Shared REST/MCP boundary for scoped memory access. `mem0-gateway` remains a
legacy product alias while clients migrate to `agent-memory-fabric`.

## Current shape

- stable REST/MCP boundary with actor, scope and permission enforcement
- Mem0 backend adapter for scoped search
- idempotent proposal queue; public requests never write directly to Mem0
- encrypted, content-addressed RAW proposal storage and auditable catalog
- encrypted transcript-event ingestion with a persistent outbox and session reader
- local JSON auth registry, with optional n8n Data Table fallback
- legacy REST v1, MCP SSE and MCP Streamable HTTP compatibility
- canonical PAM read/search through an internal stdio adapter; proposal queue
  status remains a separate surface
- request-bound conversation context tokens and monotonic curator/apply receipts
- purpose-specific authorization and exact HMAC context intersection across PAM records and v2 sessions
- one Fabric transaction for receipt state, proposal lifecycle and durable audit
- authoritative REST/MCP/v1 schemas and Principia fixture under `config/contracts/` and `scripts/fixtures/contracts/`

## Architecture and integrations

- [Obsidian Second Brain integration](docs/obsidian-second-brain.md): implemented, opt-in
  standalone, shadow, and active client architecture with swappable data,
  memory, model, and retrieval backends.

## Auth registry

Set `AMF_AUTH_REGISTRY_PATH` to a local JSON registry. The legacy
`MEM0_AUTH_REGISTRY_PATH` name remains supported. Relative paths resolve from the
repo root; deployments should use an absolute mounted secret path.

```bash
AMF_AUTH_REGISTRY_PATH=/run/secrets/agent-memory-fabric-auth.json
MEM0_AUTH_CACHE_TTL_MS=15000
```

```json
{
  "rows": [
    {
      "tokenSha256": "5232b8b43646788aa6ee169eadc914fc21bcdfa56c52e914413569e1f7affe81",
      "active": true,
      "actor": "main-openclaw",
      "mode": "allow_all",
      "allowedScopes": "*",
      "allowedVaults": ["vault-personal"],
      "permissions": "memory:search,memory:read,memory:propose,memory:add,memory:status,sessions:read,raw:decrypt,raw:ingest,documents:search,documents:read,documents:write,purpose:operator_review"
    }
  ]
}
```

`tokenSha256` is the lowercase SHA-256 digest of the bearer token; bearer values are
checked with a constant-time comparison and need not be stored in the registry.
`allowedScopes` and `permissions` accept arrays or comma-separated strings. `allowedVaults`
is an optional array used by the document corpus; scoped actors fail closed when it is absent. The
fabric also accepts a bare row array and the n8n-compatible `{ "data": [...] }`
shape. When no local path is configured, n8n remains available as a compatibility
source through `N8N_API_BASE_URL`, `N8N_AUTH_TABLE_ID`, and `N8N_API_KEY`.

## Storage

`AMF_RAW_ENCRYPTION_KEY` is required before proposal endpoints accept data. It
must be exactly 32 bytes encoded as canonical padded base64, or exactly 64
hexadecimal characters. Without it,
health and search compatibility remain available but proposals return `503`.

The catalog abstraction supports SQLite for local use and an explicit PostgreSQL
production adapter. PostgreSQL never activates implicitly: set
`AMF_CATALOG_KIND=postgres` and provide its dedicated connection and SSL settings.
See [PostgreSQL catalog operations](docs/postgres-catalog.md). HKDF derives
independent encryption, content-address and catalog-tag keys.
RAW proposal bodies use AES-256-GCM with authenticated version, content id and key id.
A keyed HMAC-SHA256 content address allows deduplication without exposing a guessable
plaintext digest. The key ring reads old key ids while new writes use the configured
current key. Catalog actor, scope, source and idempotency values are opaque keyed tags.
Use `AMF_RAW_KEY_RING_PATH` for a mounted production secret. Idempotency retries
compare the authorized existing canonical payload, so active-key rotation does not
turn a valid retry into a conflict.

Catalog health and audit persistence are bounded. Audit is fail-closed: an audit
outage returns `503` rather than allowing an unaudited success. PostgreSQL pool
acquisition, queries and statements use validated finite timeouts documented in
[PostgreSQL catalog operations](docs/postgres-catalog.md). Importing the server
module while `AMF_SERVER_ENABLED` is false does not construct storage or parse
storage secrets.
Proposal failures never locally delete content-addressed RAW, even after a proven
rollback: another concurrent proposal may already reference the same blob. Orphan
collection requires a separately approved, catalog-coordinated reference proof.
RAW v2 sessions bind only stable routing invariants (`conversation`, optional
`room`, optional `thread`), plus runtime and conversation kind. Actor, sender,
person, relationship and source identity remain event-scoped, so user, system and
assistant observations can share one conversation. A room/thread/conversation
change is rejected before ciphertext commit. Failures or binding races after
commit retain the encrypted object for reconciliation; physical deletion still
requires the same catalog reference proof.

Transcript clients encrypt each event before it reaches the HTTP boundary. Configure
the server with `AMF_INGEST_KEY_RING_PATH`; the mounted JSON maps every key id to its
allowed actor and source instances and includes an independent, rotation-stable
`digestKey`. The authenticated stable digest provides logical idempotency: the same
event encrypted again, including after an encryption-key rotation, is a duplicate;
changed plaintext under the same event id is a conflict. Actor, source instance,
event, session, projection and key id are bound into AES-GCM AAD. The catalog event,
session update and audit row commit in one transaction.

Provision collector actors and per-client handoffs with the fail-closed
[RAW collector provisioning runbook](docs/raw-collector-provisioning.md). The
operator CLI stores only bearer digests server-side and fixes collector access
to `memory:status` plus `raw:ingest`.

Provision the independent `agent:vitae` read-only recall credential and context-signing handoff
with the [recall consumer provisioning runbook](docs/recall-consumer-provisioning.md). This path
does not read or create RAW collector material. Approved group/topic contexts can add bounded,
manifest-bound canonical `room:`, `person:` and `relationship:` scopes through repeatable
`--scope` options; wildcard and broader scope classes are rejected.

## API v2

Success uses `{ "ok": true, "data": ..., "meta": ... }`; errors use
`{ "ok": false, "error": { "code", "message", "details" }, "meta": ... }`.

- `POST /v2/memory/search`
- `POST /v2/context/search` (interleaved canonical-memory and editorial-document recall)
- `POST /v2/memory/proposals` (requires `Idempotency-Key`)
- `POST /v2/ingest/raw-events` (requires `raw:ingest`)
- `GET /v2/memory/:id` (canonical record, rationale and expected revision)
- `GET /v2/memory/proposals/:id` (status only; no record decryption)
- `GET /v2/internal/curation/proposals?status=queued&limit=50&cursor=...`
  (bounded metadata only; requires `memory:curate`)
- `GET /v2/internal/curation/proposals/:id` (one proposal and canonical digest;
  requires `memory:curate` and an audited decrypt intent)
- `POST /v2/internal/curation/receipts` (scope-bound decision/apply receipt)
- `POST /v2/internal/curation/reconcile` with `{limit?,cursor?}` (actor-scoped,
  bounded receipt reconciliation; requires `memory:apply-receipt`; `allow_all`
  remains an explicit administrative policy mode)
- `POST /v2/sessions/search` (requires `purpose`)
- `GET /v2/sessions/:id?purpose=...`
- `GET /v2/sessions/:id/transcript?purpose=...&view=redacted|original`
- `GET /v2/status`

The proposal body is exactly `{record,rationale,expectedRevision?}`. `record`
must conform to PAM 0.6 `amf-memory/v1`: canonical scope IDs, exact fields and
strict timestamps/provenance/lifecycle. `confidence` is required and exactly
`{score,basis,assessedAt}` with a finite `[0,1]` score, approved basis and UTC
timestamp. Restricted/confidential and
person/relationship records must carry a sealed AES-256-GCM envelope with
canonical base64, 12-byte IV, 16-byte tag, opaque `kekId`/`keyRef`, and the PAM
canonical AAD digest. A successful REST or MCP acknowledgement exposes
`{status,proposalId,duplicate,idempotencyKey}`; the last field is the exact
authoritative retry key accepted or derived by the Fabric.

Curation cursors bind actor, requested statuses, and the current scope ACL, so
they cannot cross filters or credentials. Exact payload reads support
`queued`, `review`, and `promoted` recovery, while rejected/revoked proposals
return not-found before RAW decryption.

The canonical index hot-reloads from
`/srv/brain-shared/memory/amf/record-index.json`. PAM writes non-secret
`contextRefs`; Fabric derives opaque HMAC tags with its dedicated routing key.
Index and routing-key files must be owner-owned regular mode-`0600` files.

Every memory/session transport, including MCP, errors and status, is private and
`no-store`. Session calls require one opaque purpose code: `conversation_recall`,
`continuity_resume`, `incident_debug`, `operator_review`, or `memory_curation`.
MCP sessions have TTL, global/per-actor caps, and revalidate token activity and
policy on every call. Original transcripts additionally require `raw:decrypt`;
redacted is the default and returns only bounded, normalized `user`/`assistant`
text from authenticated v2 observations. System, tool, structured and path/media
payloads are omitted. A non-empty `sessions_search.query` searches that redacted
text only after exact signed-context filtering. Redacted `session_transcript`
also accepts `query`; the query, context and cursor are request-bound, while
`original` plus `query` is rejected. Text search scans at most the newest 256
events per candidate session and 16 MiB of ciphertext. Candidate sessions are
context/time-filtered before each bounded 64-session page; a server-MACed keyset
cursor continues without a `>64` outage. Only the preferred, non-conflicted,
non-tombstoned logical observation is eligible. Older history can be selected
with a signed time window. Signed `canonicalScopes` are checked against the
server registry before session access. REST GET clients send the signed context
only in `X-AMF-Context-Token`; dedicated actors such as Vitae cannot place it in
the query string. The session reader is configured automatically when the
ingest key ring and catalog are available; otherwise MCP advertises
`sessionReader: false` and the routes return `session_reader_unconfigured` (`503`).

MCP advertises `memory_search`, `memory_read`, `memory_propose`, `context_search`,
`memory_proposal_status`, `sessions_search`,
`session_get`, `session_transcript`, and `memory_status`, plus legacy
`list_scopes` and `gateway_health` tools.

`POST /v1/memory/add` remains available with HTTP `200`, deprecation/sunset
headers and a deterministic derived idempotency key when an old client sends none. It reports the accepted
proposal as `queued`/non-canonical, and never calls `Mem0.add()` directly. Search
v1 and both MCP transports remain compatible.

## Run locally

```bash
npm install
cp .env.example .env.local
# Point AMF_POLICY_PATH at a reviewed policy, inject secrets and explicitly enable:
export AMF_SERVER_ENABLED=true
bash scripts/run.sh
```

Do not commit real secrets or runtime `.env` files.

Session recall also requires `AMF_SESSION_ROUTE_MANIFEST_PATH`. Create or update that signed,
private manifest with `npm run operator:provision-session-routes -- ...`; the full root-only,
dry-run-first procedure is in `docs/recall-consumer-provisioning.md`.

## Transcript ingestion CLI

`scripts/amf-transcript-ingest.mjs` supports allowlisted Codex and Claude sources,
durable encrypted outbox delivery, replay, deduplicated backfill and polling. A real
run requires explicit `AMF_INGEST_ENDPOINT` (HTTPS), `AMF_INGEST_TOKEN`,
`AMF_INGEST_ACTOR_ID`, source instance, key id, encryption key and independent digest
key. `AMF_OUTBOX_KEY_RING_PATH` and `AMF_CURSOR_KEY_RING_PATH` retain old decrypt
keys during rotation; `AMF_INGEST_CHECKPOINT_KEY` is independent and stable so
existing rolling checkpoints do not change when encryption keys rotate. The local
test sink cannot be selected outside test mode. Polling verifies
bounded rolling checkpoints; use `--full-audit` for an explicit whole-history audit.
Backfill uses a PID/host/nonce lease with heartbeat and only takes over a stale local
lease after its owner is dead. Delivery failures remain queued and do not block the
source runtime.
The HTTP timeout covers request, headers and the complete streamed response body;
responses are capped by `AMF_INGEST_HTTP_MAX_RESPONSE_BYTES` before JSON parsing.
Live polling is fail-closed when its encrypted cursor is absent. Initialize a new
poller exactly once with `--cursor-namespace realtime --bootstrap-tail`; this records
the last complete-line boundary, retains an in-progress final line, and keeps the
Codex native session hint encrypted. Subsequent polls use
`--cursor-namespace realtime` without the bootstrap flag. Historical ingestion uses
`--backfill --cursor-namespace backfill`, so it cannot consume or overwrite realtime
cursors even when both namespaces share one cursor directory.

Native JSONL records are bounded at 4 MiB including their line ending. Double Base64
expansion for encrypted RAW envelopes is covered by the shared 8 MiB request contract:
server `AMF_MAX_RAW_INGEST_BODY_BYTES` and client
`AMF_INGEST_HTTP_MAX_REQUEST_BYTES` both default to `8388608` and production values
cannot be lower. Other API routes retain the smaller `AMF_MAX_BODY_BYTES` limit.

## Deployment block

The Mem0 backend defaults to `disabled`. The adapter is pinned to Mem0 3.0.13 and
uses only the public `mem0ai/oss` export, loaded lazily after configuration checks.
Typed Mem0 port/dimension/timeout/boolean settings are validated before configured
state is accepted. Only read-side `search`/`getAll` operations may recreate and
retry the shared Memory instance; the internal compatibility `add` hook never
retries a failed write.
Do not deploy with `MEM0_BACKEND_KIND=mem0-oss` until the target collection and data
migration are explicitly reviewed. Proposal queuing/storage can be tested with Mem0
disabled.

`compose.agent-memory-fabric.yml` is the source overlay prepared for CT113. It
builds the pinned Dockerfile with `npm ci`, requires an explicitly approved
`.115` bind address, and mounts reviewed production policy, auth registry and
key ring files. The PAM routing ring, workspace config and applicator state key
are mounted together from `AMF_PAM_RUNTIME_PRIVATE_DIR` into a dedicated parent
owned by the configured service UID and GID; individual mounts into root-owned
`/run/secrets` or `/run/config` are unsupported. Run
`npm run operator:preflight-pam-runtime` inside the container before rollout.
No example policy is a runtime fallback. The generic service
retains `mem0-gateway` only as a network alias.
This change does not apply or deploy that overlay.
