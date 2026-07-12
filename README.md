# Agent Memory Fabric

Shared REST/MCP boundary for scoped memory access. `mem0-gateway` remains a
legacy product alias while clients migrate to `agent-memory-fabric`.

## Current shape

- stable REST/MCP boundary with actor, scope and permission enforcement
- Mem0 backend adapter for scoped search
- idempotent proposal queue; public requests never write directly to Mem0
- encrypted, content-addressed RAW proposal storage and auditable catalog
- local JSON auth registry, with optional n8n Data Table fallback
- legacy REST v1, MCP SSE and MCP Streamable HTTP compatibility

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
      "permissions": "memory:search,memory:read,memory:propose,memory:add,memory:status,sessions:read,raw:decrypt"
    }
  ]
}
```

`tokenSha256` is the lowercase SHA-256 digest of the bearer token; bearer values are
checked with a constant-time comparison and need not be stored in the registry.
`allowedScopes` and `permissions` accept arrays or comma-separated strings. The
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

## API v2

Success uses `{ "ok": true, "data": ..., "meta": ... }`; errors use
`{ "ok": false, "error": { "code", "message", "details" }, "meta": ... }`.

- `POST /v2/memory/search`
- `POST /v2/memory/proposals` (requires `Idempotency-Key`)
- `GET /v2/memory/:id` (canonical record, rationale and expected revision)
- `GET /v2/memory/proposals/:id` (status only; no record decryption)
- `POST /v2/sessions/search` (requires `purpose`)
- `GET /v2/sessions/:id?purpose=...`
- `GET /v2/sessions/:id/transcript?purpose=...&view=redacted|original`
- `GET /v2/status`

The proposal body is exactly `{record,rationale,expectedRevision?}`. `record`
must conform to PAM 0.6 `amf-memory/v1`: canonical scope IDs, exact fields and
strict timestamps/provenance/lifecycle. Restricted/confidential and
person/relationship records must carry a sealed AES-256-GCM envelope with
canonical base64, 12-byte IV, 16-byte tag, opaque `kekId`/`keyRef`, and the PAM
canonical AAD digest. A successful REST or MCP acknowledgement exposes
`{status,proposalId,duplicate,idempotencyKey}`; the last field is the exact
authoritative retry key accepted or derived by the Fabric.

Every memory/session transport, including MCP, errors and status, is private and
`no-store`. Session calls require one opaque purpose code: `conversation_recall`,
`continuity_resume`, `incident_debug`, `operator_review`, or `memory_curation`.
MCP sessions have TTL, global/per-actor caps, and revalidate token activity and
policy on every call. Original transcripts additionally require `raw:decrypt`;
redacted is the default. MCP initialize advertises `sessionReader: false` and the
routes return `session_reader_unconfigured` (`503`) until an adapter is wired.

MCP advertises `memory_search`, `memory_read`, `memory_propose`,
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
key ring files. No example policy is a runtime fallback. The generic service
retains `mem0-gateway` only as a network alias.
This change does not apply or deploy that overlay.
