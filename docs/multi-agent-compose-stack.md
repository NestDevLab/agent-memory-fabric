# Multi-agent compose stack (design)

Status: approved (2026-07-18); v1 local smoke **passed** (2026-07-18, macOS +
Rancher Desktop): stack healthy; 2090 vault documents ingested in shadow mode;
outage recovery via outbox/drain with zero pending and zero failed;
`/v2/context/search` AMF-vs-direct ID comparison matching; manual semantic
reindex executing (no-op on empty PAM). Server deployment is next. Supersedes
no existing doc; extends `ARCHITECTURE.md`, `obsidian-second-brain.md`,
`postgres-catalog.md`, and `semantic-search.md` with a concrete, containerized
deployment for a shared multi-agent fabric.

## Context and goal

The Obsidian second brain today runs entirely on one Mac: Obsidian edits the
vault, Claude Code hooks invoke the `obsidian_amf` bridge, ollama serves
embeddings on localhost, and all state is local SQLite. The bridge already
speaks the AMF v2 API, but no shared fabric is deployed.

The goal is a modular `docker compose` stack that runs AMF centrally and
serves several agents (Claude Code, OpenClaw, Hermes, Codex) as isolated
actors against one canonical memory, while the vault remains a plain local
Obsidian vault. The multi-agent need is confirmed as near-term (a second
agent consuming shared memory within weeks), which satisfies the recorded
standalone → shadow → active escalation gate.

## Goals and non-goals

Goals:

- Central, shared, multi-tenant fabric reachable by all agents.
- Modular services, one `docker compose up`, repeatable on any Docker host.
- Vault stays canonical for documents and fully usable in the Obsidian app.
- Per-actor isolation delivered by configuration (tokens, key rings, ACLs),
  not by duplicating containers.

Non-goals (deferred to v1.1+):

- Scheduled vault sync poller as a container.
- Automated semantic reindex (cron / curation tick).
- A separate curator container splitting proposal application out of
  amf-server.
- The integrated graph + MCP layer (see the v1.1 section below).
- A dedicated graph database (see decision 8 — Postgres edges first, with
  explicit reversal triggers).
- HA, replication, multi-host orchestration.

## Locked decisions

1. **Vault relationship: source + selective projection.** The vault is the
   canonical document corpus and feeds AMF. Selected canonical PAM records may
   be explicitly projected back into the vault's managed `.amf/records/`
   namespace. There is no bidirectional sync of the same files and no second
   authoritative store for hand-authored notes. The guardrails are already
   enforced by the `obsidian_amf` client: projections require an explicit
   `project` command, write only under `.amf/records/` with directory-relative
   no-follow operations, accept only active plaintext PAM records, and the
   scanner excludes that namespace, so projection feedback loops are
   impossible by construction.
2. **Edge/central split.** Containers host only central services. The
   `obsidian_amf` bridge remains a host CLI on the Mac, invoked by the Claude
   Code hooks exactly as today; Obsidian needs real local files and the hooks
   run on the host regardless. Containerizing the bridge (bind-mounted vault)
   or git-syncing the vault to the server were considered and rejected for v1.
3. **PAM is not a service and not a database.** AMF runs PAM as an MCP child
   process (`AMF_PAM_MCP_SERVER_PATH`) against a file workspace
   (`/srv/brain-shared`). The stack therefore needs a shared volume and a
   mounted PAM source tree, not a PAM container.
4. **One PostgreSQL, one database.** Catalog, document corpus, and semantic
   embeddings (`canonical_embeddings_v1`) share one database on a pgvector
   image. `AMF_SEMANTIC_DATABASE_URL` is left unset and falls back to
   `AMF_CATALOG_DATABASE_URL`.
5. **One pinned ollama container** serving `nomic-embed-text` (768-dim), the
   same model the Mac hook uses, so host-side and fabric-side vector spaces
   stay consistent. **Enforced 2026-07-18:** both images pinned by digest in
   compose; the model digest
   (`sha256:0a109f422b47e3a30ba2b10eca18548e944e8a23073ee3f3e947efcf3c45e59f`)
   is recorded in `deploy/.env.example` (`NOMIC_EMBED_TEXT_DIGEST`) and pulled
   by digest on the container and every edge host. ollama's embed API rejects
   digest-qualified model names, so enforcement is pinned pulls plus the
   digest-comparison check in `deploy/README.md`.
6. **Semantic search enabled, ingestion by manual reindex.** AMF never embeds
   at document-ingest time; only `scripts/amf-reindex-semantic.mjs` embeds and
   upserts. v1 documents the manual reindex; automation is v1.1.
7. **`/srv/brain-shared` mounted read-write** (deliberate deviation from
   `compose.agent-memory-fabric.yml`, which mounts it read-only). In this
   self-contained stack amf-server is the single writer that applies curated
   proposals. Verify at deploy time that no existing apply flow on the target
   host conflicts; revisit a curator container in v1.1.
8. **Tier 2: three services, no TLS proxy.** `amf-server` + `postgres`
   (pgvector) + `ollama`; amf-server binds the host LAN address directly,
   matching the existing reference compose (`192.168.1.115:8787:8787`, no
   TLS anywhere). Bearer tokens ride the trusted LAN; add a reverse proxy or
   Tailscale later if traffic ever crosses untrusted networks — that change is
   additive and touches nothing else. AMF's catalog defaults to SQLite
   (`fabric-store.mjs`) and `AMF_DOCUMENT_BACKEND=sqlite` exists, so Postgres
   is a choice, not a requirement; it is kept in v1 because the semantic layer
   (pgvector) is in scope and re-standing-up the data layer later would land
   exactly when the second agent arrives.
9. **Shadow-first deployment.** The stack is mode-agnostic; the mode lives in
   the edge client (`OBSIDIAN_AMF_MODE`). The bridge is deployed against the
   stack in `shadow` (direct SQLite authoritative, AMF delivery observed).
   Building and running the stack is not an active-mode cutover; `active`
   remains a separate, explicitly gated decision.
10. **Graph store: Postgres edges first, dedicated engine deferred — not
    rejected.** The v1.1 link layer stores Obsidian `[[wikilink]]` edges as a
    plain Postgres table and traverses them with recursive CTEs. Rationale:
    (a) every graph result must be filtered through per-actor vault ACLs, and
    co-locating edges with the authorization data keeps that a SQL join
    inside the enforcing layer rather than cross-store stitching; (b) at vault
    scale (hundreds of notes; even 10k notes / 50k edges) fixed-shape
    traversals (neighbors, backlinks, shortest path) are single-digit
    milliseconds in Postgres; (c) one stateful store means one backup story
    (`pg_dump` covers catalog, documents, embeddings, and edges atomically)
    and joins across edges ↔ document metadata ↔ embeddings in one query.
    **Apache AGE** (openCypher as a Postgres extension) is the intermediate
    option if Cypher expressiveness is wanted without a second store.
    **FalkorDB-class engines are revisited when a trigger fires:** corpus
    >~100k edges, hot 4+-hop queries, or the v1.2 LLM entity-extraction layer
    landing (entity graphs are denser and graph-algorithm-heavy). Edges are
    derived state re-parseable from the vault, so any later migration is a
    rebuild, not a data migration.
11. **HangarX (cortex GraphRAG) evaluated as reference, not component.** The
    hangarx-obsidian plugin + cortex-api stack was compared in detail
    (2026-07-18). It optimizes for single-user GraphRAG Q&A UX; this stack
    optimizes for governed, multi-tenant shared memory. We adopt its proven
    *ideas* — the graph tool surface (`neighbors`, `paths`, `backlinks`,
    per-note links) as our v1.1 result shapes, the one-click MCP adapter
    pattern, compose healthcheck hygiene, and in-Obsidian UX as v1.2
    inspiration. We deliberately do **not** adopt: the cortex-api image,
    FalkorDB for now (decision 10), unauthenticated MCP surfaces, secrets
    baked into vault-root compose files, ungoverned agent write/delete tools,
    or entity→markdown pull (our projection discipline is stricter).

## Topology (v1 — Tier 2)

```
┌─ Mac (edge, host processes — unchanged) ─────────────────────┐
│ Obsidian ↔ WORK-WIKI vault (canonical documents)             │
│ Claude Code hooks → python3 -m obsidian_amf                  │
│   (OBSIDIAN_AMF_TOKEN_FILE + owner-only context key ring)    │
└──────────────┬───────────────────────────────────────────────┘
               │ HTTP :8787 on the LAN (bearer + purpose-bound
               │ signed context tokens; trusted-network binding)
┌──────────────▼── central docker compose stack ───────────────┐
│ amf-server   /v2/documents, /v2/context/search,              │
│              /v2/memory/proposals, /v2/status; auth registry,│
│              policy, vault ACLs, idempotency; PAM MCP child  │
│              process reading /srv/brain-shared               │
│              → published on ${AMF_BIND_ADDRESS}:8787         │
│ postgres     pgvector image; one DB: catalog + documents +   │
│              canonical_embeddings_v1; compose network only   │
│ ollama       nomic-embed-text pinned by digest;              │
│              compose network only                            │
└───────────────────────────────────────────────────────────────┘
```

Inter-service traffic stays on the compose network; postgres and ollama are
never exposed to the host or LAN. The only published port is amf-server's
8787, bound to the host LAN address. If agents ever run off-LAN, front
amf-server with a proxy/Tailscale (see decision 8).

## Services

### amf-server

- Build: this repository's `Dockerfile` (node 22 slim, production deps,
  `USER node`). Tag `agent-memory-fabric:<release>`; v1 builds from a
  reviewed checkout, not a floating registry tag (first deployment pin:
  `0.6.0`).
- Hardening inherited from `compose.agent-memory-fabric.yml`: `read_only`,
  `init: true`, non-root `user`, `tmpfs` `/tmp`.
- Port: `"${AMF_BIND_ADDRESS:-127.0.0.1}:8787:8787"`.
- Environment (contract verified against `.env.example` and
  `docs/semantic-search.md`):
  - Server/auth: `AMF_SERVER_ENABLED=true`, `AMF_POLICY_PATH`,
    `AMF_AUTH_REGISTRY_PATH`, `AMF_RAW_KEY_RING_PATH`,
    `AMF_INGEST_KEY_RING_PATH`, `AMF_CONTEXT_KEY_RING_PATH`,
    `AMF_POLICY_REVISION` (required). Session routes
    (`AMF_SESSION_ROUTE_MANIFEST_PATH`) are optional and not wired in v1.
  - PAM: `AMF_PAM_MCP_SERVER_PATH=/opt/portable-agent-memory/tools/pam-mcp-server.mjs`,
    `AMF_PAM_WORKSPACE=/srv/brain-shared`,
    `AMF_PAM_RECORD_INDEX_PATH=/srv/brain-shared/memory/amf/record-index.json`,
    `AMF_PAM_RUNTIME_PRIVATE_DIR=/run/amf-pam-private`,
    `AMF_PAM_ROUTING_KEY_RING_PATH`, `PAM_WORKSPACE_CONFIG`,
    `PAM_APPLICATOR_STATE_KEY_FILE` (last three under the runtime private dir).
  - Persistence: `AMF_DATA_PATH=/var/lib/agent-memory-fabric`,
    `AMF_CATALOG_KIND=postgres`,
    `AMF_CATALOG_DATABASE_URL=postgresql://agent_memory_fabric:<pw>@postgres:5432/agent_memory_fabric`,
    `AMF_DOCUMENT_BACKEND=postgresql`, catalog pool/timeout overrides as
    needed. `MEM0_BACKEND_KIND=disabled`.
  - Semantic: `AMF_SEMANTIC_SEARCH_ENABLED=true`,
    `AMF_SEMANTIC_EMBEDDING_BASE_URL=http://ollama:11434`,
    `AMF_SEMANTIC_EMBEDDING_MODEL=nomic-embed-text`,
    `AMF_SEMANTIC_EMBEDDING_DIMS=768`; `AMF_SEMANTIC_DATABASE_URL` unset.
- Mounts: policy (`ro`), auth registry and three key rings (`ro`), PAM source
  checkout → `/opt/portable-agent-memory` (`ro`), `brain-shared` **host dir**
  → `/srv/brain-shared` (**rw**, see decision 7), `pam-runtime` **host dir**
  (owned 1000:1000, mode 0700 — it holds key material, so it is a host path
  for ownership control, not a named volume) → `/run/amf-pam-private`,
  `amf-data` volume → `/var/lib/agent-memory-fabric` (the image pre-creates
  this path `chown`ed to the service uid, so a named volume works), and this
  repo's `scripts/` → `/app/scripts:ro` (addition vs the reference compose so
  the reindex runs inside the hardened container; its imports resolve against
  the image's `/app/src`).
- Healthcheck: TCP connect to 8787 from inside the container (liveness).
  `/v2/status` requires a `memory:status` bearer (verified against
  `src/server.mjs`), so HTTP probing would need a token in the healthcheck;
  deep-check manually with curl instead.

### postgres

- Image: `pgvector/pgvector:pg16` (pin by digest) — stock Postgres plus the
  `vector` extension.
- One database `agent_memory_fabric`, one application role
  `agent_memory_fabric` owning the schema. The application role cannot
  `CREATE EXTENSION`; the one-time bootstrap runs as superuser.
- No host port; compose network only. Healthcheck: `pg_isready`.
- State: `pgdata` volume.

### ollama

- Image: `ollama/ollama` (pin by digest).
- No host port; compose network only. AMF reaches it at
  `http://ollama:11434`.
- Model: `nomic-embed-text` pulled once and pinned by digest
  (`docker compose exec ollama ollama pull nomic-embed-text@sha256:...`).
  The Mac hook pins the same digest.
- State: `ollama-models` volume.

## Volumes and state

| Volume          | Contents                                            | Backup              |
| --------------- | --------------------------------------------------- | ------------------- |
| `pgdata`        | Catalog, document corpus, `canonical_embeddings_v1` | `pg_dump`           |
| `brain-shared` (host path) | Canonical PAM records + `memory/amf/record-index.json` | Filesystem snapshot |
| `pam-runtime` (host path, 0700) | Routing key ring, PAM workspace config, applicator state key | Treat as secret     |
| `amf-data`      | AMF service data path                               | `pg_dump` covers catalog; snapshot optional |
| `ollama-models` | Embedding model blobs                               | Re-pullable; no backup |

## Secrets and per-actor configuration

Secrets are host files mounted read-only, never environment literals, never
committed — matching the existing client model (`OBSIDIAN_AMF_TOKEN_FILE`,
local owner-only key rings). Contrast with the HangarX local setup, which
bakes API keys into a compose file at the vault root; that pattern is
explicitly rejected here (decision 11).

- `agent-memory-fabric-policy.json` — reviewed policy; `AMF_POLICY_REVISION`
  must name the mounted revision (see `config/policies.example.json`).
- `agent-memory-fabric-auth.json` — auth registry; one entry per actor
  (see `config/auth-registry.example.json`).
- Three key rings (raw, ingest, context) per
  `config/ingest-key-ring.example.json` and peers.
- Session-route manifest directory.
- Database password and any runtime overrides via `.env.runtime`
  (gitignored), consumed through `env_file`.

Multi-tenancy is configuration: each agent (Claude Code, OpenClaw, Hermes,
Codex) gets its own bearer entry, its own context key-ring entry, and vault
ACL scopes in policy. Adding an actor = registry + key-ring entries and
restarting amf-server; no new containers.

## Data flows

1. **Ingest.** Mac bridge `scan` reads markdown (vault is canonical) and
   delivers `PUT /v2/documents/{id}` with an `Idempotency-Key`
   (`amf.document/v1`). amf-server persists to the Postgres catalog and
   document store. On outage the bridge outbox retains events; `drain`
   replays them with no provider fallback and no loss.
2. **Search.** The bridge signs each exact query locally and calls
   `POST /v2/context/search` with `X-AMF-Context-Token`. amf-server verifies
   the token against the actor's context key ring, the policy revision, and
   the vault ACL, then returns combined snippets: canonical memory from PAM
   (MCP child on `brain-shared`) plus the document corpus, with pgvector KNN
   when semantic is populated.
3. **Memory proposals.** `POST /v2/memory/proposals` (`amf-memory/v1`,
   idempotency-keyed) enters the curation lane; nothing writes PAM directly.
   Reviewed proposals are applied by amf-server, the single writer of
   `brain-shared` in v1.
4. **Projection.** An explicit `project` on the Mac reads an active plaintext
   PAM record and writes a managed note under `.amf/records/`. The scanner
   excludes that namespace, so projected notes are never re-ingested.
5. **Semantic reindex (manual in v1).**
   `docker compose exec amf-server node scripts/amf-reindex-semantic.mjs`
   embeds plain claim texts via ollama and upserts
   `canonical_embeddings_v1`. Sealed records are never embedded.

## First-boot runbook

1. Clone this repository and `portable-agent-memory` on the Docker host at
   reviewed revisions.
2. Create the secrets directory (policy, auth registry, three key rings,
   session routes) and `.env.runtime`; gitignore both.
3. `docker compose build && docker compose up -d`.
4. Once, as superuser:
   `docker compose exec postgres psql -U postgres -d agent_memory_fabric -c 'CREATE EXTENSION IF NOT EXISTS vector;'`.
5. Pull the pinned embedding model:
   `docker compose exec ollama ollama pull nomic-embed-text@sha256:<digest>`.
6. Provision each actor (auth registry + context key ring + ACL scopes);
   distribute bearer files to edges (`OBSIDIAN_AMF_TOKEN_FILE` on the Mac,
   plus the actor's local context key ring).
7. Smoke test (Mac): run the bridge in `shadow` mode — `scan`, `drain`,
   `status` show zero pending; `search` returns the direct result plus the
   AMF diagnostic with matching IDs. Then run the reindex once (step above)
   and confirm semantic hits.
8. Backups: scheduled `pg_dump` of `agent_memory_fabric` plus a filesystem
   snapshot of `brain-shared`.

## Verification plan

- `obsidian-second-brain` unit tests
  (`python3 -m unittest discover -s tests -v`) remain green unchanged;
  standalone mode is untouched.
- Shadow-mode trial against the stack: direct SQLite stays authoritative
  while AMF delivery is observed; compare document IDs per the client's
  shadow search output.
- Outage drill: stop amf-server, run a scan, restart, `drain`; expect zero
  pending and exactly-once delivery via idempotency keys.
- Projection round-trip: propose → review/apply → `project` → managed note
  appears under `.amf/records/` and a rescan ingests nothing from that
  namespace.
- Multi-actor check: two actors with disjoint ACLs cannot read each other's
  scoped vault content through `/v2/context/search`.

## v1.1 — integrated graph + MCP layer

**One canonical vault-backed memory, reachable by multiple agents through one
governed surface: Docker + pgvector + graph + MCP bridge.** Informed by the
HangarX evaluation (decision 11); everything here stays AMF-mediated and
ACL-enforced.

1. **Obsidian link-graph awareness (headline).** Server-side, deterministic
   extraction of `[[wikilinks]]` from ingested markdown (AMF already receives
   full note text tagged `provenance.sourceKind: "obsidian"`) into an edges
   table in Postgres (decision 10), with neighbor / backlink / shortest-path
   expansion in `/v2/context/search`. Result shapes modeled on HangarX's
   proven surface: per-note content + outgoing links + backlinks, `related`,
   `paths`. No new service; no LLM; edges are derived and rebuildable.
2. **Governed MCP adapter — DELIVERED EARLY (2026-07-18, in v1).** Pulled
   forward from v1.1 by request: `obsidian_amf/mcp_server.py` in
   obsidian-second-brain wraps the bridge as an MCP stdio server
   (`amf_search`, `amf_status`, `amf_propose`), always `active` mode, one
   actor's credentials per adapter process, all enforcement server-side.
   OpenCode and Claude Desktop wiring is documented in the client README;
   `dev-opencode` was the first MCP-adapter actor. Remaining v1.1 scope for
   this item: per-harness one-click setup scripts and, after item 1 lands,
   graph tools on the same surface.
3. **Automated semantic reindex** (cron / curation tick replacing the manual
   v1 step).
4. **Scheduled sync poller** as a container (the deferred option-4 scope).
5. **Graph-store checkpoint** before v1.2: evaluate Apache AGE and FalkorDB
   against decision 10's reversal triggers.

## v1.2+ (noted, not planned)

- **LLM entity extraction** as a *derived, read-only* enrichment layered over
  the deterministic link graph — typed entities, inferred relations,
  communities. Deterministic links come first; HangarX's need to ship
  dedupe/rebuild tooling is the cautionary maintenance tale. Read-only and
  derived: never a write path into canonical memory.
- **In-Obsidian UX**: cited-answer panel, graph-view highlighting of cited
  entities, inline `[[wikilink]]` suggestions — driven by canonical-memory
  matches (a capability HangarX does not have).

## Assumptions (confirm at deploy time)

- Host: the LAN server (`192.168.1.115`, per the existing reference compose);
  the stack is host-agnostic — only `.env.runtime` and the bind address
  change.
- First image pin: `0.6.0` (per the reference compose).
- `brain-shared` rw: verify no existing apply flow on the target host writes
  the same workspace (decision 7).
- All agents v1 are on the trusted LAN; no TLS at the app layer (decision 8).

## Appendix: reference compose skeleton

The normative shape is implemented in `deploy/docker-compose.yml`, which is
the single source of truth (with `deploy/.env.example` and
`deploy/README.md`). Deviations from the original review skeleton, resolved
at implementation (2026-07-18):

- Session routes are omitted (optional feature, not needed for v1).
- `brain-shared` and `pam-runtime` are host directories (ownership control:
  1000:1000, 0700 for `pam-runtime` since it holds key material), not named
  volumes.
- The catalog URL is constructed in the compose file from `AMF_DB_PASSWORD`
  (compose does not interpolate values inside `.env` files).
- amf-server's healthcheck is a TCP connect to 8787; `/v2/status` requires a
  `memory:status` bearer, so an HTTP probe would need a token.
- `AMF_SERVICE_UID`/`AMF_SERVICE_GID` parameterize the container uid (matches
  the reference compose): macOS maps bind-mount owners to `503:20` and AMF
  validates mount ownership against the process euid.
- `AMF_HOST_PORT` moves the published port when 8787 is already taken.
- `AMF_CATALOG_SSL_MODE=disable` locally (Postgres never leaves the compose
  network); the code default is `verify-full`.
- `AMF_MAX_BODY_BYTES` raised to 1 MiB from the 256 KiB default: large
  accumulated notes exceed the default once JSON-wrapped (`amf_http_413`).
- Dev-secret lessons from the smoke: requested scopes must be registered in
  the policy file's `scopes` map (`scope_forbidden` otherwise, even for
  `allow_all`), registry permissions must include each `purpose:<name>` used,
  and `record-index.json` must exist at exactly mode `0600`.
