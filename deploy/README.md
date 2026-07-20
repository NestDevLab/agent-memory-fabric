# deploy/ — multi-agent compose stack

Artifacts for the v1 stack designed in
[../docs/multi-agent-compose-stack.md](../docs/multi-agent-compose-stack.md):
`amf-server` + `postgres` (pgvector) + `ollama` (Tier 2, decision 8). The only
published port is amf-server on `${AMF_BIND_ADDRESS}:8787`. Read the design
doc for decisions, data flows, and the verification plan.

## Layout

- `docker-compose.yml` — three services, hardened amf-server (read-only,
  non-root, tmpfs), healthchecks on amf-server and postgres.
- `.env.example` — copy to `.env` (gitignored) and fill in.
- `.env.runtime` — optional extra container env (gitignored), merged via
  `env_file`.

## Prerequisites

- Docker with compose v2.
- A reviewed `portable-agent-memory` checkout (`PAM_SOURCE_DIR`).
- Secret/config files (policy, auth registry, three key rings) — formats in
  `../config/*.example.json`, provisioning in `../docs/*-provisioning.md`.
  For a throwaway local set see "Local dev secrets" below.
- Host dirs owned by uid 1000: `PAM_RUNTIME_DIR` (mode 0700) and
  `BRAIN_SHARED_DIR`. These hold PAM key material and canonical records, so
  they are host paths (ownership control), not named volumes.

## First boot

```sh
cp .env.example .env   # then edit values
docker compose build
docker compose up -d
# once, as superuser (the app role is the image-created superuser here):
docker compose exec postgres psql -U agent_memory_fabric -d agent_memory_fabric \
  -c 'CREATE EXTENSION IF NOT EXISTS vector;'
# pull the embedding model AT THE PINNED DIGEST (see .env):
docker compose exec ollama ollama pull "nomic-embed-text@${NOMIC_EMBED_TEXT_DIGEST}"
# and pin the same digest on every edge host whose hook embeds locally:
ollama pull "nomic-embed-text@${NOMIC_EMBED_TEXT_DIGEST}"
```

### Verify the shared embedding digest

The ollama API rejects digest-qualified model names, so consistency is
enforced by pinned pulls plus this comparison — the two digests must match:

```sh
docker run --rm --network amf-stack_default curlimages/curl -s \
  http://ollama:11434/api/tags | grep -o '"digest":"[^"]*"'
curl -s http://localhost:11434/api/tags | grep -o '"digest":"[^"]*"'
```

Then point an edge bridge at `http://<bind>:8787` in **shadow** mode
(`OBSIDIAN_AMF_MODE=shadow`, `OBSIDIAN_AMF_TOKEN_FILE`,
`OBSIDIAN_AMF_CONTEXT_KEY_RING`, `OBSIDIAN_AMF_POLICY_REVISION` matching
`.env`) and run `scan` → `drain` → `status` (expect zero pending). After
corpus changes, refresh the semantic index manually:

```sh
docker compose exec amf-server node scripts/amf-reindex-semantic.mjs
```

## Local dev secrets (throwaway, gitignored)

Verified recipe (local smoke, 2026-07-18):

```sh
mkdir -p secrets.local/pam-runtime ../var/brain-shared/memory/amf
chmod 0700 secrets.local/pam-runtime
printf '{"records": {}}\n' > ../var/brain-shared/memory/amf/record-index.json
chmod 0600 ../var/brain-shared/memory/amf/record-index.json   # exact 0600 required
```

- `secrets.local/policy.json` — actors **and registered scopes** (an
  unregistered scope is `scope_forbidden` even for `allow_all` actors):
  `{"actors": {"dev-claude-code": {"mode": "allow_all"}}, "scopes": {"work-wiki": {"backendUserId": "dev"}}}`
- Key rings — format per `../config/ingest-key-ring.example.json`; generate
  keys with `openssl rand 32 | base64`.
- `secrets.local/auth-registry.json` — one row modeled on
  `../config/auth-registry.example.json`: `tokenSha256` =
  `printf '%s' '<dev-token>' | shasum -a 256 | cut -d' ' -f1`, actor
  `dev-claude-code`, `mode: allow_all`, your vault id in `allowedVaults`, and
  permissions including `memory:*`, `documents:*` **and every
  `purpose:<name>`** you will use (`conversation_recall`, `operator_review`,
  `continuity_resume`, `memory_curation`) — a missing purpose permission is a
  bare 403. Put the plaintext token in the edge's `OBSIDIAN_AMF_TOKEN_FILE`.
- `secrets.local/pam-runtime/` — exactly three files, each `0600`:
  `agent-memory-fabric-routing-key-ring.json` (routing key ring),
  `pam-workspace-config.json` (see `portable-agent-memory/docs/amf-curator.md`,
  `amfApplicator` block; the applicator token's sha256 must match
  `PAM_APPLICATOR_TOKEN` in `.env`), `pam-applicator-state-key`.
- Edge copies (`secrets.local/edge/`): the plaintext token file and the
  context key ring must be `0600` — the bridge refuses unsafe files.

Restart amf-server after changing the policy or auth registry
(`docker compose restart amf-server`).

## Notes

- The amf-server healthcheck is a TCP connect to 8787 (liveness only).
  `/v2/status` requires a bearer with `memory:status`; deep-check manually:
  `curl -H "Authorization: Bearer <token>" http://127.0.0.1:8787/v2/status`.
- Session routes (`AMF_SESSION_ROUTE_MANIFEST_PATH`) are intentionally not
  wired in v1; add per `../docs/recall-consumer-provisioning.md` when session
  recall is needed.
- **macOS uid mapping:** bind-mounted host dirs appear as uid/gid `503:20`
  inside containers (Docker Desktop / Rancher Desktop), and AMF validates
  mount ownership against the process euid — so `AMF_SERVICE_UID=503` /
  `AMF_SERVICE_GID=20` in `.env` on a Mac, and chown the `amf-data` volume to
  match if it was created earlier
  (`docker run --rm -v amf-stack_amf-data:/data alpine chown -R 503:20 /data`).
  Linux hosts keep the `1000:1000` defaults.
- `AMF_HOST_PORT` moves the published port when 8787 is taken locally.
- Production deltas: set `AMF_BIND_ADDRESS` to the LAN IP, pin images by
  digest, provision real secrets per the provisioning docs, and confirm
  nothing else writes `BRAIN_SHARED_DIR` (single-writer rule, decision 7).
