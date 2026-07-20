# Semantic canonical search

Concept-level recall for canonical memory records, unioned into the existing
substring + token search in `CanonicalPamBridge`. It is **default-off** and
independent of the mem0/openmemory backend: it talks to a dedicated pgvector
table and an embedding endpoint directly.

## How it works

- On search, the query is embedded and matched by cosine distance (KNN) against
  `agent_memory_fabric.canonical_embeddings_v1`, scope-filtered and bounded by
  `topK`/`maxDistance`. Returned ids are unioned with lexical hits; the record
  read, time-window filter, and the authoritative scope/visibility/context-tag
  gates in `performCanonicalSearch` run on every candidate regardless of source.
- Ingestion is by reindex: plain claim texts are embedded and upserted; sealed
  claims are skipped (ciphertext carries no lexical signal); vanished ids are
  pruned. `upsert` is idempotent on `record_id`, so reruns are safe.
- A failing embed on one record is counted and skipped — the batch continues.

## One-time schema prerequisite (superuser)

The app role cannot `CREATE EXTENSION`. Run once per database as a superuser:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

The table and cosine HNSW index are created idempotently by
`SemanticIndex.ensureSchema()` (invoked by the reindex script) as the app role,
which needs `CREATE` on the `agent_memory_fabric` schema:

```sql
CREATE TABLE IF NOT EXISTS agent_memory_fabric.canonical_embeddings_v1 (
  record_id  text PRIMARY KEY,
  scope      text NOT NULL,
  claim_text text NOT NULL,
  embedding  vector(768) NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS canonical_embeddings_v1_scope_idx
  ON agent_memory_fabric.canonical_embeddings_v1 (scope);
CREATE INDEX IF NOT EXISTS canonical_embeddings_v1_hnsw
  ON agent_memory_fabric.canonical_embeddings_v1 USING hnsw (embedding vector_cosine_ops);
GRANT SELECT, INSERT, UPDATE, DELETE
  ON agent_memory_fabric.canonical_embeddings_v1 TO <app_role>;
```

The embedding dimension must match the embedder (`nomic-embed-text` → 768). A
dimension change requires a new table.

## Configuration

Set in the same service environment as the fabric (the PAM MCP child inherits
it):

| Variable | Meaning | Default |
|---|---|---|
| `AMF_SEMANTIC_SEARCH_ENABLED` | Master switch; anything but `true` = inert | off |
| `AMF_SEMANTIC_EMBEDDING_BASE_URL` | Ollama base URL (`/api/embed` appended) | required |
| `AMF_SEMANTIC_EMBEDDING_MODEL` | Embedding model | required |
| `AMF_SEMANTIC_EMBEDDING_DIMS` | Embedding dimension | 768 |
| `AMF_SEMANTIC_EMBEDDING_TIMEOUT_MS` | Per-embed HTTP timeout | 8000 |
| `AMF_SEMANTIC_DATABASE_URL` | Vector DB URL (falls back to `AMF_CATALOG_DATABASE_URL`) | catalog URL |
| `AMF_SEMANTIC_TOP_K` | Max KNN candidates per query | 10 |
| `AMF_SEMANTIC_MAX_DISTANCE` | Max cosine distance (0–2) for a hit | 0.55 |

TLS follows `AMF_CATALOG_SSL_MODE` (same helper as the catalog pool). A simple
single-shot parameterized KNN `SELECT` is safe under pgbouncer transaction
pooling (no session state, client-side `query_timeout` bounds it).

## Reindex

```sh
docker exec agent-memory-fabric-agent-memory-fabric-1 \
  /usr/local/bin/node /app/scripts/amf-reindex-semantic.mjs
```

The image contains only this operator script from `scripts/`; it uses the
running container's environment rather than a host-side copy of database, PAM,
or embedding configuration. `--force` re-embeds every plain claim when an
embedding model is intentionally changed:

```sh
docker exec agent-memory-fabric-agent-memory-fabric-1 \
  /usr/local/bin/node /app/scripts/amf-reindex-semantic.mjs --force
```

The normal path reads the indexed `(record_id, claim_text)` pairs once and
does not embed an unchanged claim. Its JSON result reports:

| Counter | Meaning |
|---|---|
| `upserted` | New or changed plain claims embedded and written. |
| `unchanged` | Plain claims already indexed with identical text; no embed call. |
| `skipped` | Sealed or unreadable claims. |
| `failed` | Per-record embed/upsert failures; the remaining batch continues. |
| `removed` | Indexed records no longer present in the canonical index. |

## Scheduled production lane

`deploy/systemd/amf-semantic-reindex.service` and `.timer` run the same command
inside the existing fabric container every five minutes. The service runs as
`root` solely to use the Docker socket; `stt` is deliberately not added to the
Docker group. `flock -n` prevents overlapping ticks, `TimeoutStartSec` bounds a
stalled reindex, and timer jitter avoids synchronized load.

Install the committed units on the fabric host, then enable the independent
timer:

```sh
install -m 0644 deploy/systemd/amf-semantic-reindex.service /etc/systemd/system/
install -m 0644 deploy/systemd/amf-semantic-reindex.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now amf-semantic-reindex.timer
systemctl start amf-semantic-reindex.service
```

This lane is intentionally not chained to a curation tick: an Ollama outage
can make semantic recall stale, but cannot fail curation. Read the latest JSON
result with `journalctl -u amf-semantic-reindex.service`; a healthy no-change
tick has `upserted: 0` and a positive `unchanged` count.
