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
node scripts/amf-reindex-semantic.mjs
```

Reads the record index, ensures the schema, embeds plain claims, upserts, and
prunes ids no longer present. Run after enabling, and whenever the corpus
changes (or on a schedule / after a curation tick).
