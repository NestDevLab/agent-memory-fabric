# Link graph (Postgres engine)

Wikilink-adjacency retrieval over the document corpus. When enabled, an
`/v2/context/search` request expands its returned documents by one or more
wikilink hops and unions the neighbours in as additional recall — surfacing
related notes the lexical/semantic match alone would miss.

This branch ships the **Postgres engine only** (`src/link-graph.mjs`, "Path A",
recursive-CTE traversal). A second FalkorDB engine exists on the both-engines
branch behind the same `AMF_LINK_GRAPH_ENGINE` switch; see
`docs/benchmark-link-graph.md` for why Postgres is the default.

## Data model

Edges live in `agent_memory_fabric.document_links_v1`, one row per wikilink:

| column | meaning |
|---|---|
| `src_document_id` | document the link is written in |
| `src_vault_id` | vault of the source document (the ACL boundary) |
| `src_path` | source document path |
| `target_raw` | raw wikilink target as written (`[[Note]]` → `Note`) |
| `target_path` | resolved path, or null if the target is a dangler |
| `dst_document_id` | resolved destination document id, or null |
| `alias` | `[[Note\|alias]]` alias, if any |

Primary key `(src_document_id, target_raw)`; indexes on `dst_document_id` and
`src_vault_id`. The parser (`src/link-parser.mjs`) handles `[[Note]]`,
`[[Note|alias]]`, `[[folder/Note]]`, and `[[Note#heading]]`.

## Traversals

`LinkGraph` exposes read methods, all vault-scoped (an empty vault list returns
nothing — fail closed):

- `neighbors({ documentId, vaults, depth })` — outbound reachable docs, deduped
  to the shortest distance; depth bounded to 1–4.
- `backlinks({ documentId, vaults })` — docs linking *to* this one.
- `related({ documentId, vaults, limit })` — docs sharing outbound targets,
  ranked by shared-target count.
- `shortestPath({ fromId, toId, vaults, maxDepth })` — undirected BFS path.
  Explores all paths to `maxDepth` before filtering, so it is a diagnostic
  traversal, not on the search hot path.
- `expand({ seedDocumentIds, vaults, limit })` — the search integration: runs
  `neighbors` from each seed at the configured depth, dedupes against the seeds,
  tags each hit `source: 'graph'`, and caps at `maxExpansion`.

Vault scoping is enforced per hop, so a traversal cannot cross an
unauthorized-vault edge to reach a node.

## Enabling it

Off by default. To turn it on for `/v2/context/search`:

```bash
AMF_LINK_GRAPH_ENABLED=true            # required; anything else = inert
AMF_CATALOG_DATABASE_URL=postgresql://…  # reused from the catalog store
AMF_LINK_GRAPH_MAX_DEPTH=1             # optional, 1–4 (default 1)
AMF_LINK_GRAPH_MAX_EXPANSION=20        # optional, 1–200 (default 20)
```

`AMF_LINK_GRAPH_ENGINE` defaults to `postgres`. Setting it to `falkor` on this
branch yields an inert (unconfigured) graph, since the FalkorDB engine is not
shipped here.

When disabled or unconfigured, `context_search` behaves exactly as before —
canonical-memory + document interleave, no graph source, no `graph` count.

## Reindexing

The edge table is derived and rebuildable. `scripts/amf-reindex-graph.mjs`
reads the live document heads, parses wikilinks, resolves targets to document
ids, replaces each document's edges transactionally, and prunes edges for
tombstoned documents:

```bash
AMF_CATALOG_DATABASE_URL=postgresql://… node scripts/amf-reindex-graph.mjs
# → {"ok":true,"docs":N,"edges":M,"failed":0}
```

Idempotent — safe to re-run. Run it after bulk document changes; a per-write
hook is out of scope for this engine.

## Tests

- `scripts/test-link-parser.mjs` — wikilink parser (no DB).
- `scripts/test-link-graph.mjs` — engine traversals + env factory. DB-backed
  tests gate on `AMF_TEST_DATABASE_URL` and skip without it.
- `scripts/test-link-graph-search.mjs` — `/v2/context/search` graph-union wiring.

DB-backed tests need a reachable Postgres and must run on the compose network
(`127.0.0.1` will not connect to the container). See
`docs/benchmark-link-graph.md` for the container-runner pattern.

## Verified live (2026-07-21)

Exercised end-to-end against the live corpus (~16k edges, `work-wiki`) with the
engine enabled, driving `context_search` over the MCP transport. The graph
source appears in the response `sources` count:

| query | memory | document | graph |
|---|---|---|---|
| `agentBerry` | 0 | 10 | 10 |
| `HolmesGPT` | 0 | 25 | 20 |

A non-zero `graph` count confirms `expand()` ran: the returned documents were
one-hop wikilink-expanded, deduped against results already present, and unioned
in as `source:'graph'` items. With the engine disabled the `graph` count is
absent and `context_search` is document-interleave only.
