# Link-graph engine benchmark: Postgres vs FalkorDB

> Note: this branch ships the Postgres engine only. The FalkorDB engine
> (`src/link-graph-falkor.mjs`) and the head-to-head harness
> (`scripts/amf-benchmark-graph.mjs`) referenced below live on the both-engines
> branch. The results are kept here as the record behind the Postgres-first default.

Head-to-head comparison of the two link-graph traversal engines — Path A
(Postgres recursive CTE, `src/link-graph.mjs`) and Path B (FalkorDB,
`src/link-graph-falkor.mjs`) — on the live corpus. This benchmark exists to
decide the FalkorDB-vs-Postgres question with measured data rather than the
assumed edge-count trigger recorded in `docs/multi-agent-compose-stack.md`
decision 10.

**Bottom line:** at the current corpus size neither engine wins. Correctness is
identical (5/5 parity); latency is a wash (Postgres faster on 3 of 5 seeds,
FalkorDB on 2 of 5, all differences single-digit-to-low-double-digit
milliseconds). This confirms the Postgres-first default — FalkorDB earns no
measurable advantage at this scale and stays deferred.

## Method

- **Harness:** `scripts/amf-benchmark-graph.mjs`.
- **Corpus:** live `agent_memory_fabric.document_links_v1` — 16,320 edges
  (13,385 with a non-null `dst_document_id`), single vault `work-wiki`.
- **Seeds:** the 5 most-connected source documents (highest fan-out).
- **Sync:** `fk.syncFromPostgres()` mirrors the Postgres edges into FalkorDB's
  `:Doc`/`:LINKS` graph before timing (Postgres is the source of truth).
- **Per seed:** run each traversal on both engines, assert result parity
  (order-insensitive doc-id sets; `related` compared as `{documentId, shared}`
  tuples), then time 20 iterations for p50/p95 latency on `neighbors` at
  depth 2. Exit non-zero if any parity check fails.

### Re-running

Both Postgres and FalkorDB must be reachable (compose-network only; `127.0.0.1`
will not connect). Run from the repo root:

```bash
NET=amf-stack_default
PW=$(docker compose -f deploy/docker-compose.yml exec -T amf-server sh -c 'echo "$AMF_CATALOG_DATABASE_URL"' | sed -E 's#.*://[^:]+:([^@]+)@.*#\1#')
docker run --rm --network "$NET" \
  -v "$PWD/src":/app/src -v "$PWD/scripts":/app/scripts -v "$PWD/node_modules":/app/node_modules -w /app \
  -e AMF_FALKOR_URL="redis://falkor:6379" \
  -e AMF_CATALOG_DATABASE_URL="postgresql://agent_memory_fabric:${PW}@postgres:5432/agent_memory_fabric" \
  agent-memory-fabric:0.6.0 node scripts/amf-benchmark-graph.mjs
```

## Results

Live corpus, 16,320 edges, single vault `work-wiki`, `neighbors` at depth 2,
5 highest-fan-out seeds. Exit code 0.

| seed | parity | Postgres p50/p95 (ms) | FalkorDB p50/p95 (ms) | faster (p50) |
|---|---|---|---|---|
| doc_457174b9… | PASS | 16.09 / 30.46 | 17.39 / 24.47 | Postgres |
| doc_68e571c5… | PASS | 11.63 / 12.35 | 9.13 / 10.84 | FalkorDB |
| doc_80c67246… | PASS | 11.16 / 11.51 | 8.36 / 8.94 | FalkorDB |
| doc_263917d2… | PASS | 4.59 / 5.18 | 5.52 / 9.47 | Postgres |
| doc_06e923b6… | PASS | 4.80 / 6.09 | 4.89 / 5.29 | Postgres |

### Correctness

**5/5 parity PASS.** Path A and Path B returned identical ACL-filtered doc-id
sets for every seed. No divergence on the live corpus. (One divergence class —
`related` shared-count inflation from duplicate raw-link rows — was found and
fixed during review so both engines now collapse duplicates identically; the
benchmark parity-checks `related` as tuples to guard it.)

### Latency

Mixed and close — no overall winner:

- **Postgres faster on 3 of 5 seeds** (the top-fan-out seed and the two
  lowest-fan-out seeds, where FalkorDB's per-call client round-trip dominates).
- **FalkorDB faster on 2 of 5 seeds** (the mid-tier high-fan-out seeds, up to
  ~27% lower p50).
- The highest-fan-out seed produces the worst p95 on both engines; Postgres's
  CTE has the single highest p95 in the run (30.46 ms), FalkorDB's is 24.47 ms.

At 16,320 edges, depth-2, single vault, differences are single-digit
milliseconds. FalkorDB's GraphBLAS advantage does not materialize at this scale.

### Reproduction — 2026-07-21

Re-ran the `Projects/agentBerry.md` seed (`doc_80c67246…`) against the live
corpus using the same method (5 warm-up calls, then 20 timed iterations for
p50/p95; `fk.syncFromPostgres()` paid once upfront), adding a depth-1 data point:

| depth | neighbors | parity | Postgres p50/p95 (ms) | FalkorDB p50/p95 (ms) | faster (p50) |
|---|---|---|---|---|---|
| 1 | 395 | PASS | 0.84 / 3.95 | 1.10 / 7.27 | Postgres |
| 2 | 1403 | PASS | 12.07 / 12.95 | 7.71 / 10.71 | FalkorDB |

The depth-2 result reproduces the original run for this seed (was 11.16 / 8.36;
now 12.07 / 7.71 — same ordering and magnitude). The new depth-1 point shows the
crossover direction: **Postgres wins the shallow, high-selectivity hop; FalkorDB
wins as hop count grows.** Consistent with the decision-10 reversal triggers.

**Measurement caveat (learned this run):** a single un-warmed call is not
comparable to these p50/p95 figures. A first cold Postgres call on this seed
measured ~28 ms (plan parse + cold buffer cache) versus a warm p50 of 0.84 ms,
and a single FalkorDB call right after sync measured ~3 ms against an
already-hot in-memory graph. Always warm up and report percentiles; do not quote
one-shot timings head-to-head.

## Conclusion

Building both engines and measuring confirmed the deferral recorded in
`docs/multi-agent-compose-stack.md` decision 10: **Postgres-first is correct at
this scale.** FalkorDB adds a second stateful container, a sync step, and a
per-edge ACL-provenance surface, in exchange for no measurable speedup. It stays
available (`AMF_LINK_GRAPH_ENGINE=falkor`) but is not the default.

Re-run this benchmark when a decision-10 reversal trigger approaches — corpus
past ~100k edges, hot 4+-hop queries as a real workload, or an automatic
entity-extraction layer — to see whether the crossover has arrived.

## Scope and caveats

- Only `neighbors` (depth 2) is timed for latency; `backlinks`, `related`,
  `shortestPath` are parity-checked but not latency-profiled.
- Single vault (`work-wiki`) — the per-hop vault ACL filter is exercised but not
  a multi-vault workload.
- No scale sweep: these numbers are for the live corpus size only, not a stress
  test at higher edge counts. A `--scale` crossover curve is a possible
  follow-up.
- `shortestPath` on Path A explores all paths to `maxDepth` before filtering, so
  it is expensive from very high-degree nodes at depth 3–4; the benchmark bounds
  it to depth 2. It is a diagnostic traversal, not on the `/v2/context/search`
  path.
