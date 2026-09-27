# Audit retention and raw-event garbage collection v1

Status: v1 implements audit retention only — the classification table (§2.1),
`memory_status` sampling (§3), and the Phase A bounded delete with a read-only
inventory (§4.2). Postgres schema stays at version 7, so deploy and rollback are
a plain image swap. Partitioning (§4.3) and raw-event GC (§5–§6) are
deferred (§0). Nothing here has run against CT112. Tracked as MGT-0322.

This tranche is orthogonal to `docs/identity-retention.md`. That document
governs `raw_retention_v2`, which is populated only for content submitted
through a curation proposal (`enqueueProposalWithRaw`, `src/fabric-store.mjs`)
and gates identity-scoped forget/revoke lifecycle. It does not cover ordinary
raw-event ingestion: `raw_retention_v2` rows are never created for the bulk of
`raw_events_v2`, so its GC-candidate machinery cannot be reused as-is for
session/event-level physical deletion. This document defines a parallel
mechanism for that.

## 0. Delivery scope and deferrals

Production measurement (read-only) before v1: AMF 0.6.0 on schema v7;
`AMF_CONVERSATION_READER_MODE` and `AMF_CONVERSATION_EXTRACTOR_MODE` unset, so the
reader mode is `disabled` and session reads use the legacy reader directly on
`raw_events_v2`. PostgreSQL 16. `audit_events_v2` holds 7.70M rows / 3.3 GB and now
grows ~16 MB/day; `memory_status` volume has collapsed. 38% of rows (2.94M) used
actions the original table did not know, because it was built from
`src/server.mjs` only; §2.1 now covers every action written anywhere in `src/`.

Deferred, with the independent review findings recorded in the management ledger
under MGT-0322:

- **Partitioning (§4.3).** Not needed at current growth, and the reviewed
  cutover could strand rows and break every audit INSERT. No v8 schema.
- **Raw-event GC (§5–§6).** Requires the M4 reader to be `active`; production is
  `disabled`, so no session can qualify. The reviewed engine also had data-loss
  paths (younger sibling sessions, shadow mode, uncommitted cursors).

§4.3, §5, and §6 are future design, not part of this release: nothing in them is
implemented and none of their steps may be run. The current procedure is
`docs/audit-retention-gc-operator-runbook.md`.

## 1. Current state (verified against `src/fabric-store.mjs` and `src/server.mjs`)

- `audit_events_v2` (Postgres schema v7): `id, ts, actor_tag, action, outcome,
  request_id, target_id, scope_tag, details_json`, one btree index on `ts`. No
  partitioning, no FK targets it (safe to restructure).
- Audit actions are written from `src/server.mjs`, `src/fabric-store.mjs`
  (ingest, decrypt intents, recovery, reconcile, curation receipts, document
  writes via the server) and the M4 operators (`raw_redacted_decrypt_intent`).
  The full list is the §2.1 table; `scripts/test-audit-retention.mjs` fails if a
  literal action in `src/` is missing from it.

- Audit writes are **fail-closed**: `auditRequired()` wraps `fabricStore.audit()`
  in `boundedDependency()` with a 2s default timeout
  (`AMF_AUDIT_TIMEOUT_MS`, `src/server.mjs:45`); if the audit write fails or
  times out, the request that triggered it fails too (`server.mjs:338-339`).
  Any volume-reduction design must not change this for actions that gate an
  authorization decision — see §2.
- `memory_status` is an MCP tool (`mcp__amf__memory_status` and its
  session-scoped variant) called with `outcome: 'allowed'` on every successful
  invocation, with no existing rate limit. It is the highest-frequency action
  in the schema by construction: every harness/session across the fleet that
  polls AMF health produces one row per call. This matches the ledger's
  "memory_status entries" volume driver.
- Every raw ingest writes two rows: `raw_ingest_decrypt_intent/authorized` and
  `raw_event_ingest/stored|duplicate` (2.49M each in production). Session reads
  add `raw_redacted_decrypt_intent`, `raw_decrypt_intent`, and
  `raw_session_search_decrypt_intent`.
- `raw_retention_v2` / `retention_tombstones_v2` / `applyRetention()`
  (`fabric-store.mjs:2512-2570`) already tombstone content and emit a
  `gcCandidate` boolean, but the only reference check performed is against
  `fabric_proposals` (`status NOT IN ('revoked','rejected')`). It never checks
  `raw_events_v2`, `logical_messages_v2`, `logical_message_aliases_v2`, or
  `raw_sessions_v1`. `physicalDeletionPerformed` is hardcoded `false`
  (`fabric-store.mjs:773, 1152, 2555`) and no deletion job consumes the
  tombstones. This is the gap §5 closes — for `raw_events_v2`, not by
  extending the existing content-level path, but with a new session/logical-
  message-scoped path, because the existing path was never wired to ordinary
  ingested events in the first place.
- Session reads (`session_get`, `session_transcript`, `sessions_search`, and
  their MCP equivalents) are served by `conversationSessionReader`, selected in
  `src/conversation-session-runtime.mjs` by `AMF_CONVERSATION_READER_MODE`
  (default `disabled`):
  - `disabled` (production today, §0): session reads use the legacy reader
    directly on `raw_events_v1`/`raw_events_v2`.
  - `shadow`: live reads are served by `legacyReader`
    (`fabricStore.createSessionReader()`); the v3 `conversation_archive_events_v1`
    copy is only read in the background for parity comparison.
  - `active`: live reads are served by `archiveReader`
    (`conversation_archive_events_v1`, the M4 v3 deterministic archive);
    `raw_events_v2` is no longer on the live read path.

## 2. Differentiated audit retention

### 2.1 Category assignment

Classification is a pure function of `(action, outcome)` defined once in
`AUDIT_RETENTION_TABLE` (`src/audit-retention.mjs`). Rules: decrypt intents are
`security_review`, except `curation_proposal_decrypt_intent`; curation, identity,
retention, reconcile, recovery, and document writes are `long_retained` on every
outcome; `denied`/`failed` of any other action is `security_review`. **Any pair
not in the table is `long_retained`** and is never deleted; classification never
throws on a production path (`classifyAuditEventStrict` exists for tests).

| Class | Window | `action` / `outcome` |
|---|---|---|
| `ephemeral_status` | 1–3 days (default 2) | `memory_status/allowed` |
| `ephemeral_operational` | 7–14 days (default 10) | `/allowed` of `context_search`, `document_read`, `documents_search`, `memory_proposal_status`, `memory_read`, `memory_search`, `raw_extractor_session_read`, `raw_extractor_sessions_read`, `raw_extractor_transcript_read`, `session_get`, `session_transcript`, `sessions_search`; `raw_event_ingest/stored\|duplicate`; `raw_delivery_proof/verified` |
| `security_review` | 90 days | `raw_ingest_decrypt_intent`, `raw_redacted_decrypt_intent`, `raw_decrypt_intent`, `raw_session_search_decrypt_intent` (`authorized`, `denied`, `failed`); `authenticate/denied\|failed`; `denied`/`failed` of every action in the two rows above |
| `long_retained` | kept | every outcome of `curation_proposal_decrypt_intent`, `curation_proposal_list`, `curation_proposal_read`, `curation_receipt`, `curation_reconcile`, `curation_decision_receipt`, `curation_apply_receipt`, `memory_propose`, `identity_create`, `identity_read`, `identity_merge`, `identity_split`, `retention_plan`, `retention_apply`, `raw_reconcile`, `raw_event_recovery`, `document_upsert`, `document_delete`; every unknown pair |

Decided from code semantics (the owner rules did not name them), taking the
longer window when in doubt: `raw_event_recovery` (rewrites an event's content
reference and may retire an object: an administrative repair) and
`document_upsert` (a durable vault write, the counterpart of `document_delete`)
are `long_retained`; `raw_event_ingest` and `raw_delivery_proof` keep their
operational class because the paired decrypt intent already carries the
security record for 90 days.

### 2.2 Configuration shape

Extend the existing scope-override pattern from `identity-retention.mjs`
(`policy.scopeDays`) with a parallel, explicit, non-inferred audit policy:

```json
{
  "auditRetention": {
    "ephemeral_status": { "days": 2 },
    "ephemeral_operational": { "days": 10 },
    "security_review": { "days": 90 },
    "long_retained": { "days": null, "externalArchive": false }
  }
}
```

`days: null` with `externalArchive: false` means "keep indefinitely in
Postgres" (the default, matching current behavior for this class). Setting
`externalArchive: true` is a documented extension point (ship export-then-drop
tooling later); it is out of scope to implement here.

### 2.3 Enforcement

v1 enforces with the operator-run Phase A bounded row `DELETE` (§4.2).
Partition-drop is deferred (§0). `long_retained` is never pruned.

## 3. Reducing `memory_status` audit volume

The fail-closed contract (§1) must be preserved for every action that gates an
authorization or write decision. `memory_status` gates nothing — it is a
read-only health probe — so it is the only action safe to sample without
touching the fail-closed guarantee. Nothing else in the action list qualifies
for sampling under this rule; do not extend it.

Design: replace "one row per call" with "one row per (actor_tag, outcome,
time-bucket)", using a bounded in-process counter flushed on a fixed interval,
not a per-request DB write:

- Each `memory_status` call still increments an in-memory counter keyed by
  `(actorTag, outcomeClass)` for the current bucket (default bucket width: 5
  minutes) and still returns its result to the caller synchronously —
  **the response and the fail-closed `healthRequired()` check are unaffected**;
  only the audit *write* is deferred/aggregated.
- A timer flushes each bucket once, on rollover, as a single upserted audit row
  with `outcome: 'allowed'` and `details: { sampledCount: N, windowStart,
  windowEnd }`. This turns up to one row per `memory_status` call into at most
  one row per actor per 5-minute window — a >100x reduction at the fleet
  concurrency implied by CT112's volume, without losing per-actor,
  per-window observability.
- A bucket is removed only after its row is written. A failed write is logged
  (`memory_status_audit_sample_flush_failed`) and retried on the next flush, so
  delivery is at-least-once: a write that times out but later commits can be
  counted twice. Pending buckets are capped (10,000); overflow drops the oldest
  and logs it.
- On `server.close()` the sampler flushes and is awaited before the fabric store
  closes. **Bounded loss:** a crash or a kill without `server.close()` loses the
  buckets still in memory — at most one window per actor plus any buckets whose
  writes were still failing. Counts of successful status calls only; no denial
  is ever sampled.
- Only `memory_status/allowed` is sampled. Every other action keeps its
  per-call fail-closed write. Failed `memory_status` calls are not audited today;
  if that is added, it must go through `auditRequired`, not the sampler.
- Implementation surface: a small in-process `AuditSampler` wrapping the single
  `auditRequired(... action: 'memory_status', outcome: 'allowed' ...)` call
  site (`server.mjs:779` and its session-scoped twin near `server.mjs:1847`).
  No schema change: the aggregated row uses the existing `audit_events_v2`
  shape with `details.sampledCount/windowStart/windowEnd`.

## 4. Space-reclaiming migration for `audit_events_v2`

### 4.1 Constraint

~4 GiB free on a 20 GiB filesystem, `audit_events_v2` alone at ~3 GB/7.37M
rows. `VACUUM FULL`, `pg_repack`, or any strategy that holds a full second copy
of the current table (~3 GB) is not safe against 4 GiB free with no other
margin for WAL, other tables' growth, or ingest continuing during the
operation. The strategy below never holds two full copies at once — it deletes
first, so the copy step that follows only ever moves the small survivor set.

### 4.2 Phase A and B (this release)

**Phase A — bounded delete under the new policy, on the existing table.**
The predicate is generated from `AUDIT_RETENTION_TABLE` (`buildPhaseAPredicate`):
one clause per deletable class, each an explicit `(action, outcome) IN (...)`
list plus `ts < cutoff`, where the cutoff is `asOf` minus the window in fixed
milliseconds (the same arithmetic as `isAuditRetentionExpired`, so DST cannot
move a boundary). Unknown and `long_retained` pairs are never in any list.

```sql
WITH victims AS (
  SELECT id FROM "agent_memory_fabric"."audit_events_v2"
  WHERE ((action, outcome) IN (('memory_status','allowed')) AND ts < $2)
     OR ((action, outcome) IN (('context_search','allowed'), ...) AND ts < $3)
     OR ((action, outcome) IN (('authenticate','denied'), ...) AND ts < $4)
  ORDER BY ts LIMIT $1
)
DELETE FROM "agent_memory_fabric"."audit_events_v2" a USING victims
WHERE a.id = victims.id RETURNING a.action, a.outcome, a.ts;
```

Each batch runs in its own transaction with `lock_timeout` and
`statement_timeout`; every returned row is re-classified and the batch rolls
back if any row is `long_retained` or not expired. `previewPhaseA` and
`countAuditRowsByPair` (inventory, including unknown pairs) run in `READ ONLY`
transactions. Only `audit_events_v2` is accepted as the target table.

DELETE leaves dead tuples; plain `VACUUM` (never `FULL`) makes pages reusable
but returns space to the OS only for trailing pages, and DELETE generates WAL.
The operator therefore runs small batches with pauses, re-measures free space on
the database server's data filesystem, and stops on any decline beyond its
threshold (runbook). **Requires the approval checkpoint in §8 before it runs on
CT112.**

**Phase B — measure, then decide whether partitioning is still needed.** Phase
A alone may relieve the immediate disk-pressure crisis (growth driver removed,
internal free space reclaimed for reuse) even before the file shrinks on disk.
Re-measure; if headroom is comfortably restored, partitioning becomes a
non-emergency follow-up rather than a second urgent operation.

### 4.3 Future design, not in this release: partitioning (Phases C/D)

Not implemented and not runnable; kept to record the design (§0).

**Phase C.** Create a
new table, `LIST`-partitioned on a stored `retention_class` column, with the
`ephemeral` branch further `RANGE`-partitioned by `ts` (weekly granularity —
tighter than monthly, which matters because a partition can only be dropped
once *every* row in it is past *its own* category's window; weekly caps that
lag at ~21 days instead of monthly's ~44):

```sql
CREATE TABLE agent_memory_fabric.audit_events_v2_next (
  id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  actor_tag TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  request_id TEXT,
  target_id TEXT,
  scope_tag TEXT,
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  retention_class TEXT NOT NULL CHECK (retention_class IN
    ('ephemeral_status','ephemeral_operational','security_review','long_retained')),
  PRIMARY KEY (retention_class, ts, id)   -- partition key columns required in the PK pre-PG17
) PARTITION BY LIST (retention_class);

CREATE TABLE audit_events_v2_long_retained PARTITION OF audit_events_v2_next
  FOR VALUES IN ('long_retained');

CREATE TABLE audit_events_v2_ephemeral PARTITION OF audit_events_v2_next
  FOR VALUES IN ('ephemeral_status','ephemeral_operational')
  PARTITION BY RANGE (ts);            -- weekly child partitions, pre-created on a rolling basis

CREATE TABLE audit_events_v2_security_review PARTITION OF audit_events_v2_next
  FOR VALUES IN ('security_review')
  PARTITION BY RANGE (ts);            -- monthly child partitions (low volume, lag less important)
```

Copy survivors from the old table in `ts`-ordered batches (resumable via a
`ts` high-water-mark cursor — see §5's `raw_gc_operations_v1` for the same
pattern applied to a different table), computing `retention_class` per §2.1's
rule in the `SELECT`. Verify row-count and a per-batch digest match between
old and new before proceeding. Because Phase A already reduced the survivor
set to a small fraction of the original 3 GB, this copy's peak transient space
is small — confirm the exact figure live against current free space
immediately before running (explicit go/no-go gate, not an assumption).

**Phase D.** In one short transaction: catch up any rows inserted
during the copy window (same `ts` cursor), `ALTER TABLE audit_events_v2 RENAME
TO audit_events_v2_legacy_<date>`, `ALTER TABLE audit_events_v2_next RENAME TO
audit_events_v2`, bump `POSTGRES_SCHEMA_VERSION` and add the migration to
`POSTGRES_SCHEMA_SQL` (idempotent, following the existing `CREATE TABLE IF NOT
EXISTS` / `ADD COLUMN IF NOT EXISTS` style at `fabric-store.mjs:1380-1550`).
Update the application `insertAudit` call sites to populate `retention_class`
at write time (implementation work, not part of this design). Keep
`audit_events_v2_legacy_<date>` renamed-but-present for 7–14 days as an instant
rollback path (`RENAME` back), then `DROP TABLE` it — by then it holds only
already-small survivor rows, so the final drop reclaims little but closes the
loop cleanly.

**Steady state.** A scheduled job pre-creates upcoming weekly/monthly
partitions and, for each existing partition whose upper `ts` bound plus its
category's max window has fully elapsed, runs `ALTER TABLE ... DETACH
PARTITION ... CONCURRENTLY` (PG14+; verify CT112's version in §8 — use a plain
`DETACH` + `DROP` inside a short maintenance window if older) then `DROP
TABLE`. This replaces per-row `DELETE` entirely for `ephemeral_*` and
`security_review` going forward: partition drop is near-instant and returns
space to the OS immediately, no `VACUUM` required.

`long_retained` is not partitioned by time and is never auto-dropped by this
job.

## 5. Future design, not in this release: verifiable "session fully archived" proof

Not implemented and not runnable (§0); requires reader mode `active`.

"Archived," for GC-eligibility purposes, is **not** the same thing as
"curated" or "promoted." Only 31 of 253 proposals are promoted; the vast
majority of raw content will never be curated, and treating curation as a
GC precondition would make physical GC nearly a no-op. Archival instead means:
this session's raw events are durably and completely mirrored into the M4 v3
deterministic conversation archive (`conversation_archive_events_v1`) *and*
that archive is provably the one serving live reads for this session — not a
side copy nobody reads from yet.

A session is **archived** iff all of the following hold, checked live at GC
time (a cached proof is an optimization, never a substitute for the live
check):

1. **Coverage.** Every `raw_events_v2` row for the session has a matching row
   in `conversation_archive_events_v1`, keyed via the already-implemented
   `deriveM4V3ConversationIdFromLegacySessionId` /
   `deriveM4V3EventIdFromLegacyEventId` mapping
   (`conversation-session-runtime.mjs:103-104`). Row counts must match
   exactly; a partial copy is not archived.
2. **Read-path authority.** `AMF_CONVERSATION_READER_MODE = 'active'` for the
   deployment (live reads already come from the v3 archive, not
   `raw_events_v2`), **or**, if still in `shadow` mode, the runtime's shadow
   comparison for this session's operations (`get`/`transcript`/`search`) has
   run since the coverage check and reports zero `mismatched`,
   `inconclusive`, and `unavailable` counts. In `shadow` mode, live reads are
   still legacy-backed (§1) — archival coverage existing is not sufficient by
   itself; deleting `raw_events_v2` rows while in `shadow` mode with an
   unproven or stale comparison would silently break live reads even though a
   v3 copy exists. This condition is the direct fix for the risk the ledger
   flagged generically as "breaking references."
3. **Retention elapsed.** The session's events are past the applicable
   retention deadline, computed with the existing pure function
   `retentionDeadline(originalTimestamp, scope, policy)`
   (`identity-retention.mjs:88-97`) against `raw_sessions_v1.first_occurred_at`
   (or the session's `lastOccurredAt`, whichever policy chooses to anchor on —
   pick one and hold it fixed) — default 3 years, scope override honored. No
   new persisted deadline column is required; this is computed at GC time.
4. **No live curation reference.** For every distinct `content_id` used by the
   session's events, no `fabric_proposals` row exists with `status NOT IN
   ('revoked','rejected')` — reusing exactly the check already implemented in
   `applyRetention()` (`fabric-store.mjs:2549-2552`), extended to enumerate
   content ids from `raw_events_v2` rather than only from `raw_retention_v2`.
5. **Logical-message atomicity.** GC never removes one observation out of a
   still-live logical message. The GC unit is the full logical message: all of
   `logical_messages_v2.event_ids` and every row in
   `logical_message_aliases_v2` pointing at it. If any event in that set fails
   conditions 1–4, the whole logical message is retained. This guarantees
   `logical_messages_v2.preferred_observation_id` never dangles.
6. **No shared-content survivors elsewhere.** `raw_objects_v2` rows (and their
   `storage_ref` blobs) are only physically deleted once zero rows in
   `raw_events_v2` reference that `content_id` **anywhere** in the system, not
   just within the session being processed — `raw_objects_v2` is
   content-addressed and a payload can in principle be shared across events.

`session_get` / `session_transcript` / `sessions_search` keep working for
anything not yet GC'd because condition 2 is exactly "the read path this
session is served from is not the one being deleted from" — either the read
path has already moved to the archive (`active`), or GC refuses to run for
that session at all (`shadow`/`disabled` with unproven parity).

## 6. Future design, not in this release: idempotent physical GC

Not implemented and not runnable (§0); none of the tables below exist.

New, small, purpose-built tables (naming follows the existing `*_v1`/`*_v2`
convention; none of this reuses or mutates `raw_retention_v2`):

```sql
CREATE TABLE agent_memory_fabric.session_archive_proof_v1 (
  session_id TEXT PRIMARY KEY,
  v3_conversation_id TEXT NOT NULL,
  source_event_count BIGINT NOT NULL,
  archived_event_count BIGINT NOT NULL,
  reader_mode_at_verification TEXT NOT NULL,
  shadow_mismatch_count BIGINT,           -- null when reader_mode='active'
  verified_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE agent_memory_fabric.raw_gc_tombstones_v1 (
  id TEXT PRIMARY KEY,
  unit_type TEXT NOT NULL CHECK (unit_type IN ('logical_message','content_object')),
  unit_id TEXT NOT NULL,               -- logical_message_id, or content_id for the content pass
  session_id TEXT,
  content_ids_json JSONB NOT NULL,
  reason_code TEXT NOT NULL CHECK (reason_code IN ('retention_expired','revoked','forgotten')),
  archive_proof_ref TEXT,              -- session_archive_proof_v1.session_id, when applicable
  expired_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_memory_fabric.raw_gc_operations_v1 (
  id TEXT PRIMARY KEY,
  idempotency_tag TEXT NOT NULL UNIQUE,
  dry_run BOOLEAN NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running','completed','aborted')),
  cursor_state_json JSONB NOT NULL,    -- {"lastSessionId": ..., "lastLogicalMessageId": ...}
  batches_processed BIGINT NOT NULL DEFAULT 0,
  logical_messages_deleted BIGINT NOT NULL DEFAULT 0,
  content_objects_deleted BIGINT NOT NULL DEFAULT 0,
  bytes_reclaimed_estimate BIGINT NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ
);
```

**Algorithm**, run as a scheduled job, bounded per invocation:

1. Resume from `raw_gc_operations_v1` if a non-`completed` row exists for this
   job's `idempotency_tag`; otherwise start a new operation row (`status =
   'running'`) from the last completed run's cursor.
2. For a bounded batch of sessions past their retention deadline (§5.3), in
   `raw_sessions_v1.session_id` order from the cursor: verify or refresh
   `session_archive_proof_v1` (§5, conditions 1–2); if verification fails,
   skip the session, advance the cursor past it, and record a metric — do not
   retry it forever inside the same run.
3. For each archived session, per-logical-message: within one transaction,
   re-check conditions 4–6 immediately before deleting (references are
   re-proven at delete time, not trusted from a stale proof — same discipline
   `applyRetention()` already uses), insert a `raw_gc_tombstones_v1` row, then
   `DELETE` the logical message's `raw_events_v2` rows and
   `logical_message_aliases_v2` rows, then delete any `raw_objects_v2` row
   (and issue the blob-storage delete for its `storage_ref`) whose `content_id`
   now has zero referencing `raw_events_v2` rows anywhere. Decrement
   `raw_sessions_v1.event_count`; if it reaches zero, mark the session
   fully GC'd (a `gc_completed_at` column, not a row delete — session metadata
   for audit/search-negative-result purposes is cheap to keep).
   **In `dry_run` mode, run every read/verification step and log what would be
   deleted, skip every `DELETE`/blob-delete, still advance the cursor and
   metrics.**
4. Commit the batch's transaction; update `raw_gc_operations_v1` counters and
   cursor. A crash between batches loses at most the in-flight batch (rolled
   back by Postgres) — the next run resumes from the last *committed* cursor
   and re-derives eligibility from scratch, so replay is safe by construction,
   not by special-cased crash-recovery logic.
5. Safety thresholds, checked before each batch: refuse to start (or abort a
   running operation) if fewer than N sessions in the batch pass verification
   (signals a systemic proof failure, not normal skew), if
   `bytes_reclaimed_estimate` for the run exceeds a configured ceiling (guards
   a runaway/misconfigured run), or if live filesystem free space drops below
   a configured floor mid-run.
6. Metrics emitted per run: sessions scanned/skipped/GC'd, logical messages
   and content objects deleted, bytes reclaimed (estimated from
   `raw_objects_v2.byte_length` before delete), tombstones written, proof
   failures by reason. `physicalDeletionPerformed` becomes accurate again:
   `retention/apply`'s response can report `true` once this job is the one
   consuming its tombstones for a given content id — or, more precisely, this
   job supersedes `physicalDeletionPerformed: false` for the `raw_events_v2`
   path specifically; `retention/apply`'s own content-level path (§1) is
   unchanged by this design.
7. **Rollback path:** `raw_gc_tombstones_v1` retains enough (`content_ids_json`,
   `session_id`, `reason_code`, `archive_proof_ref`) to identify exactly what
   was removed and why. Actual data rollback is "restore from the
   pre-migration/pre-GC verified backup" (§8) — there is no live undo of a
   physical `DELETE`; the tombstone table's job is auditability and matching
   against a restore, not in-place undelete.

## 7. Test plan

- `scripts/test-audit-retention.mjs`: owner-fixed pairs, a scan of `src/` for
  literal audit actions missing from the table, unknown pairs → `long_retained`,
  the generated predicate lists exactly the deletable pairs, boundary arithmetic,
  and sampler retry/serialization/close behavior.
- `scripts/test-postgres-audit-retention-integration.mjs` (real PostgreSQL, gated
  on `AMF_TEST_POSTGRES_URL` + `AMF_TEST_POSTGRES_ALLOW_MUTATION=true` and a
  `/test/i` database name): every table pair at cutoff −1 ms, at the cutoff, and
  +1 ms for each window, plus unknown pairs (including `memory_status` with a
  non-`allowed` outcome); asserts the SQL predicate, preview, and bounded delete
  select exactly what the classifier says, and that preview/inventory leave every
  table in the schema unchanged.
- `scripts/test-fabric-server.mjs`: sampled `memory_status` is written before
  the fabric store closes on shutdown.

## 8. Operational rollout plan for CT112

This is a live-system plan; no step mutates CT112 without the checkpoint in
step 4. The operator procedure is `docs/audit-retention-gc-operator-runbook.md`.

1. **Deploy.** The image carries the classifier and sampler only; schema stays
   v7, so rollback is the previous image.
2. **Inventory (read-only).** Row counts per `(action, outcome)` and class,
   unknown pairs, Phase A eligibility per class, table size, database identity,
   and free space on the database server's data filesystem.
3. **Backup with verified restore** of `agent_memory_fabric`, restored on an
   isolated instance with matching `audit_events_v2` counts. The CLI records the
   backup id as an operator attestation; it cannot verify it.
4. **Checkpoint — Joseph's point-in-time approval** for Phase A's first bulk
   delete against `audit_events_v2`. Partitioning and raw GC are deferred (§0)
   and would each need their own approval.
5. **Phase A** in small batches with pauses, off-peak, stopping on any error or
   free-space decline (§4.2). Rollback is restore from step 3; deleted rows have
   no in-place undo.
