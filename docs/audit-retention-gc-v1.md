# Audit retention and raw-event garbage collection v1

Status: design only; nothing in this document has been implemented, migrated, or
run against CT112. It defines the target for MGT-0322.

This tranche is orthogonal to `docs/identity-retention.md`. That document
governs `raw_retention_v2`, which is populated only for content submitted
through a curation proposal (`enqueueProposalWithRaw`, `src/fabric-store.mjs`)
and gates identity-scoped forget/revoke lifecycle. It does not cover ordinary
raw-event ingestion: `raw_retention_v2` rows are never created for the bulk of
`raw_events_v2`, so its GC-candidate machinery cannot be reused as-is for
session/event-level physical deletion. This document defines a parallel
mechanism for that.

## 1. Current state (verified against `src/fabric-store.mjs` and `src/server.mjs`)

- `audit_events_v2` (Postgres schema v7): `id, ts, actor_tag, action, outcome,
  request_id, target_id, scope_tag, details_json`, one btree index on `ts`. No
  partitioning, no FK targets it (safe to restructure).
- Every audit action name in the codebase (`grep -oE "action:\s*'[a-z_]+'"
  src/server.mjs`, plus the two dynamic `identity_${operation}` actions):

  `authenticate, context_search, curation_proposal_decrypt_intent,
  curation_proposal_list, curation_proposal_read, curation_receipt,
  curation_reconcile, document_read, documents_search, identity_create,
  identity_merge, identity_read, identity_split, memory_proposal_status,
  memory_propose, memory_read, memory_search, memory_status,
  raw_delivery_proof, raw_event_ingest, raw_extractor_session_read,
  raw_extractor_sessions_read, raw_extractor_transcript_read, retention_apply,
  retention_plan, session_get, session_transcript, sessions_search`

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
- "ingest/decrypt authorizations" and "ingest receipts" in the ledger map to
  `raw_event_ingest` (one row per `/v2/ingest/raw-events` call — success
  outcomes `stored`/`duplicate`/`recovered`) and `raw_delivery_proof`
  respectively. There is no separate high-volume decrypt action;
  `curation_proposal_decrypt_intent` is proposal-scoped and, at 253 total
  proposals, negligible by volume.
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
  - `disabled`: reader is `null` → the server falls back to
    `createUnconfiguredSessionReader()` (`server.mjs:1733`), a stub. Session
    reads would not function at all in this mode.
  - `shadow`: live reads are served by `legacyReader`
    (`fabricStore.createSessionReader()`, backed directly by
    `raw_events_v1`/`raw_events_v2`); the v3 `conversation_archive_events_v1`
    copy is only read asynchronously in the background for parity comparison
    (`conversation-session-runtime.mjs:206-225`). **This is almost certainly
    CT112's actual mode** — it is the only mode consistent with the ledger's
    observation that reads hit `raw_events_v2` directly while curation
    proposals exist independently.
  - `active`: live reads are served by `archiveReader`
    (`conversation_archive_events_v1`, the M4 v3 deterministic archive);
    `raw_events_v2` is no longer on the live read path.
  CT112's actual `AMF_CONVERSATION_READER_MODE` and
  `AMF_CONVERSATION_EXTRACTOR_MODE` must be confirmed live (§8, step 1) before
  any `raw_events_v2` row is treated as GC-eligible — this is the single
  highest-risk unverified assumption in this design.

## 2. Differentiated audit retention

### 2.1 Category assignment

Classification is a pure function of `(action, outcome)`, evaluated at audit
write time — never backfilled by scanning the existing 7.37M-row table (see
§4). Rule: an action already in the `long_retained` family keeps that
classification regardless of outcome (a denied `identity_merge` is still an
identity-lifecycle record worth a year). For every other action, `outcome IN
('denied', 'failed')` forces `security_review` (90 days) regardless of the
action's normal-outcome class, because a rejected authorization attempt is
itself the security-relevant event, independent of how routine the underlying
action is.

| Class | Window | Actions (successful-outcome default) |
|---|---|---|
| `ephemeral_status` | 1–3 days (default 2) | `memory_status` |
| `ephemeral_operational` | 7–14 days (default 10) | `context_search`, `document_read`, `documents_search`, `memory_proposal_status`, `memory_read`, `memory_search`, `raw_delivery_proof`, `raw_event_ingest`, `raw_extractor_session_read`, `raw_extractor_sessions_read`, `raw_extractor_transcript_read`, `session_get`, `session_transcript`, `sessions_search` |
| `security_review` | 90 days | any action above with `outcome IN ('denied','failed')`; `authenticate` (only ever audited on denial today) |
| `long_retained` | ≥ 1 year / external archive | `curation_proposal_decrypt_intent`, `curation_proposal_list`, `curation_proposal_read`, `curation_receipt`, `curation_reconcile`, `memory_propose`, `identity_create`, `identity_read`, `identity_merge`, `identity_split`, `retention_plan`, `retention_apply` — **any outcome** |

`long_retained` volume is bounded by curation/identity/retention call volume
(hundreds to low thousands, per the 253-proposal figure), not by ingest or
status-check volume, so a 1-year-plus window here costs negligible space.

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

Enforcement is partition-drop, not row `DELETE`, for the two ephemeral classes
and `security_review` — see §4. `long_retained` is never auto-pruned by this
design.

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
- Process restart/crash loses at most the current unflushed bucket (a few
  minutes of aggregate counts, never individual denials). Acceptable because
  §3's guarantee is specifically about denials/failures, not about
  success-count precision.
- **Never sampled, always written per-call, at full fidelity:** any
  `memory_status` call with a non-`allowed` outcome (`healthRequired()`
  throwing, permission denial), and every other action in the schema. This
  design touches `memory_status`/`outcome=allowed` only.
- Implementation surface: a small in-process `AuditSampler` wrapping the single
  `auditRequired(... action: 'memory_status', outcome: 'allowed' ...)` call
  site (`server.mjs:779` and its session-scoped twin near `server.mjs:1847`).
  No schema change is required for this item alone; the aggregated row uses
  the same `audit_events_v2` shape, `retention_class = 'ephemeral_status'`.

## 4. Space-reclaiming migration for `audit_events_v2`

### 4.1 Constraint

~4 GiB free on a 20 GiB filesystem, `audit_events_v2` alone at ~3 GB/7.37M
rows. `VACUUM FULL`, `pg_repack`, or any strategy that holds a full second copy
of the current table (~3 GB) is not safe against 4 GiB free with no other
margin for WAL, other tables' growth, or ingest continuing during the
operation. The strategy below never holds two full copies at once — it deletes
first, so the copy step that follows only ever moves the small survivor set.

### 4.2 Sequencing (delete-first, then partition)

**Phase A — bulk delete under the new policy, on the existing unpartitioned
table, before touching schema.** Classification is computed inline in the
`DELETE` predicate (a `CASE`/`IN`-list mirroring §2.1), never persisted onto
the 7.37M existing rows — an `UPDATE` to backfill a `retention_class` column
across the whole table would itself bloat the table further, working against
the goal.

```sql
-- one batch; repeat with a short pause between batches, off-peak, until 0 rows affected
WITH victims AS (
  SELECT id FROM agent_memory_fabric.audit_events_v2
  WHERE (
      (action = 'memory_status' AND outcome = 'allowed' AND ts < now() - interval '2 days')
   OR (action IN ('context_search','document_read','documents_search','memory_proposal_status',
                   'memory_read','memory_search','raw_delivery_proof','raw_event_ingest',
                   'raw_extractor_session_read','raw_extractor_sessions_read',
                   'raw_extractor_transcript_read','session_get','session_transcript','sessions_search')
       AND outcome NOT IN ('denied','failed') AND ts < now() - interval '10 days')
   OR (outcome IN ('denied','failed') AND action NOT IN (<long_retained actions>) AND ts < now() - interval '90 days')
   OR (action = 'authenticate' AND ts < now() - interval '90 days')
  )
  ORDER BY ts LIMIT 20000
)
DELETE FROM agent_memory_fabric.audit_events_v2 a USING victims WHERE a.id = victims.id;
```

Given the ledger's own numbers (6.65M of 7.37M rows already older than 7 days,
volume dominated by `memory_status`/ingest/receipts — all short-window
classes), Phase A is expected to remove the large majority of rows and bytes.
Run plain `VACUUM (ANALYZE) audit_events_v2` (non-`FULL`; brief lock, safe
under load) every few batches so freed space becomes reusable and Postgres can
truncate trailing empty pages back to the OS where the freed pages are
contiguous at the end of the file. Track `pg_total_relation_size`,
`pg_stat_user_tables.n_dead_tup`, and filesystem free space after every
handful of batches; stop and reassess if free space is not recovering as
expected. **Requires the Joseph approval checkpoint in §8 before it runs on
CT112** — this is the first deletion of any CT112 data.

**Phase B — measure, then decide whether partitioning is still needed.** Phase
A alone may relieve the immediate disk-pressure crisis (growth driver removed,
internal free space reclaimed for reuse) even before the file shrinks on disk.
Re-measure; if headroom is comfortably restored, partitioning becomes a
non-emergency follow-up rather than a second urgent operation.

**Phase C — partition, sized against the now-small survivor set.** Create a
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

**Phase D — cutover.** In one short transaction: catch up any rows inserted
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

## 5. Verifiable "session fully archived" proof

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

## 6. Idempotent physical GC

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

Follow the existing real-Postgres integration convention
(`scripts/test-postgres-catalog-integration.mjs`): gated on
`AMF_TEST_POSTGRES_URL` + `AMF_TEST_POSTGRES_ALLOW_MUTATION=true`, asserting
the database name matches `/test/i` before running, no mocks. Required cases:

- **Retention classification.** For every `(action, outcome)` pair in §2.1,
  assert the computed `retention_class` and confirm a row exactly at its
  boundary (`ts = now() - window`) and just inside/outside it is
  included/excluded correctly by the Phase-A delete predicate.
- **Reference integrity.** Seed a logical message with two aliased events, one
  past retention and one not: assert GC refuses to delete either (atomicity,
  §5.5). Seed two events sharing one `content_id` (dedup case, §5.6): assert
  the shared `raw_objects_v2` row survives until *both* referencing events are
  gone. Seed a `fabric_proposals` row in `status='promoted'` referencing a
  session's content: assert GC skips it, and that it proceeds once the status
  is `revoked`/`rejected`.
- **Replay/idempotency.** Run the same `raw_gc_operations_v1` idempotency tag
  twice; assert the second run performs zero additional deletes and returns
  the same counters. Run a batch, then re-run with a manually rewound cursor;
  assert re-verification (not a cached proof) is what prevents double
  deletion.
- **Crash recovery mid-GC.** Kill the test process (or roll back the batch
  transaction manually) after tombstone insert but before the `DELETE`
  commits; assert the next run either completes that batch cleanly or skips
  it without a partial/inconsistent state (no orphaned tombstone pointing at
  data that was never actually deleted, and no `raw_events_v2` row deleted
  without a corresponding tombstone).
- **Transcripts stay readable for retained sessions.** After a GC run against
  a fixture with a mix of expired/archived and fresh/unarchived sessions,
  assert `session_transcript`/`sessions_search` still return correct results
  for every session that was *not* GC'd, in both `shadow` and `active` reader
  modes, and that a session skipped for failing the archive proof (§5.2) is
  provably untouched (row counts unchanged).
- **Audit partitioning.** Exercise the Phase A→D migration end-to-end against
  a seeded table: row-count and digest parity between old and new table before
  cutover; confirm a partition becomes droppable only after every row's own
  category window has elapsed, not merely the partition's nominal date range.
- **`memory_status` sampling.** Assert a burst of N calls within one bucket
  produces exactly one aggregated audit row with `sampledCount = N`; assert a
  denied/failed call is never aggregated, even mid-burst.

## 8. Operational rollout plan for CT112

This is a live-system plan; none of it runs without the approval gate below.

1. **Inventory (read-only).** Confirm on CT112: Postgres major version
   (`DETACH ... CONCURRENTLY` needs PG14+); current `AMF_CONVERSATION_READER_MODE`
   and `AMF_CONVERSATION_EXTRACTOR_MODE`; exact `pg_total_relation_size` for
   `audit_events_v2` and `raw_events_v2`; exact filesystem free space; count of
   rows per §2.1 category to size Phase A's expected deletions; count of
   sessions likely to pass §5's archive proof today (probably near zero if
   mode is `shadow` with no verified parity yet — expect Phase A/audit work to
   land well before any `raw_events_v2` GC is possible).
2. **Backup with verified restore.** Full `pg_dump`/base-backup of
   `agent_memory_fabric` (or filesystem/volume snapshot, whichever CT112's
   existing backup path uses — confirm it before assuming) taken immediately
   before Phase A. **Verified** means: restore it to a separate, isolated
   instance and confirm row counts for `audit_events_v2` and `raw_events_v2`
   match the source pre-Phase-A counts, and that `session_transcript` works
   against the restored copy for a sample of sessions. A backup that has not
   been restore-tested does not satisfy this requirement.
3. **Temporary space estimate.** Recorded live at step 1, not assumed here:
   Phase A needs no extra space (it only deletes and periodically vacuums).
   Phase C's copy needs space equal to the post-Phase-A survivor set, measured
   before Phase C starts, with an explicit go/no-go against current free
   space (§4.2, Phase C). §5–6's GC needs no extra space (it only deletes,
   with tombstone rows that are tiny relative to what they remove).
4. **Rollback plan.** Phase A: none needed beyond the verified backup — deletes
   are the intended change once approved, and it is bulk `DELETE`, not a
   schema change. Phase D (audit table cutover): rename back
   (`audit_events_v2_legacy_<date>` → `audit_events_v2`), no data loss, until
   the legacy table is finally dropped 7–14 days later. §6's GC: no in-place
   undo of a physical `DELETE` — rollback means restoring from the step-2
   backup taken before that GC run; this is why every GC run must itself be
   preceded by a fresh verified backup, not just the one from step 2.
5. **Checkpoint — requires Joseph's point-in-time approval before running
   against live CT112 data.** This applies separately to: (a) Phase A's first
   bulk delete against `audit_events_v2`, (b) the Phase C/D audit table
   partitioning migration, and (c) the first `raw_gc_operations_v1` run against
   `raw_events_v2`/`raw_objects_v2` with `dry_run = false`. Each of these three
   is its own approval, not one blanket sign-off — they land at different
   times and (c) in particular depends on CT112's reader-mode reality (step 1)
   in a way that may not be resolved when (a) is ready to run. `dry_run = true`
   runs of §6 may be exercised for measurement without this gate, since they
   perform no writes; nothing else in this plan may run against CT112 without
   it, including inventory read-only commands only in the sense that those are
   pre-approved as read-only — no mutation step is implicitly authorized by an
   earlier one.
