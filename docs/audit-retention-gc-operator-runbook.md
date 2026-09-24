# Audit retention and raw-event GC: operator runbook

Drives `docs/audit-retention-gc-v1.md` against a live database from
`scripts/amf-audit-retention-gc-operator.mjs` (`npm run operator:audit-retention-gc --`).
Read the design doc first for *why*; this doc is the *how*, for CT112.

Every mutating subcommand is dry-run unless you pass `--apply`. `--apply`
additionally requires, together, every time:

- `--approval <checkpoint-id>` — one of `audit-bulk-delete`,
  `audit-partition-migration`, `raw-gc-live`, matching the subcommand.
  Approvals are per checkpoint, per design §8.5; a wrong or missing one
  refuses before anything runs.
- `--i-know-this-is-live`
- `--confirm-target <host:port/dbname>` — must equal the database the
  `--database-url` actually resolves to. This is the accidental-target guard:
  it is independent of the test-database name check the integration tests
  use, so a typo'd `--database-url` refuses instead of silently running.
- `--backup-id <id> --backup-verified-at <ISO8601>` (all subcommands except
  `audit-rollback`, which is itself the recovery path) — refused if older
  than `--max-backup-age-hours` (default 24).

A free-space floor check (`--free-space-floor-bytes`, default 2 GB, checked
against `--filesystem-path`, default cwd) runs before every apply; Phase C
copy also adds a live estimate of the temporary space it needs.

## Prerequisites

- A verified backup: taken, then **restored to a separate instance** and
  checked (row counts for `audit_events_v2`/`raw_events_v2` match, a sample
  `session_transcript` works). An unverified backup does not satisfy
  `--backup-verified-at`.
- `psql`/network access from wherever you run this to CT112's Postgres.
- Run this from the AMF checkout on CT112 (or wherever it can read the same
  `AMF_CONVERSATION_READER_MODE`/`AMF_CONVERSATION_EXTRACTOR_MODE`/fabric
  configuration the live server uses), so `raw-gc` builds the real
  conversation-session runtime, not the null fallback.
- Joseph's point-in-time approval for the specific checkpoint you are about
  to run (design §8.5). Get it before you compute `--confirm-target`, not
  after.

## Step 1 — Inventory (read-only, no approval needed)

```sh
npm run operator:audit-retention-gc -- inventory \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full \
  --filesystem-path /var/lib/postgresql --json
```

Confirm before anything else:

- `postgresMajorVersion` ≥ 14 (needed for `DETACH ... CONCURRENTLY` later).
- `tables.audit_events_v2.totalBytes` and `.raw_events_v2.totalBytes` against
  `filesystem.freeBytes`.
- `wouldDeleteByRetentionClass` sizes Phase A's expected impact.
- `conversationReaderMode` / `conversationExtractorMode` — the single
  highest-risk unverified assumption per design §1. If this is not `shadow`
  or `active`, `raw-gc --apply` will refuse later; that is expected, not a
  bug to work around.

`inventory` never writes and needs none of the mutation flags.

## Step 2 — Phase A: bulk delete (checkpoint `audit-bulk-delete`)

Dry-run first (no `--apply`): reports `wouldDeleteByRetentionClass` and the
next batch's `wouldDeleteTotal`, writes nothing.

```sh
npm run operator:audit-retention-gc -- audit-phase-a \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

Once Joseph approves checkpoint **(a)**, run batches with `--apply`. Each
invocation is one bounded batch (`--batch-size`, default 20000); call it
repeatedly — it is naturally resumable, since the predicate re-selects
whatever is still eligible rather than tracking a cursor:

```sh
npm run operator:audit-retention-gc -- audit-phase-a --apply \
  --approval audit-bulk-delete --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

Stop when `deletedCount` is `0`. Run `VACUUM (ANALYZE) audit_events_v2` and
re-check `inventory`'s filesystem free space every few batches (design §4.2);
this CLI does not run `VACUUM` for you between batches by design — do it from
`psql` so you control the pacing against live load.

Re-running Step 2 after it drains is safe and reports `deletedCount: 0` (idempotent).

## Step 3 — Phase B: re-measure

Re-run `inventory`. If free space is comfortably restored, Phase C/D can wait
as a non-emergency follow-up (design §4.2 Phase B). If not, continue.

## Step 4 — Phase C/D: partition migration (checkpoint `audit-partition-migration`)

Same checkpoint id covers schema, copy, and cutover — this is approval
**(b)**, one sign-off for the whole partitioning migration, not three.

**4a. Schema** (idempotent, `IF NOT EXISTS` throughout):

```sh
npm run operator:audit-retention-gc -- audit-phase-c-schema --apply \
  --approval audit-partition-migration --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full
```

**4b. Copy**, resumable via `--cursor-file` (survives a restart between
invocations; `copyAuditEventsBatch`'s own `ON CONFLICT DO NOTHING` also makes
it idempotent even if that file were lost). Free space is checked against a
live `pg_total_relation_size` estimate of the source table, not assumed:

```sh
npm run operator:audit-retention-gc -- audit-phase-c-copy --apply \
  --approval audit-partition-migration --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --cursor-file /var/lib/amf/audit-phase-c-cursor.json \
  --batch-size 5000 --max-batches 50 \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

Repeat until the result's `drained: true`.

**4c. Cutover** — one short transaction, catches up any rows inserted during
the copy window, then renames tables:

```sh
npm run operator:audit-retention-gc -- audit-phase-d --apply \
  --approval audit-partition-migration --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full
```

Keep `audit_events_v2_legacy_<suffix>` for 7-14 days (design §4.2 Phase D),
then `DROP TABLE` it by hand once satisfied — this CLI never drops it for you.

**Rollback**, while the legacy table is still retained. No backup attestation
is required here on purpose: this command *is* the emergency recovery, and
demanding a fresh backup of an already-broken state would only slow it down.
Still requires the same checkpoint, live confirmation, and target match:

```sh
npm run operator:audit-retention-gc -- audit-rollback --apply \
  --approval audit-partition-migration --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --legacy-table agent_memory_fabric.audit_events_v2_legacy_20261001 \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full
```

## Step 5 — raw-event GC (checkpoint `raw-gc-live` only for `--apply`)

`dry_run` needs no approval or backup (design §8.5 explicitly exempts
measurement-only runs); `--apply` needs approval **(c)**, which depends on
`conversationReaderMode` from Step 1 and may not be ready when (a)/(b) are.

Before `--apply`, the CLI itself refuses if `AMF_CONVERSATION_READER_MODE` in
its own environment is not `shadow` or `active` (`raw_gc_reader_mode_disabled`)
— this is in addition to, never a replacement for, the per-session archive
proof `RawGcEngine` re-checks for every session (design §5). Neither this
CLI check nor the engine's own gate can be bypassed by a flag.

```sh
# measurement only, no writes, no approval needed — use its own throwaway tag,
# never the tag you intend to apply with (RawGcEngine binds dry_run to the tag)
npm run operator:audit-retention-gc -- raw-gc \
  --idempotency-tag raw-gc-2026-10-preview \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

```sh
npm run operator:audit-retention-gc -- raw-gc --apply \
  --approval raw-gc-live --i-know-this-is-live \
  --confirm-target ct112-host:5432/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --idempotency-tag raw-gc-2026-10 --max-runs 20 \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

Each `--max-runs` unit is one bounded, transactional batch of
`raw_gc_operations_v1` (session batch size `--session-batch-size`, default
50). Re-running with the same `--idempotency-tag` resumes from its persisted
cursor and is idempotent — a drained backlog reports zero additional deletes.
Print and check each run's `counters` between invocations; the engine itself
stops on its own safety thresholds
(`raw_gc_verification_floor_breached`, `raw_gc_bytes_ceiling_breached`,
`raw_gc_free_space_floor_breached`) without operator intervention.

**Rollback**: there is no in-place undelete for physical `DELETE` (design §8
step 4). Recovery means restoring from the verified backup taken immediately
before that specific GC run — which is exactly why `--backup-verified-at`'s
freshness window matters here more than anywhere else in this runbook.

## Checkpoint summary

| Checkpoint id | Covers | Backup required |
|---|---|---|
| `audit-bulk-delete` | Phase A bulk delete | yes |
| `audit-partition-migration` | Phase C schema, Phase C copy, Phase D cutover, and its rollback | yes (not for rollback) |
| `raw-gc-live` | `raw-gc --apply` | yes |

Each is Joseph's separate point-in-time sign-off. None is implied by another,
and none is implied by a prior read-only `inventory` run.
