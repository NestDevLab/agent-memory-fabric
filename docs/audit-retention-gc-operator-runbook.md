# Audit retention: operator runbook

Runs the Phase A audit retention delete from `docs/audit-retention-gc-v1.md` §4.2
with `scripts/amf-audit-retention-gc-operator.mjs`
(`npm run operator:audit-retention-gc --`). Read the design doc first for the why.
Partitioning and raw-event GC are deferred, so this CLI has only two subcommands:
`inventory` and `audit-phase-a`.

## What the CLI enforces, and what it doesn't

Enforced:

- **Target identity.** On connect the CLI reads `system_identifier` from
  `pg_control_system()`, `current_database()`, and `data_directory`, and prints
  them in every output (errors included). `--confirm-target` must equal
  `<system_identifier>/<database>` of the connected server. A hostname never
  counts.
- **Free space on the database server.** `--db-host-probe pct --proxmox-host
  <host> --ctid <id>` runs exactly two commands:

  ```sh
  ssh -o BatchMode=yes <host> pct exec <ctid> -- df -B1 --output=avail,size <data_directory>
  ssh -o BatchMode=yes <host> pct exec <ctid> -- su postgres -c "psql -XAt -c 'select system_identifier from pg_control_system()'"
  ```

  The second must return the connected `system_identifier`, otherwise the probe
  refuses. `<host>` accepts only hostname/IP characters and `<ctid>` only an
  integer; the CLI builds argument arrays and never a local shell string. The
  CLI host's own disk is never measured. Without a probe, `inventory` and the
  preview report free space as `unknown`; `--apply` refuses.

  Caveat: a physical replica shares the primary's `system_identifier`, and `df`
  on `data_directory` doesn't see a separate WAL mount. Before applying, confirm
  the probed container runs the primary (`select pg_is_in_recovery()` returns
  `f` there) and, if `pg_wal` is a separate filesystem, check its free space
  yourself.
- **Read-only previews.** `inventory` and `audit-phase-a` without `--apply` run
  in `READ ONLY` transactions, each query bounded by `--statement-timeout-ms`
  (default 300000). They scan the whole audit table, so run them off-peak.
- **Target table.** Only `agent_memory_fabric.audit_events_v2`; `--table` with
  any other value refuses.

Not enforced, recorded only: `--approval`, `--backup-id`, and
`--backup-verified-at` are **operator attestations**. The CLI checks their
shape and that the backup timestamp is recent (`--max-backup-age-hours`,
default 24); it cannot know whether the approval was given or whether the
backup exists and restores. A second person must check those records before
`--apply`.

**Operator log.** `--operator-log <path>` is required with `--apply`. Every record
is one JSON line, fsynced before the CLI moves on, all sharing the run's `runId`:

- `refused`: the attempt stopped before any delete (target identity,
  checkpoint, backup attestation, error).
- `start`: written before the first delete (target identity, checkpoint, backup
  attestation, options, first free-space probe).
- `batch`: one per committed batch (index, deleted counts by class, the probe
  taken after it).
- `end`: outcome `completed` or `stopped`, stop reason, totals.

If a write fails after a batch, the run stops and reports
`operator_log_write_failed`, never success. A run with `start` but no `end` was
interrupted: at most one committed batch after the last `batch` record is
unlogged, so reconcile with `inventory` before rerunning.

## Prerequisites

- The database role can read `pg_control_system()` and `data_directory`
  (superuser, or `pg_monitor` + `pg_read_all_settings`).
- SSH with key auth (`BatchMode=yes`) from the CLI host to the Proxmox node that
  runs the database container.
- A backup of `agent_memory_fabric`, restored on an isolated instance with
  matching `audit_events_v2` counts.
- Joseph's point-in-time approval for checkpoint `audit-bulk-delete`.

## Step 1: inventory (read-only)

```sh
npm run operator:audit-retention-gc -- inventory \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full \
  --db-host-probe pct --proxmox-host <proxmox-host> --ctid <ctid> --json
```

Check `target` is the server you mean, `table.unknownPairs` (unknown pairs are
kept forever; report new ones so the table can be extended),
`table.rowsByRetentionClass`, `phaseA.eligibleByClass`, and `freeSpace`.

## Step 2: preview

```sh
npm run operator:audit-retention-gc -- audit-phase-a \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full \
  --db-host-probe pct --proxmox-host <proxmox-host> --ctid <ctid> --json
```

Reports `eligibleByClass` and `eligibleTotal`; `long_retained` is always 0.

## Step 3: first apply, one small batch

Off-peak, delete a single small batch and measure before anything else:

```sh
npm run operator:audit-retention-gc -- audit-phase-a --apply \
  --approval audit-bulk-delete --i-know-this-is-live \
  --confirm-target <system_identifier>/agent_memory_fabric \
  --backup-id <backup-id> --backup-verified-at <iso8601> \
  --operator-log /var/log/amf/audit-retention-operator.jsonl \
  --db-host-probe pct --proxmox-host <proxmox-host> --ctid <ctid> \
  --batch-size 1000 --max-batches 1 \
  --free-space-floor-bytes 2000000000 --max-free-space-drop-bytes 268435456 \
  --database-url "$AMF_OPERATOR_DATABASE_URL" --ssl-mode verify-full --json
```

Then check, before any further run:

- the `batch` record's `deletedByClass` holds only the classes you expected;
- batch latency, and whether anything waited on locks (`pg_stat_activity`,
  `pg_locks`) or hit `lock_timeout`/`statement_timeout`;
- WAL and archive backlog (`pg_stat_archiver`, `pg_wal` size, replication lag);
- dead tuples on the table (`pg_stat_user_tables.n_dead_tup`);
- free space on the database data filesystem and on any separate WAL mount.

Stop on any failed probe, timeout, unexpected class, or shrinking headroom.

## Step 4: paced runs

Only while Step 3's measurements stay safe:

```sh
npm run operator:audit-retention-gc -- audit-phase-a --apply \
  <same guard, log, and probe flags as Step 3> \
  --batch-size 5000 --pause-ms 1000 --max-batches 20 \
  --free-space-floor-bytes 2000000000 --max-free-space-drop-bytes 268435456
```

Behavior:

- Free space is probed before the first batch and after every committed batch,
  the last one included. The run stops when it is below
  `--free-space-floor-bytes` or dropped by more than
  `--max-free-space-drop-bytes` since the previous probe (DELETE writes WAL
  before any space comes back).
- Each batch is one transaction with `--lock-timeout-ms` (default 5000) and
  `--statement-timeout-ms` (default 120000 for apply), deleting at most
  `--batch-size` of the oldest eligible rows; it rolls back if any deleted row
  disagrees with the classifier. `--pause-ms` sleeps between batches.
- Stops on the first error, at `--max-batches`, or when a batch deletes nothing
  (`stopReason: drained`).
- `--vacuum-every N` runs plain `VACUUM (ANALYZE)` on the audit table after every
  N batches (N at most `--max-batches`). Never `VACUUM FULL`. Without the flag,
  run it yourself from `psql` when load allows. VACUUM makes space reusable; it
  rarely returns it to the OS.

Re-measure between runs as in Step 3. The predicate re-selects whatever is still
eligible, so rerunning after a stop is safe; after draining, a rerun deletes
nothing.

## Rollback

Deleted rows have no in-place undo. Recovery is restoring the backup from the
prerequisites, then reconciling audit rows written since.
