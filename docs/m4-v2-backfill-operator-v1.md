# M4 V2 Backfill Operator v1

The operator is an explicit, file-referenced wrapper around the M4 v2 runner.
Its `plan` command verifies private evidence and configuration without opening
Fabric, a lease, outbox, archive, or progress store. It returns one redacted
confirmation digest. `run` reloads every private input, recomputes that digest,
and constructs delayed resources only after an exact match.

The confirmation binds the runner plan, validated configuration, every private
reference, and selected archive and state resources. Individual paths, keys,
connection strings, checkpoints, and digests never appear in output.

The private delivery ring has one current key, one to 32 canonical 32-byte HMAC
keys for verification rotation, a canonical 32-byte archive cursor key, and a
retention period of 1 through 3,650 days. The current key signs projected and
outbox events; both current and retired keys remain available to the archive.

The operator is not a deployment, live-run authorization, cutover, retention,
or cleanup procedure.

The Fabric configuration supports system-trust PostgreSQL TLS modes. Custom CA
paths are intentionally rejected until they have a separately bound private
file contract.

Private JSON shapes are exact and all referenced paths are normalized absolute
paths: `operator/v1` has `gate` (four evidence/key paths), `fabricConfigPath`,
`deliveryKeyRingPath`, `archiveConfigPath`, `leasePath`, `outboxRoot`, and
`progressRoot`. `fabric/v1` has `rootPath` and `env`; it explicitly selects
`AMF_DATA_PATH`, `AMF_CATALOG_KIND`, `AMF_RAW_V2_CUTOVER`, RAW key source,
ingest ring, and either SQLite `AMF_CATALOG_PATH` or a PostgreSQL URL.
`delivery-key-ring/v1` has `currentKeyId`, `keys`, `cursorKey`, and
`retentionDays`. Archive config is exactly SQLite `{schema,kind,filename}` or
PostgreSQL `{schema,kind,connectionString}`.

Use `plan --config /absolute/private.json --max-events N`, then `run` with the
same flags and `--confirmed-plan-digest sha256:...`. Output is limited to
operation, run/phase, confirmation digest (plan), and counts/complete (run).
Files must be regular, owner-only (no group/other permissions; 0600 is the
normal mode and 0400 is also accepted), and free of symlink components.
The operator does not authorize a live run, deployment, cutover, cleanup, or
roadmap completion.
