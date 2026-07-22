# M4 v3 reconciliation source adapter v1

`scripts/amf-m4-reconciliation-collect.mjs` makes the M4 reconciliation collector executable for the native `v3` archive only. It accepts exactly `plan --config FILE` or `run --config FILE --confirmed-plan-digest DIGEST`.

The operator configuration remains an owner-only private JSON artifact and binds the digest of its source configuration into the plan. The source configuration is also an owner-only, absolute, regular JSON file. It has schema `amf.m4-v3-reconciliation-source-adapter/v1`, archive `v3`, and exactly one driver configuration:

- SQLite: `driver`, `databasePath`, and bounded `pageSize`. The database must be an owner-only, regular, non-symlink file no larger than 16 TiB inside an owner-only directory reached through safe traversal directories. The adapter pins both the database inode and its directory before opening it read-only, retains both descriptors until collection closes, and therefore applies the same trust boundary to SQLite WAL and SHM siblings.
- PostgreSQL: `driver`, credentials and endpoint fields, bounded `pageSize` and four bounded timeout fields, plus explicit `sslMode` (`disable`, `require`, or `verify-full`). `verify-full` additionally requires an owner-only CA file and is the authenticated TLS mode. `require` encrypts the connection but deliberately does not authenticate the certificate or hostname.

Planning does not open the database or make a network connection. Running uses the existing repeatable-read, read-only collector transaction and closes the database handle or pool once on every completion path. Errors are stable codes and the CLI emits no source paths, endpoints, credentials, connection strings, or CA contents.

This closes executable collection for `v3` only. `legacy-v2` is deliberately rejected by this adapter; its deployment adapter remains required.
