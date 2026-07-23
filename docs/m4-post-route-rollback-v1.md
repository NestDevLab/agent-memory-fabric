# M4 post-route rollback v1

This owner-private operator restores the exact R1 pre-route configuration only
when a verified active R1 result is bound to a verified failed R2 observation.
It verifies the original private backup and canonical metadata, restores bytes
atomically, invokes the fixed in-process rollback hook, then requires readiness
to return `true`.

Its exact input schema is `amf.m4-post-route-rollback-input/v1`: rollback ID and
revision; owner-private artifact, R1 result, R2 observation/key, runtime, and
backup paths; plus fixed adapter and hook identifiers. The content-free plan
binds pinned identities and digests for the config, evidence files, runtime,
artifact/backup roots, backup directory/files, hook IDs, derived output, shared
lock, R1/R2 evidence, backup checkpoint, and rollback revision. It exposes the
active digest and restored digest unambiguously.

The result schema is `amf.m4-post-route-rollback-result/v1`. It repeats only
route execution evidence, signed observation evidence, backup evidence,
rollback revision, active/restored digests, and three state records. The only
valid tuples are: `rolled_back` with `(passed, passed, passed)`; or
`rollback_failed` with `(failed, not_run, not_run)`, `(passed, failed, not_run)`,
or `(passed, passed, failed)` for restore, rollback hook, and readiness.

The state machine is `planned` then either `rolled_back` (restore, hook, and
readiness all passed) or `rollback_failed`. It shares R1's exclusive route lock.
Pre-mutation failures release that lock; every failure after mutation begins,
including result-write failure, retains it for deliberate recovery.

The lock is the same exclusive R1 route-executor lock. It is pinned by identity
and rechecked around restoration, hooks, readiness, output, and release. Fault
injection is test-only dependency input, never configuration or public evidence;
production adapters remain fixed in-process code.

## Live release gate

The public CLI deliberately has an empty adapter registry. Before any live
cutover, the source-controlled release assembly must be the only injected
execution path and must add two pre-mutation checks:

- an owner-private current-execution marker must match the R1 execution ID,
  revision, plan digest, and active configuration digest referenced by R2;
- the R2 observation key and R1 authorization key must have different key IDs
  and non-equivalent effective HMAC-SHA256 key bytes.

The separation check must use the same key documents consumed by the execution,
not parallel declarations. The marker prevents a failed observation from an
older, byte-identical route execution from being attributed to the currently
active execution. A release adapter that cannot prove both checks must fail
before restoration, and every alternative adapter must enforce the same gate.

Plans, results, and errors are content-free: no config bytes, filesystem paths,
service names, or topology are published. This operator never deletes backups,
data, archives, legacy rows, or any unrelated file. It performs no cleanup.
