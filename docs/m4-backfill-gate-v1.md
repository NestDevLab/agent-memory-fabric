# M4 backfill gate v1

The M4 backfill gate authenticates one signed aggregate pause manifest and one signed
rollback manifest before the backfill coordinator can plan a batch. The
rollback record must reference the exact pause evidence, retain the pause source
checkpoint, name a target checkpoint, and record a passed restore test.

`verifyM4BackfillGate` returns only the coordinator gate shape: bounded
identifiers, signed-evidence references, and source and target checkpoints. It
never returns signing keys, recovery content, commands, or filesystem paths.
`createM4BackfillGateVerifier` snapshots that verified result so later caller
mutation cannot change an approved plan.

`createM4RollbackManifest` and `verifyM4RollbackManifest` use the public
migration-manifest integrity domain. They accept only the declarative rollback
fields defined by the published contract. They do not create a recovery copy,
perform a restore, change a route, open an archive, or approve cleanup.

This module is source preparation only. It does not read live evidence files,
run a backfill, cut over consumers, delete legacy data, or satisfy an M4 roadmap
checkbox by itself.
