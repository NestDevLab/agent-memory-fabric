# V3 migration safety v1

## Manifest and gates

The versioned migration manifest is declarative evidence, not an execution
recipe. It contains no filesystem paths, globs, shell commands, or data copies.
Each signed manifest contains exactly one phase body: `pause`, `rollback`,
`reconciliation`, or `cleanup`; other phase bodies are forbidden. A migration
pause reports `paused`, never healthy.

## Pause and rollback

Pause evidence preserves collector cursors, pending outboxes,
acknowledgements, dead letters, source checkpoints, and native transcript
authority. Each is identified and digested; pause evidence is signed.

Rollback references signed pause evidence and names immutable source and target
checkpoints, a compatibility-route revision, and a recovery-copy identifier and
digest with restore-test state.
Rollback never destroys either archive. A failed or absent restore test blocks
rollback readiness.

## Reconciliation and cutover

Reconciliation references signed pause and rollback readiness evidence. It
records counts, stable IDs, payload and logical digests, time ranges, edits,
replacements, tombstones, conflicts, the paused interval, replay queues, and
source checkpoints in one checkpoint-and-digest binding. A complete record has
`completeness=1` and `unresolvedMismatchCount=0`; tolerance is reporting only.
Any mismatch blocks cutover. A pending reconciliation is valid evidence but is
not cutover-ready.

## Cleanup boundary

Cleanup names exact legacy object identifiers and digests only: no wildcard or
range target is valid. Its own body references a complete reconciliation
manifest, signed catalog-unreferenced proof, a passed cutover canary, and one
recovery copy with a passed restore test.
Destructive execution is separately explicitly approved and is not implemented
by this contract.

## Verification

Conformance fixtures cover ready evidence and blocked states. The contract test
checks signatures, digests, phase coverage, semantic gate ordering, exact
cleanup targets, and the no-path/no-command manifest boundary.
