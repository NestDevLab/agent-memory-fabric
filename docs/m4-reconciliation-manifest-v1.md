# M4 reconciliation manifest v1

This module converts a fully validated M4 reconciliation report into the
standard signed `amf.migration-manifest/v1` reconciliation phase record. It is
pure and has no filesystem, network, archive-write, route, cutover, or cleanup
dependency.

## Report validation

The report validator accepts only the twelve canonical M4 dimensions in their
published order. It validates each source and target evidence shape, timestamp
range, checkpoint map, mismatch counter, and bounded content-free sample. The
unresolved mismatch total and state must agree with the dimension evidence.
The validator then recomputes the complete report binding and deterministic
binding ID before returning an isolated copy.

A completed comparison can still be `pending` when it contains mismatches. Its
`completeness` is `1`, its tolerance is always `0`, and it cannot be represented
as `complete`. A complete report has no unresolved mismatch.

## Migration evidence gates

Creation verifies the aggregate pause manifest and rollback manifest directly
with their signing keys. The rollback record must reference the exact signed
pause evidence and paused source checkpoint, and its restore test must be
`passed`. Unverified callbacks or caller assertions are not accepted as
evidence.

The signed reconciliation body contains only state, pause and rollback
evidence, dimension names, the report binding, completeness, tolerance, and
the unresolved mismatch count. Detailed dimension evidence, samples, event
content, paths, commands, credentials, and private error messages are excluded.

`verifyM4ReconciliationManifest` independently validates the exact manifest
shape, reconciliation semantics, key ID, payload digest, and HMAC signature.
It compares signatures in constant time and returns an isolated copy.

## Boundary

This contract does not enumerate either archive, create source or target
projections, run reconciliation, write the manifest to disk, authorize cutover,
perform a recovery test, or remove legacy data. A complete signed manifest is
necessary evidence for later M4 gates but does not satisfy a roadmap item by
itself.
