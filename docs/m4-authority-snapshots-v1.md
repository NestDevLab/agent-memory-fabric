# M4 authority snapshots v1

M4 uses two signed, content-free authority snapshots to prevent a cleanup or
plaintext-closure signer from inventing its own evidence.

`amf.m4-catalog-reference-snapshot/v1` is produced by a read-only catalog
collector under a catalog-specific key. It records a bounded validity window,
catalog revision, every scanned legacy transcript object, and every opaque
catalog reference to those objects. The collector canonicalizes the scan and
derives object and reference counts, the complete scan digest, exact
zero-reference targets, and per-selector eligible counts. Verification
recomputes every derived field. Cleanup must use exactly the signed eligible
target list; a subset, superset, changed count, or changed digest is rejected.

`amf.m4-selector-scope-snapshot/v1` is produced by a read-only scope collector
under a different scope-authority key. It binds the canonical digest and
revision of the active content-protection policy to the complete sorted set of
approved conversation selectors and a bounded validity window. Preservation
must cover exactly that selector set and the same policy. Cutover authorization
re-verifies the authority snapshot rather than trusting the preservation signer.

Consumers receive the catalog and scope verification keys as configured trust
anchors outside claimant-controlled evidence. Evidence cannot supply or replace
those keys. A trust anchor may not reuse either the key identifier or key
material of the preservation, cleanup, or cutover signer it constrains.

Validity timestamps use strict UTC calendar validation, including leap-year and
nanosecond rules; nonexistent dates are rejected rather than normalized. Each
authority window is limited to seven exact days.

Offline evidence timestamps do not establish wall-clock freshness by
themselves. Any cutover or cleanup executor must compare its trusted current UTC
time with `validThrough` and re-verify the snapshot immediately before acting.
Back-dating `provedAt`, `authorizedAt`, or `inventoriedAt` never extends an
expired authority window.

The collectors accept abstract read-only sources and do not contain a live
database adapter, service address, credential, route switch, or mutation. The
catalog and policy services remain the authorities for scan completeness and
active-policy selection. Their keys are intentionally separate from cleanup,
preservation, and cutover authorization keys.
