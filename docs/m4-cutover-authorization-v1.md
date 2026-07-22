# M4 cutover authorization v1

`amf.m4-cutover-authorization/v1` is the final signed evidence gate for an M4
route decision. It is independent of `amf.migration-manifest/v1`; no additional
migration phase is introduced.

Authorization requires a complete verified reconciliation manifest, the
independently restore-tested recovery pair, a verified extractor alias manifest,
a passed bounded canary, and a passed preservation and plaintext-closure proof.
It independently re-verifies the exact selector-scope authority snapshot,
active policy binding, and validity window used by the preservation proof.
The scope verification key is configured outside authorization evidence and
cannot reuse preservation or authorization key identity or material.
It also binds exact public-reader and extractor configuration revisions, the
conversation-v3 state boundary, the archive coverage verification checkpoint,
and a rollback revision checkpoint. The rollback revision must exactly match
the revision exercised by the signed canary drill.
The legacy recovery-copy checkpoint is retained explicitly for the existing
cleanup manifest input.

The alias binding includes the signed manifest digest and the complete
pre-cutoff conversation and alias digests. Public reads must be declared
`active`; the internal extractor must be declared `v3` with its separate state
generation. Any failed or unverifiable dependency blocks authorization.

The module only verifies and signs content-free evidence. It does not edit
configuration, switch a route, migrate state, run a canary, change a content
policy, or authorize destructive cleanup.
