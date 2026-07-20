# Content protection policy v1 and canonical memory v2

`amf.content-protection-policy/v1` selects storage protection by the exact
`sourceInstanceId` and one content class: `conversation`, `proposal`,
`canonical-memory`, or `document`. Source identifiers use the shared `src_`
namespace used by conversation events. Wildcards are invalid.

All four defaults are explicitly `plaintext`. An enabled rule may override one
exact selector. A policy is malformed and must fail closed if it has duplicate
selectors, an unknown codec or class, an invalid identifier, or a rule
that violates its key-reference requirements. `plaintext` and every disabled
rule carry no key reference. Only an enabled `aes-256-gcm` rule carries
`writeKeyRef` and non-empty `readKeyRefs`; these are opaque identifiers, never
key material. `writeKeyRef` selects new encrypted writes and must also appear in
`readKeyRefs`. That list contains accepted current and retired identifiers, so
previously encrypted objects remain readable during rotation and migration.

`amf-memory/v2` is the next AMF transport revision. It accepts `plain` and
`sealed` claims independently of visibility: a restricted plain claim and a
shared sealed claim are both structurally valid. Policy selection determines
whether a writer may produce a sealed claim; this schema does not implement
that selection or encryption.

Portable Agent Memory remains authoritative for its workspace and file rules.
This repository does not vendor a Portable Agent Memory JSON Schema; its
existing `amf-memory/v1` validator is a synchronized AMF transport adapter.
Readers accept v1 unchanged during migration. New writes use v2 only after the
separate migration gates are accepted; this contract does not alter v1 or
enable a write path.

For a sealed v2 claim, `alg` is `AES-256-GCM`, `kekId` identifies the wrapping
key lineage, and `keyRef` identifies the data-key reference. The canonical AAD
digest is SHA-256 over canonical JSON of:

`["amf-memory/v2/aad", schema, id, revision, claimType, scope, visibility, subjects, confidence, lifecycle, provenance, createdAt, updatedAt, {alg, kekId, keyRef}]`

Canonical JSON sorts object keys recursively and preserves array order. The
schema carries only sealed bytes and identifiers; implementations must reject
invalid base64, a non-12-byte IV, a non-16-byte tag, an empty ciphertext, or an
AAD mismatch. Runtime encryption and key handling are outside this contract.
