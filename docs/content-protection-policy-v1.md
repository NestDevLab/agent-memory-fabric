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

The reusable runtime boundary selects one rule by the exact source and class;
it is caller-composed and does not change existing stores or native transcript
paths. It accepts generic content bytes, so storage adapters can compose it
without coupling the policy to one record schema.
Plaintext remains the default for every class and requires no key. AES rules
require 32-byte key material, use AES-256-GCM with a random 12-byte IV and a
16-byte tag, and bind canonical public metadata into AAD. A removed read key
reference makes ciphertext using that reference unreadable by policy. During a
plaintext-to-AES migration, valid plaintext envelopes remain readable while new
writes follow the active AES rule. An AES rule may set `readPlaintext: false`
only after migration reconciliation to close that downgrade window. Content is
limited to 16 MiB, metadata to 16 KiB and 32,768 visited values, and
authenticated decompression uses the same 16 MiB output bound.

An enabled AES rule may declare `compression: "deflate-raw"`. Compression is
performed at a fixed level before encryption and the selection is AAD-bound.
The reviewed policy change is accepted only with class-bound evidence showing
at least 64 bytes of complete-envelope savings. The runtime follows the
operator-owned policy; it does not trust a per-write caller assertion about
performance. The evidence generator verifies the candidate size against the
real protected envelope, and ciphertext is never presented to compression.
Readers accept both compressed and uncompressed AES envelopes while the active
rule changes; new writes follow the current rule. Omitted compression retains
the `none` write behavior. Compressed byte identity is not a cross-version
compatibility contract; readers rely on the declared algorithm and bounded
decompression.

The measurement method and current synthetic results are recorded in
[Content protection evidence v1](content-protection-evidence-v1.md).

Deploy the updated schema and compatible runtime before, or in the same release
as, a policy using `compression` or `readPlaintext`. Older strict validators
reject these fields because policy rules disallow unknown properties.

Compression leaks the compressed length of each protected object. Do not place
attacker-controlled probes and unrelated secret material in the same compressed
content unit. The exact-selector policy, one-record envelope boundary, and
bounded output reduce exposure but do not remove this general compression side
channel.

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
