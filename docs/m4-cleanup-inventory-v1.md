# M4 cleanup inventory v1

`amf.m4-cleanup-inventory/v1` is a signed, exact inventory of legacy
conversation transcript rows and blobs that may be presented to the existing
cleanup manifest. It accepts no path, range, glob, command, or content.

Every target has one opaque identifier and digest, a fixed transcript object
type, an approved conversation source selector, and a zero catalog-reference
count. Targets are sorted and unique. Their per-selector counts must exactly
equal the cleanup dispositions in the verified preservation proof.

The inventory re-verifies a separately signed catalog-reference snapshot and
must exactly equal its derived zero-reference target list. The snapshot binds a
bounded validity window, catalog revision, complete canonical object/reference
scan, recomputed counts and digest, and per-selector eligible counts. Target
identifiers and digests cannot overlap catalog evidence, disposition evidence,
restore evidence, or protected proposal, canonical-memory, and document
aggregates.
The catalog verification key is a configured trust anchor outside inventory
input and cannot reuse the cleanup, preservation, or cutover signing authority.

The inventory verifies a signed cutover authorization and its preservation
evidence before it can become `ready`. A projection helper emits the exact
evidence fields used by `amf.migration-manifest/v1` cleanup without changing
that contract. A second constructor signs the standard four-phase cleanup
manifest from those verified inputs; it does not add a cutover or canary phase.

The adjacent authority collector reads only its supplied catalog source and
derives the snapshot; this inventory module does not discover or alter targets.
Neither module deletes data, switches routes, or executes cleanup. Actual
deletion remains a separate destructive action requiring explicit approval.
