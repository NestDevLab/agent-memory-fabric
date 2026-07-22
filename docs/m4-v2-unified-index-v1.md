# M4 v2 unified index v1

`prepareM4V2UnifiedIndex` is the Fabric-owned adapter for the complete v2
catalog archive. It emits the `v2-archive` part of the unified logical index;
it does not change live state, archive state, cutover, recovery, or delivery.

The adapter snapshots its catalog, encrypted-store, reader, verifier, audit,
and bound inputs once. It pages the v2 logical catalog completely and validates
each group through `buildM4V2LogicalGroup`, yielding stable positions ordered by
logical message ID then event ID. Each index record binds the validated catalog
row and exact encrypted envelope with a canonical SHA-256 digest; neither is
returned in index evidence. Index preparation authenticates envelope metadata
without decrypting conversation content.

Materialization rescans the complete catalog and rereads every envelope to
prove the same position ordering, retaining only the requested envelope. It
checks the authority, event, position, record digest, selected signed alias,
and projection digest before calling the audited `readM4V2Observation` boundary.
The result is the standard six-field unified observation only.

The adapter bounds entries, total decoded ciphertext bytes, per-record decoded
ciphertext bytes, and signed logical variants. Returned attestation entries and
projection digests are deeply frozen.
