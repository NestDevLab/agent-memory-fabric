# M4 preserved replay coordinator v2

`createM4PreservedReplayCoordinator` is a pure injected coordinator for the
encrypted legacy outbox and deadletter records preserved by the M2 pause. It
does not read files, decrypt payloads, open a network connection, write an
archive, change routes, cut over traffic, or delete data by itself.

## Authority and source bounds

The authority binds signed pause evidence and the preserved acknowledgement
checkpoint. It has separate descriptors for `outbox` and `deadletter`. Each
descriptor binds the matching pause checkpoint, an exact numeric interval and
chain checkpoint, and its own initial resume checkpoint. Before a reader is
opened, the coordinator verifies the pause evidence and both queue checkpoints,
not only the selected queue.

An empty preserved queue is represented by an interval whose
`endInclusive` equals `startExclusive`; natural completion is still required.

The reader attests its source kind, pause checkpoint, interval, chain, and
natural completion. Positions must be strictly increasing inside the selected
interval. A batch durably enqueues, delivers, and acknowledges at most
`maxEvents` records. After that bound, the coordinator may read one unprocessed
record solely to distinguish a full batch from natural completion; it never
authorizes, decrypts, enqueues, delivers, or acknowledges that probe. It visits
at most 10,000 processed records. Ciphertext must be a non-empty buffer no larger than 16
MiB. On resume, `afterSequence` is passed to the reader so it can begin with
the previously acknowledged row; the coordinator re-derives and verifies that
row checkpoint before processing its successor. Unknown resume checkpoints,
out-of-range sequences, and incomplete scans fail closed.

## Authorized normalization and identity

The coordinator recomputes the declared SHA-256 envelope digest before calling
authorization or the decoder. The decoder receives an isolated ciphertext
copy only after authorization and must return an attestation bound to the same
legacy event ID and envelope digest plus one valid conversation event.

The v3 event ID must equal the deterministic legacy `evt_*` to v3 `cevt_*`
mapping used by the v2 conversation projector. Queue kind is deliberately not
part of that event identity: the same preserved event encountered in both the
outbox and deadletter queue remains one v3 event. Queue kind remains part of
the replay checkpoint and acknowledgement evidence.

## Durable outcomes

Normalized events enter the existing injected v3 plaintext outbox. That
outbox, rather than process-local memory, owns durable duplicate and conflict
decisions across batches and restarts:

- a new event is delivered through the native v3 sink and acknowledged as
  `accepted`;
- the same event ID and payload digest is acknowledged as `duplicate`;
- the same event ID with a changed payload digest is durably preserved by the
  outbox and emitted as content-free `conflict` evidence without delivery.

Acknowledgements expose only schema, sequence, queue kind, opaque checkpoint,
event ID, payload digest, outcome, duplicate state, and optional conflict
metadata. They never include ciphertext, decoded content, paths, hosts,
commands, credentials, or private error messages.

## Boundary

This contract does not implement the filesystem reader or authorized legacy
decoder, configure the durable outbox or native sink, run replay, reconcile
archives, perform a canary, cut over reads, or clean up legacy data. It does
not satisfy the M4 replay checklist item without a bounded operator run and
reconciliation evidence.
