# M4 Progress Store v1

`M4ProgressStore` is an owner-only, durable file implementation of the
`checkpointStore` dependency accepted by the M4 backfill coordinator. A store
is bound at construction to one run ID, phase, and confirmed plan digest.
`load` accepts only its bound run and phase. `commit` accepts only the exact
M4 progress record for that same namespace.

Progress is private, compact metadata: the plan digest, source sequence,
checkpoint, event ID, and payload digest. It never stores text, RAW data,
base64 payloads, keys, paths, or archive content. State files and their parent
directory are owner-only. Writes use a private temporary file, file fsync,
atomic rename, and directory fsync. Recognized interrupted temporary files are
removed during construction.

The first committed sequence is `1`. Later commits must be exactly one higher
and carry a new checkpoint. Repeating the exact current record is idempotent;
rollback, gaps, changed same-sequence records, and malformed state fail with
fixed error codes. Returned records and acknowledgements are defensive copies.

The coordinator lease is the single-writer contract. The store still rejects
unsafe ownership, symlinked paths, and detected filesystem replacement or
mutation while reading its pinned state descriptor.

This store does not open sources, deliver events, verify gates, reconcile
archives, perform a cutover, or satisfy an M4 roadmap checkbox.
