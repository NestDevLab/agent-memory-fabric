# M4 backfill coordinator v1

This module coordinates one bounded, source-neutral M4 backfill batch. It is a
library API, not a CLI, and it provides no filesystem, network, or concrete
archive adapter.

`planM4BackfillBatch` first calls an injected gate verifier and validates its
already-verified approved gate. The returned plan binds the run, phase, pause
and rollback evidence references, source and target checkpoints, and a batch
limit of 1 through 1,000 events. Its canonical SHA-256 `planDigest` contains no
content, paths, commands, keys, hostnames, or credentials.

`runM4BackfillBatch` recomputes the plan and requires the exact confirmed
digest before acquiring a lease, reading a checkpoint, opening a source, or
touching an outbox. It opens a source only with `{runId, phase, after,
afterSequence, maxEvents}`. `afterSequence` is zero initially and the loaded
progress sequence on resume. For each strictly ascending source row it heartbeats the lease,
enqueues the opaque event, delivers its returned event ID, requires a compact
acknowledgement, and only then commits compact progress. The store must return
an exact durable progress acknowledgement before the row is counted. Progress
also carries the plan digest, so changing gate evidence, checkpoints, phase, or
batch limit requires a new plan and progress namespace. A commit failure can
therefore be retried as an exact duplicate after restart.

The injected sink must expose `deliver`. Source events remain opaque to the
coordinator except for their `eventId` and `integrity.payloadDigest` metadata;
the enqueue receipt and delivery acknowledgement must match both values.

The coordinator processes at most the planned limit and reads one additional
row only to distinguish a complete source from a continuation. It never
processes that extra row. Every acquired lease and opened iterator is released
or closed in a finally path; primary failures remain authoritative.

This is orchestration evidence only. Concrete v2/native sources, replay queue
mode, signing, live gates, archive writes outside the injected outbox path,
cutover, and cleanup remain separate work. This module does not satisfy an M4
roadmap checkbox by itself.
