# M4 V2 Backfill Runner v1

`planM4V2Backfill` verifies supplied signed gate input and returns the exact
coordinator plan without constructing a lease, source, outbox, archive, or
progress store. `runM4V2Backfill` recomputes that plan and requires its exact
confirmed digest before validating or calling any delayed resource factory.

The runner invokes factories in this order: lease, source, outbox, archive,
and checkpoint store. After confirmation, it snapshots the five factory
references, validates each result before calling the next factory, and stops
construction on the first invalid result. It constructs the M4 archive sink
from the archive bundle and passes all resources to the bounded coordinator.
Factory inputs contain only run, phase, plan digest, and compact checkpoints.
Closeable resources already created are closed in reverse construction order;
a primary execution failure remains authoritative over cleanup failure.

The runner loads no environment, files, or live configuration. It does not
provide a CLI, perform a deployment, reconcile archives, or satisfy an M4
roadmap checkbox.
