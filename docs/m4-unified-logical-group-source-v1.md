# M4 unified logical-group source v1

`prepareM4UnifiedLogicalGroupSource` prepares a content-free source compatible
with `runM4PreservedGroupReplay`. It accepts three authority-bound complete
index attestations keyed by `v2-archive`, `preserved-outbox`, and
`preserved-deadletter`, a canonical logical-ID resolver, and one private
materializer per origin.

Each index entry is limited to origin, position, legacy event ID, record digest,
and at most 128 sorted logical-ID-to-projection-digest variants. Preparation
resolves aliases, selects the digest of the canonical variant, rejects changed
projection evidence for the same legacy event, and coalesces all
locators, and builds canonical descriptors before any private observation is
materialized. The resulting source materializes and compares every locator for
each member only when a caller consumes a yielded group. Every materializer gets
the canonical logical ID and deterministic migration sequence; all locator
results must produce the same minimal observation and projection digest before
the source emits one observation. A locator position is globally unique within
its origin, and one event may have at most one locator per origin. Concrete
materializers must bind the reopened record to the locator's event ID and record
digest before decoding it.

The source accepts the replay request schema exactly, resumes only from an exact
known group digest, and enforces at most 100 groups and 1,000 members per call.
Prepared index/group inventory is separately capped at 1,000,000, so larger
valid inventories paginate rather than fail at the 100-group run bound. It
stops cleanly before the next group that would exceed either per-call bound and
reports `complete: false`; descriptors, completions, and errors contain no
content.
