# M4 preserved logical-group replay v1

`runM4PreservedGroupReplay` is an injected, file-free coordinator for immutable,
content-free logical-group descriptors. Each canonical member has one
`legacyEventId`, one `projectionDigest`, and a sorted nonempty `locators` list.
Every locator carries its closed-source `origin`, preserved `position`, and
authority-bound `recordDigest`. This permits one event present in archive,
pending, and deadletter state to produce exactly one materialized observation.
The runner recomputes `groupDigest` from canonical members, the authority digest,
and the logical-message ID before private input is accepted. It maps private
observations by unique legacy event ID and recomputes each projection digest.
Origin and position remain closed-source locator evidence; they are never
derived from runtime `sourceTag`, migration sequence, or projection source kind.
A source therefore supplies complete private logical observations only
after closing membership across the v2 archive and preserved queues. The
coordinator projects each group with
`projectM4V2LogicalGroup`, delivers its events in projector order, and commits
one content-free checkpoint only after every event reaches `accepted`,
`duplicate`, or `conflict`.

The descriptor and checkpoint bind one `authorityDigest` and contain no
ciphertext, visible text, paths, or raw payload. Excluded groups commit no event
outcomes. A later run resumes from the last committed group digest; replayed
event delivery is delegated to the injected durable outbox idempotency contract.

One call processes at most 100 groups, 1,000 source observations, and 1,000
projected events. A group is never partially checkpointed. When the next group
would exceed the remaining observation or projected-event capacity, it is left
without outbox delivery or checkpointing, the iterator is closed, and the run
returns `complete: false` for a later resume.
