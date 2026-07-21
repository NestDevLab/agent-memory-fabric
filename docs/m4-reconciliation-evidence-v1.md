# M4 reconciliation evidence v1

This module produces a read-only, content-free comparison report for the twelve
frozen M4 migration dimensions: counts, stable IDs, payload digests, logical
digests, time ranges, edits, replacements, tombstones, conflicts, paused
interval, replay queues, and source checkpoints.

## Inputs and bounds

Source and target are strictly ascending async iterables of compact event
projections. Every projection has exactly six required fields: `eventId`,
`payloadDigest`, `logicalDigest`, `sourceOccurredAt`, `occurredAt`, and `state`.
It can additionally carry only its state-appropriate relationship:
`replacesEventId`, `tombstonesEventId`, or `conflictsWithEventIds`.

Timestamps are calendar-valid UTC RFC 3339 values. Conflict references are
strictly ascending event IDs, so their projection has one canonical order.
Unknown fields, content, paths, commands, and secrets are rejected. Static
evidence has an exact bounded checkpoint shape and is copied before either
iterator is read.

The reader retains only counters, SHA-256 states, time bounds, and up to the
configured mismatch samples. `maxVisitedEvents` is a hard fail-closed limit on
the combined source and target rows; it may not exceed 5,000,000. The report is
not emitted if the complete comparison cannot be performed.
`maxMismatchSamples` may be zero and may not exceed 1,000; samples contain only
an event ID, dimension, and mismatch kind.

## Evidence and result

Each event dimension exposes compact `{count,digest}` evidence. Time ranges
also expose independent `sourceOccurredAt` and `occurredAt` min/max bounds.
Relationship evidence hashes only event IDs and relationship IDs. Static
dimensions expose only their strict checkpoint objects.

Mismatch counts are exact within a completed run. Missing and extra rows affect
every applicable metadata dimension; the counts dimension is derived only after
both iterables are exhausted. The report is `complete` only when
`completeness` is `1` and `unresolvedMismatchCount` is `0`; tolerance is always
zero and never permits a mismatch.

`dimensionsBinding` is a deterministic SHA-256 digest of the report evidence,
dimension order, exact counters, completion fields, state, and ordered bounded
mismatch samples, excluding the binding itself. This slice does not sign
reports or create migration manifests.

## Non-goals

This reader does not read visible content, write either archive, backfill,
change routes, copy data, cut over traffic, or delete anything. It is evidence
preparation only, so no M4 roadmap item is satisfied by this module alone.
