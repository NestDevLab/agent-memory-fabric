# M4 V2 Catalog Enumerator v1

`listM4V2LogicalGroups` is an internal, read-only catalog operation for M4.
It returns a bounded keyset page of canonical logical-message groups and their
mapped v2 observations. The only cursor is the previous canonical
`logicalMessageId`; pages are ordered ascending by that ID.

Each group contains the strict projector logical shape and exact mapped v2 row
metadata. The catalog column logical ID is canonical. The embedded projection
JSON remains untouched because it is ciphertext-bound and can retain its
original key-rotation primary ID and aliases. Content IDs and opaque owner/source
tags are internal migration metadata, not public session output.

Memory uses a cloned synchronous snapshot. SQLite uses one transaction for the
logical page and each observation group. PostgreSQL uses one repeatable-read,
read-only client transaction. Both SQL catalogs maintain
`raw_events_v2_logical_message_idx` for bounded per-group observation reads.
Every adapter rejects malformed group membership, request bounds, and backend
failures with fixed content-free errors.

This enumerator does not decrypt, backfill, enqueue, replay, reconcile, cut
over, delete, deploy, or access live systems. It alone closes no M4 roadmap
checkbox.
