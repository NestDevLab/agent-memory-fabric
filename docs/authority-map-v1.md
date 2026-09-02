# Authority map v1

This map assigns one owner to each durable concern. Consumers may cache or
index an owner's data, but must not become a competing source of truth.

| Concern | Authority | Boundary |
|---|---|---|
| Content bytes and native permissions | Source systems | Sources own the bytes and their native permission model. |
| Provider and catalog identity | Atlas Registry | Owns provider/catalog bindings, declarations, mappings, assertions, and dispositions. Derived indexes are rebuildable. |
| Retrieval access | AMF | Owns retrieval authorization, ranking, pagination, and opaque references. It does not own content bytes or catalog identity. |
| Curated durable memory | PAM | Owns curated durable memory and its lifecycle. |
| Tasks and approvals | Management ledger | Owns task and approval state. |
| Future authority model | Realm | Reserved; absent in v1 and grants no authority. |
| Git topology | Syncwheel | Owns repository, branch, worktree, stack, and integration topology. |

## Rules

1. Write durable facts only through the authority that owns them.
2. Treat indexes and projections as disposable: rebuild them from their
   declared source and preserve provenance when rebuilding.
3. AMF may decide whether and how to return an authorized result, but may not
   mint catalog identity, alter source permissions, or replace PAM memory.
4. An unknown, conflicting, or stale ownership assertion fails closed and is
   reported for reconciliation; it is not resolved by inference.
5. v1 behavior remains available during migration. Legacy data is migrated
   only from explicit mappings; names, paths, labels, or similar values never
   imply a new identity or grant.

## Change check

Before adding a field or workflow, name its owning authority, its canonical
source, and its rebuild or migration evidence. If ownership is unclear, record
the item as unresolved rather than adding a second authority.
