# M4 v2 conversation projector v1

This pure in-memory module converts strict normalized v2 logical groups into
validated v3 conversation events. It has no catalog, RAW-store, filesystem,
network, checkpoint, or CLI dependency.

The projector validates every wrapper and recomputes the v2 logical selection
before doing any projection. It filters to user and assistant text
observations in supported conversation directions and kinds. A preferred
ineligible observation excludes the whole group. Delivery handoffs with an
equal normalized payload digest are deduplicated using the existing v2
observation comparator.

Derived conversation, event, and source-instance IDs use only opaque v2 IDs,
session IDs, and catalog-safe opaque source tags in the exact
`<keyId>:<64-lowercase-hex>` form. Text, timestamps, paths, display names, and RAW
bytes never participate in derived identifiers. Context tags are preserved;
thread IDs are not invented. Source-instance IDs use only observations that
actually produce an event, so filtered observations cannot change output
identity.

One digest becomes an active event. Compatible native revisions form an
active/edit chain; ambiguous variants become explicit conflicts. There are no
v2-to-v3 replacement mappings. An authoritative deletion may use
`contentType: none` and null visible text. It becomes a tombstone only when a
validated eligible predecessor supplies its role, direction, conversation kind,
and context; it must order strictly after that predecessor. Additional deletion
observations are deduplicated only when their normalized digest agrees, and
deletion over a conflicting history fails closed. Edit chains require matching
role, direction, conversation kind, context tags, and source tag. Conflict
history is bounded before signing to the v3 reference limit.

Before a tombstone is signed, its deletion observation must also match the
predecessor's source kind, catalog source tag, and canonical context tags.
Equal normalized payload digests are deduplicated only when their non-deletion
semantic identity (role, direction, conversation kind, and context tags) also
matches.

All source timestamps are converted to canonical UTC `Z` before ordering or
event creation. The original fractional precision, up to nine digits, is
retained during conversion.

The injected integrity callback receives only legacy event ID, derived event
ID, state, and revision. The callback's returned integrity input is passed to
the production v3 event creator.

Pure projection alone satisfies no M4 roadmap checkbox. Concrete catalog
reading, decryption, replay, live gate verification, and live execution remain
separate work.
