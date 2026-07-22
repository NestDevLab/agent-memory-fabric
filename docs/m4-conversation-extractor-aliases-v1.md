# M4 conversation extractor aliases v1

The signed alias manifest preserves the extraction identity of every
conversation present at the M4 coverage cutoff. Backfilled conversations bind
their deterministic `ccon_` identifier to the originating `ses_` identifier;
native conversations bind their `ccon_` identifier to itself.

Entries are exact, unique, and sorted. The signed body includes an inclusive UTC
coverage cutoff, the entry count, a digest of the sorted covered conversation
identifiers, and a digest of the complete alias list. A legacy alias is accepted
only when the production M4 derivation reproduces its conversation identifier.

The internal extractor reader resolves each result through the verified
manifest. A conversation whose first visible event is at or before the coverage
cutoff must have an entry. Conversations beginning after the cutoff use their
v3 identifier. Missing covered aliases, changed ordering, digest drift, or a bad
MAC fail closed with content-free errors. Before startup becomes ready, the
runtime independently derives the complete set of visible conversations whose
first event is at or before the cutoff from the selected archive. Its count and
digest must equal the signed coverage binding; a signed but incomplete manifest
therefore cannot authorize startup.

The alias manifest is evidence for identity continuity only. It does not switch
a reader, migrate extractor cursor state, authorize a cutover, or delete legacy
data.
