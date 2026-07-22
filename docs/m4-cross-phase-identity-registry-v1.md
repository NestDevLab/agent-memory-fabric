# M4 cross-phase identity registry v1

The signed cross-phase registry keeps paused-native replay in the same identity
space as the v2 archive backfill. It contains no conversation text, native
identifiers, paths, credentials, ciphertext, or raw transcript rows.

The registry is split first by deterministic two-hex-digit buckets and then
into ordered, type-specific shards of at most 10,000 entries. Signed page
descriptors bind the shard key, identifier range, kind, counts, and digest. The signed root
binds every non-empty shard descriptor, the total session and event counts, the
completed backfill digest, the catalog revision digest, and an inclusive UTC
coverage cutoff. A resolver uses signed identifier ranges to load only the shard required for one
opaque legacy `ses_` or `evt_` identifier; it never loads the global registry.
Each shard is deterministically subdivided at whichever boundary is reached
first: 10,000 entries or 32 MiB of canonical serialized data. The verified page cache is
bounded, and the complete authority is bounded to two million content-free
entries.

Session entries bind a legacy session to its deterministic v3 conversation,
conversation kind, and stable session routing tags. Event entries bind an
accepted backfill observation to its deterministic v3 event and conversation,
the exact sorted set of opaque catalog source tags used by that logical group,
the resulting source-instance identifier, authorization tags, role, direction,
state, revision, and content-free edit, tombstone, or conflict references.
Event-level source bindings are required because different logical messages in
one conversation can have different source-tag sets.
Registry creation rejects any event whose conversation, kind, or session routing
does not exactly match its registered session.

Before replay becomes ready, an operator must build entries from the exact
accepted output of the v2 projector and create an immutable signed
`amf.m4-cross-phase-identity-traversal-completion/v1` document. That document
has its own manifest identifier and revision, binds the verified v2 archive
completion and unchanged catalog baseline, a durable complete traversal record,
and the exact read-only spool coverage. Its completion key, catalog key,
archive-completion key, and registry key are distinct. The registry key is
represented only by a keyed commitment in the document.

The streaming writer accepts no caller-supplied cutoff or archive binding. It
verifies that signed completion, requires its expected block, block, session,
and event counts to exactly equal the durable spool counts, then derives the
cutoff and archive binding from it. The completion digest is atomically stored
with the seal intent; retries must provide the same document before any page is
published. A valid signature alone does not prove complete coverage.

For an already registered event, paused replay must present an equivalent
content-free v2 projection and one of the bound source tags. A new revision of a
registered event reuses its predecessor's conversation and source instance, so
an edit or tombstone can reference the archived event without crossing the
archive's source boundary. Missing or ambiguous covered predecessors fail
closed. A genuinely new event derives v3 identity from its v2-compatible
projection only when its effective timestamp is strictly later than the signed
cutoff. New-session revisions derive their predecessor event identifier locally
and retain the same single-source binding only through an injected, persistent,
content-free post-cutoff event store. A caller-provided predecessor identifier
is never sufficient: missing, pre-cutoff, cross-session, or cross-source local
bindings fail closed. The returned post-cutoff binding must be persisted before
a later lifecycle event can reference it after restart.

Source adapters remain responsible for producing the content-free v2
projection with the same namespaces and routing, logical-message, and
normalization key rings used before the pause. The gateway validates that
projection and never receives those key rings through the registry. The
registry does not read transcripts, authorize cutover, change extractor
cursors, or permit cleanup.
