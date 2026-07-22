# M4 v3 extractor reader

The M4 extractor reader is a service-only, read-only view over Conversation
Archive v1. It is separate from the public conversation reader and defaults to
off through `AMF_CONVERSATION_EXTRACTOR_MODE=legacy`.

Mode `v3` requires one read-only SQLite or PostgreSQL archive target, a private
cursor key, a signed alias manifest, and a separate alias verification key.
Those keys must not equal each other or the public reader key. Startup verifies
the archive schema and alias signature before the service accepts traffic. It
also recomputes the count and digest of every visible pre-cutoff conversation
from the selected archive and compares them with the signed manifest, so an
incomplete but validly signed manifest fails startup.

## Read contract

- Search is newest-first and uses signed strict-keyset cursors.
- Metadata covers the complete visible user/assistant event set.
- Transcripts are redacted, newest-first, bounded to 100 items per page, and
  truncate individual visible text to 4,096 Unicode code points.
- Expired events, conflicts, tombstones, replacement targets, and tombstone
  targets are not returned.
- A conversation fails closed when visible events disagree on source,
  conversation kind, or authorization context.
- SQLite is opened through an anchored read-only descriptor. PostgreSQL uses a
  bounded pool with read-only sessions; the database role remains the grant
  authority.

Only the authenticated internal extractor routes receive this reader. Public
REST and MCP routes continue to use the independently selected public reader.
The single-conversation metadata route exists so an approved canary can select
one exact conversation without scanning the archive.

## Identity and state continuity

Each search or metadata result contains an `extractionIdentity` verified by the
signed M4 alias manifest. Backfilled conversations retain their legacy session
identity, while native and post-cutoff conversations use their conversation id.
The extractor uses this identity for proposal keys and provenance but keeps the
conversation id for reader routes.

Legacy and v3 reader cursors are intentionally incompatible. The extractor
migrates to an independent v2 state file only at a completed legacy cycle
boundary and preserves the legacy state file for rollback. Reader selection,
state migration, alias verification, and live cutover authorization remain
separate gates.
