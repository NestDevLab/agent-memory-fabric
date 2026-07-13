# Obsidian document bridge threat model

## Protected assets

- vault content and attachment bytes;
- stable document identities and revision history;
- AMF authorization context, audit records and provider configuration;
- PAM records, which remain a separate canonical store;
- projection annotations written by a human.

## Trust boundaries

Vault files, filenames, symlinks, embedded links and note text are untrusted.
The bridge process is trusted only for its configured vault and AMF scopes. AMF
authenticates every operation; retrieval engines and model providers receive
only the data selected for their configured role.

## Required controls

| Threat | Required control | Failure behavior |
|---|---|---|
| Path escape or symlink swap | Directory-descriptor traversal, no-follow reads, relative canonical paths and post-open identity checks | Reject item and expose degraded health |
| Prompt injection in notes | Label retrieved document text as untrusted data; never compose it into policy/system instructions | Return content with provenance, no authority elevation |
| Projection ingest loop | Exclude `.amf/records/`; bind projection provenance and digest | Skip and audit |
| Concurrent edits | Monotonic revision plus `expectedRevision` | Preserve both states and return conflict |
| Ambiguous rename | Stable registry; require strong single-match evidence | Emit delete/create, never merge silently |
| Outbox tampering or replay | Owner-only storage, integrity metadata, idempotency key and bounded retry | Quarantine invalid entry, continue fail-soft |
| Backend double writer | Exclusive backend/owner configuration validated at startup | Refuse active mode |
| Provider substitution | Explicit provider ID and no implicit fallback | Mark extraction failed/degraded |
| Cross-vault disclosure | Vault-scoped ACL and purpose-bound context token | Fail closed and audit denial |
| Oversized or hostile content | Size/type limits and isolated extractors | Inventory metadata; mark unsupported/failed |

## Security gates

The Markdown vertical slice must test path traversal, symlink replacement,
idempotent replay, rename ambiguity and outage queuing. Active projections add
loop and conflict tests. Full-corpus extraction adds parser isolation, resource
limits and provider-routing tests. No fleet rollout proceeds while drift,
conflict or an unreviewed high-severity finding remains.
