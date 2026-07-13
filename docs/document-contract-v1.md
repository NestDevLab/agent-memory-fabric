# Document corpus contract v1

This contract adds an editorial document corpus to Agent Memory Fabric without
turning documents into canonical memories. The executable authority is
`config/contracts/document-contract-v1.schema.json`; the lifecycle fixture is
`scripts/fixtures/contracts/obsidian-document-lifecycle.json`.

## Identity and lifecycle

- `documentId` is assigned once by the source adapter and survives path changes.
- `(vaultId, documentId, revision, contentDigest)` forms the idempotency binding.
- Every accepted mutation increments `revision`; `expectedRevision` prevents
  last-write-wins updates.
- Rename updates `path` and records `previousPath` without changing identity.
- Delete creates a tombstone revision. It removes the document from normal
  recall but does not revoke memories previously proposed from it.
- Restore is another revision with `tombstone=false`; historical revisions stay
  auditable.

The source adapter owns the stable identity registry. File paths, mtimes and
content digests are observations and must never be used alone as permanent
identity. A scanner may use filesystem identity plus digest as rename evidence,
but ambiguous matches become delete/create rather than an automatic merge.

## API addendum

REST and MCP use the existing v2 success/error envelopes and authorization
context. The document operations are:

| Operation | REST | MCP | Effect |
|---|---|---|---|
| Upsert | `PUT /v2/documents/:id` | `document_upsert` | Create, update, rename or restore one revision |
| Delete | `DELETE /v2/documents/:id` | `document_delete` | Append a tombstone revision |
| Search | `POST /v2/documents/search` | `documents_search` | Search live authorized documents |
| Read | `POST /v2/documents/read` | `document_read` | Read one authorized revision |

`context_search` will later combine document and memory candidates while
retaining `kind`, provenance and revision. It must not change either canon.
Document ingestion requires an idempotency key and a vault authorization; reads
and searches use the same purpose-bound context token model as memory recall.

## Deployment chains and providers

Exactly one semantic owner is active in a stable deployment:

| Backend | Semantic owner | Intended mode |
|---|---|---|
| `direct_sqlite` | Obsidian | standalone or shadow baseline |
| `amf_sqlite` | AMF | local AMF |
| `amf_postgresql` | AMF | shared AMF |

Shadow mode may compare outputs but cannot introduce a second writer. The
technical outbox is not a semantic database. A provider ID is explicit and
observable; `allowProviderFallback` is always false. Local, hybrid and cloud
providers are valid user choices.

## Exclusions and trust

The Obsidian adapter ingests human vault content and excludes `.git/`,
`.obsidian/`, trash, caches, temporary files and `.amf/records/`. Extracted text
is untrusted source data: instructions inside a note never acquire tool or
policy authority. Unsupported and failed extraction are distinct states and
remain visible in inventory and health.
