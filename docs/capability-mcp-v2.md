# Capability MCP v2

Capability MCP v2 advertises exactly `search`, `read`, `propose`,
`proposal_status`, and `status`. It preserves the v1 tool names, bounded
requests, proposal-only curation, status redaction, aliases, and failure
semantics. V1 remains available with its legacy string scope grammar; this v2
contract accepts only structured `ScopeRef` values. The executable conformance
manifest is `config/contracts/amf.capability-mcp-v2.schema.json`.

## Public boundary

`ScopeRef` is `{ tenantId, type, scopeId }`. Its identity is
`(tenantId, scopeId)`; `type` is descriptive and is neither a grant nor an
inherited authorization decision. V2 never accepts, normalizes, or derives a
scope from a legacy string, prefix, path, or historical name. An approved
migration mapping is outside this public API and ambiguity fails closed.

Every request is single-tenant. Mixed-tenant scope sets fail as
`invalid_request`; repeated `(tenantId, scopeId)` identities also fail even if
their descriptive `type` values differ. Multiple scopes use union semantics:
an admitted candidate must belong to at least one requested scope and the
current grant must authorize that exact scope. Scope membership never grants
access by itself.

`search` keeps the v1 defaults: omitted `kinds` means exactly
`canonical_memory` and `document`. V2 adds kind `resource` and purpose
`context_recall`. `conversation` and `resource` are always explicit kinds.
`conversation` requires `conversation_recall` or `context_recall`; `resource`
may be requested under an authorized recall purpose. `read` reuses the requested purpose and
ScopeRef set. `propose` remains limited to `memory_curation`; it only queues a
proposal and never applies one.

`search` also accepts optional `delivery`, exactly `results` or `notice`, and
defaults to `results`. `delivery=notice` is available only with
`purpose=context_recall`. It returns a bounded `notice_only` envelope after
current-grant admission, with no resource IDs, snippets, provenance payload,
or cursor. It does not add a tool. Manual capsule recall uses
`search(delivery=results)`; the private capsule adapter maps expansion
references to the existing `rid_*` scheme, and explicit expansion is a normal,
separately reauthorized `read(id=<rid_*>)`.

| Tool | Permission | Authorized purposes | Scope binding | Denial result |
|---|---|---|---|---|
| search | fabric:search | memory_recall, conversation_recall, context_recall | required ScopeRef[] | forbidden |
| read | fabric:read | memory_recall, conversation_recall, context_recall | required ScopeRef[] | not_found |
| propose | fabric:propose | memory_curation | required ScopeRef | forbidden |
| proposal_status | fabric:proposal_status | memory_curation | required ScopeRef[] | not_found |
| status | fabric:status | none | none | forbidden |

No request or result contains a provider ID, backend, topology, locator, or
administrative control. `status` reports only the five public capability names
and `ready` or `unavailable` state. Migration aliases are unadvertised routing
aliases only and preserve the target tool's complete authorization boundary.

## Composite retrieval, admission, and coverage

There is one public `search` capability assignment. Its assigned internal
composite performs the only allowed retrieval fan-out, over the explicitly
requested kinds; fan-out members are implementation details. Every candidate
is admitted only after current authorization, exact ScopeRef membership, and
purpose/kind compatibility pass. A failed admission is omitted without a
target-specific signal.

The composite builds four candidate lanes: exact, lexical, fuzzy, and vector.
It deduplicates logical resources before ranking. The frozen order is: current
ACL admission, exact-anchor flag, authority rank, freshness rank, reciprocal
rank fusion over the four lane positions with `k=60`, recency, then opaque
resource ID. Missing lane membership contributes zero. Native provider scores
are never compared directly. The coverage snapshot, authorization revision,
lane positions, ranking-policy revision, and UTC `rankedAt` instant are fixed
when page one is issued.

Authority uses one ascending ordinal domain, independent of provider-native
scores: `unknown=0`, `derived_projection=1`, `attributed_observation=2`,
`reviewed_canonical=3`, and `source_authority=4`. `source_authority` requires a
direct result from the declared current source authority for that resource
kind; a provider assertion alone is insufficient. `reviewed_canonical`
requires an explicit accepted/canonical lifecycle decision.
`attributed_observation` has verifiable source and observation provenance but
is not canonical. `derived_projection` is an index, summary, or transform that
retains provenance. Anything that cannot establish one of those classes is
`unknown`. Higher ordinal sorts first.

Freshness also uses one ascending ordinal domain, computed from the page-one
UTC `rankedAt` instant and the first valid timestamp in this order:
`effective_at`, `observed_at`, `source_modified_at`, `ingested_at`. A timestamp
after `rankedAt` rejects the candidate; an expired candidate is excluded before
ranking. With age measured in whole non-negative seconds, the classes are
`current=4` for 0..86400, `recent=3` for 86401..604800, `aged=2` for
604801..2592000, `old=1` above 2592000, and `unknown=0` when no valid timestamp
exists. Higher ordinal sorts first. The public result exposes only a bounded
position and safe match reasons; it does not expose classes, ordinals, raw
scores, or provider identity. Equal snapshot inputs therefore produce the same
complete order and page boundaries.

Search always reports coverage for the requested kinds. `complete` means every
requested kind was queried under the snapshot; `partial` names only requested
kinds not covered and generic operational reasons. Coverage never identifies a
provider or reveals whether a particular resource exists. A partial result is
not a complete-world claim.

Each returned resource has an explicit contradiction state (`none`, `present`,
or `unknown`). A contradiction remains visible; ranking may order it but never
silently resolves, suppresses, or rewrites it.

## Opaque resources and paging

Resource identifiers and cursors remain bounded opaque references. A resource
reference binds the issuing tenant-qualified ScopeRef identity set, purpose,
kind, and grant. `read` first reauthorizes the current grant and then requires
that exact binding; revocation, scope mismatch, purpose mismatch, absent, and
unauthorized targets all return `not_found`. This is intentionally not an
existence oracle.

A cursor binds the originating query, explicit-or-default kinds, ordered
ScopeRef identities, purpose, limit, ranking policy revision, and coverage
snapshot. It preserves the issued opaque candidate order across pages. Every
page is reauthorized; a malformed or mismatched cursor is `invalid_request`,
and a current authorization denial is `forbidden`. Reauthorization can remove
newly unauthorized items but cannot widen the snapshot or disclose them.

## Operator boundary

The operator registry is startup-only and is never a public result. It assigns
exactly one provider to every enabled public capability. For `search`, that
single assignment is the internal composite; only that composite may fan out.
Missing, ambiguous, or disabled-capability assignments are startup failures.
There is no public provider selection, merge, fallback, failover, or identity
exposure.

This document specifies a source contract only. It does not claim a v2 runtime
deployment or modify the v1 runtime.
