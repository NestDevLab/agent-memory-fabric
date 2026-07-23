# Capability MCP v1

This public MCP advertises exactly `search`, `read`, `propose`,
`proposal_status`, and `status`. It advertises no administrative, destructive,
apply, provider, or implementation tool. The executable conformance manifest
is `config/contracts/amf.capability-mcp-v1.schema.json`.

`search` accepts bounded query, scopes, purpose, optional kinds, limit, and
cursor. Omitted kinds deterministically mean `canonical_memory` and `document`.
`conversation` is never implicit: it requires an explicit requested kind,
purpose `conversation_recall`, and authorized requested scopes. `read` and
`proposal_status` use scope-bound identifiers. A target outside authorized
scope returns `not_found`, indistinguishable from an absent target.
Successful search items and reads return only an opaque resource identifier,
kind, and authorized text. Search returns at most 50 items and an opaque
cursor; read returns one resource.
A search cursor is bound to the originating query, kinds, scopes, purpose, and
limit. Every page is re-authorized against the current grant. A malformed or
mismatched cursor returns `invalid_request`; a current authorization denial
returns `forbidden` without widening or revealing results.

`propose` only queues a proposal under `memory_curation`; it cannot apply or
change canonical memory. A queued proposal returns an opaque identifier, while
`proposal_status` returns that identifier and its bounded lifecycle state.
`status` returns only per-capability readiness (`ready` or `unavailable`), never
provider, backend, topology, inventory, or usage data.
All request objects reject unknown fields and all arrays and text are bounded by
the schema.

| Tool | Capability / permission | Purpose | Scope binding | Failure |
|---|---|---|---|---|
| search | search / fabric:search | memory_recall, conversation_recall | required | forbidden |
| read | read / fabric:read | memory_recall, conversation_recall | required | not_found |
| propose | propose / fabric:propose | memory_curation | required | forbidden |
| proposal_status | proposal_status / fabric:proposal_status | memory_curation | required | not_found |
| status | status / fabric:status | none | none | forbidden |

At startup, the operator registry separately lists enabled capability names and
provider assignments. Every enabled capability has exactly one assignment; zero
or more than one assignment, or an assignment for a disabled capability, is a
startup failure.
There is no merge, fallback, failover, or implicit selection. Provider IDs are
operator/config-only and never occur in public tool schemas or results.

Provider-conformance search comparisons are content-safe and aggregate-only.
Authorization and non-success outcomes must match exactly. For two successful
pages, the tolerated result-count delta is at most 2, fingerprint overlap is at
least 0.80, and ranking agreement is at least 0.70. Comparison reports never
contain result text, opaque IDs, locators, or provider identities.

When independently composed providers share an opaque-reference store, a
resource or proposal remains bound to the exact grant, scope set, and purpose
used to issue it. Routing a later read or proposal-status call to another
provider cannot widen any of those bindings; a mismatch returns the normal
non-disclosing `not_found` result. An exact authorized binding may resolve
through its assigned provider.

Migration aliases may be accepted only as unadvertised routing aliases. They
must preserve the target tool's complete authorization rule and cannot widen
permissions, purpose, or scope.

## Runtime and transport

The capability runtime is source-ready and opt-in. It listens only on a
configured loopback endpoint after policy, authorization, composition, and
readiness checks succeed; this documentation does not claim that it is deployed.
Streamable HTTP at `/mcp` is the primary transport. SSE remains a compatibility
transport for clients that require it. Both transports authenticate each request
and expose the same canonical public tools.

`fabric:*` permissions are strict: each tool requires its matching permission,
and non-status operations also require the exact declared purpose. Optional
aliases are routing-only compatibility names, remain unadvertised in
`tools/list`, and inherit the target tool's full authorization boundary.
