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

Migration aliases may be accepted only as unadvertised routing aliases. They
must preserve the target tool's complete authorization rule and cannot widen
permissions, purpose, or scope.
