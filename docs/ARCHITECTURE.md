# Agent Memory Fabric

Target shape:

- clients talk only to this fabric
- the fabric enforces actor, scope and permission policy
- backend memory engines remain abstracted and replaceable
- public proposals enter an idempotent queue, never the Mem0 write API
- v2 proposals carry the complete `amf-memory/v1` record, rationale and expected revision
- PAM 0.6 structural validation is a dedicated adapter with shared conformance fixtures; restricted records are sealed and envelope/AAD/key fields fail closed
- proposal RAW is content-addressed and encrypted independently from catalog metadata
- downstream workers perform curation and PAM promotion outside the request path

Surfaces:

- REST v2: `/v2/*`, with stable envelopes and bounded inputs
- REST compatibility: `/v1/*`; `memory/add` preserves HTTP 200 while queuing instead of writing directly
- MCP SSE: `/mcp/:clientName/sse/:identity` and `/mcp/messages/`
- MCP Streamable HTTP: `/mcp/:clientName/:identity`

Trust rules:

- Mem0/OpenMemory is not the security boundary
- policy and audit live in the fabric
- transcript output is redacted by default
- original transcript access requires `raw:decrypt` and is audited
- all memory/session transports, status and errors are private and `no-store`
- session access requires an opaque purpose code plus owner/scope authorization
- MCP sessions expire, are globally/per-actor bounded, and revalidate token and policy on every call
- memory read is a distinct permission and authorization precedes RAW decryption
- proposal status is a catalog-only read; canonical record reads use `GET /v2/memory/:id`
- proposal acknowledgements echo the authoritative idempotency key on REST and MCP
- catalog identity/routing values are opaque keyed tags
- auth registries and encryption keys are runtime secrets, never tracked files

The current vertical slice uses a SQLite catalog and filesystem RAW store. Both sit
behind interfaces with in-memory implementations for deterministic tests. PostgreSQL
and native-session readers can replace them without changing REST or MCP contracts.

Compatibility:

- product identity is `agent-memory-fabric`; `mem0-gateway` is a legacy alias
- `AMF_AUTH_REGISTRY_PATH` supersedes `MEM0_AUTH_REGISTRY_PATH`
- `AMF_POLICY_PATH` supersedes `MEM0_GATEWAY_POLICY_PATH`
- v1 search, SSE and Streamable HTTP continue to work during migration
- v1 REST responses carry deprecation/sunset headers and missing add idempotency keys are derived deterministically
- the process is disabled unless `AMF_SERVER_ENABLED=true` and an explicit policy path is set; the CT113 source overlay builds a pinned image and mounts policy/auth/key material read-only
