# Agent Memory Fabric

Target shape:

- clients talk only to this fabric
- the fabric enforces actor, scope and permission policy
- backend memory engines remain abstracted and replaceable
- public proposals enter an idempotent queue, never the Mem0 write API
- v2 proposals carry the complete `amf-memory/v1` record, rationale and expected revision
- PAM 0.6 structural validation is a dedicated adapter with shared conformance fixtures; restricted records are sealed and envelope/AAD/key fields fail closed
- proposal RAW is content-addressed and encrypted independently from catalog metadata
- transcript RAW is encrypted at the source and ingested through a durable outbox
- downstream workers perform curation and PAM promotion outside the request path
- curator discovery is bounded and metadata-only; exact reads and receipts are
  least-privilege, audited, and proposal-digest-bound
- PAM refreshes its record index atomically; Fabric hot-reloads it and derives
  sensitive routing tags from non-secret refs with a server-only key ring

Surfaces:

- REST v2: `/v2/*`, with stable envelopes and bounded inputs
- REST compatibility: `/v1/*`; `memory/add` preserves HTTP 200 while queuing instead of writing directly
- MCP SSE: `/mcp/:clientName/sse/:identity` and `/mcp/messages/`
- MCP Streamable HTTP: `/mcp/:clientName/:identity`

Trust rules:

- Mem0/OpenMemory is not the security boundary
- policy and audit live in the fabric
- transcript output is redacted by default: only bounded normalized text from
  authenticated v2 `user`/`assistant` observations is returned after durable audit
- textual session search is context-first and decrypts only the newest bounded
  256-event window of at most 64 candidate sessions per continuation page, with
  a shared 16 MiB ciphertext budget; keyset continuation replaces candidate-count outages
- redacted transcript queries use the same newest-event window and bind query,
  context and cursor; original transcript queries are forbidden
- session/event ordering uses effective `occurredAt` plus a stable id tiebreak;
  only preferred logical observations survive conflict/tombstone/dedup gates
- session context tokens sign canonical route scopes, which must be registered
  and actor-allowlisted server-side; group/channel/thread recall requires a room scope
- cursors carry a server-side MAC; REST GET context tokens use
  `X-AMF-Context-Token`, never a query parameter for dedicated actors
- original transcript access requires `raw:decrypt` and is audited
- all memory/session transports, status and errors are private and `no-store`
- session access requires an opaque purpose code plus owner/scope authorization
- MCP sessions expire, are globally/per-actor bounded, and revalidate token and policy on every call
- memory read is a distinct permission and authorization precedes RAW decryption
- proposal status is a catalog-only read; canonical record reads use `GET /v2/memory/:id`
- proposal acknowledgements echo the authoritative idempotency key on REST and MCP
- catalog identity/routing values are opaque keyed tags
- canonical sensitive routing is derived from PAM `contextRefs` with the
  mandatory server-side routing ring; client-supplied/precomputed tags are not
  authoritative
- curation receipts bind proposal scope and digest and are accepted only under
  the submitting actor's current scope ACL
- rejected/revoked proposals are terminal at both receipt preflight and catalog
  transaction boundaries; only an identical persisted receipt can replay
- curation pagination cursors are server-HMAC-authenticated
- auth registries and encryption keys are runtime secrets, never tracked files
- ingest keys are authorized per actor/source before decryption; those bindings and
  the stable logical digest are authenticated as AES-GCM AAD
- RAW event, session catalog and audit mutations are one atomic catalog transaction

The current vertical slice uses a SQLite or PostgreSQL catalog and filesystem RAW
store, with in-memory implementations for deterministic tests. The same catalog
provides policy-delegated redacted sessions and decrypts originals only after
`raw:decrypt` policy. Redacted text is internally decrypted only after owner/context
authorization and a durable decrypt-intent audit; RAW, system, tool and structured
payloads never enter that response.
Codex and Claude adapters use bounded rolling checkpoints during polling and retain
an explicit full-history audit mode.

Compatibility:

- integrated recall + curation release identity is `0.5.5` (recall hardening
  originated in `0.5.4`)
- product identity is `agent-memory-fabric`; `mem0-gateway` is a legacy alias
- `AMF_AUTH_REGISTRY_PATH` supersedes `MEM0_AUTH_REGISTRY_PATH`
- `AMF_POLICY_PATH` supersedes `MEM0_GATEWAY_POLICY_PATH`
- v1 search, SSE and Streamable HTTP continue to work during migration
- v1 REST responses carry deprecation/sunset headers and missing add idempotency keys are derived deterministically
- the process is disabled unless `AMF_SERVER_ENABLED=true` and an explicit policy path is set; the CT113 source overlay builds a pinned image and mounts policy/auth/key material read-only
