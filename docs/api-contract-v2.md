# Canonical API contract v2

The portable authority for REST, MCP tool payloads and Principia consumers is
`config/contracts/agent-memory-fabric-v2.schema.json`. The executable
cross-repository fixture is
`scripts/fixtures/contracts/principia-canonical-contract.json`.

All successful REST responses use exactly `{ok,data,meta}`. Canonical memory
search and read fail closed when PAM is unconfigured; Mem0 results are exposed
only by the explicitly non-canonical candidate-ranking operation. Context-token
request digests use the exact normalized shapes in the fixture, including
sorted scope arrays and explicit pagination/time nulls.

Transcript responses always use `items`. Redacted and original items are
different explicit schemas; the legacy `messages` field is forbidden.
