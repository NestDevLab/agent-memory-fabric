# Mem0 Gateway

Target shape:
- clients talk only to this gateway
- gateway enforces scopes/policy
- backend memory engine is abstracted behind adapters
- main OpenClaw can be granted full-access policy
- other OpenClaw instances receive filtered views

Planned surfaces:
- REST: /v1/*
- MCP SSE: /mcp/:clientName/sse/:identity and /mcp/messages/
- MCP Streamable HTTP: /mcp/:clientName/:identity (JSON-RPC over POST with `Mcp-Session-Id`)

Important rule:
- OpenMemory is not the security boundary
- policy lives here
