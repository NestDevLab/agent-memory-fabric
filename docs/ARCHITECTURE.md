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

Auth registry:
- preferred source is a local JSON file selected with `MEM0_AUTH_REGISTRY_PATH`
- local auth registry files may be mounted Docker secrets or files under `config/`
- if the local path is set, the gateway does not call n8n
- n8n Data Table auth remains a fallback only when the local path is unset
