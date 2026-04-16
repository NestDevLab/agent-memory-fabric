# mem0-gateway

Custom REST/MCP gateway for scoped access to Mem0 OSS.

## Goals
- expose a stable REST/MCP boundary to clients
- enforce actor/scope policy outside the memory backend
- support public HTTPS exposure through a reverse proxy or Cloudflare Tunnel
- keep Mem0 as backend engine, not as the public trust boundary

## Current shape
- REST endpoints for health, policy resolution, memory search, memory add
- MCP SSE transport for memory search and scope listing
- auth registry backed by n8n Data Table
- backend adapter currently targeting Mem0 OSS over pgvector

## Run locally
```bash
npm install
cp .env.example .env.local
# adjust values for your environment
bash scripts/run.sh
```

## Important
Do not commit real secrets or runtime `.env` files. Use local secret storage and env injection for deployment. The helper scripts intentionally use placeholder defaults only.
