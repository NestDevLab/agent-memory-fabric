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
- first-class local JSON auth registry, with optional n8n Data Table fallback
- backend adapter currently targeting Mem0 OSS over pgvector

## Auth registry
Use `MEM0_AUTH_REGISTRY_PATH` to point the gateway at a local JSON registry. When this
is set, the gateway reads only that file and does not call n8n. Relative paths resolve
from the repo root; Docker deployments should prefer an absolute mounted secret path.

Example:
```bash
MEM0_AUTH_REGISTRY_PATH=/run/secrets/mem0-auth-registry.json
MEM0_AUTH_CACHE_TTL_MS=15000
```

Schema:
```json
{
  "rows": [
    {
      "token": "replace-with-a-random-secret-token",
      "active": true,
      "actor": "main-openclaw",
      "mode": "allow_all",
      "allowedScopes": "*",
      "permissions": "memory:search,memory:add"
    }
  ]
}
```

`allowedScopes` and `permissions` may be comma-separated strings or arrays. The
gateway also accepts a bare array of rows and the n8n-compatible `{ "data": [...] }`
shape. Keep real registry files out of git.

n8n remains supported for older deployments when `MEM0_AUTH_REGISTRY_PATH` is unset
and `N8N_API_BASE_URL`, `N8N_AUTH_TABLE_ID`, and `N8N_API_KEY` are all configured.

## Run locally
```bash
npm install
cp .env.example .env.local
# adjust values for your environment
bash scripts/run.sh
```

## Important
Do not commit real secrets or runtime `.env` files. Use local secret storage and env injection for deployment. The helper scripts intentionally use placeholder defaults only.
