#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f /root/.openclaw/secrets/n8n-itermodus.env ]; then
  set -a; . /root/.openclaw/secrets/n8n-itermodus.env; set +a
fi
export AMF_SERVER_ENABLED="${AMF_SERVER_ENABLED:-false}"
if [ "$AMF_SERVER_ENABLED" != "true" ]; then
  echo "agent-memory-fabric is disabled; set AMF_SERVER_ENABLED=true explicitly" >&2
  exit 78
fi
export AMF_AUTH_REGISTRY_PATH="${AMF_AUTH_REGISTRY_PATH:-}"
export AMF_AUTH_CACHE_TTL_MS="${AMF_AUTH_CACHE_TTL_MS:-15000}"
export PORT="${PORT:-8787}"
cd "$ROOT"
exec node src/server.mjs
