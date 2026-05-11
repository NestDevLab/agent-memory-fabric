#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f /root/.openclaw/secrets/n8n-itermodus.env ]; then
  set -a; . /root/.openclaw/secrets/n8n-itermodus.env; set +a
fi
if [ -f /root/.openclaw/secrets/mem0-gateway-auth.env ]; then
  set -a; . /root/.openclaw/secrets/mem0-gateway-auth.env; set +a
fi
export MEM0_BACKEND_KIND="${MEM0_BACKEND_KIND:-mem0-oss}"
export MEM0_LLM_MODEL="${MEM0_LLM_MODEL:-qwen3.5:9b}"
export MEM0_LLM_BASE_URL="${MEM0_LLM_BASE_URL:-http://localhost:11434}"
export MEM0_EMBEDDER_MODEL="${MEM0_EMBEDDER_MODEL:-nomic-embed-text:latest}"
export MEM0_EMBEDDER_BASE_URL="${MEM0_EMBEDDER_BASE_URL:-http://localhost:11434}"
export MEM0_EMBEDDING_DIMS="${MEM0_EMBEDDING_DIMS:-768}"
export MEM0_VECTOR_DB_HOST="${MEM0_VECTOR_DB_HOST:-localhost}"
export MEM0_VECTOR_DB_PORT="${MEM0_VECTOR_DB_PORT:-5432}"
export MEM0_VECTOR_DB_USER="${MEM0_VECTOR_DB_USER:-change-me}"
export MEM0_VECTOR_DB_PASSWORD="${MEM0_VECTOR_DB_PASSWORD:-change-me}"
export MEM0_VECTOR_DB_NAME="${MEM0_VECTOR_DB_NAME:-change-me}"
export MEM0_VECTOR_STORE_COLLECTION="${MEM0_VECTOR_STORE_COLLECTION:-change-me}"
export MEM0_VECTOR_STORE_HNSW="${MEM0_VECTOR_STORE_HNSW:-true}"
export MEM0_VECTOR_STORE_DISKANN="${MEM0_VECTOR_STORE_DISKANN:-false}"
export MEM0_AUTH_REGISTRY_PATH="${MEM0_AUTH_REGISTRY_PATH:-}"
export MEM0_AUTH_CACHE_TTL_MS="${MEM0_AUTH_CACHE_TTL_MS:-15000}"
export PORT="${PORT:-8787}"
cd "$ROOT"
exec node src/server.mjs
