#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${AMF_SERVER_ENABLED:-false}" != "true" ]; then
  echo "agent-memory-fabric is disabled; set AMF_SERVER_ENABLED=true explicitly" >&2
  exit 78
fi
LOG_DIR="${MEM0_GATEWAY_LOG_DIR:-/root/.openclaw/workspace/logs}"
PIDFILE="${MEM0_GATEWAY_PIDFILE:-$LOG_DIR/mem0-gateway.pid}"
LOGFILE="${MEM0_GATEWAY_LOGFILE:-$LOG_DIR/mem0-gateway.log}"
mkdir -p "$LOG_DIR"
if pgrep -af "node .*mem0-gateway/src/server.mjs" >/dev/null 2>&1; then
  exit 0
fi
if [ -f /root/.openclaw/secrets/n8n-itermodus.env ]; then
  set -a; . /root/.openclaw/secrets/n8n-itermodus.env; set +a
fi
if [ -f /root/.openclaw/secrets/mem0-gateway-auth.env ]; then
  set -a; . /root/.openclaw/secrets/mem0-gateway-auth.env; set +a
fi
cd "$ROOT"
nohup env \
  AMF_SERVER_ENABLED="${AMF_SERVER_ENABLED:-false}" \
  MEM0_BACKEND_KIND="${MEM0_BACKEND_KIND:-disabled}" \
  MEM0_LLM_MODEL="${MEM0_LLM_MODEL:-qwen3.5:9b}" \
  MEM0_LLM_BASE_URL="${MEM0_LLM_BASE_URL:-http://localhost:11434}" \
  MEM0_EMBEDDER_MODEL="${MEM0_EMBEDDER_MODEL:-nomic-embed-text:latest}" \
  MEM0_EMBEDDER_BASE_URL="${MEM0_EMBEDDER_BASE_URL:-http://localhost:11434}" \
  MEM0_EMBEDDING_DIMS="${MEM0_EMBEDDING_DIMS:-768}" \
  MEM0_VECTOR_DB_HOST="${MEM0_VECTOR_DB_HOST:-localhost}" \
  MEM0_VECTOR_DB_PORT="${MEM0_VECTOR_DB_PORT:-5432}" \
  MEM0_VECTOR_DB_USER="${MEM0_VECTOR_DB_USER:-change-me}" \
  MEM0_VECTOR_DB_PASSWORD="${MEM0_VECTOR_DB_PASSWORD:-change-me}" \
  MEM0_VECTOR_DB_NAME="${MEM0_VECTOR_DB_NAME:-change-me}" \
  MEM0_VECTOR_STORE_COLLECTION="${MEM0_VECTOR_STORE_COLLECTION:-change-me}" \
  MEM0_VECTOR_STORE_HNSW="${MEM0_VECTOR_STORE_HNSW:-true}" \
  MEM0_VECTOR_STORE_DISKANN="${MEM0_VECTOR_STORE_DISKANN:-false}" \
  MEM0_AUTH_REGISTRY_PATH="${MEM0_AUTH_REGISTRY_PATH:-}" \
  MEM0_AUTH_CACHE_TTL_MS="${MEM0_AUTH_CACHE_TTL_MS:-15000}" \
  N8N_API_BASE_URL="${N8N_API_BASE_URL:-http://localhost:5678}" \
  N8N_AUTH_TABLE_ID="${N8N_AUTH_TABLE_ID:-change-me}" \
  N8N_API_KEY="${N8N_API_KEY:-}" \
  PORT="${PORT:-8787}" \
  node src/server.mjs >>"$LOGFILE" 2>&1 </dev/null &
echo $! > "$PIDFILE"
sleep 1
