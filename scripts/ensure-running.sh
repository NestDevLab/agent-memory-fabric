#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${AMF_SERVER_ENABLED:-false}" != "true" ]; then
  echo "agent-memory-fabric is disabled; set AMF_SERVER_ENABLED=true explicitly" >&2
  exit 78
fi
LOG_DIR="${AMF_LOG_DIR:-$ROOT/var/logs}"
PIDFILE="${AMF_PIDFILE:-$LOG_DIR/agent-memory-fabric.pid}"
LOGFILE="${AMF_LOGFILE:-$LOG_DIR/agent-memory-fabric.log}"
mkdir -p "$LOG_DIR"
if pgrep -af "node .*src/server.mjs" | grep -F -- "$ROOT" >/dev/null 2>&1; then
  exit 0
fi
if [ -f /root/.openclaw/secrets/n8n-itermodus.env ]; then
  set -a; . /root/.openclaw/secrets/n8n-itermodus.env; set +a
fi
cd "$ROOT"
nohup env \
  AMF_SERVER_ENABLED="${AMF_SERVER_ENABLED:-false}" \
  AMF_AUTH_REGISTRY_PATH="${AMF_AUTH_REGISTRY_PATH:-}" \
  AMF_AUTH_CACHE_TTL_MS="${AMF_AUTH_CACHE_TTL_MS:-15000}" \
  N8N_API_BASE_URL="${N8N_API_BASE_URL:-http://localhost:5678}" \
  N8N_AUTH_TABLE_ID="${N8N_AUTH_TABLE_ID:-change-me}" \
  N8N_API_KEY="${N8N_API_KEY:-}" \
  PORT="${PORT:-8787}" \
  node src/server.mjs >>"$LOGFILE" 2>&1 </dev/null &
echo $! > "$PIDFILE"
sleep 1
