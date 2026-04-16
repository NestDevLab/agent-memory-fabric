#!/usr/bin/env bash
set -euo pipefail
SCRIPT="/root/.openclaw/workspace/mem0-gateway/scripts/ensure-running.sh"
TMP=$(mktemp)
(crontab -l 2>/dev/null || true) | grep -v 'mem0-gateway/scripts/ensure-running.sh' > "$TMP"
printf '%s\n' '@reboot /usr/bin/bash /root/.openclaw/workspace/mem0-gateway/scripts/ensure-running.sh' >> "$TMP"
printf '%s\n' '*/1 * * * * /usr/bin/bash /root/.openclaw/workspace/mem0-gateway/scripts/ensure-running.sh' >> "$TMP"
crontab "$TMP"
rm -f "$TMP"
crontab -l
