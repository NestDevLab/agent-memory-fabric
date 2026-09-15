#!/usr/bin/env node
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

import {
  createInteractiveRecallBridgeFromDirectory,
  INTERACTIVE_RECALL_HANDOFF_ENV
} from '../src/operator/interactive-recall-mcp.mjs';
import {
  createInteractiveMcpBridgeFromDirectory,
  INTERACTIVE_MCP_HANDOFF_ENV
} from '../src/operator/interactive-mcp.mjs';

const COMPLETE_LAUNCHER_PATH = fileURLToPath(new URL('./amf-interactive-mcp.mjs', import.meta.url));

function safeError(error) {
  const code = String(error?.message || 'interactive_recall_bridge_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'interactive_recall_bridge_failed';
}

async function run() {
  const compatibilityArgument = process.argv[2];
  const completeMode = Boolean(process.env[INTERACTIVE_MCP_HANDOFF_ENV]);
  if (process.argv.length > 3 || (compatibilityArgument && (!completeMode || compatibilityArgument !== COMPLETE_LAUNCHER_PATH))) {
    throw new Error('interactive_recall_cli_argument_unknown');
  }
  const bridge = completeMode
    ? createInteractiveMcpBridgeFromDirectory(process.env[INTERACTIVE_MCP_HANDOFF_ENV])
    : createInteractiveRecallBridgeFromDirectory(process.env[INTERACTIVE_RECALL_HANDOFF_ENV]);
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let message;
    try { message = JSON.parse(line); } catch {
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
      continue;
    }
    const response = await bridge.handleRpc(message);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  }
}

run().catch(error => {
  process.stderr.write(`${JSON.stringify({ ok: false, error: safeError(error) })}\n`);
  process.exitCode = 1;
});
