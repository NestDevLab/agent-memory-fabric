#!/usr/bin/env node
import readline from 'node:readline';

import {
  createInteractiveRecallBridgeFromDirectory,
  INTERACTIVE_RECALL_HANDOFF_ENV
} from '../src/operator/interactive-recall-mcp.mjs';

function safeError(error) {
  const code = String(error?.message || 'interactive_recall_bridge_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'interactive_recall_bridge_failed';
}

async function run() {
  if (process.argv.length !== 2) throw new Error('interactive_recall_cli_argument_unknown');
  const bridge = createInteractiveRecallBridgeFromDirectory(process.env[INTERACTIVE_RECALL_HANDOFF_ENV]);
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
