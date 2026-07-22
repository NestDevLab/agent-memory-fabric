#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { planM4LiveOperator, runM4LiveOperator } from '../src/operator/m4-live-operator.mjs';

const STAGES = new Set(['reconciliation', 'recovery', 'canary', 'authorization']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function parse(argv) {
  const stage = argv[2]; const operation = argv[3];
  if (!STAGES.has(stage) || !['plan', 'run'].includes(operation)) fail('m4_live_cli_argument_invalid');
  const allowed = operation === 'plan' ? new Set(['--config']) : new Set(['--config', '--confirmed-plan-digest']);
  const values = {};
  for (let index = 4; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!allowed.has(name) || values[name] !== undefined || !value || value.startsWith('--')) fail('m4_live_cli_argument_invalid');
    values[name] = value;
  }
  if ([...allowed].some(name => values[name] === undefined)
    || !path.isAbsolute(values['--config']) || path.normalize(values['--config']) !== values['--config']) {
    fail('m4_live_cli_argument_invalid');
  }
  return { operation, request: { stage, configPath: values['--config'],
    ...(operation === 'run' ? { confirmedPlanDigest: values['--confirmed-plan-digest'] } : {}) } };
}

export async function runM4LiveCli(argv = process.argv, dependencies) {
  const parsed = parse(argv);
  return parsed.operation === 'plan'
    ? planM4LiveOperator(parsed.request, dependencies)
    : runM4LiveOperator(parsed.request, dependencies);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runM4LiveCli().then(value => process.stdout.write(`${JSON.stringify({ ok: true, ...value })}\n`)).catch(error => {
    const code = typeof error?.code === 'string' && error.code.startsWith('m4_live_') ? error.code : 'm4_live_cli_failed';
    process.stderr.write(`${JSON.stringify({ ok: false, error: code })}\n`); process.exitCode = 78;
  });
}
