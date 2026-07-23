#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { M4_BACKFILL_MAX_EVENTS } from '../src/migration/m4-backfill-coordinator.mjs';
import { planM4V2BackfillOperator, runM4V2BackfillOperator } from '../src/operator/m4-v2-backfill-operator.mjs';

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function parse(argv) {
  const operation = argv[2]; if (!['plan', 'run'].includes(operation)) fail('m4_operator_argument_invalid');
  const allowed = operation === 'plan' ? new Set(['--config', '--max-events']) : new Set(['--config', '--max-events', '--confirmed-plan-digest']); const values = {};
  for (let index = 3; index < argv.length; index += 2) { const key = argv[index]; const value = argv[index + 1]; if (!allowed.has(key) || values[key] !== undefined || !value || value.startsWith('--')) fail('m4_operator_argument_invalid'); values[key] = value; }
  for (const key of allowed) if (values[key] === undefined) fail('m4_operator_argument_invalid');
  if (!path.isAbsolute(values['--config']) || path.normalize(values['--config']) !== values['--config']) fail('m4_operator_argument_invalid');
  const maxEvents = Number(values['--max-events']); if (!Number.isSafeInteger(maxEvents) || maxEvents < 1 || maxEvents > M4_BACKFILL_MAX_EVENTS) fail('m4_operator_argument_invalid');
  if (operation === 'run' && !/^sha256:[a-f0-9]{64}$/.test(values['--confirmed-plan-digest'])) fail('m4_operator_argument_invalid');
  return { operation, input: { configPath: values['--config'], maxEvents, ...(operation === 'run' ? { confirmedPlanDigest: values['--confirmed-plan-digest'] } : {}) } };
}
export async function runM4V2BackfillCli(argv = process.argv) { const request = parse(argv); return request.operation === 'plan' ? planM4V2BackfillOperator(request.input) : runM4V2BackfillOperator(request.input); }
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) runM4V2BackfillCli().then(value => process.stdout.write(`${JSON.stringify({ ok: true, ...value })}\n`)).catch(error => { process.stderr.write(`${JSON.stringify({ ok: false, error: error?.code?.startsWith?.('m4_operator_') ? error.code : 'm4_operator_failed' })}\n`); process.exitCode = 78; });
