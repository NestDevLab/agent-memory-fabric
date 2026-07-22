#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { planM4ReconciliationCollection,
  runM4ReconciliationCollection } from '../src/operator/m4-reconciliation-collector-operator.mjs';
import { createM4V3ReconciliationSourceFactory } from '../src/operator/m4-v3-reconciliation-source-adapter.mjs';

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function parse(argv) {
  const operation = argv[2];
  if (!['plan', 'run'].includes(operation)) fail('m4_reconciliation_collect_cli_argument_invalid');
  const allowed = operation === 'plan' ? new Set(['--config']) : new Set(['--config', '--confirmed-plan-digest']);
  const values = {};
  for (let index = 3; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if (!allowed.has(name) || values[name] !== undefined || !value || value.startsWith('--')) fail('m4_reconciliation_collect_cli_argument_invalid');
    values[name] = value;
  }
  if ([...allowed].some(name => values[name] === undefined)
    || !path.isAbsolute(values['--config']) || path.normalize(values['--config']) !== values['--config']) {
    fail('m4_reconciliation_collect_cli_argument_invalid');
  }
  if (operation === 'run' && !/^sha256:[a-f0-9]{64}$/.test(values['--confirmed-plan-digest'])) fail('m4_reconciliation_collect_cli_argument_invalid');
  return { operation, request: { configPath: values['--config'],
    ...(operation === 'run' ? { confirmedPlanDigest: values['--confirmed-plan-digest'] } : {}) } };
}

export async function runM4ReconciliationCollectCli(argv = process.argv, rawDependencies = {}) {
  const parsed = parse(argv);
  const dependencies = { ...rawDependencies,
    createSource: createM4V3ReconciliationSourceFactory(rawDependencies) };
  return parsed.operation === 'plan'
    ? planM4ReconciliationCollection(parsed.request, dependencies)
    : runM4ReconciliationCollection(parsed.request, dependencies);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  runM4ReconciliationCollectCli().then(value => process.stdout.write(`${JSON.stringify({ ok: true, ...value })}\n`)).catch(error => {
    const value = typeof error?.code === 'string' && (error.code.startsWith('m4_reconciliation_')
      || error.code.startsWith('m4_v3_reconciliation_')) ? error.code : 'm4_reconciliation_collect_cli_failed';
    process.stderr.write(`${JSON.stringify({ ok: false, error: value })}\n`); process.exitCode = 78;
  });
}
