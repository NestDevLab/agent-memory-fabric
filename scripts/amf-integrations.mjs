#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

import { describeIntegration, listIntegrations } from '../src/integrations/catalog.mjs';
import {
  adoptIntegration,
  buildPlan,
  disableIntegration,
  enableIntegration,
  installIntegration,
  integrationStatus,
  loadConfirmedPlan,
  runIntegration,
  serializePlan,
  uninstallIntegration,
} from '../src/integrations/lifecycle.mjs';
import {
  buildHarnessRawCapturePlan,
  disableHarnessRawCapture,
  enableHarnessRawCapture,
  harnessRawCaptureStatus,
  installHarnessRawCapture,
  loadConfirmedHarnessRawCapturePlan,
  runHarnessRawCapture,
  serializeHarnessRawCapturePlan,
  uninstallHarnessRawCapture,
} from '../src/integrations/harness-raw-capture.mjs';

const cliArgs = process.argv.slice(2);
if (cliArgs[0] === 'integrations') cliArgs.shift();
const command = cliArgs[0];
const id = cliArgs[1];

function usage() {
  process.stderr.write(`usage:
  amf integrations list
  amf integrations describe <id>
  amf integrations plan <id> --instance ID --vault PATH --vault-id ID --actor ACTOR --amf-url URL --source-instance ID --client-root PATH --service-user USER --service-group GROUP --interval-sec N --jitter-sec N --output PATH
  amf integrations plan harness-raw-capture --instance ID --runtime codex|claude --adapter-root PATH --runtime-config PATH --environment-file PATH --trigger-path PATH --capture-mode hook-push --conflict-policy fail|disable-managed --max-triggers-per-pass N --output PATH
  amf integrations status <id> --instance ID
  amf integrations <install|adopt|run|enable|disable|uninstall> <id> --plan PATH --confirm-sha256 HEX\n`);
}

function output(value) { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`); }

function options(definitions) {
  const { values, positionals } = parseArgs({ args: cliArgs.slice(2), options: definitions, allowPositionals: true, strict: true });
  if (positionals.length) throw new Error(`integration_unexpected_argument:${positionals[0]}`);
  return values;
}

function required(values, names) {
  for (const name of names) if (values[name] === undefined || values[name] === '') throw new Error(`integration_option_required:${name}`);
}

function writePlan(target, bytes) {
  if (!path.isAbsolute(target) || path.normalize(target) !== target) throw new Error('integration_path_invalid:output');
  const parent = path.dirname(target);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) throw new Error('integration_path_unsafe:output');
  const temporary = path.join(parent, `.${path.basename(target)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, target);
  } catch (error) {
    try { fs.unlinkSync(temporary); } catch { /* no residue */ }
    throw error;
  }
}

function loadMutationPlan() {
  const values = options({
    plan: { type: 'string' },
    'confirm-sha256': { type: 'string' },
  });
  required(values, ['plan', 'confirm-sha256']);
  const plan = id === 'harness-raw-capture'
    ? loadConfirmedHarnessRawCapturePlan(values.plan, values['confirm-sha256'])
    : loadConfirmedPlan(values.plan, values['confirm-sha256']);
  if (plan.integrationId !== id) throw new Error('integration_plan_id_mismatch');
  return plan;
}

async function main() {
  if (command === 'list' && !id) return output(listIntegrations().map(item => ({ id: item.id, category: item.category, version: item.version, capabilities: item.capabilities })));
  if (command === 'describe' && id) return output(describeIntegration(id));
  if (command === 'plan' && id) {
    if (id === 'harness-raw-capture') {
      const values = options({ instance: { type: 'string' }, runtime: { type: 'string' },
        'adapter-root': { type: 'string' }, 'runtime-config': { type: 'string' },
        'environment-file': { type: 'string' }, 'trigger-path': { type: 'string' },
        'capture-mode': { type: 'string' }, 'conflict-policy': { type: 'string' },
        'max-triggers-per-pass': { type: 'string' }, output: { type: 'string' } });
      required(values, ['instance', 'runtime', 'adapter-root', 'runtime-config', 'environment-file', 'trigger-path',
        'capture-mode', 'conflict-policy', 'max-triggers-per-pass', 'output']);
      const plan = buildHarnessRawCapturePlan(id, { instance: values.instance, runtime: values.runtime,
        adapterRoot: values['adapter-root'], runtimeConfig: values['runtime-config'],
        environmentFile: values['environment-file'], triggerPath: values['trigger-path'],
        captureMode: values['capture-mode'], conflictPolicy: values['conflict-policy'],
        maxTriggersPerPass: Number(values['max-triggers-per-pass']) });
      const bytes = serializeHarnessRawCapturePlan(plan); writePlan(values.output, bytes);
      return output({ written: values.output, sha256: (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex'), planDigest: plan.planDigest });
    }
    const values = options({
      instance: { type: 'string' }, vault: { type: 'string' }, 'vault-id': { type: 'string' }, actor: { type: 'string' },
      'amf-url': { type: 'string' }, 'source-instance': { type: 'string' }, 'client-root': { type: 'string' },
      'service-user': { type: 'string' }, 'service-group': { type: 'string' }, 'interval-sec': { type: 'string' },
      'jitter-sec': { type: 'string' }, output: { type: 'string' },
    });
    required(values, ['instance', 'vault', 'vault-id', 'actor', 'amf-url', 'source-instance', 'client-root', 'service-user', 'service-group', 'interval-sec', 'jitter-sec', 'output']);
    const plan = buildPlan(id, {
      instance: values.instance,
      vault: values.vault,
      vaultId: values['vault-id'],
      actor: values.actor,
      amfUrl: values['amf-url'],
      sourceInstance: values['source-instance'],
      clientRoot: values['client-root'],
      serviceUser: values['service-user'],
      serviceGroup: values['service-group'],
      intervalSec: Number(values['interval-sec']),
      jitterSec: Number(values['jitter-sec']),
    });
    const bytes = serializePlan(plan);
    writePlan(values.output, bytes);
    return output({ written: values.output, sha256: (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex'), planDigest: plan.planDigest });
  }
  if (command === 'status' && id) {
    const values = options({ instance: { type: 'string' } });
    required(values, ['instance']);
    return output(id === 'harness-raw-capture'
      ? harnessRawCaptureStatus(id, values.instance) : integrationStatus(id, values.instance));
  }
  if (['install', 'adopt', 'run', 'enable', 'disable', 'uninstall'].includes(command) && id) {
    const plan = loadMutationPlan();
    if (id === 'harness-raw-capture') {
      if (command === 'adopt') throw new Error('integration_operation_unsupported');
      const handlers = { install: installHarnessRawCapture, run: runHarnessRawCapture,
        enable: enableHarnessRawCapture, disable: disableHarnessRawCapture, uninstall: uninstallHarnessRawCapture };
      return output(handlers[command](plan));
    }
    const handlers = { install: installIntegration, adopt: adoptIntegration, run: runIntegration, enable: enableIntegration, disable: disableIntegration, uninstall: uninstallIntegration };
    return output(handlers[command](plan));
  }
  usage();
  process.exitCode = 64;
}

main().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
