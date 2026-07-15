#!/usr/bin/env node
import { provisionInteractiveRecall } from '../src/operator/interactive-recall-provisioning.mjs';

const VALUE_OPTIONS = new Map([
  ['--profile', 'profile'],
  ['--auth-registry', 'authRegistryPath'],
  ['--policy', 'policyPath'],
  ['--context-key-ring', 'contextKeyRingPath'],
  ['--handoff', 'handoffPath'],
  ['--backup-root', 'backupRoot'],
  ['--backend-user-id', 'backendUserId'],
  ['--service-owner-uid', 'serviceOwnerUid'],
  ['--policy-revision', 'policyRevision'],
  ['--endpoint', 'endpoint']
]);

function parseArguments(argv) {
  const output = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--dry-run') {
      if (Object.hasOwn(output, 'dryRun')) throw new Error('cli_argument_duplicate');
      output.dryRun = true; continue;
    }
    if (!VALUE_OPTIONS.has(option)) throw new Error('cli_argument_unknown');
    const key = VALUE_OPTIONS.get(option); const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error('cli_argument_value_required');
    if (Object.hasOwn(output, key)) throw new Error('cli_argument_duplicate');
    output[key] = value; index += 1;
  }
  if ([...VALUE_OPTIONS.values()].some(key => !Object.hasOwn(output, key))) throw new Error('cli_argument_required');
  output.serviceOwnerUid = Number(output.serviceOwnerUid);
  if (!Number.isSafeInteger(output.serviceOwnerUid) || output.serviceOwnerUid < 0) throw new Error('cli_argument_invalid');
  return output;
}

function safeError(error) {
  const code = String(error?.message || 'interactive_recall_provisioning_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'interactive_recall_provisioning_failed';
}

try {
  process.stdout.write(`${JSON.stringify(provisionInteractiveRecall(parseArguments(process.argv.slice(2))))}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: safeError(error) })}\n`);
  process.exitCode = 1;
}
