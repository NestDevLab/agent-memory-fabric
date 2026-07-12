#!/usr/bin/env node
import { provisionRawCollector } from '../src/operator/raw-collector-provisioning.mjs';

const VALUE_OPTIONS = new Map([
  ['--auth-registry', 'authRegistryPath'],
  ['--policy', 'policyPath'],
  ['--ingest-key-ring', 'ingestKeyRingPath'],
  ['--routing-key-ring', 'routingKeyRingPath'],
  ['--actor', 'actorId'],
  ['--source-instance', 'sourceInstanceId'],
  ['--key-id', 'keyId'],
  ['--handoff', 'handoffPath'],
  ['--backup-root', 'backupRoot'],
  ['--service-owner-uid', 'serviceOwnerUid']
]);
const FLAG_OPTIONS = new Map([['--dry-run', 'dryRun']]);

function parseArguments(argv) {
  const output = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (FLAG_OPTIONS.has(option)) {
      const key = FLAG_OPTIONS.get(option);
      if (Object.hasOwn(output, key)) throw new Error('cli_argument_duplicate');
      output[key] = true; continue;
    }
    if (!VALUE_OPTIONS.has(option)) throw new Error('cli_argument_unknown');
    const key = VALUE_OPTIONS.get(option); const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error('cli_argument_value_required');
    if (Object.hasOwn(output, key)) throw new Error('cli_argument_duplicate');
    output[key] = value; index += 1;
  }
  const required = [...VALUE_OPTIONS.values()];
  if (required.some(key => !Object.hasOwn(output, key))) throw new Error('cli_argument_required');
  output.serviceOwnerUid = Number(output.serviceOwnerUid);
  if (!Number.isSafeInteger(output.serviceOwnerUid) || output.serviceOwnerUid < 0) throw new Error('cli_argument_invalid');
  return output;
}

function safeError(error) {
  const code = String(error?.message || 'collector_provisioning_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'collector_provisioning_failed';
}

try {
  const result = provisionRawCollector(parseArguments(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: safeError(error) })}\n`);
  process.exitCode = 1;
}
