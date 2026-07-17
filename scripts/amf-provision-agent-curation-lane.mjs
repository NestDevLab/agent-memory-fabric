#!/usr/bin/env node
import { provisionAgentCurationLane } from '../src/operator/agent-curation-lane-provisioning.mjs';

const VALUE_OPTIONS = new Map([
  ['--lane-name', 'laneName'],
  ['--scope', 'scope'],
  ['--auth-registry', 'authRegistryPath'],
  ['--pam-config', 'pamConfigPath'],
  ['--reference-worker-env', 'referenceWorkerEnvPath'],
  ['--curation-root', 'curationRoot'],
  ['--unit-dir', 'unitDir'],
  ['--backup-root', 'backupRoot'],
  ['--service-owner-uid', 'serviceOwnerUid'],
  ['--service-owner-gid', 'serviceOwnerGid'],
  ['--workspace-root', 'workspaceRoot'],
  ['--timer-interval-sec', 'timerIntervalSec']
]);
const REQUIRED = ['authRegistryPath', 'pamConfigPath', 'referenceWorkerEnvPath', 'curationRoot', 'backupRoot', 'serviceOwnerUid', 'serviceOwnerGid'];

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
  if (REQUIRED.some((key) => !Object.hasOwn(output, key))) throw new Error('cli_argument_required');
  return output;
}

function safeError(error) {
  const code = String(error?.message || 'agent_curation_lane_provisioning_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'agent_curation_lane_provisioning_failed';
}

try {
  process.stdout.write(`${JSON.stringify(provisionAgentCurationLane(parseArguments(process.argv.slice(2))))}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ ok: false, error: safeError(error) })}\n`);
  process.exitCode = 1;
}
