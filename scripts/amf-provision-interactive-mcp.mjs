#!/usr/bin/env node
import { provisionInteractiveMcp } from '../src/operator/interactive-mcp-provisioning.mjs';

const VALUE_OPTIONS = new Map([
  ['--runtime', 'runtime'], ['--auth-registry', 'authRegistryPath'], ['--policy', 'policyPath'],
  ['--context-key-ring', 'contextKeyRingPath'], ['--handoff', 'handoffPath'], ['--backup-root', 'backupRoot'],
  ['--backend-user-id', 'backendUserId'], ['--service-owner-uid', 'serviceOwnerUid'],
  ['--policy-revision', 'policyRevision'], ['--endpoint', 'endpoint']
]);
function parseArguments(argv) {
  const output = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--dry-run') { if (output.dryRun) throw new Error('cli_argument_duplicate'); output.dryRun = true; continue; }
    if (option === '--read-scope' || option === '--propose-scope' || option === '--read-vault' || option === '--write-vault' || option === '--tool') {
      const value = argv[++index]; if (!value || value.startsWith('--')) throw new Error('cli_argument_value_required');
      const key = option === '--read-scope' ? 'readScopes' : option === '--propose-scope' ? 'proposeScopes'
        : option === '--read-vault' ? 'readVaults' : option === '--write-vault' ? 'writeVaults' : 'tools';
      (output[key] ||= []).push(value); continue;
    }
    const key = VALUE_OPTIONS.get(option); const value = argv[++index];
    if (!key) throw new Error('cli_argument_unknown');
    if (!value || value.startsWith('--') || Object.hasOwn(output, key)) throw new Error('cli_argument_value_required');
    output[key] = value;
  }
  if ([...VALUE_OPTIONS.values()].some(key => !Object.hasOwn(output, key)) || !output.readScopes?.length || !output.proposeScopes?.length
    || !output.readVaults?.length || !output.writeVaults?.length || !output.tools?.length) throw new Error('cli_argument_required');
  output.serviceOwnerUid = Number(output.serviceOwnerUid);
  if (!Number.isSafeInteger(output.serviceOwnerUid) || output.serviceOwnerUid < 0) throw new Error('cli_argument_invalid');
  return output;
}
try { process.stdout.write(`${JSON.stringify(provisionInteractiveMcp(parseArguments(process.argv.slice(2))))}\n`); }
catch (error) { process.stderr.write(`${JSON.stringify({ ok: false, error: /^[a-z0-9_]{1,128}$/.test(String(error?.message || '')) ? error.message : 'interactive_mcp_provisioning_failed' })}\n`); process.exitCode = 1; }
