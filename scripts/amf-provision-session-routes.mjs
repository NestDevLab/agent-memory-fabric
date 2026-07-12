#!/usr/bin/env node
import { provisionSessionRoutes } from '../src/operator/session-route-provisioning.mjs';

function args(argv) {
  const output = { dryRun: false };
  const names = new Map([['--input', 'inputPath'], ['--context-key-ring', 'contextKeyRingPath'],
    ['--manifest', 'manifestPath'], ['--service-owner-uid', 'serviceOwnerUid'], ['--key-version', 'keyVersion']]);
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--dry-run') {
      if (output.dryRun) throw new Error('cli_argument_duplicate');
      output.dryRun = true; continue;
    }
    const name = names.get(argv[index]);
    if (!name) throw new Error('cli_argument_unknown');
    if (Object.hasOwn(output, name)) throw new Error('cli_argument_duplicate');
    if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) throw new Error('cli_argument_value_required');
    output[name] = name === 'serviceOwnerUid' ? Number(argv[++index]) : argv[++index];
  }
  return output;
}

try { process.stdout.write(`${JSON.stringify(provisionSessionRoutes(args(process.argv.slice(2))))}\n`); }
catch (error) { process.stderr.write(`${JSON.stringify({ ok: false, error: error?.message || 'internal_error' })}\n`); process.exitCode = 1; }
