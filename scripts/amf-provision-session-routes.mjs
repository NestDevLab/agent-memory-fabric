#!/usr/bin/env node
import { provisionSessionRoutes } from '../src/operator/session-route-provisioning.mjs';

function args(argv) {
  const output = { dryRun: false };
  const names = new Map([['--input', 'inputPath'], ['--context-key-ring', 'contextKeyRingPath'],
    ['--manifest', 'manifestPath'], ['--service-owner-uid', 'serviceOwnerUid']]);
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--dry-run') { output.dryRun = true; continue; }
    const name = names.get(argv[index]);
    if (!name || index + 1 >= argv.length) throw new Error('cli_argument_unknown');
    output[name] = name === 'serviceOwnerUid' ? Number(argv[++index]) : argv[++index];
  }
  return output;
}

try { process.stdout.write(`${JSON.stringify(provisionSessionRoutes(args(process.argv.slice(2))))}\n`); }
catch (error) { process.stderr.write(`${JSON.stringify({ ok: false, error: error?.message || 'internal_error' })}\n`); process.exitCode = 1; }
