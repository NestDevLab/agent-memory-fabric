#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  aggregatePauseCheckpointInputs,
  createPauseManifest,
  migrationPauseLimits,
  readMigrationKeyFile,
  readPauseCheckpointInput,
  readPauseCollectorRoster,
  readPauseManifestFile,
  verifyAggregatePauseCheckpointInput,
  verifyPauseManifestAgainstCheckpointInputs,
  verifyPauseManifestFiles,
  writeOwnerOnlyAtomic
} from '../src/migration-pause.mjs';

const COMMANDS = Object.freeze({
  aggregate: { singles: ['--roster', '--output'], repeated: ['--input'] },
  generate: { singles: ['--input', '--roster', '--key-file', '--output'], repeated: ['--checkpoint'] },
  verify: { singles: ['--manifest', '--key-file'], repeated: [] },
  'verify-set': { singles: ['--manifest', '--roster', '--key-file'], repeated: ['--input'] }
});

function invalidArgument() {
  return Object.assign(new Error('migration_pause_argument_invalid'), { code: 'migration_pause_argument_invalid' });
}

function parseArguments(argv) {
  const command = argv[2]; const spec = COMMANDS[command];
  if (!spec) throw Object.assign(new Error('migration_pause_command_invalid'), { code: 'migration_pause_command_invalid' });
  const values = Object.fromEntries(spec.repeated.map(name => [name, []]));
  for (let index = 3; index < argv.length; index += 2) {
    const name = argv[index]; const value = argv[index + 1];
    if ((!spec.singles.includes(name) && !spec.repeated.includes(name)) || !value || value.startsWith('--')) throw invalidArgument();
    if (spec.singles.includes(name)) {
      if (values[name] !== undefined) throw invalidArgument();
      values[name] = value;
    } else {
      values[name].push(value);
      if (values[name].length > migrationPauseLimits.maxCheckpointInputs) throw invalidArgument();
    }
  }
  for (const name of spec.singles) if (!values[name]) throw invalidArgument();
  for (const name of spec.repeated) if (!values[name].length) throw invalidArgument();
  for (const value of Object.values(values).flat()) if (!path.isAbsolute(value)) throw invalidArgument();
  return { command, values };
}

export function runMigrationPauseCli() {
  const { command, values } = parseArguments(process.argv);
  if (command === 'aggregate') {
    const roster = readPauseCollectorRoster(values['--roster']);
    const aggregate = aggregatePauseCheckpointInputs(values['--input'].map(readPauseCheckpointInput), roster);
    writeOwnerOnlyAtomic(values['--output'], aggregate);
    return { ok: true, operation: 'aggregate', manifestId: aggregate.manifestId,
      revision: aggregate.revision, collectorCount: roster.collectors.length };
  }
  if (command === 'generate') {
    const roster = readPauseCollectorRoster(values['--roster']);
    const inputs = values['--checkpoint'].map(readPauseCheckpointInput);
    const aggregate = verifyAggregatePauseCheckpointInput(readPauseCheckpointInput(values['--input']), inputs, roster);
    const manifest = createPauseManifest(aggregate, readMigrationKeyFile(values['--key-file']));
    writeOwnerOnlyAtomic(values['--output'], manifest);
    return { ok: true, operation: 'generate', manifestId: manifest.manifestId, phase: 'pause', revision: manifest.revision };
  }
  if (command === 'verify') {
    const verified = verifyPauseManifestFiles(values['--manifest'], values['--key-file']);
    return { ok: true, operation: 'verify', manifestId: verified.manifestId, phase: 'pause', revision: verified.revision, state: verified.state, health: verified.health };
  }
  const roster = readPauseCollectorRoster(values['--roster']);
  const inputs = values['--input'].map(readPauseCheckpointInput);
  const manifest = readPauseManifestFile(values['--manifest']);
  const verified = verifyPauseManifestAgainstCheckpointInputs(manifest, readMigrationKeyFile(values['--key-file']), inputs, roster);
  return { ok: true, operation: 'verify-set', manifestId: verified.manifestId, phase: 'pause', revision: verified.revision,
    state: verified.state, health: verified.health, collectorCount: roster.collectors.length };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  try {
    process.stdout.write(`${JSON.stringify(runMigrationPauseCli())}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: error?.code?.startsWith?.('migration_pause_') ? error.code : 'migration_pause_failed' })}\n`);
    process.exitCode = 78;
  }
}
