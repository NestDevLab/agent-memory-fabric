#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  createPauseManifest,
  readMigrationKeyFile,
  readPauseCheckpointInput,
  verifyPauseManifestFiles,
  writeOwnerOnlyAtomic
} from '../src/migration-pause.mjs';

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : '';
}

function requiredAbsolute(name) {
  const value = argument(name);
  if (!value || !path.isAbsolute(value)) throw Object.assign(new Error('migration_pause_argument_invalid'), { code: 'migration_pause_argument_invalid' });
  return value;
}

export function runMigrationPauseCli() {
  const command = process.argv[2];
  if (command === 'generate') {
    const inputPath = requiredAbsolute('--input');
    const keyPath = requiredAbsolute('--key-file');
    const outputPath = requiredAbsolute('--output');
    const manifest = createPauseManifest(readPauseCheckpointInput(inputPath), readMigrationKeyFile(keyPath));
    writeOwnerOnlyAtomic(outputPath, manifest);
    return { ok: true, operation: 'generate', manifestId: manifest.manifestId, phase: 'pause', revision: manifest.revision };
  }
  if (command === 'verify') {
    const manifestPath = requiredAbsolute('--manifest');
    const keyPath = requiredAbsolute('--key-file');
    const verified = verifyPauseManifestFiles(manifestPath, keyPath);
    return { ok: true, operation: 'verify', manifestId: verified.manifestId, phase: 'pause', revision: verified.revision, state: verified.state, health: verified.health };
  }
  throw Object.assign(new Error('migration_pause_command_invalid'), { code: 'migration_pause_command_invalid' });
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
