#!/usr/bin/env node
// Deprecated compatibility CLI; canonical mode parsing and gate checks live in
// amf-conversation-memory-extractor.mjs.
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { main } from './amf-conversation-memory-extractor.mjs';
export * from './amf-conversation-memory-extractor.mjs';
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(value => process.stdout.write(`${value}\n`)).catch(error => { process.stderr.write(`${/^quality_|^extractor_/.test(error?.message || '') ? error.message : 'extractor_failed'}\n`); process.exitCode = 1; });
}
