#!/usr/bin/env node
import { createCanonicalPamBridgeFromEnv } from '../src/canonical-memory-bridge.mjs';
import { reindexSemanticIndex } from '../src/semantic-index.mjs';

async function main() {
  const bridge = createCanonicalPamBridgeFromEnv(process.env);
  if (!bridge.configured) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: 'canonical_store_unconfigured' })}\n`);
    process.exitCode = 1;
    return;
  }
  if (!bridge.semanticIndex?.configured) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: 'semantic_index_unconfigured' })}\n`);
    process.exitCode = 1;
    if (typeof bridge.close === 'function') await bridge.close();
    return;
  }
  try {
    const result = await reindexSemanticIndex({
      semanticIndex: bridge.semanticIndex,
      bridge,
      log: (message) => process.stderr.write(`${message}\n`)
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exitCode = result.ok ? 0 : 1;
  } finally {
    if (typeof bridge.close === 'function') await bridge.close();
  }
}

main().catch((error) => {
  const code = String(error?.message || 'semantic_reindex_failed');
  process.stderr.write(`${JSON.stringify({ ok: false, error: /^[a-z0-9_]{1,128}$/.test(code) ? code : 'semantic_reindex_failed' })}\n`);
  process.exitCode = 1;
});
