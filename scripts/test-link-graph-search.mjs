import assert from 'node:assert/strict';
import test from 'node:test';
import { buildContextSearchResult } from '../src/server.mjs';

const memory = { items: [], scopes: ['work-wiki'] };
const docs = [{ documentId: 'doc_a', path: 'A.md' }, { documentId: 'doc_b', path: 'B.md' }];

test('graph off: no graph source, docs unchanged', async () => {
  const linkGraph = { configured: false, async expand() { return []; } };
  const r = await buildContextSearchResult({ memoryResult: memory, documents: docs, linkGraph, vaults: ['work-wiki'], limit: 20 });
  assert.equal(r.sources.graph, 0);
  assert.ok(!r.items.some(i => i.source === 'graph'));
});

test('graph on: appends new graph docs, tagged', async () => {
  const linkGraph = { configured: true, async expand() { return [{ documentId: 'doc_z', source: 'graph', distance: 1, seed: 'doc_a' }]; } };
  const r = await buildContextSearchResult({ memoryResult: memory, documents: docs, linkGraph, vaults: ['work-wiki'], limit: 20 });
  assert.equal(r.sources.graph, 1);
  assert.ok(r.items.some(i => i.documentId === 'doc_z' && i.source === 'graph'));
});

test('graph on: never duplicates a doc already in results', async () => {
  const linkGraph = { configured: true, async expand() { return [{ documentId: 'doc_b', source: 'graph', distance: 1, seed: 'doc_a' }]; } };
  const r = await buildContextSearchResult({ memoryResult: memory, documents: docs, linkGraph, vaults: ['work-wiki'], limit: 20 });
  assert.equal(r.sources.graph, 0);
});
