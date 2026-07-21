import assert from 'node:assert/strict';
import test from 'node:test';
import { LinkGraph } from '../src/link-graph.mjs';
import { resolveTargets } from './amf-reindex-graph.mjs';

const URL = process.env.AMF_TEST_DATABASE_URL;
const maybe = URL ? test : test.skip;

async function fresh() {
  const g = new LinkGraph({ connectionString: URL });
  await g.ensureSchema();
  await g.pool.query('TRUNCATE agent_memory_fabric.document_links_v1');
  return g;
}

maybe('replaceDocumentEdges then listSrcDocumentIds', async () => {
  const g = await fresh();
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [
    { targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }
  ]);
  assert.deepEqual(await g.listSrcDocumentIds(), ['doc_a']);
  await g.close();
});

maybe('replace is idempotent and overwrites prior edges', async () => {
  const g = await fresh();
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [
    { targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }
  ]);
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [
    { targetRaw: 'C', targetPath: 'C.md', dstDocumentId: 'doc_c', alias: null }
  ]);
  const rows = (await g.pool.query('SELECT target_raw FROM agent_memory_fabric.document_links_v1 WHERE src_document_id=$1', ['doc_a'])).rows;
  assert.deepEqual(rows.map(r => r.target_raw), ['C']);
  await g.close();
});

maybe('pruneDocuments removes edges for vanished sources', async () => {
  const g = await fresh();
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [{ targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }]);
  await g.replaceDocumentEdges('doc_x', 'work-wiki', 'X.md', [{ targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }]);
  await g.pruneDocuments(['doc_a']);
  assert.deepEqual(await g.listSrcDocumentIds(), ['doc_a']);
  await g.close();
});

async function seedChain(g) {
  await g.pool.query('TRUNCATE agent_memory_fabric.document_links_v1');
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [{ targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }]);
  await g.replaceDocumentEdges('doc_b', 'work-wiki', 'B.md', [{ targetRaw: 'C', targetPath: 'C.md', dstDocumentId: 'doc_c', alias: null }]);
  await g.replaceDocumentEdges('doc_c', 'work-wiki', 'C.md', [{ targetRaw: 'A', targetPath: 'A.md', dstDocumentId: 'doc_a', alias: null }]);
}

maybe('neighbors depth 1 returns direct targets only', async () => {
  const g = await fresh(); await seedChain(g);
  const n = await g.neighbors({ documentId: 'doc_a', vaults: ['work-wiki'], depth: 1 });
  assert.deepEqual(n, [{ documentId: 'doc_b', distance: 1 }]);
  await g.close();
});

maybe('neighbors depth 2 expands, cycle-safe', async () => {
  const g = await fresh(); await seedChain(g);
  const n = await g.neighbors({ documentId: 'doc_a', vaults: ['work-wiki'], depth: 2 });
  assert.deepEqual(n.map(r => r.documentId).sort(), ['doc_b', 'doc_c']);
  await g.close();
});

maybe('neighbors excludes other vaults (ACL)', async () => {
  const g = await fresh(); await seedChain(g);
  const n = await g.neighbors({ documentId: 'doc_a', vaults: ['other-vault'], depth: 2 });
  assert.deepEqual(n, []);
  await g.close();
});

maybe('backlinks returns sources pointing at target', async () => {
  const g = await fresh(); await seedChain(g);
  const b = await g.backlinks({ documentId: 'doc_b', vaults: ['work-wiki'] });
  assert.deepEqual(b, [{ documentId: 'doc_a' }]);
  await g.close();
});

maybe('related ranks by shared targets', async () => {
  const g = await fresh();
  await g.pool.query('TRUNCATE agent_memory_fabric.document_links_v1');
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [
    { targetRaw: 'X', targetPath: 'X.md', dstDocumentId: 'doc_x', alias: null },
    { targetRaw: 'Y', targetPath: 'Y.md', dstDocumentId: 'doc_y', alias: null }
  ]);
  await g.replaceDocumentEdges('doc_b', 'work-wiki', 'B.md', [
    { targetRaw: 'X', targetPath: 'X.md', dstDocumentId: 'doc_x', alias: null },
    { targetRaw: 'Y', targetPath: 'Y.md', dstDocumentId: 'doc_y', alias: null }
  ]);
  await g.replaceDocumentEdges('doc_c', 'work-wiki', 'C.md', [
    { targetRaw: 'X', targetPath: 'X.md', dstDocumentId: 'doc_x', alias: null }
  ]);
  const r = await g.related({ documentId: 'doc_a', vaults: ['work-wiki'], limit: 10 });
  assert.deepEqual(r, [{ documentId: 'doc_b', shared: 2 }, { documentId: 'doc_c', shared: 1 }]);
  await g.close();
});

maybe('shortestPath finds A..C over chain', async () => {
  const g = await fresh();
  await g.replaceDocumentEdges('doc_a', 'work-wiki', 'A.md', [{ targetRaw: 'B', targetPath: 'B.md', dstDocumentId: 'doc_b', alias: null }]);
  await g.replaceDocumentEdges('doc_b', 'work-wiki', 'B.md', [{ targetRaw: 'C', targetPath: 'C.md', dstDocumentId: 'doc_c', alias: null }]);
  const p = await g.shortestPath({ fromId: 'doc_a', toId: 'doc_c', vaults: ['work-wiki'], maxDepth: 4 });
  assert.deepEqual(p, ['doc_a', 'doc_b', 'doc_c']);
  await g.close();
});

maybe('shortestPath returns [] when unreachable within depth', async () => {
  const g = await fresh(); await seedChain(g);
  const p = await g.shortestPath({ fromId: 'doc_a', toId: 'doc_missing', vaults: ['work-wiki'], maxDepth: 4 });
  assert.deepEqual(p, []);
  await g.close();
});

test('resolveTargets resolves exact and .md-suffixed paths, keeps danglers', () => {
  const pathToDocId = new Map([['B.md', 'doc_b'], ['Projects/agentBerry.md', 'doc_ab']]);
  const edges = resolveTargets({
    links: [
      { target: 'B', alias: null },
      { target: 'Projects/agentBerry', alias: 'bot' },
      { target: 'Ghost Note', alias: null }
    ],
    pathToDocId
  });
  assert.deepEqual(edges, [
    { targetRaw: 'B', alias: null, targetPath: 'B.md', dstDocumentId: 'doc_b' },
    { targetRaw: 'Projects/agentBerry', alias: 'bot', targetPath: 'Projects/agentBerry.md', dstDocumentId: 'doc_ab' },
    { targetRaw: 'Ghost Note', alias: null, targetPath: null, dstDocumentId: null }
  ]);
});
