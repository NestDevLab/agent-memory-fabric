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
