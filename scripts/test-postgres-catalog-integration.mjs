import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { PostgresCatalog } from '../src/fabric-store.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';

test('real PostgreSQL catalog integration in an explicitly isolated test database', { skip: !enabled }, async () => {
  const databaseName = decodeURIComponent(new URL(connectionString).pathname.replace(/^\//, ''));
  assert.match(databaseName, /(^|[-_])test($|[-_])/i, 'AMF_TEST_POSTGRES_URL must reference an isolated test database');
  const catalog = new PostgresCatalog({ connectionString, ssl: process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? false : { rejectUnauthorized: true } });
  const suffix = crypto.randomUUID();
  const contentId = crypto.createHash('sha256').update(suffix).digest('hex');
  const record = {
    id: `proposal-${suffix}`, ownerTag: `owner-${suffix}`, scopeTag: `scope-${suffix}`, status: 'queued', contentId,
    idempotencyTag: `idempotency-${suffix}`, sourceTag: `source-${suffix}`, createdAt: new Date().toISOString()
  };
  const raw = { contentId, mediaType: 'application/vnd.agent-memory-fabric.proposal+json', byteLength: 1, storageRef: `${contentId}.enc.json`, createdAt: record.createdAt };
  try {
    await catalog.ready();
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) => catalog.enqueueProposalWithRaw({ ...record, id: `${record.id}-${index}` }, raw)));
    assert.equal(results.filter((result) => result.duplicate === false).length, 1);
    assert.equal(new Set(results.map((result) => result.record.id)).size, 1);
    assert.equal((await catalog.getProposal(results[0].record.id)).contentId, contentId);
    assert.equal((await catalog.health()).healthy, true);
  } finally {
    await catalog.close();
  }
});
