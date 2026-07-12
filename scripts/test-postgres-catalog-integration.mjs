import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { FabricStore, MemoryRawStore, PostgresCatalog } from '../src/fabric-store.mjs';

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
  const rawStore = new MemoryRawStore({ encryptionKey: crypto.randomBytes(32).toString('base64'), keyId: `test-${suffix}` });
  let sequence = 0;
  const idFactory = () => `${suffix}-${++sequence}`;
  const clock = () => new Date('2026-07-12T12:00:00.000Z');
  const storeA = new FabricStore({ rawStore, catalog, clock, idFactory, identityPolicy: { allowAutomaticStrongMerge: true } });
  const storeB = new FabricStore({ rawStore, catalog, clock, idFactory, identityPolicy: { allowAutomaticStrongMerge: true } });
  const scope = `person:test-${suffix}`;
  const otherScope = `person:test-other-${suffix}`;
  const evidence = (marker, type = 'operator_attestation') => ({
    type,
    issuer: `integration-${suffix}`,
    observedAt: '2026-07-12T11:00:00.000Z',
    claims: type === 'verified_account'
      ? { provider: 'integration-idp', accountId: `account-${marker}`, verificationId: `verification-${marker}` }
      : { ticketId: `ticket-${marker}`, assertion: `assertion-${marker}` }
  });
  const cleanupContentIds = new Set([contentId]);
  let catalogReady = false;
  try {
    await catalog.ready();
    catalogReady = true;

    // Existing proposal transaction/idempotency baseline.
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) => catalog.enqueueProposalWithRaw({ ...record, id: `${record.id}-${index}` }, raw)));
    assert.equal(results.filter((result) => result.duplicate === false).length, 1);
    assert.equal(new Set(results.map((result) => result.record.id)).size, 1);
    assert.equal((await catalog.getProposal(results[0].record.id)).contentId, contentId);

    // Identity evidence is encrypted outside the catalog; actual PostgreSQL
    // rows carry only opaque tags, references, revisions and response snapshots.
    const source = await storeA.createIdentity({ actor: 'integration-curator', kind: 'person', externalKey: `source-${suffix}`, scope, evidence: evidence('source'), idempotencyKey: `identity-source-${suffix}` });
    const target = await storeA.createIdentity({ actor: 'integration-curator', kind: 'person', externalKey: `target-${suffix}`, scope, evidence: evidence('target'), idempotencyKey: `identity-target-${suffix}` });
    const otherScopeTarget = await storeA.createIdentity({ actor: 'integration-curator', kind: 'person', externalKey: `other-scope-${suffix}`, scope: otherScope, evidence: evidence('other-scope'), idempotencyKey: `identity-other-scope-${suffix}` });
    const crossKindTarget = await storeA.createIdentity({ actor: 'integration-curator', kind: 'agent', externalKey: `agent-${suffix}`, scope, evidence: evidence('agent'), idempotencyKey: `identity-agent-${suffix}` });

    await assert.rejects(storeA.mergeIdentity(source.id, {
      actor: 'integration-curator', scope, targetId: otherScopeTarget.id, expectedRevision: 1,
      evidence: evidence('cross-scope'), automatic: false, idempotencyKey: `merge-cross-scope-${suffix}`
    }), error => error.message === 'identity_not_found' && error.status === 404);
    await assert.rejects(storeA.mergeIdentity(source.id, {
      actor: 'integration-curator', scope, targetId: crossKindTarget.id, expectedRevision: 1,
      evidence: evidence('cross-kind'), automatic: false, idempotencyKey: `merge-cross-kind-${suffix}`
    }), error => error.message === 'identity_not_found' && error.status === 404);

    const mergeInput = {
      actor: 'integration-curator', scope, targetId: target.id, expectedRevision: 1,
      evidence: evidence('strong-merge', 'verified_account'), automatic: true,
      idempotencyKey: `merge-strong-${suffix}`
    };
    const merged = await storeA.mergeIdentity(source.id, mergeInput);
    assert.deepEqual({ status: merged.status, revision: merged.revision, canonicalIdentityId: merged.canonicalIdentityId }, { status: 'merged', revision: 2, canonicalIdentityId: target.id });

    // Two independent FabricStore instances race the same expected revision;
    // PostgreSQL row locking/CAS permits exactly one transition.
    const splitInputs = ['a', 'b'].map(marker => ({
      actor: 'integration-curator', scope, expectedRevision: 2, evidence: evidence(`split-${marker}`), idempotencyKey: `split-${marker}-${suffix}`
    }));
    const splitRace = await Promise.allSettled([
      storeA.splitIdentity(source.id, splitInputs[0]),
      storeB.splitIdentity(source.id, splitInputs[1])
    ]);
    assert.equal(splitRace.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(splitRace.filter(result => result.status === 'rejected' && ['revision_conflict', 'identity_state_conflict'].includes(result.reason.message)).length, 1);
    const split = splitRace.find(result => result.status === 'fulfilled').value;
    assert.deepEqual({ status: split.status, revision: split.revision, canonicalIdentityId: split.canonicalIdentityId }, { status: 'active', revision: 3, canonicalIdentityId: null });
    const immutableMergeReplay = await storeB.mergeIdentity(source.id, mergeInput);
    assert.deepEqual(
      { status: immutableMergeReplay.status, revision: immutableMergeReplay.revision, canonicalIdentityId: immutableMergeReplay.canonicalIdentityId },
      { status: 'merged', revision: 2, canonicalIdentityId: target.id }
    );

    // Retention scope isolation, exact operation replay, tombstone creation and
    // GC candidacy are exercised against real PostgreSQL. RAW remains present.
    const retained = await storeA.propose({
      actor: 'integration-curator', scope, text: `retention-${suffix}`,
      metadata: { originalTimestamp: '2020-01-01T00:00:00.000Z', nativePointer: `native://integration/${suffix}` },
      idempotencyKey: `retention-source-${suffix}`
    });
    cleanupContentIds.add(retained.contentId);
    const deniedPlan = await storeA.planRetention({ asOf: '2026-07-12T12:00:00.000Z', scope: otherScope, limit: 10 }, { allowedScopes: [otherScope] });
    assert.equal(deniedPlan.candidates.some(candidate => candidate.contentId === retained.contentId), false);
    const plan = await storeA.planRetention({ asOf: '2026-07-12T12:00:00.000Z', scope, limit: 10 }, { allowedScopes: [scope] });
    assert.ok(plan.candidates.some(candidate => candidate.contentId === retained.contentId));
    const applyInput = {
      actor: 'integration-curator', idempotencyKey: `retention-apply-${suffix}`,
      candidateIds: [retained.contentId], expectedPlanAsOf: plan.asOf, reason: 'retention_expired'
    };
    const applied = await storeA.applyRetention(applyInput, { allowedScopes: [scope] });
    assert.equal(applied.physicalDeletionPerformed, false);
    assert.equal(applied.results.length, 1);
    assert.equal(applied.results[0].gcCandidate, true);
    assert.equal(rawStore.blobs.has(retained.contentId), true, 'Fabric must never physically delete RAW during retention apply');
    assert.deepEqual(await storeB.applyRetention(applyInput, { allowedScopes: [scope] }), applied, 'real PostgreSQL operation replay must be stable');
    await assert.rejects(storeB.applyRetention({ ...applyInput, reason: 'revoked' }, { allowedScopes: [scope] }), /idempotency_key_conflict/);

    const tombstone = await catalog.pool.query({
      text: `SELECT content_id,content_checksum,source_pointer_tag,reason_code FROM agent_memory_fabric.retention_tombstones_v2 WHERE content_id=$1`,
      values: [retained.contentId]
    });
    assert.equal(tombstone.rows.length, 1);
    assert.equal(tombstone.rows[0].content_checksum, retained.contentId);
    assert.equal(tombstone.rows[0].reason_code, 'retention_expired');
    assert.ok(tombstone.rows[0].source_pointer_tag);

    for (const id of rawStore.blobs.keys()) cleanupContentIds.add(id);
    assert.equal((await catalog.health()).healthy, true);
  } finally {
    // The database-name guard above is mandatory. Cleanup is additionally
    // scoped to unique ids/content hashes created by this test.
    for (const id of rawStore.blobs.keys()) cleanupContentIds.add(id);
    let cleanupClient;
    try {
      if (catalogReady) {
        const ids = [...cleanupContentIds];
        cleanupClient = await catalog.pool.connect();
        await cleanupClient.query('BEGIN');
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.retention_operations_v2 WHERE id LIKE $1`, values: [`${suffix}-%`] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.retention_tombstones_v2 WHERE content_id = ANY($1::text[])`, values: [ids] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.raw_retention_v2 WHERE content_id = ANY($1::text[])`, values: [ids] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.fabric_proposals WHERE id LIKE $1 OR content_id = ANY($2::text[])`, values: [`%${suffix}%`, ids] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.identity_events_v2 WHERE identity_id LIKE $1`, values: [`${suffix}-%`] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.identity_records_v2 WHERE id LIKE $1`, values: [`${suffix}-%`] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.raw_objects_v2 WHERE content_id = ANY($1::text[])`, values: [ids] });
        await cleanupClient.query('COMMIT');
      }
    } catch (cleanupError) {
      try { await cleanupClient?.query('ROLLBACK'); } catch {}
      throw cleanupError;
    } finally {
      cleanupClient?.release();
      await catalog.close();
    }
  }
});
