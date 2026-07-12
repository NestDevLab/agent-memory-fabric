import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { FabricStore, MemoryRawStore, POSTGRES_SCHEMA_VERSION, PostgresCatalog } from '../src/fabric-store.mjs';

const connectionString = String(process.env.AMF_TEST_POSTGRES_URL || '').trim();
const enabled = connectionString && process.env.AMF_TEST_POSTGRES_ALLOW_MUTATION === 'true';

function digest(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function opaque(namespace, value) { return `hmac-sha256:integration:${digest(`${namespace}:${value}`)}`; }
function rawV2Fixture({ suffix, marker, sessionId, role, actor, sender, conversation = 'conversation-a', room = 'room-a', thread = null }) {
  const eventId = `evt_${digest(`${suffix}:event:${marker}`)}`;
  const logicalMessageId = `lmsg_${digest(`${suffix}:logical:${marker}`)}`;
  const contentId = digest(`${suffix}:content:${marker}`);
  const contextTags = {
    actor: [opaque('actor', actor)], sender: [opaque('sender', sender)],
    conversation: [opaque('conversation', conversation)], room: [opaque('room', room)],
    ...(thread ? { thread: [opaque('thread', thread)] } : {})
  };
  const projection = {
    schema: 'amf.raw-event-projection/v2', eventId, sessionId, logicalMessageId, logicalMessageAliases: [],
    derivationVersion: 'amf-logical-message/v1', keyVersion: 'integration', sourceKind: 'hermes', observationClass: 'native',
    direction: role === 'assistant' ? 'outbound' : 'inbound', conversationKind: 'group', contextTags, subtype: 'message',
    occurredAt: `2026-07-12T12:00:0${marker}.000Z`, editedAt: null, nativeRevision: Number(marker), sourceSequence: Number(marker),
    authoritativeDeletion: false, role, contentType: 'text', contentParts: 1, hasContent: true,
    normalizationVersion: 'amf-observation-normalization/v1', normalizedPayloadDigest: `hmac-sha256:integration:${digest(`${suffix}:payload:${marker}`)}`
  };
  return {
    record: { eventId, sessionId, logicalMessageId, contentId, payloadDigest: `hmac-sha256:integration:${digest(`${suffix}:cipher:${marker}`)}`, projection, ownerTag: opaque('owner', actor), sourceTag: opaque('source', actor), createdAt: projection.occurredAt },
    raw: { contentId, mediaType: 'application/vnd.agent-memory-fabric.raw-event-ciphertext+json', byteLength: 1, storageRef: `integration/${contentId}.enc.json`, createdAt: projection.occurredAt }
  };
}

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
  const cleanupSessionIds = new Set();
  let catalogReady = false;
  try {
    await catalog.ready();
    catalogReady = true;
    const readinessStore = new FabricStore({ rawStore, catalog, clock, idFactory, legacyV1Writes: false });
    await readinessStore.ready();
    assert.equal(readinessStore.status().rawProjectionV2Ready, true);
    assert.equal(readinessStore.status().rawProjectionV2ReadinessReason, null);
    const migrationProof = await catalog.pool.query('SELECT schema_version,backend,alias_orphan_count,legacy_field_count,literal_scan_count FROM agent_memory_fabric.raw_projection_v2_migration_state WHERE singleton=1');
    assert.deepEqual({ schemaVersion: Number(migrationProof.rows[0].schema_version), backend: migrationProof.rows[0].backend, aliasOrphans: Number(migrationProof.rows[0].alias_orphan_count), legacyFields: Number(migrationProof.rows[0].legacy_field_count), literalTags: Number(migrationProof.rows[0].literal_scan_count) }, { schemaVersion: POSTGRES_SCHEMA_VERSION, backend: 'postgres', aliasOrphans: 0, legacyFields: 0, literalTags: 0 });

    // A schema-6 row is backfilled on startup while preserving the former
    // full context metadata for binary rollback compatibility.
    const legacySessionId = `ses_${digest(`${suffix}:legacy-session`)}`;
    cleanupSessionIds.add(legacySessionId);
    const legacyContext = { actor: [opaque('actor', 'legacy')], sender: [opaque('sender', 'legacy')], conversation: [opaque('conversation', 'legacy')], room: [opaque('room', 'legacy')] };
    await catalog.pool.query({
      text: `INSERT INTO agent_memory_fabric.raw_sessions_v1(session_id,runtime,owner_tag,source_tag,conversation_kind,context_tags_json,session_binding_json,first_occurred_at,last_occurred_at,event_count,created_at) VALUES ($1,'hermes',$2,$3,'group',$4::jsonb,NULL,now(),now(),0,now())`,
      values: [legacySessionId, opaque('owner', 'legacy'), opaque('source', 'legacy'), JSON.stringify(legacyContext)]
    });
    const migrationCatalog = new PostgresCatalog({ connectionString, ssl: process.env.AMF_TEST_POSTGRES_SSL === 'disable' ? false : { rejectUnauthorized: true } });
    await migrationCatalog.ready();
    const migratedSession = await migrationCatalog.pool.query({ text: 'SELECT context_tags_json,session_binding_json FROM agent_memory_fabric.raw_sessions_v1 WHERE session_id=$1', values: [legacySessionId] });
    assert.deepEqual(migratedSession.rows[0].context_tags_json, legacyContext);
    assert.deepEqual(migratedSession.rows[0].session_binding_json, { conversation: legacyContext.conversation, room: legacyContext.room });
    await migrationCatalog.close();

    // Multi-role/realtime/backfill events share one session. Actor, sender and
    // source tags remain event-local; room/thread changes fail closed.
    const rawSessionId = `ses_${digest(`${suffix}:multi-role-session`)}`;
    cleanupSessionIds.add(rawSessionId);
    const userEvent = rawV2Fixture({ suffix, marker: '1', sessionId: rawSessionId, role: 'user', actor: 'person', sender: 'person' });
    const systemEvent = rawV2Fixture({ suffix, marker: '2', sessionId: rawSessionId, role: 'system', actor: 'system', sender: 'system' });
    const assistantEvent = rawV2Fixture({ suffix, marker: '3', sessionId: rawSessionId, role: 'assistant', actor: 'assistant', sender: 'assistant' });
    for (const fixture of [userEvent, systemEvent, assistantEvent]) {
      cleanupContentIds.add(fixture.record.contentId);
      const result = await catalog.ingestRawEventV2(fixture.record, fixture.raw, { id: `${suffix}-raw-audit-${fixture.record.eventId}`, ts: fixture.record.createdAt, actorTag: fixture.record.ownerTag, action: 'raw_event_ingest', targetId: fixture.record.eventId, details: {} });
      assert.equal(result.duplicate, false);
    }
    const retry = await catalog.ingestRawEventV2(assistantEvent.record, assistantEvent.raw, { id: `${suffix}-raw-audit-retry`, ts: assistantEvent.record.createdAt, actorTag: assistantEvent.record.ownerTag, action: 'raw_event_ingest', targetId: assistantEvent.record.eventId, details: {} });
    assert.equal(retry.duplicate, true);
    const persistedEvents = await catalog.listSessionEvents(rawSessionId);
    assert.equal(persistedEvents.length, 3);
    assert.equal(new Set(persistedEvents.map(event => event.ownerTag)).size, 3);
    assert.equal(await catalog.hasSessionParticipant(rawSessionId, [opaque('owner', 'assistant')]), true);
    assert.equal(await catalog.hasSessionParticipant(rawSessionId, [opaque('owner', 'outsider')]), false);
    assert.deepEqual(await catalog.listSessionEventsPage({ id: rawSessionId, offset: 0, limit: 2 }).then(page => ({ count: page.items.length, hasMore: page.hasMore })), { count: 2, hasMore: true });
    assert.deepEqual(await catalog.listSessionEventsPage({ id: rawSessionId, offset: 2, limit: 2 }).then(page => ({ count: page.items.length, hasMore: page.hasMore })), { count: 1, hasMore: false });
    assert.equal((await catalog.listSessionEventsPage({ id: rawSessionId, from: '2026-07-12T14:00:03+02:00' })).items.length, 1, 'offset boundary is inclusive');
    assert.equal((await catalog.listSessionEventsPage({ id: rawSessionId, from: '2026-07-12T12:00:01.001Z' })).items.length, 2, 'fractional from excludes the earlier event');
    assert.equal((await catalog.listSessionEventsPage({ id: rawSessionId, to: '2026-07-12T12:00:00.999Z' })).items.length, 0, 'fractional to excludes all later events');
    for (const actor of ['person', 'system', 'assistant']) {
      const visible = await catalog.searchSessions({ ownerTags: [opaque('owner', actor)], query: '', limit: 10 });
      assert.equal(visible.some(session => session.id === rawSessionId), true);
    }
    assert.equal((await catalog.searchSessions({ ownerTags: [opaque('owner', 'outsider')], query: '', limit: 10 })).some(session => session.id === rawSessionId), false);
    const rebindings = [
      rawV2Fixture({ suffix, marker: '4', sessionId: rawSessionId, role: 'assistant', actor: 'assistant', sender: 'assistant', room: 'room-b' }),
      rawV2Fixture({ suffix, marker: '5', sessionId: rawSessionId, role: 'assistant', actor: 'assistant', sender: 'assistant', conversation: 'conversation-b' }),
      rawV2Fixture({ suffix, marker: '6', sessionId: rawSessionId, role: 'assistant', actor: 'assistant', sender: 'assistant', thread: 'thread-b' })
    ];
    for (const rebound of rebindings) {
      cleanupContentIds.add(rebound.record.contentId);
      await assert.rejects(catalog.ingestRawEventV2(rebound.record, rebound.raw, { id: `${suffix}-raw-audit-rebind-${rebound.record.eventId}`, ts: rebound.record.createdAt, actorTag: rebound.record.ownerTag, action: 'raw_event_ingest', targetId: rebound.record.eventId, details: {} }), /raw_session_binding_conflict/);
    }

    // Existing proposal transaction/idempotency baseline.
    const results = await Promise.all(Array.from({ length: 8 }, (_, index) => catalog.enqueueProposalWithRaw({ ...record, id: `${record.id}-${index}` }, raw)));
    assert.equal(results.filter((result) => result.duplicate === false).length, 1);
    assert.equal(new Set(results.map((result) => result.record.id)).size, 1);
    assert.equal((await catalog.getProposal(results[0].record.id)).contentId, contentId);
    const receipt = { kind: 'decision', proposalId: results[0].record.id, decisionId: `decision-${suffix}`, status: 'review_required', decisionDigest: crypto.createHash('sha256').update(`decision-${suffix}`).digest('hex'), proposalDigest: crypto.createHash('sha256').update(`proposal-${suffix}`).digest('hex'), policyDigest: crypto.createHash('sha256').update(`policy-${suffix}`).digest('hex'), timestamp: clock().toISOString() };
    const receiptResults = await Promise.all([
      catalog.recordCuratorReceipt(receipt, { id: `${suffix}-receipt-audit-1`, ts: clock().toISOString(), actorTag: `actor-${suffix}`, action: 'curation_decision_receipt', requestId: `request-${suffix}-1`, targetId: receipt.proposalId, details: {} }),
      catalog.recordCuratorReceipt(receipt, { id: `${suffix}-receipt-audit-2`, ts: clock().toISOString(), actorTag: `actor-${suffix}`, action: 'curation_decision_receipt', requestId: `request-${suffix}-2`, targetId: receipt.proposalId, details: {} })
    ]);
    assert.equal(receiptResults.filter(result => result.duplicate === false).length, 1);
    assert.equal(receiptResults.filter(result => result.duplicate === true).length, 1);
    assert.equal((await catalog.getProposal(receipt.proposalId)).status, 'review');

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
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.curator_receipt_state_v1 WHERE proposal_id LIKE $1`, values: [`%${suffix}%`] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.audit_events_v2 WHERE id LIKE $1`, values: [`${suffix}-%`] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.logical_message_aliases_v2 WHERE logical_message_id IN (SELECT logical_message_id FROM agent_memory_fabric.raw_events_v2 WHERE session_id = ANY($1::text[]))`, values: [[...cleanupSessionIds]] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.logical_messages_v2 WHERE logical_message_id IN (SELECT logical_message_id FROM agent_memory_fabric.raw_events_v2 WHERE session_id = ANY($1::text[]))`, values: [[...cleanupSessionIds]] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.raw_events_v2 WHERE session_id = ANY($1::text[])`, values: [[...cleanupSessionIds]] });
        await cleanupClient.query({ text: `DELETE FROM agent_memory_fabric.raw_sessions_v1 WHERE session_id = ANY($1::text[])`, values: [[...cleanupSessionIds]] });
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
