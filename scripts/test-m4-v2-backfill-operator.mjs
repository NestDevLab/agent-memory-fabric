import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest } from '../src/migration/m4-backfill-gate.mjs';
import { createFabricStoreFromEnv } from '../src/fabric-store.mjs';
import { EncryptedOutbox } from '../src/ingest/outbox.mjs';
import { deriveEventIdV2, deriveLogicalMessageIds, deriveSessionIdV2, opaqueContextTag } from '../src/ingest/raw-projection-v2.mjs';
import { normalizeIngestKeyRing, normalizedObservationDigest } from '../src/ingest/raw-event-contract.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { deriveM4V2ArchiveRegistryBinding } from '../src/migration/m4-v2-backfill-completion.mjs';
import { attestM4V2CatalogRevision } from '../src/migration/m4-v2-catalog-revision-attestation.mjs';
import { planM4V2BackfillOperator, runM4V2BackfillOperator } from '../src/operator/m4-v2-backfill-operator.mjs';

const digest = value => `sha256:${value.repeat(64)}`;
const key = (keyId, byte) => ({ schema: 'amf.migration-signing-key/v1', keyId, key: Buffer.alloc(32, byte).toString('base64') });
function write(file, value) { fs.writeFileSync(file, JSON.stringify(value)); fs.chmodSync(file, 0o600); }
function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-operator-')); const pauseKey = key('pause-k1', 1); const rollbackKey = key('rollback-k1', 2);
  const sourceCheckpoint = { id: 'source-checkpoint-runner', digest: digest('1') }; const pauseInput = { schema: 'amf.migration-pause-checkpoints/v1', manifestId: 'pause-manifest-runner', revision: 1, keyId: pauseKey.keyId, pause: { state: 'paused', collectorCursor: { id: 'collector-cursor-runner', digest: digest('2') }, pendingOutbox: { id: 'pending-outbox-runner', digest: digest('3') }, acknowledgements: { id: 'acknowledgements-runner', digest: digest('4') }, deadLetters: { id: 'dead-letters-runner', digest: digest('5') }, sourceCheckpoint, nativeTranscriptAuthority: { id: 'native-authority-runner', digest: digest('6') }, evidence: { id: `pause-collector-${'a'.repeat(64)}`, digest: digest('7') } } };
  const roster = { schema: 'amf.migration-pause-collector-roster/v1', manifestId: pauseInput.manifestId, revision: 1, keyId: pauseKey.keyId, collectors: [pauseInput.pause.evidence.id] };
  const pause = createPauseManifest(aggregatePauseCheckpointInputs([pauseInput], roster), pauseKey);
  const rollback = createM4RollbackManifest({ schema: 'amf.migration-manifest/v1', manifestId: 'rollback-manifest-runner', phase: 'rollback', revision: 1, rollback: { pauseEvidence: { manifestId: pause.manifestId, digest: pause.integrity.payloadDigest, signature: pause.integrity.signature }, sourceCheckpoint: pause.pause.sourceCheckpoint, targetCheckpoint: { id: 'target-checkpoint-runner', digest: digest('8') }, compatibilityRouteRevision: 'compatibility-route-runner', recoveryCopy: { id: 'recovery-copy-runner', digest: digest('9') }, restoreTest: 'passed' } }, rollbackKey);
  const files = { pause: path.join(root, 'pause.json'), pauseKey: path.join(root, 'pause-key.json'), rollback: path.join(root, 'rollback.json'), rollbackKey: path.join(root, 'rollback-key.json'), fabric: path.join(root, 'fabric.json'), delivery: path.join(root, 'delivery.json'), archive: path.join(root, 'archive.json'), config: path.join(root, 'config.json') };
  write(files.pause, pause); write(files.pauseKey, pauseKey); write(files.rollback, rollback); write(files.rollbackKey, rollbackKey);
  write(files.fabric, { schema: 'amf.m4-v2-backfill-fabric/v1', rootPath: root, env: { AMF_RAW_ENCRYPTION_KEY: Buffer.alloc(32, 3).toString('base64'), AMF_RAW_ENCRYPTION_KEY_ID: 'raw-k1', AMF_DATA_PATH: path.join(root, 'fabric'), AMF_CATALOG_KIND: 'sqlite', AMF_CATALOG_PATH: path.join(root, 'fabric', 'catalog.sqlite'), AMF_RAW_V2_CUTOVER: 'true', AMF_INGEST_KEY_RING_JSON: JSON.stringify({ keys: { ingest: Buffer.alloc(32, 4).toString('base64') }, digestKey: Buffer.alloc(32, 5).toString('base64'), logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': Buffer.alloc(32, 6).toString('base64') } }, authorizations: { ingest: { actors: ['synthetic-actor'], sourceInstances: ['synthetic-source'] } } }) } });
  write(files.delivery, { schema: 'amf.m4-v2-delivery-key-ring/v1', currentKeyId: 'delivery-k1', keys: { 'delivery-k1': Buffer.alloc(32, 7).toString('base64'), 'delivery-old': Buffer.alloc(32, 8).toString('base64') }, cursorKey: Buffer.alloc(32, 9).toString('base64'), retentionDays: 30 });
  write(files.archive, { schema: 'amf.m4-v2-backfill-archive/v1', kind: 'sqlite', filename: path.join(root, 'archive.sqlite') });
  write(files.config, { schema: 'amf.m4-v2-backfill-operator/v1', gate: { pauseManifestPath: files.pause, pauseKeyPath: files.pauseKey, rollbackManifestPath: files.rollback, rollbackKeyPath: files.rollbackKey }, fabricConfigPath: files.fabric, deliveryKeyRingPath: files.delivery, archiveConfigPath: files.archive, leasePath: path.join(root, 'lease.json'), outboxRoot: path.join(root, 'outbox'), progressRoot: path.join(root, 'progress') });
  return { root, files };
}

function enableV2Completion(item) {
  const artifactRoot = path.join(item.root, 'artifacts'); fs.mkdirSync(artifactRoot, { mode: 0o700 }); fs.chmodSync(artifactRoot, 0o700);
  item.files.catalogAttestationKey = path.join(item.root, 'catalog-attestation-key.json');
  item.files.completionKey = path.join(item.root, 'completion-key.json');
  write(item.files.catalogAttestationKey, key('catalog-attestation-k1', 21));
  write(item.files.completionKey, key('archive-completion-k1', 22));
  const config = JSON.parse(fs.readFileSync(item.files.config));
  write(item.files.config, { ...config, schema: 'amf.m4-v2-backfill-operator/v2', artifactRoot,
    manifestId: 'v2-backfill-completion', revision: 1,
    catalogAttestationKeyPath: item.files.catalogAttestationKey, completionKeyPath: item.files.completionKey });
  return { artifactRoot, target: path.join(artifactRoot, 'm4', 'v2-backfill', 'v2-backfill-completion-r1.json') };
}

function rawItem(suffix, role = 'user', direction = role === 'assistant' ? 'outbound' : 'inbound') {
  const keyValue = Buffer.alloc(32, 4).toString('base64'); const logicalKey = Buffer.alloc(32, 6).toString('base64'); const tagKey = Buffer.alloc(32, 9).toString('base64');
  const ring = { keys: { ingest: keyValue }, digestKey: Buffer.alloc(32, 5).toString('base64'), logicalMessageKeys: { currentKeyVersion: 'logical-k1', keys: { 'logical-k1': logicalKey } }, authorizations: { ingest: { actors: ['synthetic-actor'], sourceInstances: ['synthetic-source'] } } };
  const tag = (namespace, value) => opaqueContextTag(namespace, value, tagKey, 'routing-k1'); const sender = tag('sender', 'synthetic-sender'); const conversation = tag('conversation', 'synthetic-conversation');
  const logical = { canonicalSenderIdentity: 'synthetic-sender', senderTag: sender, conversationTag: conversation, direction, nativePlatform: 'synthetic', nativeConversationId: 'synthetic-conversation', nativeMessageId: `synthetic-${suffix}` };
  const derived = deriveLogicalMessageIds(logical, ring.logicalMessageKeys); const raw = Buffer.from(`synthetic-${suffix}`); const eventId = deriveEventIdV2({ sourceKind: 'codex', observationClass: 'native', rawBytes: raw }); const sessionId = deriveSessionIdV2({ sourceKind: 'codex', conversationTag: conversation });
  const event = { schema: 'amf.raw-event/v2', eventId, sessionId, occurredAt: '2026-07-22T12:00:00Z', source: { runtime: 'codex', subtype: 'message' }, logical, normalized: { role, contentType: role === 'system' ? 'structured' : 'text', value: role === 'system' ? { ignored: true } : `visible ${suffix}` }, raw: { encoding: 'base64', line: raw.toString('base64'), lineEnding: 'lf' } };
  const projection = { schema: 'amf.raw-event-projection/v2', eventId, sessionId, logicalMessageId: derived.logicalMessageId, logicalMessageAliases: derived.aliases, derivationVersion: 'amf-logical-message/v1', keyVersion: derived.keyVersion, sourceKind: 'codex', observationClass: 'native', direction, conversationKind: 'dm', contextTags: { actor: [tag('actor', 'synthetic-actor')], sender: [sender], conversation: [conversation] }, subtype: 'message', occurredAt: event.occurredAt, editedAt: null, nativeRevision: 1, sourceSequence: 1, authoritativeDeletion: false, role, contentType: event.normalized.contentType, contentParts: 1, hasContent: true, normalizationVersion: 'amf-observation-normalization/v1', normalizedPayloadDigest: normalizedObservationDigest({ event }, normalizeIngestKeyRing(ring).digestKey) };
  return { event, projection, ring };
}
async function seedFabric(item) {
  const fabric = JSON.parse(fs.readFileSync(item.files.fabric)); const store = createFabricStoreFromEnv({ rootPath: fabric.rootPath, env: fabric.env });
  try {
    for (const value of [rawItem('user'), rawItem('assistant', 'assistant'), rawItem('system', 'system', 'internal')]) {
      const outboxRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-operator-envelope-'));
      try { const envelope = new EncryptedOutbox({ rootPath: outboxRoot, encryptionKey: Buffer.alloc(32, 4).toString('base64'), digestKey: Buffer.alloc(32, 5).toString('base64'), sourceInstanceId: 'synthetic-source', actorId: 'synthetic-actor', keyId: 'ingest' }).encrypt({ event: value.event, projection: value.projection }); await store.ingestRawEvent({ actor: 'synthetic-actor', sourceInstanceId: 'synthetic-source', projection: value.projection, envelope }); }
      finally { fs.rmSync(outboxRoot, { recursive: true, force: true }); }
    }
  } finally { await store.close(); }
}

test('catalog revision attestation traverses a non-empty catalog deterministically across pages and rejects order or chain changes', async () => {
  const item = setup();
  try {
    await seedFabric(item);
    const fabric = JSON.parse(fs.readFileSync(item.files.fabric));
    const store = createFabricStoreFromEnv({ rootPath: fabric.rootPath, env: fabric.env });
    try {
      const catalogKey = key('catalog-attestation-k1', 21);
      const baseline = await attestM4V2CatalogRevision({ catalog: store.catalog, keyDocument: catalogKey, pageLimit: 1 });
      assert.deepEqual(baseline.traversal.groupCount, 3);
      assert.deepEqual(baseline.traversal.observationCount, 3);

      const reordered = {
        async listM4V2LogicalGroups(request) {
          const page = store.catalog.listM4V2LogicalGroups(request);
          return request.after === null ? { ...page, items: [...page.items].reverse() } : page;
        },
      };
      await assert.rejects(() => attestM4V2CatalogRevision({ catalog: reordered, keyDocument: catalogKey, pageLimit: 2 }), { code: 'm4_v2_catalog_attestation_catalog_invalid' });

      const changed = {
        async listM4V2LogicalGroups(request) {
          const page = store.catalog.listM4V2LogicalGroups(request);
          const copy = structuredClone(page);
          if (copy.items.length > 0) copy.items[0].observations[0].createdAt = '2026-07-23T12:00:00Z';
          return copy;
        },
      };
      const changedAttestation = await attestM4V2CatalogRevision({ catalog: changed, keyDocument: catalogKey, pageLimit: 1 });
      assert.notEqual(changedAttestation.traversal.finalChain, baseline.traversal.finalChain);
      assert.notEqual(changedAttestation.traversal.catalogRevisionDigest, baseline.traversal.catalogRevisionDigest);
    } finally { await store.close(); }
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('plan is resource-free and returns only redacted confirmation material', async () => {
  const item = setup(); try { const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); assert.deepEqual(Object.keys(plan).sort(), ['confirmationDigest', 'operation', 'phase', 'runId', 'schema']); assert.match(plan.confirmationDigest, /^sha256:/); assert.equal(fs.existsSync(path.join(item.root, 'fabric')), false); assert.equal(fs.existsSync(path.join(item.root, 'archive.sqlite')), false); } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('wrong confirmation and referenced-file drift construct zero delayed resources', async () => {
  const item = setup(); try { const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); let calls = 0; const dependencies = { createFabricStoreFromEnv() { calls += 1; }, BackfillLease: class { constructor() { calls += 1; } }, ConversationEventPlaintextOutbox: class { constructor() { calls += 1; } }, SqliteConversationArchive: class { constructor() { calls += 1; } }, PostgresConversationArchive: class { constructor() { calls += 1; } }, M4ProgressStore: class { constructor() { calls += 1; } } };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: digest('f') }, { dependencies }), { code: 'm4_operator_confirmation_invalid' }); assert.equal(calls, 0);
    write(item.files.delivery, { schema: 'amf.m4-v2-delivery-key-ring/v1', currentKeyId: 'delivery-k1', keys: { 'delivery-k1': crypto.randomBytes(32).toString('base64') }, cursorKey: crypto.randomBytes(32).toString('base64'), retentionDays: 30 });
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: 'm4_operator_confirmation_invalid' }); assert.equal(calls, 0);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('run validates hostile input and bounds before it reads private configuration', async () => {
  let reads = 0; const original = fs.readFileSync; fs.readFileSync = (...args) => { reads += 1; return original(...args); };
  try {
    const hostile = {}; Object.defineProperty(hostile, 'configPath', { enumerable: true, get() { throw new Error('private'); } });
    await assert.rejects(() => runM4V2BackfillOperator(hostile), { code: 'm4_operator_run_input_invalid' });
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: '/absolute/private.json', maxEvents: 1001, confirmedPlanDigest: digest('a') }), { code: 'm4_operator_run_input_invalid' });
    assert.equal(reads, 0);
  } finally { fs.readFileSync = original; }
});

test('real persisted Fabric v2 input resumes through the operator into SQLite and excludes system observations', async () => {
  const item = setup(); try {
    await seedFabric(item); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    let nonce = 0; const operatorOptions = { clock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => `nonce${String(++nonce).padStart(11, '0')}` }; const first = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, operatorOptions);
    const secondPlan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    const second = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: secondPlan.confirmationDigest }, operatorOptions);
    assert.deepEqual([first.processed, first.complete, second.processed, second.complete], [1, false, 1, true]);
    const eventId = value => `cevt_${crypto.createHash('sha256').update(canonicalJson(['amf.m4/v2-event-id/v1', value.event.eventId]), 'utf8').digest('hex')}`;
    const deliveryKey = Buffer.alloc(32, 7); const archive = new SqliteConversationArchive({ filename: path.join(item.root, 'archive.sqlite'), resolveIntegrityKey: keyId => keyId === 'delivery-k1' ? deliveryKey : null, resolveExpiresAt: () => '2026-12-31T00:00:00Z', cursorKey: Buffer.alloc(32, 9) });
    const rows = archive.db.prepare('SELECT event_id,event_json FROM conversation_archive_events_v1 ORDER BY event_id').all();
    assert.deepEqual(rows.map(row => row.event_id), [eventId(rawItem('user')), eventId(rawItem('assistant', 'assistant'))].sort());
    assert.deepEqual(rows.map(row => JSON.parse(row.event_json).role).sort(), ['assistant', 'user']);
    assert.equal(rows.some(row => row.event_id === eventId(rawItem('system', 'system', 'internal'))), false);
    const events = rows.map(row => JSON.parse(row.event_json)); assert.deepEqual(events.map(event => event.integrity.keyId), ['delivery-k1', 'delivery-k1']); assert.equal(events.every(event => /^2026-07-22T[0-9:.]+Z$/.test(event.integrity.sentAt)), true); assert.equal(new Set(events.map(event => event.integrity.nonce)).size, 2); assert.deepEqual(archive.db.prepare('SELECT expires_at FROM conversation_archive_events_v1 ORDER BY event_id').all().map(row => row.expires_at), ['2026-08-21T12:00:00.000Z', '2026-08-21T12:00:00.000Z']); archive.close();
    const catalog = new Database(path.join(item.root, 'fabric', 'catalog.sqlite')); assert.equal(catalog.prepare("SELECT count(*) AS count FROM audit_events_v2 WHERE action='raw_redacted_decrypt_intent'").get().count >= 2, true); catalog.close();
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('v2 completion publishes only after a complete run with matching signed catalog attestations', async () => {
  const item = setup(); const completion = enableV2Completion(item);
  try {
    await seedFabric(item);
    let nonce = 0; const options = { clock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => `nonce${String(++nonce).padStart(11, '0')}` };
    const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    const incomplete = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, options);
    assert.deepEqual(incomplete.completion, { state: 'pending', digest: null }); assert.equal(fs.existsSync(completion.target), false);
    const completePlan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    const complete = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: completePlan.confirmationDigest }, options);
    assert.equal(complete.completion.state, 'published'); assert.match(complete.completion.digest, /^sha256:/); assert.equal(fs.statSync(completion.target).mode & 0o777, 0o600);
    const artifact = JSON.parse(fs.readFileSync(completion.target, 'utf8'));
    assert.deepEqual(Object.keys(artifact).sort(), ['catalogAttestationDigest', 'catalogAttestationKeyId', 'completionKeyId', 'finalCheckpoint', 'gateDigest', 'integrity', 'manifestId', 'resultDigest', 'revision', 'runnerPlanDigest', 'schema', 'state']);
    assert.doesNotMatch(JSON.stringify(artifact), /visible|synthetic-|catalog-k1|sourceTag|rootPath/i);
    const stage = path.dirname(completion.target); const baseline = JSON.parse(fs.readFileSync(path.join(stage,
      fs.readdirSync(stage).find(name => name.startsWith('v2catalog-'))), 'utf8'));
    const binding = deriveM4V2ArchiveRegistryBinding(artifact, key('archive-completion-k1', 22), baseline, key('catalog-attestation-k1', 21));
    assert.match(binding.completionDigest, /^sha256:/); assert.equal(binding.catalogRevisionDigest, baseline.traversal.catalogRevisionDigest);
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: completePlan.confirmationDigest }), { code: 'm4_operator_completion_artifact_exists' });
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('v2 completion rejects a catalog change after runner completion without writing an artifact', async () => {
  const item = setup(); const completion = enableV2Completion(item);
  try {
    await seedFabric(item); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 2 }); let opens = 0;
    const dependencies = { createFabricStoreFromEnv(input) { const store = createFabricStoreFromEnv(input); opens += 1; if (opens === 4) store.catalog.listM4V2LogicalGroups = async () => ({ items: [], next: null }); return store; }, BackfillLease: (await import('../src/ingest/transcripts/backfill.mjs')).BackfillLease, ConversationEventPlaintextOutbox: (await import('../src/ingest/conversation-event-v3-outbox.mjs')).ConversationEventPlaintextOutbox, SqliteConversationArchive, PostgresConversationArchive: class {}, M4ProgressStore: (await import('../src/migration/m4-progress-store.mjs')).M4ProgressStore };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 2, confirmedPlanDigest: plan.confirmationDigest }, { dependencies, clock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => 'nonce00000000003' }), { code: 'm4_operator_catalog_baseline_mismatch' });
    assert.equal(fs.existsSync(completion.target), false);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('v2 baseline rejects catalog drift during pending work and on the next invocation', async () => {
  const item = setup(); const completion = enableV2Completion(item);
  try {
    await seedFabric(item); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    let opens = 0;
    const during = { createFabricStoreFromEnv(input) { const store = createFabricStoreFromEnv(input); opens += 1; if (opens === 4) store.catalog.listM4V2LogicalGroups = async () => ({ items: [], next: null }); return store; }, BackfillLease: (await import('../src/ingest/transcripts/backfill.mjs')).BackfillLease, ConversationEventPlaintextOutbox: (await import('../src/ingest/conversation-event-v3-outbox.mjs')).ConversationEventPlaintextOutbox, SqliteConversationArchive, PostgresConversationArchive: class {}, M4ProgressStore: (await import('../src/migration/m4-progress-store.mjs')).M4ProgressStore };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies: during, clock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => 'nonce00000000004' }), { code: 'm4_operator_catalog_baseline_mismatch' });
    assert.equal(fs.existsSync(completion.target), false);
    const next = { createFabricStoreFromEnv(input) { const store = createFabricStoreFromEnv(input); store.catalog.listM4V2LogicalGroups = async () => ({ items: [], next: null }); return store; }, BackfillLease: during.BackfillLease, ConversationEventPlaintextOutbox: during.ConversationEventPlaintextOutbox, SqliteConversationArchive, PostgresConversationArchive: class {}, M4ProgressStore: during.M4ProgressStore };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies: next }), { code: 'm4_operator_catalog_baseline_mismatch' });
    assert.equal(fs.existsSync(completion.target), false);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('v2 retry verifies the persisted catalog baseline before constructing any catalog resource', async () => {
  const item = setup(); const completion = enableV2Completion(item);
  try {
    await seedFabric(item); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 });
    await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { clock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => 'nonce00000000005' });
    const stage = path.dirname(completion.target); const baselinePath = path.join(stage, fs.readdirSync(stage).find(name => name.startsWith('v2catalog-')));
    const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')); baseline.integrity.signature = 'a'.repeat(43); write(baselinePath, baseline);
    let calls = 0; const dependencies = { createFabricStoreFromEnv() { calls += 1; throw new Error('must not open'); }, BackfillLease: class {}, ConversationEventPlaintextOutbox: class {}, SqliteConversationArchive: class {}, PostgresConversationArchive: class {}, M4ProgressStore: class {} };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: 'm4_operator_catalog_baseline_invalid' });
    assert.equal(calls, 0);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('binding mismatch and decrypt-audit outage stop before an archive write', async () => {
  const binding = setup(); try {
    await seedFabric(binding); const plan = await planM4V2BackfillOperator({ configPath: binding.files.config, maxEvents: 1 });
    const catalog = new Database(path.join(binding.root, 'fabric', 'catalog.sqlite')); catalog.prepare("UPDATE raw_events_v2 SET source_tag='invalid-source-tag'").run(); catalog.close();
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: binding.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }), error => error?.code === 'm4_backfill_source_read_failed');
    const archive = new Database(path.join(binding.root, 'archive.sqlite')); assert.equal(archive.prepare('SELECT count(*) AS count FROM conversation_archive_events_v1').get().count, 0); archive.close();
  } finally { fs.rmSync(binding.root, { recursive: true, force: true }); }
  const audit = setup(); try {
    await seedFabric(audit); const plan = await planM4V2BackfillOperator({ configPath: audit.files.config, maxEvents: 1 });
    const dependencies = { createFabricStoreFromEnv(input) { const store = createFabricStoreFromEnv(input); store.audit = async () => { throw new Error('private audit detail'); }; return store; }, BackfillLease: (await import('../src/ingest/transcripts/backfill.mjs')).BackfillLease, ConversationEventPlaintextOutbox: (await import('../src/ingest/conversation-event-v3-outbox.mjs')).ConversationEventPlaintextOutbox, SqliteConversationArchive, PostgresConversationArchive: class {}, M4ProgressStore: (await import('../src/migration/m4-progress-store.mjs')).M4ProgressStore };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: audit.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), error => error?.code === 'm4_backfill_source_read_failed' && !String(error.message).includes('private'));
    const archive = new Database(path.join(audit.root, 'archive.sqlite')); assert.equal(archive.prepare('SELECT count(*) AS count FROM conversation_archive_events_v1').get().count, 0); archive.close();
  } finally { fs.rmSync(audit.root, { recursive: true, force: true }); }
});

test('CLI emits compact JSON and rejects malformed argv before private reads', async () => {
  const item = setup(); try {
    const script = path.resolve('scripts/amf-m4-v2-backfill.mjs'); const invoke = args => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
    const planned = invoke(['plan', '--config', item.files.config, '--max-events', '1']); assert.equal(planned.status, 0); assert.deepEqual(Object.keys(JSON.parse(planned.stdout)).sort(), ['confirmationDigest', 'ok', 'operation', 'phase', 'runId', 'schema']);
    for (const literal of [item.root, 'delivery-k1', 'synthetic-', 'visible ', 'sqlite']) assert.equal(`${planned.stdout}${planned.stderr}`.includes(literal), false);
    for (const args of [['plan', '--config', 'relative.json', '--max-events', '1'], ['plan', '--config', item.files.config, '--max-events', '1001'], ['plan', '--config', item.files.config, '--max-events', '1', '--max-events', '1'], ['plan', '--unknown', 'x', '--config', item.files.config, '--max-events', '1'], ['plan', '--config', item.files.config, '--max-events'], ['run', '--config', item.files.config, '--max-events', '1', '--confirmed-plan-digest', 'bad']]) { const result = invoke(args); assert.equal(result.status, 78); assert.deepEqual(JSON.parse(result.stderr), { ok: false, error: 'm4_operator_argument_invalid' }); }
    const wrong = invoke(['run', '--config', item.files.config, '--max-events', '1', '--confirmed-plan-digest', digest('f')]); assert.equal(wrong.status, 78); assert.deepEqual(JSON.parse(wrong.stderr), { ok: false, error: 'm4_operator_confirmation_invalid' }); assert.equal(fs.existsSync(path.join(item.root, 'fabric')), false); assert.equal(fs.existsSync(path.join(item.root, 'archive.sqlite')), false);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('private loader and delayed resource paths reject unsafe modes, aliases, symlinks, and ring drift', async () => {
  const mode = setup(); try { fs.chmodSync(mode.files.config, 0o644); await assert.rejects(() => planM4V2BackfillOperator({ configPath: mode.files.config, maxEvents: 1 }), { code: 'm4_operator_config_invalid' }); fs.chmodSync(mode.files.config, 0o600); await assert.rejects(() => planM4V2BackfillOperator({ configPath: `${mode.root}/./config.json`, maxEvents: 1 }), { code: 'm4_operator_config_invalid' }); } finally { fs.rmSync(mode.root, { recursive: true, force: true }); }
  const link = setup(); try { const original = `${link.files.config}.real`; fs.renameSync(link.files.config, original); fs.symlinkSync(original, link.files.config); await assert.rejects(() => planM4V2BackfillOperator({ configPath: link.files.config, maxEvents: 1 }), { code: 'm4_operator_config_invalid' }); } finally { fs.rmSync(link.root, { recursive: true, force: true }); }
  const leaf = setup(); try { const plan = await planM4V2BackfillOperator({ configPath: leaf.files.config, maxEvents: 1 }); fs.mkdirSync(path.join(leaf.root, 'outbox-target')); fs.symlinkSync(path.join(leaf.root, 'outbox-target'), path.join(leaf.root, 'outbox')); await assert.rejects(() => runM4V2BackfillOperator({ configPath: leaf.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_operator_resource_unsafe' }); assert.equal(fs.existsSync(path.join(leaf.root, 'archive.sqlite')), false); } finally { fs.rmSync(leaf.root, { recursive: true, force: true }); }
  for (const kind of ['fabric-root', 'fabric-data', 'catalog-parent', 'progress', 'archive-parent']) { const item = setup(); try { const config = JSON.parse(fs.readFileSync(item.files.config)); let target; if (kind === 'fabric-root') { const fabric = JSON.parse(fs.readFileSync(item.files.fabric)); target = path.join(item.root, 'fabric-root'); fs.mkdirSync(target); fabric.rootPath = target; write(item.files.fabric, fabric); } else if (kind === 'fabric-data') { const fabric = JSON.parse(fs.readFileSync(item.files.fabric)); target = fabric.env.AMF_DATA_PATH; fs.mkdirSync(target); } else if (kind === 'catalog-parent') { const fabric = JSON.parse(fs.readFileSync(item.files.fabric)); target = path.join(item.root, 'catalog-parent'); fs.mkdirSync(target); fabric.env.AMF_CATALOG_PATH = path.join(target, 'catalog.sqlite'); write(item.files.fabric, fabric); } else if (kind === 'progress') { target = config.progressRoot; fs.mkdirSync(target); } else { const archive = JSON.parse(fs.readFileSync(item.files.archive)); target = path.join(item.root, 'archive-parent'); fs.mkdirSync(target); archive.filename = path.join(target, 'archive.sqlite'); write(item.files.archive, archive); } const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); fs.rmdirSync(target); const external = path.join(item.root, `${kind}-target`); fs.mkdirSync(external); fs.symlinkSync(external, target); await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_operator_resource_unsafe' }); } finally { fs.rmSync(item.root, { recursive: true, force: true }); } }
  const drift = setup(); try { const fabric = JSON.parse(fs.readFileSync(drift.files.fabric)); const ingestPath = path.join(drift.root, 'ingest-ring.json'); write(ingestPath, JSON.parse(fabric.env.AMF_INGEST_KEY_RING_JSON)); delete fabric.env.AMF_INGEST_KEY_RING_JSON; fabric.env.AMF_INGEST_KEY_RING_PATH = ingestPath; write(drift.files.fabric, fabric); const plan = await planM4V2BackfillOperator({ configPath: drift.files.config, maxEvents: 1 }); const changed = JSON.parse(fs.readFileSync(ingestPath)); changed.digestKey = crypto.randomBytes(32).toString('base64'); write(ingestPath, changed); await assert.rejects(() => runM4V2BackfillOperator({ configPath: drift.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_operator_confirmation_invalid' }); assert.equal(fs.existsSync(path.join(drift.root, 'archive.sqlite')), false); } finally { fs.rmSync(drift.root, { recursive: true, force: true }); }
});

test('API input properties are snapshotted exactly once', async () => {
  const item = setup(); try { const reads = { configPath: 0, maxEvents: 0, confirmedPlanDigest: 0 }; const planInput = {}; for (const [key, value] of Object.entries({ configPath: item.files.config, maxEvents: 1 })) Object.defineProperty(planInput, key, { enumerable: true, get() { reads[key] += 1; return value; } }); const plan = await planM4V2BackfillOperator(planInput); assert.deepEqual(reads, { configPath: 1, maxEvents: 1, confirmedPlanDigest: 0 }); const runInput = {}; for (const [key, value] of Object.entries({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: digest('f') })) Object.defineProperty(runInput, key, { enumerable: true, get() { reads[key] += 1; return value; } }); await assert.rejects(() => runM4V2BackfillOperator(runInput), { code: 'm4_operator_confirmation_invalid' }); assert.deepEqual(reads, { configPath: 2, maxEvents: 2, confirmedPlanDigest: 1 }); assert.match(plan.confirmationDigest, /^sha256:/); } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('delivery ring signs a bounded real batch with rotation, retention, and protected archive cursors', async () => {
  const item = setup(); try {
    await seedFabric(item); let captured; class CaptureArchive extends SqliteConversationArchive { constructor(options) { captured = options; super(options); } }
    const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 2 }); let sequence = 0;
    const dependencies = { createFabricStoreFromEnv, BackfillLease: (await import('../src/ingest/transcripts/backfill.mjs')).BackfillLease, ConversationEventPlaintextOutbox: (await import('../src/ingest/conversation-event-v3-outbox.mjs')).ConversationEventPlaintextOutbox, SqliteConversationArchive: CaptureArchive, PostgresConversationArchive: class {}, M4ProgressStore: (await import('../src/migration/m4-progress-store.mjs')).M4ProgressStore };
    const result = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 2, confirmedPlanDigest: plan.confirmationDigest }, { dependencies, deliveryClock: () => new Date('2026-07-22T12:00:00.000Z'), nonceFactory: () => `nonce${String(++sequence).padStart(11, '0')}` });
    assert.deepEqual([result.processed, result.complete], [2, true]); assert.equal(captured.resolveIntegrityKey('delivery-k1').equals(Buffer.alloc(32, 7)), true); assert.equal(captured.resolveIntegrityKey('delivery-old').equals(Buffer.alloc(32, 8)), true); assert.equal(captured.resolveIntegrityKey('unknown'), null); assert.equal(captured.cursorKey.equals(Buffer.alloc(32, 9)), true);
    const archive = new SqliteConversationArchive({ filename: path.join(item.root, 'archive.sqlite'), ...captured }); const rows = archive.db.prepare('SELECT event_json,expires_at FROM conversation_archive_events_v1 ORDER BY event_id').all(); const events = rows.map(row => JSON.parse(row.event_json)); assert.deepEqual(events.map(event => event.integrity.keyId), ['delivery-k1', 'delivery-k1']); assert.deepEqual(events.map(event => event.integrity.sentAt), ['2026-07-22T12:00:00.000Z', '2026-07-22T12:00:00.000Z']); assert.deepEqual(events.map(event => event.integrity.nonce), ['nonce00000000002', 'nonce00000000004']); assert.deepEqual(rows.map(row => row.expires_at), ['2026-08-21T12:00:00.000Z', '2026-08-21T12:00:00.000Z']); const first = archive.list(events[0].conversationId, 1, false); assert.ok(first.nextCursor); assert.equal(archive.list(events[0].conversationId, 1, false, first.nextCursor).items.length, 1); archive.close();
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('delivery ring rejects malformed values before resource construction', async () => {
  const cases = [ring => ({ ...ring, extra: true }), ring => ({ ...ring, currentKeyId: 'missing' }), ring => ({ ...ring, keys: { ...Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`key-${index}`, Buffer.alloc(32, index).toString('base64')])), 'delivery-k1': ring.keys['delivery-k1'] } }), ring => ({ ...ring, keys: { 'bad id': ring.keys['delivery-k1'] } }), ring => ({ ...ring, keys: { 'delivery-k1': 'bad' } }), ring => ({ ...ring, cursorKey: 'bad' }), ring => ({ ...ring, retentionDays: 0 })];
  for (const mutate of cases) { const item = setup(); try { const ring = JSON.parse(fs.readFileSync(item.files.delivery)); write(item.files.delivery, mutate(ring)); await assert.rejects(() => planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }), { code: 'm4_operator_reference_invalid' }); assert.equal(fs.existsSync(path.join(item.root, 'archive.sqlite')), false); } finally { fs.rmSync(item.root, { recursive: true, force: true }); } }
});

test('Fabric numeric, SSL, RAW selection, and postgres URL defects fail during planning', async () => {
  const cases = [env => ({ ...env, AMF_CATALOG_POOL_MAX: '0' }), env => ({ ...env, AMF_CATALOG_CONNECT_TIMEOUT_MS: '99' }), env => ({ ...env, AMF_CATALOG_SSL_MODE: 'invalid' }), env => ({ ...env, AMF_RAW_KEY_RING_JSON: JSON.stringify({ currentKeyId: 'raw-k1', keys: { 'raw-k1': Buffer.alloc(32, 1).toString('base64') } }) }), env => ({ ...env, AMF_CATALOG_KIND: 'postgres', AMF_CATALOG_DATABASE_URL: 'postgres://bad host', AMF_CATALOG_PATH: undefined })];
  for (const mutate of cases) { const item = setup(); try { const fabric = JSON.parse(fs.readFileSync(item.files.fabric)); fabric.env = mutate(fabric.env); for (const key of Object.keys(fabric.env)) if (fabric.env[key] === undefined) delete fabric.env[key]; write(item.files.fabric, fabric); await assert.rejects(() => planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }), { code: 'm4_operator_reference_invalid' }); } finally { fs.rmSync(item.root, { recursive: true, force: true }); } }
});

test('a held real lease blocks before any later resource, then identical retry succeeds after release', async () => {
  const item = setup(); try { const { BackfillLease } = await import('../src/ingest/transcripts/backfill.mjs'); const holder = new BackfillLease({ leasePath: path.join(item.root, 'lease.json') }); holder.acquire(); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }), { code: 'm4_runner_lease_factory_failed' }); assert.equal(fs.existsSync(path.join(item.root, 'fabric')), false); assert.equal(fs.existsSync(path.join(item.root, 'archive.sqlite')), false); assert.equal(fs.existsSync(path.join(item.root, 'outbox')), false); assert.equal(fs.existsSync(path.join(item.root, 'progress')), false); holder.release(); const result = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }); assert.equal(result.complete, true); } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('source construction failure closes its Fabric store and releases the pre-acquired lease', async () => {
  const item = setup(); try { const { BackfillLease } = await import('../src/ingest/transcripts/backfill.mjs'); let closed = 0; const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); const dependencies = { BackfillLease, createFabricStoreFromEnv() { return { catalog: {}, rawStore: {}, async close() { closed += 1; } }; }, ConversationEventPlaintextOutbox: class {}, SqliteConversationArchive: class {}, PostgresConversationArchive: class {}, M4ProgressStore: class {} }; await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: 'm4_runner_source_factory_failed' }); assert.equal(closed, 1); const fresh = new BackfillLease({ leasePath: path.join(item.root, 'lease.json') }); fresh.acquire(); fresh.release(); } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});

test('postgres selection is delayed, uses only the configured adapter, and closes fake resources', async () => {
  const item = setup(); try { const archiveConfig = JSON.parse(fs.readFileSync(item.files.archive)); write(item.files.archive, { schema: archiveConfig.schema, kind: 'postgres', connectionString: 'postgres://synthetic/private' }); const plan = await planM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1 }); let pg = 0; let sqlite = 0; let storeClosed = 0; let archiveClosed = 0; let leaseReleased = 0; class Lease { acquire() {} heartbeat() {} release() { leaseReleased += 1; } } class Pg { constructor(options) { pg += 1; assert.equal(options.connectionString, 'postgres://synthetic/private'); assert.equal(options.cursorKey.equals(Buffer.alloc(32, 9)), true); assert.equal(options.resolveIntegrityKey('delivery-k1').equals(Buffer.alloc(32, 7)), true); assert.equal(options.resolveIntegrityKey('delivery-old').equals(Buffer.alloc(32, 8)), true); } async append() {} async tombstone() {} async close() { archiveClosed += 1; } } class Sqlite { constructor() { sqlite += 1; } } const dependencies = { BackfillLease: Lease, PostgresConversationArchive: Pg, SqliteConversationArchive: Sqlite, ConversationEventPlaintextOutbox: class { async enqueue() {} async deliver() {} }, M4ProgressStore: (await import('../src/migration/m4-progress-store.mjs')).M4ProgressStore, createFabricStoreFromEnv() { return { catalog: { async listM4V2LogicalGroups() { return { items: [], next: null }; } }, rawStore: { opaqueTags() { return []; }, async getClientCiphertext() {} }, async audit() {}, async close() { storeClosed += 1; } }; } };
    await assert.rejects(() => runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: digest('f') }, { dependencies }), { code: 'm4_operator_confirmation_invalid' }); assert.deepEqual([pg, sqlite], [0, 0]); const result = await runM4V2BackfillOperator({ configPath: item.files.config, maxEvents: 1, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }); assert.equal(result.complete, true); assert.deepEqual([pg, sqlite, storeClosed, archiveClosed, leaseReleased], [1, 0, 1, 1, 1]);
  } finally { fs.rmSync(item.root, { recursive: true, force: true }); }
});
