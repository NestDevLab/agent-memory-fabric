import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import Database from 'better-sqlite3';

import {
  createM4CrossPhaseIdentityStreamingWriter,
  estimateM4CrossPhaseIdentityStreamingCapacity,
  M4_CROSS_PHASE_IDENTITY_STREAMING_MAX_PAGE_BYTES,
  preflightM4CrossPhaseIdentityStreamingCapacity,
  readM4CrossPhaseIdentityStreamingCoverage,
} from '../src/migration/m4-cross-phase-identity-streaming-writer.mjs';
import { createM4CrossPhaseIdentityResolver } from '../src/migration/m4-cross-phase-identity-registry.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from '../src/migration/m4-v2-conversation-projector.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { digest as fixtureDigest, fixture, sign } from './helpers/m4-traversal-completion-fixtures.mjs';

const SECRET = Buffer.alloc(32, 17);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const opaque = value => `hmac-sha256:test-v1:${hash(value)}`;
const tag = value => `test-v1:${hash(value)}`;
const digest = value => `sha256:${hash(value)}`;
const sessionId = value => `ses_${hash(`session:${value}`)}`;
const eventId = value => `evt_${hash(`event:${value}`)}`;
const compact = (kind, index) => `${kind}_aa${index.toString(16).padStart(62, '0')}`;

function block(label, options = {}) {
  const legacySessionId = options.legacySessionId ?? sessionId(`session:${label}`);
  const legacyEventId = options.legacyEventId ?? eventId(`event:${label}`);
  const sourceTags = options.sourceTags ?? [tag('one')];
  const conversationId = deriveM4V3ConversationIdFromLegacySessionId(legacySessionId);
  const context = { sender: [opaque(`sender:${label}`)], conversation: [opaque(`conversation:${legacySessionId}`)], room: [opaque(`room:${legacySessionId}`)] };
  const item = { legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId,
    sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags,
    conversationKind: 'dm', authorizationContextTags: context, role: 'user', direction: 'inbound',
    state: options.state ?? 'active', revision: options.revision ?? 1,
    replacesLegacyEventId: options.replacesLegacyEventId ?? null, tombstonesLegacyEventId: null, conflictsWithLegacyEventIds: [] };
  return { schema: 'amf.m4-cross-phase-projector-identity-block/v1',
    session: { legacySessionId, conversationId, conversationKind: 'dm', sessionContextTags: { conversation: context.conversation, room: context.room } },
    events: [item] };
}
function temporary() { return fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-stream-')); }
function writer(root, sink, options = {}) {
  const defaultPreflight = { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('preflight')], expectedBlockCount: 20_000 };
  return createM4CrossPhaseIdentityStreamingWriter({ databasePath: path.join(root, 'private', 'identity.sqlite'), registrySecret: SECRET,
    registryKeyId:'registry-fixture-key', capacityPreflight: defaultPreflight, pageSink: sink, ...options });
}
function sink(pages) { return { writePage: async page => { pages.set(page.pageKey, structuredClone(page)); return { pageKey: page.pageKey, digest: page.digest }; } }; }
const completions = new Map();
function completion(root, options = {}) { if (!completions.has(root)) completions.set(root, fixture({ coverage:readM4CrossPhaseIdentityStreamingCoverage({ databasePath:path.join(root, 'private', 'identity.sqlite') }), registrySecret:SECRET, ...options })); return completions.get(root); }
function seal(value, root, options = {}) { const item = completion(root, options); return value.seal({ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument }); }
function resignCompletion(value, keyDocument) { const signed=structuredClone(value); const { integrity, ...body }=signed; signed.integrity={ algorithm:'hmac-sha256', keyId:keyDocument.keyId, payloadDigest:fixtureDigest(body), signature:sign('amf.m4-cross-phase-identity-traversal-completion/v1/integrity',body,keyDocument) }; return signed; }

test('preflight samples only bounded content-free blocks and rejects before state creation', () => {
  const sample = block('capacity'); const estimate = estimateM4CrossPhaseIdentityStreamingCapacity({ sampleBlocks: [sample], expectedBlockCount: 200 });
  assert.deepEqual(Object.keys(estimate).sort(), ['estimatedBytes', 'expectedBlockCount', 'recommendedAvailableBytes', 'requiredAvailableBytes', 'sampleBlockCount', 'sampleEntryCount']);
  assert.equal(estimate.sampleBlockCount, 1); assert.equal(estimate.sampleEntryCount, 2);
  assert.throws(() => preflightM4CrossPhaseIdentityStreamingCapacity({ availableBytes: 0, sampleBlocks: [sample], expectedBlockCount: 200 }), { code: 'm4_cross_phase_identity_capacity_insufficient' });
  const root = temporary(); const target = path.join(root, 'not-created');
  try {
    assert.throws(() => writer(target, sink(new Map()), { capacityPreflight: { availableBytes: 0, sampleBlocks: [sample], expectedBlockCount: 200 } }), { code: 'm4_cross_phase_identity_capacity_insufficient' });
    assert.equal(fs.existsSync(target), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('spools exact content-free blocks, acks deterministic pages, and resolves the signed result', async () => {
  const root = temporary(); const pages = new Map(); const first = block('first'); const second = block('second');
  try {
    const value = writer(root, sink(pages)); assert.equal(value.accept(first).accepted, true); assert.equal(value.accept(first).accepted, false); value.accept(second);
    const sealed = await seal(value, root);
    assert.deepEqual(sealed.coverage, { acceptedBlockCount: 2, sessionCount: 2, eventCount: 2, pageCount: 4 });
    const resolver = createM4CrossPhaseIdentityResolver({ authority: sealed.authority, loadPage: key => pages.get(key) }, SECRET);
    const bound = resolver.resolveBinding({ legacyEventId: first.events[0].legacyEventId, legacySessionId: first.session.legacySessionId,
      sourceTags: first.events[0].sourceTags, conversationKind: 'dm', authorizationContextTags: first.events[0].authorizationContextTags,
      role: 'user', direction: 'inbound', effectiveTimestamp: '2026-07-21T00:00:00Z' });
    assert.equal(bound.eventId, first.events[0].eventId);
    for (const page of pages.values()) assert.equal(Buffer.byteLength(canonicalJson(page), 'utf8') <= M4_CROSS_PHASE_IDENTITY_STREAMING_MAX_PAGE_BYTES, true);
    const database = fs.readFileSync(path.join(root, 'private', 'identity.sqlite'), 'utf8');
    for (const forbidden of ['visibleText', 'ciphertext', 'normalizedPayloadDigest', 'logicalMessageId', 'nativeEventId', 'integrity']) assert.equal(database.includes(forbidden), false, forbidden);
    assert.deepEqual(await seal(value, root), sealed);
    assert.throws(() => value.accept(first), { code: 'm4_cross_phase_identity_streaming_sealed' }); value.close(); assert.throws(() => value.accept(first), { code: 'm4_cross_phase_identity_streaming_closed' });
    const reopened = writer(root, sink(pages)); assert.deepEqual(await seal(reopened, root), sealed);
    const altered = structuredClone(completion(root).traversalCompletion); altered.coveredThrough = '2026-07-23T00:00:00Z';
    await assert.rejects(() => reopened.seal({ traversalCompletion:altered, completionKeyDocument:completion(root).completionKeyDocument }), { code: 'm4_cross_phase_identity_traversal_completion_signature_invalid' }); reopened.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('persists exact replay across restart and fails closed on identity drift', () => {
  const root = temporary(); const pages = new Map(); const original = block('restart');
  try {
    const first = writer(root, sink(pages)); first.accept(original); first.close();
    const second = writer(root, sink(pages)); assert.equal(second.accept(original).accepted, false);
    const drift = structuredClone(original); drift.events[0].role = 'assistant'; drift.events[0].direction = 'outbound';
    assert.throws(() => second.accept(drift), { code: 'm4_cross_phase_identity_streaming_event_drift' }); second.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('initializes a pinned empty database but rejects a nonempty invalid database before mutation', () => {
  const root = temporary(); const privateRoot = path.join(root, 'private'); const databasePath = path.join(privateRoot, 'identity.sqlite'); const pages = new Map();
  try {
    fs.mkdirSync(privateRoot, { mode: 0o700 }); fs.writeFileSync(databasePath, '', { mode: 0o600 });
    const empty = writer(root, sink(pages)); empty.accept(block('empty-restart')); empty.close();
    fs.writeFileSync(databasePath, 'not-a-sqlite-database', { mode: 0o600 });
    assert.throws(() => writer(root, sink(pages)), { code: 'm4_cross_phase_identity_streaming_resource_unsafe' });
    assert.equal(fs.readFileSync(databasePath, 'utf8'), 'not-a-sqlite-database');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('rejects a same-column database with altered table SQL before mutation', () => {
  const root = temporary(); const privateRoot = path.join(root, 'private'); const databasePath = path.join(privateRoot, 'identity.sqlite'); const pages = new Map();
  try {
    fs.mkdirSync(privateRoot, { mode: 0o700 }); const db = new Database(databasePath);
    db.exec(`CREATE TABLE m4_stream_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE m4_stream_blocks (block_digest TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE m4_stream_sessions (legacy_session_id TEXT PRIMARY KEY, bucket TEXT NOT NULL CHECK(bucket<>''), payload TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE m4_stream_events (legacy_event_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, legacy_session_id TEXT NOT NULL, conversation_id TEXT NOT NULL, source_instance_id TEXT NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE m4_stream_references (legacy_event_id TEXT NOT NULL, target_legacy_event_id TEXT NOT NULL, PRIMARY KEY (legacy_event_id, target_legacy_event_id)) WITHOUT ROWID;
INSERT INTO m4_stream_meta(key,value) VALUES ('schema_version','1'),('accepted_blocks','0');`); db.close(); fs.chmodSync(databasePath, 0o600);
    const before = fs.readFileSync(databasePath);
    assert.throws(() => writer(root, sink(pages)), { code: 'm4_cross_phase_identity_streaming_resource_unsafe' });
    assert.deepEqual(fs.readFileSync(databasePath), before);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('snapshots the least-authority page sink at construction', async () => {
  const root = temporary(); const pages = new Map(); let reads = 0; let implementation = async page => { pages.set(page.pageKey, structuredClone(page)); return { pageKey: page.pageKey, digest: page.digest }; };
  const target = { get writePage() { reads += 1; return implementation; } };
  try {
    const value = writer(root, target); implementation = async () => { throw new Error('mutated'); };
    value.accept(block('sink-snapshot')); await seal(value, root);
    assert.equal(reads, 1); assert.equal(pages.size, 2); value.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('normalizes page sink exceptions without echoing private-looking text', async () => {
  const root = temporary(); const privateText = '/private/identity.sqlite confidential-token';
  try {
    const value = writer(root, { writePage: async () => { throw new Error(privateText); } }); value.accept(block('sink-error'));
    await assert.rejects(() => seal(value, root), error => {
      assert.equal(error.code, 'm4_cross_phase_identity_streaming_page_write_failed'); assert.equal(error.message.includes(privateText), false); return true;
    }); value.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('preflight expected-block bound rejects a novel block before partial inserts', async () => {
  const root = temporary(); const pages = new Map(); const preflight = { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('bound-sample')], expectedBlockCount: 1 };
  try {
    const value = writer(root, sink(pages), { capacityPreflight: preflight }); value.accept(block('bound-first'));
    assert.throws(() => value.accept(block('bound-second')), { code: 'm4_cross_phase_identity_streaming_bounds_exceeded' });
    const sealed = await seal(value, root);
    assert.deepEqual(sealed.coverage, { acceptedBlockCount: 1, sessionCount: 1, eventCount: 1, pageCount: 2 }); value.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('streams multiple buckets through primary-key ranges instead of bucket scans', async () => {
  const root = temporary(); const pages = new Map(); const preflight = { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('range-sample')], expectedBlockCount: 2 };
  const secondSession = `ses_cc${'2'.padStart(62, '0')}`; const firstEvent = `evt_bb${'1'.padStart(62, '0')}`; const secondEvent = `evt_cc${'2'.padStart(62, '0')}`;
  try {
    const value = writer(root, sink(pages), { capacityPreflight: preflight }); value.accept(block('range-one', { legacyEventId: firstEvent }));
    value.accept(block('range-two', { legacySessionId: secondSession, legacyEventId: secondEvent }));
    await seal(value, root); value.close();
    const db = new Database(path.join(root, 'private', 'identity.sqlite'), { readonly: true });
    const plan = db.prepare('EXPLAIN QUERY PLAN SELECT legacy_event_id FROM m4_stream_events WHERE legacy_event_id>? AND legacy_event_id<? ORDER BY legacy_event_id LIMIT ?').all('evt_bb', 'evt_bc', 10);
    const rows = db.prepare('SELECT legacy_event_id FROM m4_stream_events WHERE legacy_event_id>? AND legacy_event_id<? ORDER BY legacy_event_id').all('evt_bb', 'evt_bc'); db.close();
    assert.equal(plan.some(item => item.detail.includes('SEARCH') && item.detail.includes('PRIMARY KEY')), true);
    assert.deepEqual(rows.map(item => item.legacy_event_id), [firstEvent]);
    assert.deepEqual([...pages.values()].filter(page => page.entryKind === 'event').map(page => page.bucket).sort(), ['bb', 'cc']);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('rejects symlink and non-private spool targets before mutation', () => {
  const root = temporary(); const target = path.join(root, 'target'); const link = path.join(root, 'link'); const targetFile = path.join(target, 'identity.sqlite');
  try {
    fs.mkdirSync(target, { mode: 0o700 }); fs.symlinkSync(target, link);
    assert.throws(() => createM4CrossPhaseIdentityStreamingWriter({ databasePath: path.join(link, 'identity.sqlite'), registrySecret: SECRET,
      registryKeyId:'registry-fixture-key', capacityPreflight: { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('resource')], expectedBlockCount: 1 }, pageSink: sink(new Map()) }), { code: 'm4_cross_phase_identity_streaming_resource_unsafe' });
    assert.equal(fs.existsSync(targetFile), false);
    const publicRoot = path.join(root, 'public'); fs.mkdirSync(publicRoot, { mode: 0o755 }); fs.chmodSync(publicRoot, 0o755);
    assert.throws(() => createM4CrossPhaseIdentityStreamingWriter({ databasePath: path.join(publicRoot, 'identity.sqlite'), registrySecret: SECRET,
      registryKeyId:'registry-fixture-key', capacityPreflight: { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('resource')], expectedBlockCount: 1 }, pageSink: sink(new Map()) }), { code: 'm4_cross_phase_identity_streaming_resource_unsafe' });
    assert.equal(fs.existsSync(path.join(publicRoot, 'identity.sqlite')), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('rejects reopening a sealed spool with a different registry secret', async () => {
  const root = temporary(); const pages = new Map();
  try {
    const first = writer(root, sink(pages)); first.accept(block('secret')); await seal(first, root); first.close();
    assert.throws(() => createM4CrossPhaseIdentityStreamingWriter({ databasePath: path.join(root, 'private', 'identity.sqlite'), registrySecret: Buffer.alloc(32, 99),
      registryKeyId:'registry-fixture-key', capacityPreflight: { availableBytes: 5 * 1024 * 1024 * 1024, sampleBlocks: [block('preflight')], expectedBlockCount: 20_000 }, pageSink: sink(pages) }), { code: 'm4_cross_phase_identity_streaming_state_invalid' });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('validates cross-block references through SQL before publishing a page', async () => {
  const root = temporary(); const pages = new Map(); const original = block('reference');
  const edited = structuredClone(original); const replacementId = eventId('edited');
  edited.events[0].legacyEventId = replacementId; edited.events[0].eventId = deriveM4V3EventIdFromLegacyEventId(replacementId);
  edited.events[0].state = 'edited'; edited.events[0].revision = 2; edited.events[0].replacesLegacyEventId = eventId('missing');
  try {
    const value = writer(root, sink(pages)); value.accept(original); value.accept(edited);
    await assert.rejects(() => seal(value, root), { code: 'm4_cross_phase_identity_streaming_reference_invalid' });
    assert.equal(pages.size, 0); value.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('acknowledgement failure leaves deterministic orphan pages and retry re-emits them', async () => {
  const root = temporary(); const pages = new Map(); let badAck = true; const seen = [];
  try {
    const value = writer(root, { writePage: async page => { seen.push([page.pageKey, page.digest]); pages.set(page.pageKey, structuredClone(page)); if (badAck) return { pageKey: page.pageKey, digest: digest('wrong') }; return { pageKey: page.pageKey, digest: page.digest }; } });
    value.accept(block('retry'));
    await assert.rejects(() => seal(value, root), { code: 'm4_cross_phase_identity_streaming_page_ack_invalid' });
    value.close(); badAck = false; const resumed = writer(root, { writePage: async page => { seen.push([page.pageKey, page.digest]); pages.set(page.pageKey, structuredClone(page)); return { pageKey: page.pageKey, digest: page.digest }; } });
    const altered = structuredClone(completion(root).traversalCompletion); altered.coveredThrough = '2026-07-23T00:00:00Z';
    await assert.rejects(() => resumed.seal({ traversalCompletion:altered, completionKeyDocument:completion(root).completionKeyDocument }), { code: 'm4_cross_phase_identity_traversal_completion_signature_invalid' });
    const sealed = await seal(resumed, root);
    assert.equal(sealed.coverage.pageCount, 2); assert.deepEqual(seen[0], seen[1]); resumed.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('streams a 10,001-event hot bucket without retaining the pages', async () => {
  const root = temporary(); const pages = new Map(); const sharedSession = compact('ses', 1); const sourceTags = [tag('boundary')];
  try {
    const value = writer(root, sink(pages));
    for (let offset = 0; offset < 10_001; offset += 34) {
      const base = block('boundary', { legacySessionId: sharedSession, legacyEventId: compact('evt', offset), sourceTags }); base.events = [];
      for (let index = offset; index < Math.min(offset + 34, 10_001); index += 1) {
        const legacyEventId = compact('evt', index); base.events.push({ ...block('boundary', { legacySessionId: sharedSession, legacyEventId, sourceTags }).events[0],
          eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId) });
      }
      value.accept(base);
    }
    const sealed = await seal(value, root);
    const eventPages = [...pages.values()].filter(page => page.entryKind === 'event');
    assert.equal(eventPages.reduce((sum, page) => sum + page.events.length, 0), 10_001);
    assert.equal(eventPages.length >= 2, true); assert.equal(eventPages.every(page => page.events.length <= 10_000
      && Buffer.byteLength(canonicalJson(page), 'utf8') <= M4_CROSS_PHASE_IDENTITY_STREAMING_MAX_PAGE_BYTES), true);
    assert.equal(sealed.coverage.eventCount, 10_001);
    assert.equal(sealed.coverage.pageCount, 3); value.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('requires signed completion coverage to exactly match partial, extra, and capacity-mismatched spools before seal intent', async () => {
  const root = temporary(); const pages = new Map(); const preflight={ availableBytes:5*1024*1024*1024, sampleBlocks:[block('coverage-sample')], expectedBlockCount:2 };
  try {
    const value=writer(root,sink(pages),{ capacityPreflight:preflight }); value.accept(block('coverage-first'));
    const actual=readM4CrossPhaseIdentityStreamingCoverage({ databasePath:path.join(root,'private','identity.sqlite') });
    const partial=fixture({ coverage:{ ...actual, blockCount:2, sessionCount:2, eventCount:2 }, registrySecret:SECRET, groupCount:2 });
    await assert.rejects(() => value.seal({ traversalCompletion:partial.traversalCompletion, completionKeyDocument:partial.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_coverage_mismatch' });
    const capacity=fixture({ coverage:{ ...actual, expectedBlockCount:3 }, registrySecret:SECRET });
    await assert.rejects(() => value.seal({ traversalCompletion:capacity.traversalCompletion, completionKeyDocument:capacity.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_coverage_mismatch' });
    const exact=fixture({ coverage:actual, registrySecret:SECRET }); value.accept(block('coverage-extra'));
    await assert.rejects(() => value.seal({ traversalCompletion:exact.traversalCompletion, completionKeyDocument:exact.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_coverage_mismatch' });
    assert.equal(readM4CrossPhaseIdentityStreamingCoverage({ databasePath:path.join(root,'private','identity.sqlite') }).state,'open'); value.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('rejects a tampered completion before recording seal intent', async () => {
  const root=temporary(); const pages=new Map();
  try {
    const value=writer(root,sink(pages)); value.accept(block('tampered-completion')); const item=completion(root); const tampered=structuredClone(item.traversalCompletion); tampered.catalogBaselineDigest='sha256:'.concat('a'.repeat(64));
    await assert.rejects(() => value.seal({ traversalCompletion:tampered, completionKeyDocument:item.completionKeyDocument }), { code:'m4_cross_phase_identity_traversal_completion_invalid' });
    assert.equal(readM4CrossPhaseIdentityStreamingCoverage({ databasePath:path.join(root,'private','identity.sqlite') }).state,'open'); value.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('fails before page emission when a seal-intent completion digest is corrupted', async () => {
  const root=temporary(); const pages=new Map(); let writes=0;
  try {
    const value=writer(root,{ writePage:async page => { writes += 1; pages.set(page.pageKey,structuredClone(page)); return { pageKey:page.pageKey,digest:digest('bad-ack') }; } }); value.accept(block('intent-corruption'));
    await assert.rejects(() => seal(value,root), { code:'m4_cross_phase_identity_streaming_page_ack_invalid' }); value.close(); const beforeRetry=writes;
    const db=new Database(path.join(root,'private','identity.sqlite')); db.prepare("UPDATE m4_stream_meta SET value=? WHERE key='seal_completion_digest'").run('sha256:'.concat('b'.repeat(64))); db.close();
    const resumed=writer(root,sink(pages)); await assert.rejects(() => seal(resumed,root), { code:'m4_cross_phase_identity_streaming_seal_binding_invalid' }); assert.equal(writes,beforeRetry); resumed.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('snapshots the completion key document once before verification and separation', async () => {
  const root=temporary(); const pages=new Map();
  try {
    const value=writer(root,sink(pages)); value.accept(block('hostile-completion-key')); const item=completion(root); const signingDocument={ schema:'amf.migration-signing-key/v1', keyId:item.completionKeyDocument.keyId, key:SECRET.toString('base64') };
    const signed=resignCompletion(item.traversalCompletion,signingDocument); let reads=0; const hostile={ schema:'amf.migration-signing-key/v1', keyId:item.completionKeyDocument.keyId, get key() { reads += 1; return reads === 1 ? SECRET.toString('base64') : Buffer.alloc(32,99).toString('base64'); } };
    await assert.rejects(() => value.seal({ traversalCompletion:signed, completionKeyDocument:hostile }), { code:'m4_cross_phase_identity_streaming_completion_key_separation_invalid' });
    assert.equal(reads,1); assert.equal(readM4CrossPhaseIdentityStreamingCoverage({ databasePath:path.join(root,'private','identity.sqlite') }).state,'open'); value.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});

test('requires a matching registry key identity, secret commitment, and constructor binding', async () => {
  const root=temporary(); const pages=new Map();
  try {
    const missing={ databasePath:path.join(root,'missing','identity.sqlite'), registrySecret:SECRET, capacityPreflight:{ availableBytes:5*1024*1024*1024, sampleBlocks:[block('registry-missing')], expectedBlockCount:1 }, pageSink:sink(pages) };
    assert.throws(() => createM4CrossPhaseIdentityStreamingWriter(missing), { code:'m4_cross_phase_identity_streaming_request_invalid' });
    const value=writer(root,sink(pages)); value.accept(block('registry-binding')); const item=completion(root);
    const wrongCommitment=structuredClone(item.traversalCompletion); wrongCommitment.registryKeyCommitment='hmac-sha256:'.concat('a'.repeat(43));
    await assert.rejects(() => value.seal({ traversalCompletion:resignCompletion(wrongCommitment,item.completionKeyDocument), completionKeyDocument:item.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_registry_binding_invalid' }); value.close();
    const wrongSecret=writer(root,sink(pages),{ registrySecret:Buffer.alloc(32,66) }); await assert.rejects(() => wrongSecret.seal({ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_registry_binding_invalid' }); wrongSecret.close();
    const wrongKeyId=writer(root,sink(pages),{ registryKeyId:'other-registry-key' }); await assert.rejects(() => wrongKeyId.seal({ traversalCompletion:item.traversalCompletion, completionKeyDocument:item.completionKeyDocument }), { code:'m4_cross_phase_identity_streaming_completion_registry_binding_invalid' }); wrongKeyId.close();
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
