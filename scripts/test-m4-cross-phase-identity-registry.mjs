import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createM4CrossPhaseIdentityAuthority,
  createM4CrossPhaseIdentityPage,
  createM4CrossPhaseIdentityRegistry,
  createM4CrossPhaseIdentityResolver,
  describeM4CrossPhaseIdentityPage,
  verifyM4CrossPhaseIdentityAuthority,
} from '../src/migration/m4-cross-phase-identity-registry.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from '../src/migration/m4-v2-conversation-projector.mjs';

const secret = Buffer.alloc(32, 7);
const hex = value => crypto.createHash('sha256').update(value).digest('hex');
const session = value => `ses_${hex(`session:${value}`)}`;
const event = value => `evt_${hex(`event:${value}`)}`;
const tag = value => `routing:${hex(`tag:${value}`)}`;
const opaque = value => `hmac-sha256:routing-v1:${hex(`opaque:${value}`)}`;

function projection({ sessionId = session('one'), eventId = event('one'), occurredAt = '2026-07-22T00:00:01Z', editedAt = null,
  conversationKind = 'dm', conversation = opaque('conversation'), room = opaque('room'), role = 'user', direction = 'inbound' } = {}) {
  return { schema: 'amf.raw-event-projection/v2', eventId, sessionId,
    logicalMessageId: `lmsg_${hex('logical')}`, logicalMessageAliases: [],
    derivationVersion: 'amf-logical-message/v1', keyVersion: 'routing-v1', sourceKind: 'hermes',
    observationClass: 'native', direction, conversationKind,
    contextTags: { sender: [opaque(role)], conversation: [conversation], room: [room] },
    subtype: 'message', occurredAt, editedAt, nativeRevision: 1, sourceSequence: 1,
    authoritativeDeletion: false, role, contentType: 'text', contentParts: 1, hasContent: true,
    normalizationVersion: 'amf-observation-normalization/v1', normalizedPayloadDigest: opaque(`payload:${eventId}`) };
}
function fixture() {
  const legacySessionId = session('one'); const legacyEventId = event('one'); const sourceTags = [tag('a'), tag('b')].sort();
  const inputProjection = projection({ sessionId: legacySessionId, eventId: legacyEventId });
  const editLegacyEventId = event('registered-edit');
  const editProjection = projection({ sessionId: legacySessionId, eventId: editLegacyEventId,
    occurredAt: inputProjection.occurredAt, editedAt: '2026-07-22T00:00:02Z' });
  const eventEntries = [{ legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId),
    conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
    sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags,
    conversationKind: 'dm', authorizationContextTags: inputProjection.contextTags, role: 'user', direction: 'inbound',
    state: 'active', revision: 1, replacesLegacyEventId: null, tombstonesLegacyEventId: null,
    conflictsWithLegacyEventIds: [] },
  { legacyEventId: editLegacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(editLegacyEventId),
    conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
    sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags,
    conversationKind: 'dm', authorizationContextTags: editProjection.contextTags, role: 'user', direction: 'inbound',
    state: 'edited', revision: 2, replacesLegacyEventId: legacyEventId, tombstonesLegacyEventId: null,
    conflictsWithLegacyEventIds: [] }].sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  const created = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` }, sessions: [{
    legacySessionId, conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
    conversationKind: 'dm', sessionContextTags: { conversation: [opaque('conversation')], room: [opaque('room')] },
  }], events: eventEntries }, secret);
  const pages = new Map(created.pages.map(page => [page.pageKey, page]));
  return { ...created, resolver: createM4CrossPhaseIdentityResolver({ authority: created.authority,
    loadPage: pageKey => structuredClone(pages.get(pageKey)) }, secret), inputProjection, editProjection };
}

test('constructs and describes one canonical page before signing descriptor-only authority', () => {
  const value = fixture(); const sourcePage = value.pages.find(item => item.entryKind === 'event');
  const page = createM4CrossPhaseIdentityPage({ bucket: sourcePage.bucket, entryKind: sourcePage.entryKind,
    shard: sourcePage.shard, entries: sourcePage.events });
  const descriptor = describeM4CrossPhaseIdentityPage(page);
  const sessionPage = value.pages.find(item => item.entryKind === 'session');
  const session = createM4CrossPhaseIdentityPage({ bucket: sessionPage.bucket, entryKind: sessionPage.entryKind,
    shard: sessionPage.shard, entries: sessionPage.sessions });
  const authority = createM4CrossPhaseIdentityAuthority({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, pageDescriptors: [descriptor, describeM4CrossPhaseIdentityPage(session)].sort((left, right) => left.pageKey.localeCompare(right.pageKey)) }, secret);
  const { mac: ignored, ...unsigned } = authority;
  assert.deepEqual(verifyM4CrossPhaseIdentityAuthority(authority, secret), unsigned);
  assert.throws(() => createM4CrossPhaseIdentityAuthority({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, pageDescriptors: [{ ...descriptor, shard: 1, pageKey: `${descriptor.bucket}-e-0001` }] }, secret), { code: 'm4_cross_phase_identity_authority_invalid' });
  const wrongBucket = descriptor.bucket === 'ff' ? 'fe' : 'ff';
  assert.throws(() => createM4CrossPhaseIdentityAuthority({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, pageDescriptors: [{ ...descriptor, bucket: wrongBucket, pageKey: `${wrongBucket}-e-0000` }] }, secret), { code: 'm4_cross_phase_identity_authority_invalid' });
});

test('evicts LRU pages by byte cap while preserving registered resolution', () => {
  const sourceTags = Array.from({ length: 64 }, (_, index) => `${'x'.repeat(124)}${index.toString(16).padStart(4, '0')}:${'a'.repeat(64)}`);
  const context = { sender: [opaque('cache-sender')], conversation: [opaque('cache-conversation')], room: [opaque('cache-room')] };
  function makePage(bucket) {
    const legacySessionId = `ses_${bucket}${'0'.repeat(62)}`; const conversationId = deriveM4V3ConversationIdFromLegacySessionId(legacySessionId);
    const sourceInstanceId = deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags);
    const events = Array.from({ length: 1_800 }, (_, index) => {
      const legacyEventId = `evt_${bucket}${index.toString(16).padStart(62, '0')}`;
      return { legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId,
        sourceInstanceId, sourceTags, conversationKind: 'dm', authorizationContextTags: context, role: 'user', direction: 'inbound',
        state: 'active', revision: 1, replacesLegacyEventId: null, tombstonesLegacyEventId: null, conflictsWithLegacyEventIds: [] };
    });
    return createM4CrossPhaseIdentityPage({ bucket, entryKind: 'event', shard: 0, entries: events });
  }
  const pages = ['aa', 'bb', 'cc'].map(makePage); const pageMap = new Map(pages.map(page => [page.pageKey, page]));
  const authority = createM4CrossPhaseIdentityAuthority({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('cache-completion')}`, catalogRevisionDigest: `sha256:${hex('cache-catalog')}` },
    pageDescriptors: pages.map(describeM4CrossPhaseIdentityPage).sort((left, right) => left.pageKey.localeCompare(right.pageKey)) }, secret);
  assert.equal(pages.reduce((sum, page) => sum + Buffer.byteLength(canonicalJson(page), 'utf8'), 0) > 64 * 1024 * 1024, true);
  const loads = new Map(); const resolver = createM4CrossPhaseIdentityResolver({ authority, loadPage: key => {
    loads.set(key, (loads.get(key) ?? 0) + 1); return structuredClone(pageMap.get(key));
  } }, secret);
  for (const page of pages) {
    const entry = page.events[0]; const resolved = resolver.resolveBinding({ legacyEventId: entry.legacyEventId, legacySessionId: entry.legacySessionId,
      sourceTags, conversationKind: 'dm', authorizationContextTags: context, role: 'user', direction: 'inbound', effectiveTimestamp: '2026-07-21T00:00:00Z' });
    assert.equal(resolved.eventId, entry.eventId);
  }
  const first = pages[0].events[0];
  assert.equal(resolver.resolveBinding({ legacyEventId: first.legacyEventId, legacySessionId: first.legacySessionId,
    sourceTags, conversationKind: 'dm', authorizationContextTags: context, role: 'user', direction: 'inbound', effectiveTimestamp: '2026-07-21T00:00:00Z' }).eventId, first.eventId);
  assert.equal(loads.get(pages[0].pageKey), 2); assert.equal(loads.get(pages[1].pageKey), 1); assert.equal(loads.get(pages[2].pageKey), 1);
});

function crossPageLifecycleFixture() {
  const legacySessionId = `ses_aa${'1'.padStart(62, '0')}`;
  const sourceTags = [tag('a')];
  const ids = {
    active: `evt_00${'1'.padStart(62, '0')}`,
    edited: `evt_11${'1'.padStart(62, '0')}`,
    tombstone: `evt_22${'1'.padStart(62, '0')}`,
    conflict: `evt_33${'1'.padStart(62, '0')}`,
  };
  const projections = Object.fromEntries(Object.entries(ids).map(([name, eventId]) => [name,
    projection({ sessionId: legacySessionId, eventId, occurredAt: '2026-07-21T00:00:00Z' })]));
  const base = (legacyEventId, state, revision, replacesLegacyEventId = null,
    tombstonesLegacyEventId = null, conflictsWithLegacyEventIds = []) => ({
    legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId),
    conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
    sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags,
    conversationKind: 'dm', authorizationContextTags: projections.active.contextTags, role: 'user', direction: 'inbound',
    state, revision, replacesLegacyEventId, tombstonesLegacyEventId, conflictsWithLegacyEventIds,
  });
  const events = [base(ids.active, 'active', 1), base(ids.edited, 'edited', 2, ids.active),
    base(ids.tombstone, 'tombstone', 3, null, ids.edited),
    base(ids.conflict, 'conflict', 2, null, null, [ids.active, ids.edited])];
  const created = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` },
    sessions: [{ legacySessionId, conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
      conversationKind: 'dm', sessionContextTags: { conversation: [opaque('conversation')], room: [opaque('room')] } }],
    events }, secret);
  return { ...created, ids, projections };
}

test('signs bounded pages and resolves an existing v2 event with its exact source binding', () => {
  const value = fixture(); const verified = verifyM4CrossPhaseIdentityAuthority(value.authority, secret);
  assert.equal(verified.coverage.sessionCount, 1); assert.equal(verified.coverage.eventCount, 2);
  assert.doesNotMatch(JSON.stringify(value), /visibleText|ciphertext|nativeSessionId|nativeEventId/);
  const resolved = value.resolver.resolve({ projection: value.inputProjection, sourceTag: tag('a') });
  assert.equal(resolved.eventId, deriveM4V3EventIdFromLegacyEventId(value.inputProjection.eventId));
  assert.equal(resolved.sourceInstanceId, deriveM4V3SourceInstanceIdFromLegacySession(value.inputProjection.sessionId, [tag('a'), tag('b')].sort()));
  assert.equal(resolved.covered, true);
  assert.equal(resolved.state, 'active'); assert.equal(resolved.revision, 1);
});

test('resolves a registered edit through its validated legacy predecessor', () => {
  const value = fixture();
  const resolved = value.resolver.resolve({ projection: value.editProjection, sourceTag: tag('a') });
  assert.equal(resolved.covered, true);
  assert.equal(resolved.state, 'edited');
  assert.equal(resolved.revision, 2);
  assert.equal(resolved.replacesEventId, deriveM4V3EventIdFromLegacyEventId(value.inputProjection.eventId));
  assert.equal(resolved.tombstonesEventId, null);
  assert.deepEqual(resolved.conflictsWithEventIds, []);
});

test('resolveBinding matches full-v2 resolution and derives post-cutoff source instances from canonical tag sets', () => {
  const value = fixture(); const sourceTags = [tag('a'), tag('b')].sort();
  const bound = value.resolver.resolveBinding({ legacyEventId: value.inputProjection.eventId,
    legacySessionId: value.inputProjection.sessionId, sourceTags, conversationKind: value.inputProjection.conversationKind,
    authorizationContextTags: value.inputProjection.contextTags, role: value.inputProjection.role,
    direction: value.inputProjection.direction, effectiveTimestamp: value.inputProjection.occurredAt });
  const full = value.resolver.resolve({ projection: value.inputProjection, sourceTag: tag('a') });
  assert.deepEqual(bound, full);
  assert.throws(() => value.resolver.resolveBinding({ legacyEventId: value.inputProjection.eventId,
    legacySessionId: value.inputProjection.sessionId, sourceTags: [tag('a')], allowSourceTagMember: true,
    conversationKind: value.inputProjection.conversationKind, authorizationContextTags: value.inputProjection.contextTags,
    role: value.inputProjection.role, direction: value.inputProjection.direction,
    effectiveTimestamp: value.inputProjection.occurredAt }), { code: 'm4_cross_phase_identity_input_invalid' });
  const next = value.resolver.resolveBinding({ legacyEventId: event('multi-tag-post-cutoff'),
    legacySessionId: value.inputProjection.sessionId, sourceTags, conversationKind: 'dm',
    authorizationContextTags: value.inputProjection.contextTags, role: 'user', direction: 'inbound',
    effectiveTimestamp: '2026-07-22T00:00:01Z' });
  assert.equal(next.sourceInstanceId, deriveM4V3SourceInstanceIdFromLegacySession(value.inputProjection.sessionId, sourceTags));
  assert.deepEqual(next.postCutoffBinding.sourceTags, sourceTags);
});

test('validates cross-page edit, tombstone, and conflict targets with bounded page caching', () => {
  const value = crossPageLifecycleFixture();
  const pages = new Map(value.pages.map(page => [page.pageKey, page])); let loads = 0;
  const resolver = createM4CrossPhaseIdentityResolver({ authority: value.authority,
    loadPage: pageKey => { loads += 1; return structuredClone(pages.get(pageKey)); } }, secret);
  const edit = resolver.resolve({ projection: value.projections.edited, sourceTag: tag('a') });
  assert.equal(edit.replacesEventId, deriveM4V3EventIdFromLegacyEventId(value.ids.active));
  const loadsAfterEdit = loads;
  resolver.resolve({ projection: value.projections.edited, sourceTag: tag('a') });
  assert.equal(loads, loadsAfterEdit);
  const tombstone = resolver.resolve({ projection: value.projections.tombstone, sourceTag: tag('a') });
  assert.equal(tombstone.tombstonesEventId, deriveM4V3EventIdFromLegacyEventId(value.ids.edited));
  const conflict = resolver.resolve({ projection: value.projections.conflict, sourceTag: tag('a') });
  assert.deepEqual(conflict.conflictsWithEventIds,
    [value.ids.active, value.ids.edited].map(deriveM4V3EventIdFromLegacyEventId));

  const activePageKey = value.pages.find(page => page.events.some(item => item.legacyEventId === value.ids.active)).pageKey;
  const unavailable = createM4CrossPhaseIdentityResolver({ authority: value.authority,
    loadPage: pageKey => pageKey === activePageKey ? null : structuredClone(pages.get(pageKey)) }, secret);
  assert.throws(() => unavailable.resolve({ projection: value.projections.edited, sourceTag: tag('a') }),
    { code: 'm4_cross_phase_identity_page_unavailable' });
  const tamperedPages = new Map(value.pages.map(page => [page.pageKey, structuredClone(page)]));
  tamperedPages.get(activePageKey).events[0].role = 'assistant';
  const tampered = createM4CrossPhaseIdentityResolver({ authority: value.authority,
    loadPage: pageKey => tamperedPages.get(pageKey) }, secret);
  assert.throws(() => tampered.resolve({ projection: value.projections.edited, sourceTag: tag('a') }),
    { code: 'm4_cross_phase_identity_page_invalid' });
});

test('uses a registered predecessor source for post-cutoff edits and tombstones', () => {
  const value = fixture(); const changed = projection({ sessionId: value.inputProjection.sessionId, eventId: event('changed'),
    occurredAt: '2026-07-21T00:00:00Z', editedAt: '2026-07-22T00:00:01Z' });
  const resolved = value.resolver.resolve({ projection: changed, sourceTag: tag('a'), priorLegacyEventId: value.inputProjection.eventId });
  const prior = value.resolver.resolve({ projection: value.inputProjection, sourceTag: tag('a') });
  assert.equal(resolved.conversationId, prior.conversationId);
  assert.equal(resolved.sourceInstanceId, prior.sourceInstanceId);
  assert.equal(resolved.priorEventId, prior.eventId);
});

test('derives new post-cutoff sessions and revisions locally but rejects first observations at the cutoff', () => {
  const value = fixture(); const newSession = session('new'); const first = projection({ sessionId: newSession, eventId: event('new'),
    occurredAt: '2026-07-22T00:00:00.000000001Z', conversation: opaque('new-conversation'), room: opaque('new-room') });
  const local = new Map(); const pages = new Map(value.pages.map(page => [page.pageKey, page]));
  const resolver = createM4CrossPhaseIdentityResolver({ authority: value.authority,
    loadPage: pageKey => structuredClone(pages.get(pageKey)), loadPostCutoffEvent: id => local.get(id) ?? null }, secret);
  const active = resolver.resolve({ projection: first, sourceTag: tag('a') });
  assert.equal(active.covered, false);
  local.set(first.eventId, active.postCutoffBinding);
  const changed = projection({ ...first, eventId: event('new-edit'), editedAt: '2026-07-22T00:00:02Z' });
  const edit = resolver.resolve({ projection: changed, sourceTag: tag('a'), priorLegacyEventId: first.eventId });
  assert.equal(edit.sourceInstanceId, active.sourceInstanceId);
  assert.equal(edit.priorEventId, active.eventId);
  assert.throws(() => resolver.resolve({ projection: { ...first, occurredAt: '2026-07-22T00:00:00Z' }, sourceTag: tag('a') }),
    { code: 'm4_cross_phase_identity_registry_missing' });
  assert.throws(() => value.resolver.resolve({ projection: changed, sourceTag: tag('a'), priorLegacyEventId: event('arbitrary') }),
    { code: 'm4_cross_phase_identity_local_predecessor_missing' });
});

test('fails closed on source, session route, role, page, authority, or predecessor drift', () => {
  const value = fixture();
  assert.throws(() => value.resolver.resolve({ projection: value.inputProjection, sourceTag: tag('other') }), { code: 'm4_cross_phase_identity_binding_mismatch' });
  assert.throws(() => value.resolver.resolve({ projection: projection({ room: opaque('other-room') }), sourceTag: tag('a') }), { code: 'm4_cross_phase_identity_binding_mismatch' });
  assert.throws(() => value.resolver.resolve({ projection: projection({ role: 'assistant', direction: 'outbound' }), sourceTag: tag('a') }), { code: 'm4_cross_phase_identity_binding_mismatch' });
  const badAuthority = structuredClone(value.authority); badAuthority.mac = `hmac-sha256:${'a'.repeat(43)}`;
  assert.throws(() => verifyM4CrossPhaseIdentityAuthority(badAuthority, secret), { code: 'm4_cross_phase_identity_authority_invalid' });
  const badBinding = structuredClone(value.authority); badBinding.backfillBinding.completionDigest = `sha256:${hex('other')}`;
  assert.throws(() => verifyM4CrossPhaseIdentityAuthority(badBinding, secret), { code: 'm4_cross_phase_identity_authority_invalid' });
  const pages = new Map(value.pages.map(page => [page.pageKey, structuredClone(page)]));
  const eventPage = [...pages.values()].find(page => page.events.some(item => item.legacyEventId === value.inputProjection.eventId));
  eventPage.events.find(item => item.legacyEventId === value.inputProjection.eventId).role = 'assistant';
  const resolver = createM4CrossPhaseIdentityResolver({ authority: value.authority, loadPage: pageKey => pages.get(pageKey) }, secret);
  assert.throws(() => resolver.resolve({ projection: value.inputProjection, sourceTag: tag('a') }), { code: 'm4_cross_phase_identity_page_invalid' });
  const oldUnknown = projection({ sessionId: value.inputProjection.sessionId, eventId: event('old-edit'), occurredAt: '2026-07-22T00:00:01Z' });
  assert.throws(() => value.resolver.resolve({ projection: oldUnknown, sourceTag: tag('a'), priorLegacyEventId: event('missing') }),
    { code: 'm4_cross_phase_identity_local_predecessor_missing' });
});

test('rejects duplicate ordering and derived identity substitutions at creation', () => {
  const value = fixture(); const page = value.pages.find(item => item.sessions.length);
  assert.throws(() => createM4CrossPhaseIdentityRegistry({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, sessions: [page.sessions[0], page.sessions[0]], events: [] }, secret), { code: 'm4_cross_phase_identity_entries_invalid' });
  const wrong = structuredClone(page.sessions[0]); wrong.conversationId = `ccon_${hex('wrong')}`;
  assert.throws(() => createM4CrossPhaseIdentityRegistry({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, sessions: [wrong], events: [] }, secret), { code: 'm4_cross_phase_identity_binding_invalid' });
  const sessions = value.pages.flatMap(item => item.sessions).sort((left, right) => left.legacySessionId.localeCompare(right.legacySessionId));
  const events = value.pages.flatMap(item => item.events).sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  const edited = events.find(item => item.state === 'edited');
  edited.sourceTags = [tag('other')];
  edited.sourceInstanceId = deriveM4V3SourceInstanceIdFromLegacySession(edited.legacySessionId, edited.sourceTags);
  assert.throws(() => createM4CrossPhaseIdentityRegistry({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, sessions, events }, secret),
  { code: 'm4_cross_phase_identity_reference_invalid' });
  const mismatchedKind = value.pages.flatMap(item => item.events).sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  mismatchedKind[0].conversationKind = 'group';
  assert.throws(() => createM4CrossPhaseIdentityRegistry({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, sessions, events: mismatchedKind }, secret),
  { code: 'm4_cross_phase_identity_session_binding_invalid' });
  const mismatchedContext = value.pages.flatMap(item => item.events).sort((left, right) => left.legacyEventId.localeCompare(right.legacyEventId));
  mismatchedContext[0].authorizationContextTags.room = [opaque('different-room')];
  assert.throws(() => createM4CrossPhaseIdentityRegistry({ coveredThrough: value.authority.coveredThrough,
    backfillBinding: value.authority.backfillBinding, sessions, events: mismatchedContext }, secret),
  { code: 'm4_cross_phase_identity_session_binding_invalid' });
});

test('shards a registry larger than one page limit without weakening the per-page bound', () => {
  const sessions = [];
  for (let suffix = 0; suffix < 10_001; suffix += 1) {
    const legacySessionId = `ses_00${suffix.toString(16).padStart(62, '0')}`;
    sessions.push({ legacySessionId, conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
      conversationKind: 'dm', sessionContextTags: { conversation: [opaque('conversation')], room: [opaque('room')] } });
  }
  const created = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` },
    sessions, events: [] }, secret);
  assert.equal(created.authority.coverage.sessionCount, 10_001);
  assert.equal(created.pages.filter(page => page.entryKind === 'session' && page.bucket === '00').length, 2);
  assert.ok(created.pages.every(page => page.sessions.length + page.events.length <= 10_000));
  const pages = new Map(created.pages.map(page => [page.pageKey, page])); let loads = 0;
  const resolver = createM4CrossPhaseIdentityResolver({ authority: created.authority,
    loadPage: pageKey => { loads += 1; return structuredClone(pages.get(pageKey)); } }, secret);
  const last = sessions.at(-1);
  const first = sessions[0];
  const firstProjection = projection({ sessionId: first.legacySessionId, eventId: event('hot-first'),
    occurredAt: '2026-07-22T00:00:01Z' });
  const lastProjection = projection({ sessionId: last.legacySessionId, eventId: event('hot-last'),
    occurredAt: '2026-07-22T00:00:01Z' });
  resolver.resolve({ projection: firstProjection, sourceTag: tag('a') });
  resolver.resolve({ projection: firstProjection, sourceTag: tag('a') });
  resolver.resolve({ projection: lastProjection, sourceTag: tag('a') });
  assert.equal(loads, 2);
});

test('subdivides a hot bucket by canonical byte size below the entry ceiling', () => {
  const legacySessionId = `ses_bb${'1'.padStart(62, '0')}`;
  const sender = Array.from({ length: 1_000 }, (_, index) => {
    const version = `v${String(index).padStart(6, '0')}${'x'.repeat(120)}`;
    return `hmac-sha256:${version}:${hex(`large-tag:${index}`)}`;
  });
  const contextTags = { sender, conversation: [opaque('conversation')], room: [opaque('room')] };
  const sourceTags = [tag('a')];
  const events = Array.from({ length: 200 }, (_, index) => {
    const legacyEventId = `evt_55${index.toString(16).padStart(62, '0')}`;
    return { legacyEventId, legacySessionId, eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId),
      conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
      sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags,
      conversationKind: 'dm', authorizationContextTags: contextTags, role: 'user', direction: 'inbound',
      state: 'active', revision: 1, replacesLegacyEventId: null, tombstonesLegacyEventId: null,
      conflictsWithLegacyEventIds: [] };
  });
  const created = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` },
    sessions: [{ legacySessionId, conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
      conversationKind: 'dm', sessionContextTags: { conversation: [opaque('conversation')], room: [opaque('room')] } }],
    events }, secret);
  const eventPages = created.pages.filter(page => page.entryKind === 'event' && page.bucket === '55');
  assert.ok(eventPages.length > 1);
  assert.ok(eventPages.every(page => page.events.length < 10_000));
  const pages = new Map(created.pages.map(page => [page.pageKey, page]));
  const resolver = createM4CrossPhaseIdentityResolver({ authority: created.authority,
    loadPage: pageKey => structuredClone(pages.get(pageKey)) }, secret);
  for (const item of [events[0], events.at(-1)]) {
    const inputProjection = { ...projection({ sessionId: legacySessionId, eventId: item.legacyEventId }), contextTags };
    assert.equal(resolver.resolve({ projection: inputProjection, sourceTag: tag('a') }).eventId, item.eventId);
  }
});
