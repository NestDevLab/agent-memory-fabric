import assert from 'node:assert/strict';
import test from 'node:test';

import { PostgresConversationArchive, SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { PostgresConversationSessionView, SqliteConversationSessionView } from '../src/conversation-session-view-v2.mjs';

const KEY = Buffer.alloc(32, 17);
const CURSOR_KEY = Buffer.alloc(32, 23);
const TAG = `hmac-sha256:compat-v3:${'a'.repeat(64)}`;
const ACTOR_TAG = `hmac-sha256:compat-v3:${'b'.repeat(64)}`;
const CONTEXT = { contextTags: { conversation: [TAG] } };

function archiveOptions() {
  return {
    cursorKey: CURSOR_KEY,
    resolveIntegrityKey: keyId => keyId === 'compat-test' ? KEY : null,
    resolveExpiresAt: () => '2027-01-01T00:00:00Z'
  };
}

function event({ eventId, conversationId, sequence, text, state = 'active', replacesEventId, tombstonesEventId,
  source = 'src_compat0001', occurredAt, sourceOccurredAt, authorizationContextTags = { conversation: [TAG] } }) {
  const payload = {
    eventId,
    conversationId,
    sourceInstanceId: source,
    role: 'user',
    visibleText: text,
    sourceOccurredAt: sourceOccurredAt || `2026-02-03T04:05:${String(sequence).padStart(2, '0')}.1Z`,
    occurredAt: occurredAt || sourceOccurredAt || `2026-02-03T04:06:${String(sequence).padStart(2, '0')}.2Z`,
    ordering: { sourceSequence: sequence },
    direction: 'inbound',
    conversationKind: 'session',
    authorizationContextTags,
    state,
    revision: state === 'active' ? 1 : 2,
    replacesEventId,
    tombstonesEventId
  };
  if (state === 'tombstone') delete payload.visibleText;
  return createConversationEvent(payload, {
    keyId: 'compat-test',
    key: KEY,
    sentAt: '2026-02-03T04:07:00Z',
    nonce: `compat_nonce_${eventId.slice(-16)}`
  });
}

async function append(archive, value, key) {
  assert.equal((await archive.append(value, key)).outcome, 'stored');
}

async function assertInvalidContextStopsBeforeStorage(reader, calls) {
  const id = 'ccon_compatcontext01';
  const invalidContexts = [{ contextTags: {} }, { contextTags: { conversation: ['not-an-opaque-tag'] } }];
  for (const context of invalidContexts) {
    await assert.rejects(() => reader.get({ id, context }), /context_required/);
    await assert.rejects(() => reader.search({ context, query: '' }), /context_required/);
    await assert.rejects(() => reader.transcript({ id, context, view: 'redacted' }), /context_required/);
  }
  assert.equal(calls(), 0);
}

test('SQLite invalid context is rejected before metadata or candidate queries', async () => {
  let prepares = 0;
  const reader = new SqliteConversationSessionView({
    db: { prepare() { prepares += 1; throw new Error('storage must not be queried'); } },
    cursorKey: CURSOR_KEY
  });
  await assertInvalidContextStopsBeforeStorage(reader, () => prepares);
});

test('PostgreSQL invalid context is rejected before metadata or candidate queries', async () => {
  let queries = 0;
  const reader = new PostgresConversationSessionView({
    pool: { async query() { queries += 1; throw new Error('storage must not be queried'); } },
    cursorKey: CURSOR_KEY
  });
  await assertInvalidContextStopsBeforeStorage(reader, () => queries);
});

async function scenarios(name, create) {
  await test(name, async t => {
    const { archive, reader } = await create();
    t.after(async () => archive.close());

    await t.test('derives metadata from full visible event set and hides replacement chains', async () => {
      const conversationId = 'ccon_compatibility001';
      const base = event({ eventId: 'cevt_compatbase0001', conversationId, sequence: 1, text: 'first visible text' });
      const edited = event({ eventId: 'cevt_compatedit0001', conversationId, sequence: 2, text: 'replacement visible text', state: 'edited', replacesEventId: base.eventId });
      const current = event({ eventId: 'cevt_compatfinal001', conversationId, sequence: 3, text: 'current visible text', state: 'replacement', replacesEventId: edited.eventId });
      await append(archive, base, 'cai_compatbase0001');
      await append(archive, edited, 'cai_compatedit0001');
      await append(archive, current, 'cai_compatfinal001');

      const metadata = await reader.get({ id: conversationId, context: CONTEXT });
      assert.deepEqual(metadata, {
        id: conversationId, runtime: 'conversation-v3', firstOccurredAt: current.sourceOccurredAt,
        lastOccurredAt: current.sourceOccurredAt, eventCount: 1, createdAt: current.sourceOccurredAt,
        title: '', scope: '', ownerSelf: true, conversationKind: 'session', contextTags: CONTEXT.contextTags
      });
      const transcript = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted' });
      assert.deepEqual(transcript.items.map(item => item.eventId), [current.eventId]);
      assert.equal(transcript.items[0].occurredAt, current.occurredAt);
    });

    await t.test('literal Unicode-safe query and bounded cursor continuation are deterministic', async () => {
      const first = event({ eventId: 'cevt_compatsearch01', conversationId: 'ccon_compatsearch01', sequence: 4, text: `[literal]${'😀'.repeat(4096)}` });
      const second = event({ eventId: 'cevt_compatsearch02', conversationId: 'ccon_compatsearch02', sequence: 5, text: 'second [literal] result' });
      await append(archive, first, 'cai_compatsearch01');
      await append(archive, second, 'cai_compatsearch02');
      const firstPage = await reader.search({ context: CONTEXT, query: '[literal]', limit: 1 });
      assert.equal(firstPage.items.length, 1);
      assert.ok(firstPage.nextCursor);
      assert.ok(firstPage.nextCursor.length <= 512);
      const secondPage = await reader.search({ context: CONTEXT, query: '[literal]', limit: 1, cursor: firstPage.nextCursor });
      assert.equal(secondPage.items.length, 1);
      assert.notEqual(secondPage.items[0].id, firstPage.items[0].id);
      await assert.rejects(() => reader.search({ context: CONTEXT, query: '%', limit: 1, cursor: firstPage.nextCursor }), /invalid_request/);
      const text = (await reader.transcript({ id: first.conversationId, context: CONTEXT, view: 'redacted' })).items[0].content.text;
      assert.equal(Array.from(text).length, 4096);
      assert.equal(Array.from(text).at(-1), '😀');
      assert.equal(text.includes('\uFFFD'), false);
    });

    await t.test('query matching is ASCII-insensitive and non-ASCII exact', async () => {
      const conversationId = 'ccon_compatcasefold01';
      await append(archive, event({ eventId: 'cevt_compatcasefold1', conversationId, sequence: 20, text: 'Mixed ASCII Cafe café' }), 'cai_compatcasefold1');
      const ascii = await reader.search({ context: CONTEXT, query: 'mIxEd aScIi', limit: 10 });
      assert.ok(ascii.items.some(item => item.id === conversationId));
      const exactNonAscii = await reader.search({ context: CONTEXT, query: 'café', limit: 10 });
      assert.ok(exactNonAscii.items.some(item => item.id === conversationId));
      const changedNonAsciiCase = await reader.search({ context: CONTEXT, query: 'CAFÉ', limit: 10 });
      assert.equal(changedNonAsciiCase.items.some(item => item.id === conversationId), false);
    });

    await t.test('transcript uses ordered keyset cursors, literal percent and underscore matching', async () => {
      const conversationId = 'ccon_compatliteral01';
      const first = event({ eventId: 'cevt_compatliteral1', conversationId, sequence: 10, text: 'first 100%_literal text' });
      const second = event({ eventId: 'cevt_compatliteral2', conversationId, sequence: 11, text: 'second 100%_literal text' });
      await append(archive, first, 'cai_compatliteral1');
      await append(archive, second, 'cai_compatliteral2');
      const page = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', query: '%_', limit: 1 });
      assert.deepEqual(page.items.map(item => item.eventId), [first.eventId]);
      assert.ok(page.nextCursor && page.nextCursor.length <= 512);
      const next = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', query: '%_', limit: 1, cursor: page.nextCursor });
      assert.deepEqual(next.items.map(item => item.eventId), [second.eventId]);
      await assert.rejects(() => reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', query: '_', limit: 1, cursor: page.nextCursor }), /invalid_request/);
      await assert.rejects(() => reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', cursor: `csv_${'a'.repeat(509)}` }), /invalid_request/);
    });

    await t.test('more than 500 visible events remain readable and paginatable', async () => {
      const conversationId = 'ccon_compatlarge001';
      for (let index = 0; index < 501; index += 1) {
        const suffix = String(index).padStart(8, '0');
        const sourceOccurredAt = new Date(Date.UTC(2026, 1, 3, 5, 0, index)).toISOString();
        await append(archive, event({ eventId: `cevt_bulk${suffix}`, conversationId, sequence: index + 1, text: `bulk ${index}`, sourceOccurredAt }), `cai_bulk${suffix}`);
      }
      const metadata = await reader.get({ id: conversationId, context: CONTEXT });
      assert.equal(metadata.eventCount, 501);
      const first = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', limit: 100 });
      assert.equal(first.items.length, 100);
      const second = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', limit: 100, cursor: first.nextCursor });
      assert.equal(second.items.length, 100);
      assert.notEqual(second.items[0].eventId, first.items.at(-1).eventId);
    });

    await t.test('tombstones remain hidden after retention and context intersection permits non-routing subsets', async () => {
      const conversationId = 'ccon_compatretain01';
      const active = event({ eventId: 'cevt_compatretain01', conversationId, sequence: 12, text: 'removed text', authorizationContextTags: { conversation: [TAG], actor: [ACTOR_TAG] } });
      const tombstone = event({ eventId: 'cevt_compattombstone1', conversationId, sequence: 13, state: 'tombstone', tombstonesEventId: active.eventId, authorizationContextTags: { conversation: [TAG], actor: [ACTOR_TAG] } });
      await append(archive, active, 'cai_compatretain01');
      assert.equal((await archive.tombstone(tombstone, 'cai_compattombstone1')).outcome, 'stored');
      await assert.rejects(() => reader.get({ id: conversationId, context: CONTEXT }), /session_not_found/);
      assert.equal((await archive.applyRetention('2027-01-01T00:00:00Z', 1000, 'cai_compatretain02')).outcome, 'retention_expired');
      await assert.rejects(() => reader.get({ id: conversationId, context: CONTEXT }), /session_not_found/);

      const subsetId = 'ccon_compatsubset01';
      await append(archive, event({ eventId: 'cevt_compatsubset01', conversationId: subsetId, sequence: 14, text: 'subset', authorizationContextTags: { conversation: [TAG], actor: [ACTOR_TAG] } }), 'cai_compatsubset01');
      assert.equal((await reader.get({ id: subsetId, context: CONTEXT })).id, subsetId);
    });

    await t.test('RFC3339 windows use inclusive UTC-millisecond boundaries', async () => {
      const conversationId = 'ccon_compattimebound';
      const value = event({ eventId: 'cevt_compattimebound', conversationId, sequence: 15, text: 'time bound', sourceOccurredAt: '2026-02-03T04:05:00.000000001Z' });
      await append(archive, value, 'cai_compattimebound');
      const sameMillisecond = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', from: '2026-02-03T04:05:00.000999999Z', to: '2026-02-03T04:05:00.000000000Z' });
      assert.deepEqual(sameMillisecond.items.map(item => item.eventId), [value.eventId]);
      const offsetEquivalent = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', from: '2026-02-03T05:05:00.000999999+01:00', to: '2026-02-03T05:05:00.000000000+01:00' });
      assert.deepEqual(offsetEquivalent.items.map(item => item.eventId), [value.eventId]);
      const nextMillisecond = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', from: '2026-02-03T04:05:00.001Z', to: '2026-02-03T04:05:00.001Z' });
      assert.equal(nextMillisecond.items.length, 0);
      await assert.rejects(() => reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', from: '2026-02-30T04:05:00Z' }), /invalid_request/);
      await assert.rejects(() => reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', from: '2026-02-03T04:05:00.001Z', to: '2026-02-03T04:05:00.000999999Z' }), /invalid_request/);
    });

    await t.test('queryless search uses visible interval intersection, while text search uses an event window', async () => {
      const conversationId = 'ccon_compatinterval01';
      const before = event({ eventId: 'cevt_compatinterval1', conversationId, sequence: 18, text: 'outside before', sourceOccurredAt: '2026-02-03T04:00:00.000000001Z' });
      const after = event({ eventId: 'cevt_compatinterval2', conversationId, sequence: 19, text: 'outside after', sourceOccurredAt: '2026-02-03T06:00:00.000000001Z' });
      await append(archive, before, 'cai_compatinterval1');
      await append(archive, after, 'cai_compatinterval2');
      const window = { from: '2026-02-03T05:00:00Z', to: '2026-02-03T05:30:00Z' };
      const queryless = await reader.search({ context: CONTEXT, query: '', limit: 100, ...window });
      assert.ok(queryless.items.some(item => item.id === conversationId));
      const text = await reader.search({ context: CONTEXT, query: 'outside before', limit: 100, ...window });
      assert.equal(text.items.some(item => item.id === conversationId), false);
    });

    await t.test('maximum request identifiers and query bindings still produce a cursor below 512 characters', async () => {
      const conversationId = `ccon_${'c'.repeat(123)}`;
      const first = event({ eventId: `cevt_${'d'.repeat(123)}`, conversationId, sequence: 16, text: 'q'.repeat(4096) });
      const second = event({ eventId: `cevt_${'e'.repeat(123)}`, conversationId, sequence: 17, text: 'q'.repeat(4096) });
      await append(archive, first, `cai_${'f'.repeat(123)}`);
      await append(archive, second, `cai_${'g'.repeat(123)}`);
      const page = await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', query: 'q'.repeat(4096), limit: 1 });
      assert.ok(page.nextCursor);
      assert.ok(page.nextCursor.length <= 512);
      assert.deepEqual((await reader.transcript({ id: conversationId, context: CONTEXT, view: 'redacted', query: 'q'.repeat(4096), limit: 1, cursor: page.nextCursor })).items.map(item => item.eventId), [second.eventId]);
    });

    await t.test('search filters do not change full-conversation metadata or ordering-key times', async () => {
      const conversationId = 'ccon_compatmetadata1';
      const first = event({ eventId: 'cevt_compatmetadata1', conversationId, sequence: 8, text: 'nonmatching first message' });
      const matching = event({ eventId: 'cevt_compatmetadata2', conversationId, sequence: 9, text: 'target literal message' });
      await append(archive, first, 'cai_compatmetadata1');
      await append(archive, matching, 'cai_compatmetadata2');
      let cursor = null;
      let item = null;
      for (let page = 0; page < 10 && !item; page += 1) {
        const result = await reader.search({ context: CONTEXT, query: 'target literal', limit: 10, cursor });
        item = result.items.find(value => value.id === conversationId) || null;
        cursor = result.nextCursor;
      }
      assert.ok(item);
      assert.equal(item.eventCount, 2);
      assert.equal(item.firstOccurredAt, first.sourceOccurredAt);
      assert.equal(item.lastOccurredAt, matching.sourceOccurredAt);
    });

    await t.test('rejects an inconsistent authoritative visible set and never accepts null context', async () => {
      const conversationId = 'ccon_compatinvalid01';
      await append(archive, event({ eventId: 'cevt_compatinvalid1', conversationId, sequence: 6, text: 'first' }), 'cai_compatinvalid01');
      await append(archive, event({ eventId: 'cevt_compatinvalid2', conversationId, sequence: 7, text: 'second', source: 'src_compat0002' }), 'cai_compatinvalid02');
      await assert.rejects(() => reader.get({ id: conversationId, context: CONTEXT }), /session_not_found/);
      await assert.rejects(() => reader.search({ context: null, query: 'first' }), /context_required/);
    });
  });
}

await scenarios('SQLite conversation session compatibility view', async () => {
  const archive = new SqliteConversationArchive(archiveOptions());
  return { archive, reader: new SqliteConversationSessionView({ db: archive.db, cursorKey: CURSOR_KEY, scanLimit: 2 }) };
});

test('conversation view rejects scan limits beyond its fixed bound', () => {
  const archive = new SqliteConversationArchive(archiveOptions());
  assert.throws(() => new SqliteConversationSessionView({ db: archive.db, cursorKey: CURSOR_KEY, scanLimit: 501 }), /scan_limit_invalid/);
  archive.close();
});

test('conversation view retains an independent cursor key copy', () => {
  const archive = new SqliteConversationArchive(archiveOptions());
  const callerKey = Buffer.alloc(32, 31); const expected = Buffer.from(callerKey);
  const reader = new SqliteConversationSessionView({ db: archive.db, cursorKey: callerKey });
  callerKey.fill(0);
  assert.equal(reader.cursorKey.equals(expected), true);
  archive.close();
});

if (process.env.AMF_ARCHIVE_POSTGRES_TEST_URL) {
  await scenarios('PostgreSQL conversation session compatibility view', async () => {
    const archive = new PostgresConversationArchive({ connectionString: process.env.AMF_ARCHIVE_POSTGRES_TEST_URL, ...archiveOptions() });
    await archive.ready();
    await archive.pool.query('TRUNCATE agent_memory_fabric.conversation_archive_audit_v1, agent_memory_fabric.conversation_archive_conflicts_v1, agent_memory_fabric.conversation_archive_requests_v1, agent_memory_fabric.conversation_archive_events_v1');
    return { archive, reader: new PostgresConversationSessionView({ pool: archive.pool, cursorKey: CURSOR_KEY, scanLimit: 2 }) };
  });
} else {
  test('PostgreSQL conversation session compatibility view is opt-in', { skip: 'set AMF_ARCHIVE_POSTGRES_TEST_URL for real PostgreSQL parity' }, () => {});
}
