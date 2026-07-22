import assert from 'node:assert/strict';
import test from 'node:test';

import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { PostgresM4V3ExtractorReader, SqliteM4V3ExtractorReader } from '../src/m4-v3-extractor-reader.mjs';
import { createM4ConversationExtractorAliases, createM4ConversationExtractorIdentityResolver } from '../src/migration/m4-conversation-extractor-aliases.mjs';

const KEY = Buffer.alloc(32, 51);
const CURSOR_KEY = Buffer.alloc(32, 52);
const TAG = `hmac-sha256:extractor-v3:${'a'.repeat(64)}`;
const expires = new Map();
const identityResolver = ({ conversationId }) => conversationId === 'ccon_extractlegacy01' ? `ses_${'b'.repeat(64)}` : conversationId;
function signedResolver(aliases, coveredThrough = '2026-07-22T11:00:00Z') {
  return createM4ConversationExtractorIdentityResolver(createM4ConversationExtractorAliases({ coveredThrough, aliases }, KEY), KEY);
}

function options() {
  return { cursorKey: Buffer.alloc(32, 53), resolveIntegrityKey: id => id === 'extractor-test' ? KEY : null,
    resolveExpiresAt: item => expires.get(item.eventId) || '2027-01-01T00:00:00Z' };
}
function event({ eventId, conversationId, sequence, second, text, state = 'active', replacesEventId, tombstonesEventId }) {
  const payload = { eventId, conversationId, sourceInstanceId: `src_${conversationId.slice(5)}`, role: 'user', visibleText: text,
    sourceOccurredAt: `2026-07-22T10:00:${String(second).padStart(2, '0')}.${String(sequence).padStart(9, '0')}Z`,
    occurredAt: `2026-07-22T10:01:${String(second).padStart(2, '0')}Z`, ordering: { sourceSequence: sequence },
    direction: 'inbound', conversationKind: 'session', authorizationContextTags: { conversation: [TAG] }, state,
    revision: state === 'active' ? 1 : 2, replacesEventId, tombstonesEventId };
  if (state === 'tombstone') delete payload.visibleText;
  return createConversationEvent(payload, { keyId: 'extractor-test', key: KEY, sentAt: '2026-07-22T11:00:00Z', nonce: `extract_${eventId}`.slice(0, 64).padEnd(16, 'x') });
}
async function append(archive, value) { assert.equal((await archive.append(value, `cai_${value.eventId.slice(5)}`)).outcome, 'stored'); }

test('SQLite reader is newest-first, resumable, redacted, and applies archive visibility', async t => {
  const archive = new SqliteConversationArchive(options()); t.after(() => archive.close());
  const legacy = 'ccon_extractlegacy01'; const newer = 'ccon_extractnewer001'; const replaced = 'ccon_extractreplace1';
  const tombstoned = 'ccon_extracttomb001'; const expired = 'ccon_extractexpire01';
  await append(archive, event({ eventId: 'cevt_extractlegacy01', conversationId: legacy, sequence: 1, second: 1, text: 'legacy first' }));
  await append(archive, event({ eventId: 'cevt_extractlegacy02', conversationId: legacy, sequence: 2, second: 2, text: `${'x'.repeat(4100)} newest` }));
  await append(archive, event({ eventId: 'cevt_extractnewer001', conversationId: newer, sequence: 1, second: 9, text: 'newest conversation' }));
  const base = event({ eventId: 'cevt_extractreplace1', conversationId: replaced, sequence: 1, second: 3, text: 'hidden old text' });
  const current = event({ eventId: 'cevt_extractreplace2', conversationId: replaced, sequence: 2, second: 4, text: 'visible replacement', state: 'replacement', replacesEventId: base.eventId });
  await append(archive, base); await append(archive, current);
  const target = event({ eventId: 'cevt_extracttomb001', conversationId: tombstoned, sequence: 1, second: 5, text: 'hidden tombstone target' });
  await append(archive, target); assert.equal((await archive.tombstone(event({ eventId: 'cevt_extracttomb002', conversationId: tombstoned, sequence: 2, second: 6, state: 'tombstone', tombstonesEventId: target.eventId }), 'cai_extracttomb002')).outcome, 'stored');
  const old = event({ eventId: 'cevt_extractexpire01', conversationId: expired, sequence: 1, second: 7, text: 'expired text' });
  expires.set(old.eventId, '2026-07-22T12:00:00Z'); await append(archive, old);
  assert.equal((await archive.applyRetention('2026-07-22T12:00:00Z', 10, 'cai_extractexpire02')).outcome, 'retention_expired');

  const callerKey = Buffer.from(CURSOR_KEY); const reader = new SqliteM4V3ExtractorReader({ db: archive.db, cursorKey: callerKey, identityResolver }); callerKey.fill(0);
  const first = await reader.search({ limit: 1 }); assert.equal(first.items[0].id, newer); assert.ok(first.nextCursor);
  const second = await reader.search({ limit: 1, cursor: first.nextCursor }); assert.equal(second.items[0].id, replaced);
  const all = [first.items[0], second.items[0], ...(await reader.search({ limit: 10, cursor: second.nextCursor })).items];
  assert.deepEqual(all.map(item => item.id), [newer, replaced, legacy]);
  assert.equal(all.find(item => item.id === legacy).extractionIdentity, `ses_${'b'.repeat(64)}`);
  assert.equal(all.some(item => [tombstoned, expired].includes(item.id)), false);

  const transcript = await reader.transcript({ id: legacy, view: 'redacted', newest: true, limit: 1 });
  assert.equal(transcript.items[0].eventId, 'cevt_extractlegacy02'); assert.equal([...transcript.items[0].content.text].length, 4096); assert.ok(transcript.nextCursor);
  assert.deepEqual((await reader.transcript({ id: legacy, view: 'redacted', newest: true, limit: 1, cursor: transcript.nextCursor })).items.map(item => item.eventId), ['cevt_extractlegacy01']);
  assert.deepEqual((await reader.transcript({ id: replaced, view: 'redacted', newest: true })).items.map(item => item.eventId), [current.eventId]);
  await assert.rejects(() => reader.transcript({ id: newer, view: 'original' }), /m4_v3_extractor_request_invalid/);
  await assert.rejects(() => reader.transcript({ id: newer, view: 'redacted', newest: true, cursor: transcript.nextCursor }), /m4_v3_extractor_cursor_invalid/);
  const tampered = `${first.nextCursor.slice(0, -1)}${first.nextCursor.endsWith('A') ? 'B' : 'A'}`;
  await assert.rejects(() => reader.search({ cursor: tampered }), /m4_v3_extractor_cursor_invalid/);
});

test('PostgreSQL reader uses grouped newest keysets and bounded transcript queries', async () => {
  const id = 'ccon_extractpostgres1'; const eventId = 'cevt_extractpostgres1'; const calls = [];
  const metadata = { conversation_id: id, event_count: '1', source_count: '1', kind_count: '1', context_count: '1',
    conversation_kind: 'session', context_tags: JSON.stringify({ conversation: [TAG] }), first_occurred_at: '2026-07-22T10:00:00Z', last_occurred_at: '2026-07-22T10:00:00Z' };
  const pool = { async query(sql, values) {
    calls.push({ sql, values });
    if (sql.startsWith('WITH visible_events')) return { rows: [{ conversation_id: id, last_time_key: '2026-07-22T10:00:00.000000000', last_sequence: '1', last_event_id: eventId }] };
    if (sql.startsWith('SELECT e.conversation_id')) return { rows: [metadata] };
    return { rows: [{ event_id: eventId, occurred_at: '2026-07-22T10:00:00Z', source_time_key: '2026-07-22T10:00:00.000000000', source_sequence: '1', role: 'assistant', visible_text: 'redacted result' }] };
  } };
  const reader = new PostgresM4V3ExtractorReader({ pool, cursorKey: CURSOR_KEY, identityResolver });
  assert.equal((await reader.search({ limit: 1 })).items[0].id, id);
  assert.equal((await reader.transcript({ id, view: 'redacted', newest: true, limit: 1 })).items[0].content.text, 'redacted result');
  assert.match(calls[0].sql, /ROW_NUMBER\(\) OVER \(PARTITION BY e\.conversation_id ORDER BY e\.source_time_key DESC/);
  assert.match(calls.at(-1).sql, /ORDER BY e\.source_time_key DESC,e\.source_sequence DESC,e\.event_id DESC LIMIT \$2/);
  assert.deepEqual(calls.at(-1).values, [id, 2]);
});

test('SQLite and PostgreSQL startup coverage rejects a signed manifest missing a pre-cutoff conversation', async t => {
  const archive = new SqliteConversationArchive(options()); t.after(() => archive.close());
  const id = 'ccon_extractcoverage1';
  await append(archive, event({ eventId: 'cevt_extractcoverage1', conversationId: id, sequence: 1, second: 1, text: 'covered conversation' }));
  const incomplete = signedResolver([]);
  const sqliteIncomplete = new SqliteM4V3ExtractorReader({ db: archive.db, cursorKey: CURSOR_KEY, identityResolver: incomplete });
  await assert.rejects(() => sqliteIncomplete.verifyCoverage(), /m4_v3_extractor_coverage_invalid/);
  const complete = signedResolver([{ conversationId: id, extractionIdentity: id }]);
  await new SqliteM4V3ExtractorReader({ db: archive.db, cursorKey: CURSOR_KEY, identityResolver: complete }).verifyCoverage();

  const coverageRow = { conversation_id: id, first_time_key: '2026-07-22T10:00:01.000000001' };
  const pool = { async query(sql, values) {
    assert.match(sql, /GROUP BY e\.conversation_id HAVING MIN\(e\.source_time_key\)<=\$1/);
    assert.deepEqual(values, ['2026-07-22T11:00:00.000000000', 100001]);
    return { rows: [coverageRow] };
  } };
  await assert.rejects(() => new PostgresM4V3ExtractorReader({ pool, cursorKey: CURSOR_KEY, identityResolver: incomplete }).verifyCoverage(), /m4_v3_extractor_coverage_invalid/);
  await new PostgresM4V3ExtractorReader({ pool, cursorKey: CURSOR_KEY, identityResolver: complete }).verifyCoverage();
});

test('reader rejects unsafe dependencies, identities, limits, and archive drift', async () => {
  assert.throws(() => new SqliteM4V3ExtractorReader({ db: { prepare() {} }, cursorKey: Buffer.alloc(2), identityResolver }), /m4_v3_extractor_cursor_key_invalid/);
  const reader = new SqliteM4V3ExtractorReader({ cursorKey: CURSOR_KEY, identityResolver: () => null, db: { prepare() { return { get() { return { conversation_id: 'ccon_extractinvalid1', event_count: 1, source_count: 1, kind_count: 1, context_count: 1, conversation_kind: 'session', context_tags: '{}', first_occurred_at: '2026-01-01T00:00:00Z', last_occurred_at: '2026-01-01T00:00:00Z' }; } }; } } });
  await assert.rejects(() => reader.get({ id: 'ccon_extractinvalid1' }), /m4_v3_extractor_identity_invalid/);
  await assert.rejects(() => reader.search({ limit: 101 }), /m4_v3_extractor_request_invalid/);
  await assert.rejects(() => reader.get({ id: 'bad' }), /m4_v3_extractor_not_found/);
});
