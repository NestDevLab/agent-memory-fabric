import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { MemoryOpaqueReferenceStore, PostgresOpaqueReferenceStore, SqliteOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';

const BINDING = `sha256:${'a'.repeat(64)}`;
const REQUEST = `sha256:${'b'.repeat(64)}`;
const resource = { kind: 'canonical_memory', locator: 'private/synthetic/one', revision: 1, grantBinding: BINDING };
const cursor = { requestBinding: REQUEST, grantBinding: BINDING, continuation: { offset: 1, nested: ['synthetic'] }, expiresAt: '2031-01-01T00:00:00.000Z' };
const nextId = (() => { let n = 0; return prefix => `${prefix}${String(++n).padStart(32, 'a')}`.replace(/[^A-Za-z0-9_-]/g, 'a'); })();

class FakePool {
  constructor() { this.resources = new Map(); this.cursors = new Map(); this.meta = null; this.queries = []; }
  async query(sql, values = []) {
    this.queries.push({ sql, values });
    if (sql.startsWith('CREATE TABLE')) return { rows: [] };
    if (sql.startsWith('INSERT INTO capability_opaque_reference_meta')) { this.meta ||= values[0]; return { rows: [] }; }
    if (sql.startsWith('SELECT value FROM capability_opaque_reference_meta')) return { rows: [{ value: this.meta }] };
    const cursor = sql.includes('capability_opaque_cursors_v1'); const rows = cursor ? this.cursors : this.resources;
    if (sql.startsWith('SELECT *')) { const field = sql.includes('fingerprint') ? 'fingerprint' : 'id'; return { rows: [...rows.values()].filter(row => row[field] === values[0]).slice(0, 1) }; }
    if (sql.startsWith('INSERT INTO capability_opaque_')) {
      const [id, fingerprint, payloadJson, expiresAt] = values; if ([...rows.values()].some(row => row.id === id || row.fingerprint === fingerprint)) return { rows: [] };
      const createdAt = values.at(-1); const row = { id, fingerprint, payload_json: JSON.parse(payloadJson), tombstoned: false, created_at: createdAt, tombstoned_at: null, ...(cursor ? { expires_at: expiresAt } : {}) }; rows.set(id, row); return { rows: [{ id }] };
    }
    if (sql.startsWith('UPDATE')) { const row = rows.get(values.at(-1)); if (!row || row.tombstoned) return { rows: [] }; row.tombstoned = true; row.tombstoned_at = values[0]; return { rows: [{ id: row.id }] }; }
    if (sql.startsWith('DELETE')) { const matches = [...this.cursors.values()].filter(row => Date.parse(row.expires_at) <= Date.parse(values[0])).sort((a, b) => a.expires_at.localeCompare(b.expires_at)).slice(0, values[1]); for (const row of matches) this.cursors.delete(row.id); return { rows: matches.map(row => ({ id: row.id })) }; }
    throw new Error('unexpected fake query');
  }
}

async function conformance(make) {
  const store = make();
  const rid = await store.issueResource(resource); assert.match(rid, /^rid_[A-Za-z0-9_-]{8,128}$/); assert.equal(await store.issueResource(resource), rid);
  assert.deepEqual(await store.resolveResource({ id: rid, grantBinding: BINDING }), resource);
  await assert.rejects(store.resolveResource({ id: rid, grantBinding: `sha256:${'c'.repeat(64)}` }), { code: 'capability_resource_not_found' });
  await assert.rejects(store.resolveResource({ id: 'rid_bad', grantBinding: BINDING }), { code: 'capability_resource_not_found' });
  const resolved = await store.resolveResource({ id: rid, grantBinding: BINDING }); assert.equal(Object.isFrozen(resolved), true); assert.throws(() => { resolved.locator = 'changed'; }, TypeError);
  const cur = await store.issueCursor(cursor); assert.match(cur, /^cur_[A-Za-z0-9_-]{16,256}$/); assert.equal(await store.issueCursor(cursor), cur); assert.deepEqual(await store.resolveCursor({ id: cur, requestBinding: REQUEST, grantBinding: BINDING }), cursor.continuation);
  await assert.rejects(store.resolveCursor({ id: cur, requestBinding: BINDING, grantBinding: BINDING }), { code: 'capability_cursor_invalid' });
  assert.deepEqual(await store.tombstone(rid), { tombstoned: true }); assert.deepEqual(await store.tombstone(rid), { tombstoned: false }); await assert.rejects(store.resolveResource({ id: rid, grantBinding: BINDING }), { code: 'capability_resource_not_found' });
  assert.equal((await store.pruneExpired({ before: '2032-01-01T00:00:00.000Z', limit: 1 })).pruned, 1); await assert.rejects(store.resolveCursor({ id: cur, requestBinding: REQUEST, grantBinding: BINDING }), { code: 'capability_cursor_invalid' });
  return store;
}

test('memory conformance', async () => { await conformance(() => new MemoryOpaqueReferenceStore({ idFactory: nextId })); });
test('sqlite conformance and reopen persistence', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'opaque-store-')); const filename = path.join(root, 'opaque.sqlite');
  try { const store = new SqliteOpaqueReferenceStore({ filename, idFactory: nextId }); const id = await store.issueResource(resource); store.close(); const reopened = new SqliteOpaqueReferenceStore({ filename }); assert.deepEqual(await reopened.resolveResource({ id, grantBinding: BINDING }), resource); reopened.close(); await conformance(() => new SqliteOpaqueReferenceStore({ filename: ':memory:', idFactory: nextId })); } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test('postgres adapter has equivalent behavior using a parameterized fake pool', async () => {
  const pool = new FakePool(); await conformance(() => new PostgresOpaqueReferenceStore({ pool, idFactory: nextId }));
  assert.equal(pool.queries.every(query => !query.sql.includes(BINDING) && !query.sql.includes('private/synthetic/one')), true);
  assert.equal(pool.queries.filter(query => query.values.length).every(query => Array.isArray(query.values)), true);
});
test('hostile continuation values are rejected without invoking accessors', async () => {
  const store = new MemoryOpaqueReferenceStore(); const hostile = {}; Object.defineProperty(hostile, 'secret', { enumerable: true, get() { throw new Error('private'); } });
  await assert.rejects(store.issueCursor({ ...cursor, continuation: hostile }), { code: 'capability_opaque_reference_invalid' });
  const cyclic = {}; cyclic.self = cyclic; await assert.rejects(store.issueCursor({ ...cursor, continuation: cyclic }), { code: 'capability_opaque_reference_invalid' });
});

test('replay, collision, fixed-clock expiry, tombstones, and bounded pruning stay isolated', async () => {
  let now = Date.parse('2030-01-01T00:00:00.000Z'); let calls = 0;
  const store = new MemoryOpaqueReferenceStore({ now: () => now, idFactory: prefix => `${prefix}${String(++calls).padStart(prefix === 'rid_' ? 32 : 32, 'x')}` });
  const all = await Promise.all(Array.from({ length: 12 }, () => store.issueResource(resource))); const one = all[0]; assert.equal(new Set(all).size, 1);
  const changed = await store.issueResource({ ...resource, revision: 2 }); assert.notEqual(changed, one);
  await assert.rejects(store.resolveResource({ id: one, grantBinding: BINDING, expectedKind: 'document' }), { code: 'capability_resource_not_found' });
  const first = await store.issueCursor({ ...cursor, expiresAt: '2030-01-01T00:00:01.000Z' }); now += 1001; await assert.rejects(store.resolveCursor({ id: first, requestBinding: REQUEST, grantBinding: BINDING }), { code: 'capability_cursor_invalid' }); await assert.rejects(store.resolveCursor({ id: first, requestBinding: REQUEST, grantBinding: BINDING, now: '2039-01-01T00:00:00.000Z' }), { code: 'capability_cursor_invalid' });
  const oldOne = await store.issueCursor({ ...cursor, continuation: { page: 1 }, expiresAt: '2030-01-01T00:00:02.000Z' }); const oldTwo = await store.issueCursor({ ...cursor, continuation: { page: 2 }, expiresAt: '2030-01-01T00:00:03.000Z' });
  assert.deepEqual(await store.pruneExpired({ before: '2030-01-01T00:00:04.000Z', limit: 1 }), { pruned: 1 }); await assert.rejects(store.resolveCursor({ id: first, requestBinding: REQUEST, grantBinding: BINDING }), { code: 'capability_cursor_invalid' }); assert.deepEqual(await store.resolveCursor({ id: oldOne, requestBinding: REQUEST, grantBinding: BINDING }), { page: 1 }); assert.deepEqual(await store.resolveResource({ id: changed, grantBinding: BINDING }), { ...resource, revision: 2 });
  assert.deepEqual(await store.tombstone(oldTwo), { tombstoned: true }); await assert.rejects(store.resolveCursor({ id: oldTwo, requestBinding: REQUEST, grantBinding: BINDING }), { code: 'capability_cursor_invalid' }); await assert.rejects(store.issueCursor({ ...cursor, continuation: { page: 2 }, expiresAt: '2030-01-01T00:00:03.000Z' }), { code: 'capability_opaque_reference_retired' });
});

test('a generated collision never overwrites another record and retries within the bound', async () => {
  let index = 0; const repeated = `rid_${'c'.repeat(32)}`; const fresh = `rid_${'d'.repeat(32)}`;
  const store = new MemoryOpaqueReferenceStore({ idFactory: () => [repeated, repeated, fresh][Math.min(index++, 2)] });
  const first = await store.issueResource(resource); const second = await store.issueResource({ ...resource, grantBinding: `sha256:${'e'.repeat(64)}` });
  assert.equal(first, repeated); assert.equal(second, fresh); assert.deepEqual(await store.resolveResource({ id: first, grantBinding: BINDING }), resource);
});

test('collision exhaustion is bounded, content-free, and preserves the original record', async () => {
  const id = `rid_${'z'.repeat(32)}`; const first = new MemoryOpaqueReferenceStore({ idFactory: () => id }); await first.issueResource(resource);
  const exhausted = new MemoryOpaqueReferenceStore({ idFactory: () => id }); exhausted.resources.set(id, first.resources.get(id)); exhausted.resourceByFingerprint.set(first.resources.get(id).fingerprint, first.resources.get(id));
  await assert.rejects(exhausted.issueResource({ ...resource, grantBinding: `sha256:${'f'.repeat(64)}` }), failure => failure.code === 'capability_opaque_reference_unavailable' && !failure.message.includes('private/synthetic/one'));
  assert.deepEqual(await exhausted.resolveResource({ id, grantBinding: BINDING }), resource);
});

test('bounds, descriptor snapshots, mutations, and public errors do not disclose private data', async () => {
  const privateText = 'private-locator-secret'; const store = new MemoryOpaqueReferenceStore({ now: () => Date.parse('2030-01-01T00:00:00.000Z') });
  for (const bad of [{ ...cursor, expiresAt: '2029-01-01T00:00:00.000Z' }, { ...cursor, continuation: { ['x'.repeat(17000)]: true } }, { ...cursor, continuation: [, 'sparse'] }, { ...cursor, continuation: { deep: { a: { b: { c: { d: { e: { f: { g: { h: true } } } } } } } } } }]) await assert.rejects(store.issueCursor(bad), { code: 'capability_opaque_reference_invalid' });
  const proto = JSON.parse('{"__proto__":{"polluted":true}}'); const id = await store.issueCursor({ ...cursor, continuation: proto }); const result = await store.resolveCursor({ id, requestBinding: REQUEST, grantBinding: BINDING }); assert.equal(Object.getPrototypeOf(result), Object.prototype); assert.equal({}.polluted, undefined); assert.throws(() => { result.__proto__ = null; }, TypeError);
  const hostile = new Proxy({ id: 'rid_invalid', grantBinding: BINDING }, { ownKeys() { throw new Error(privateText); } }); await assert.rejects(store.resolveResource(hostile), failure => failure.code === 'capability_resource_not_found' && !failure.message.includes(privateText));
  const symbolContinuation = { safe: true }; symbolContinuation[Symbol(privateText)] = true; await assert.rejects(store.issueCursor({ ...cursor, continuation: symbolContinuation }), { code: 'capability_opaque_reference_invalid' }); const proxyContinuation = new Proxy({}, { ownKeys() { throw new Error(privateText); } }); await assert.rejects(store.issueCursor({ ...cursor, continuation: proxyContinuation }), failure => failure.code === 'capability_opaque_reference_invalid' && !failure.message.includes(privateText));
  const mutable = { page: 3, nested: { stable: true } }; const mutableId = await store.issueCursor({ ...cursor, continuation: mutable }); mutable.page = 99; mutable.nested.stable = false; assert.deepEqual(await store.resolveCursor({ id: mutableId, requestBinding: REQUEST, grantBinding: BINDING }), { page: 3, nested: { stable: true } });
  await assert.rejects(store.issueResource({ ...resource, locator: privateText, grantBinding: 'not-a-digest' }), failure => failure.code === 'capability_opaque_reference_invalid' && !failure.message.includes(privateText));
  await assert.rejects(store.pruneExpired({ before: 'bad-time', limit: 0 }), { code: 'capability_opaque_reference_invalid' });
});

test('ID limits and injected backend corruption fail closed', async () => {
  const rid = await new MemoryOpaqueReferenceStore({ idFactory: prefix => prefix === 'rid_' ? `${prefix}${'a'.repeat(124)}` : `${prefix}${'b'.repeat(252)}` }).issueResource(resource); assert.equal(rid.length, 128);
  const cursorId = await new MemoryOpaqueReferenceStore({ idFactory: prefix => prefix === 'rid_' ? `${prefix}${'a'.repeat(124)}` : `${prefix}${'b'.repeat(252)}` }).issueCursor(cursor); assert.equal(cursorId.length, 256);
  await assert.rejects(new MemoryOpaqueReferenceStore({ idFactory: () => undefined }).issueResource(resource), { code: 'capability_opaque_reference_invalid' });
  const db = new SqliteOpaqueReferenceStore(); const id = await db.issueResource(resource); db.db.prepare('UPDATE capability_opaque_resources_v1 SET fingerprint=? WHERE id=?').run(`sha256:${'f'.repeat(64)}`, id); await assert.rejects(db.resolveResource({ id, grantBinding: BINDING }), { code: 'capability_resource_not_found' }); const corruptCursorId = await db.issueCursor(cursor); db.db.prepare('UPDATE capability_opaque_cursors_v1 SET tombstoned=1,tombstoned_at=NULL WHERE id=?').run(corruptCursorId); await assert.rejects(db.resolveCursor({ id: corruptCursorId, requestBinding: REQUEST, grantBinding: BINDING }), { code: 'capability_cursor_invalid' }); db.close();
});

test('spoofed backend codes and messages are always normalized', async () => {
  class SpoofedStore extends MemoryOpaqueReferenceStore { async _findResource() { throw Object.assign(new Error('private-backend-secret'), { code: 'capability_opaque_reference_retired' }); } }
  await assert.rejects(new SpoofedStore().issueResource(resource), failure => failure.code === 'capability_opaque_reference_unavailable' && !failure.message.includes('private-backend-secret'));
});

test('memory rows corrupt fail closed and poolFactory receives only connectionString', async () => {
  const store = new MemoryOpaqueReferenceStore(); const id = await store.issueResource(resource); store.resources.get(id).payload = { unexpected: true }; await assert.rejects(store.resolveResource({ id, grantBinding: BINDING }), { code: 'capability_resource_not_found' });
  let options; new PostgresOpaqueReferenceStore({ connectionString: 'postgres://synthetic/opaque', poolFactory(value) { options = value; return { async query() { return { rows: [] }; } }; } }); assert.deepEqual(options, { connectionString: 'postgres://synthetic/opaque' });
});
