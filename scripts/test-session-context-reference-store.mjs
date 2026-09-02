import assert from 'node:assert/strict';
import test from 'node:test';

import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createSessionContextReferenceStore } from '../src/session-context-reference-store.mjs';

const scopes = [{ tenantId: 'tenant_alpha', type: 'project', scopeId: 'atlas' }];
const grant = { actor: 'synthetic', revision: 'grant-v1', context: { contextTags: { room: ['opaque'] } } };
const capsuleId = 'csc_reference0001';
const sourceSnapshot = { view: 'redacted', excerpts: [{ eventId: 'cevt_reference0001', occurredAt: '2026-09-01T09:00:00Z', role: 'assistant', text: 'Bounded source snapshot.', redacted: true }] };

function setup() {
  let now = Date.parse('2026-09-01T10:00:00.000Z'); let id = 0;
  const opaqueReferenceStore = new MemoryOpaqueReferenceStore({ now: () => now, idFactory: prefix => `${prefix}${String(++id).padStart(24, 'a')}` });
  const store = createSessionContextReferenceStore({ opaqueReferenceStore, now: () => now, cursorTtlMs: 60_000 });
  return { store, advance(ms) { now += ms; } };
}

test('expansion references bind grant, scope identity, purpose, expiry, and redaction', async () => {
  const { store, advance } = setup();
  const id = await store.issueExpansion({ conversationId: 'ccon_reference001', capsuleId, query: 'Atlas', scopes, purpose: 'context_recall', grant, expiresAt: '2026-09-01T10:01:00.000Z', observedAt: '2026-09-01T09:00:00.000Z', sourceSnapshot });
  assert.match(id, /^rid_/);
  const resolved = await store.resolveExpansion({ id, scopes: [{ ...scopes[0], type: 'room' }], purpose: 'context_recall', grant });
  assert.deepEqual(({ target: resolved.target, capsuleId: resolved.capsuleId, conversationId: resolved.conversationId, purpose: resolved.purpose, redactionPolicy: resolved.redactionPolicy }), ({ target: 'expansion', capsuleId, conversationId: 'ccon_reference001', purpose: 'context_recall', redactionPolicy: 'session-context-capsule/v1' }));
  assert.equal(store.assertExpansionSnapshot({ reference: resolved, sourceSnapshot }), true);
  assert.throws(() => store.assertExpansionSnapshot({ reference: resolved, sourceSnapshot: { ...sourceSnapshot, excerpts: [{ ...sourceSnapshot.excerpts[0], text: 'Changed live transcript.' }] } }), { code: 'session_context_reference_not_found' });
  await assert.rejects(store.resolveExpansion({ id, scopes: [{ ...scopes[0], scopeId: 'outside' }], purpose: 'context_recall', grant }), { code: 'session_context_reference_not_found' });
  await assert.rejects(store.resolveExpansion({ id, scopes, purpose: 'conversation_recall', grant }), { code: 'session_context_reference_not_found' });
  await assert.rejects(store.resolveExpansion({ id, scopes, purpose: 'context_recall', grant: { ...grant, revision: 'grant-v2' } }), { code: 'session_context_reference_not_found' });
  advance(60_001); await assert.rejects(store.resolveExpansion({ id, scopes, purpose: 'context_recall', grant }), { code: 'session_context_reference_not_found' });
});

test('cursors bind the complete request, grant, scope, purpose, and expiry', async () => {
  const { store, advance } = setup();
  const request = { query: 'Atlas', kinds: ['conversation'], delivery: 'results', limit: 2 };
  const id = await store.issueCursor({ request, scopes, purpose: 'context_recall', grant, continuation: { readerCursor: 'private-next' } });
  assert.match(id, /^cur_/); assert.deepEqual(await store.resolveCursor({ id, request, scopes, purpose: 'context_recall', grant }), { readerCursor: 'private-next' });
  await assert.rejects(store.resolveCursor({ id, request: { ...request, query: 'Other' }, scopes, purpose: 'context_recall', grant }), { code: 'session_context_cursor_invalid' });
  await assert.rejects(store.resolveCursor({ id, request, scopes, purpose: 'context_recall', grant: { ...grant, revision: 'grant-v2' } }), { code: 'session_context_cursor_invalid' });
  advance(60_001); await assert.rejects(store.resolveCursor({ id, request, scopes, purpose: 'context_recall', grant }), { code: 'session_context_cursor_invalid' });
});

test('mixed tenants, duplicate logical identities, invalid times, and hostile grants fail closed', async () => {
  const { store } = setup();
  const base = { conversationId: 'ccon_reference001', capsuleId, query: '', purpose: 'context_recall', grant, expiresAt: '2026-09-01T10:01:00.000Z', observedAt: '2026-09-01T09:00:00.000Z', sourceSnapshot };
  await assert.rejects(store.issueExpansion({ ...base, scopes: [...scopes, { tenantId: 'tenant_beta', type: 'project', scopeId: 'atlas' }] }), { code: 'capability_mcp_v2_invalid_request' });
  await assert.rejects(store.issueExpansion({ ...base, scopes: [...scopes, { ...scopes[0], type: 'room' }] }), { code: 'capability_mcp_v2_invalid_request' });
  await assert.rejects(store.issueExpansion({ ...base, scopes, expiresAt: 'invalid' }), { code: 'session_context_reference_invalid' });
  await assert.rejects(store.issueExpansion({ ...base, scopes, capsuleId: 'csc_bad' }), { code: 'session_context_reference_invalid' });
  const hostile = {}; Object.defineProperty(hostile, 'secret', { enumerable: true, get() { throw new Error('private'); } });
  await assert.rejects(store.issueExpansion({ ...base, scopes, grant: hostile }), failure => failure.code === 'session_context_reference_invalid' && !failure.message.includes('private'));
});
