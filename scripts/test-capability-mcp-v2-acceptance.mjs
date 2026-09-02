import assert from 'node:assert/strict';
import test from 'node:test';

import { createCapabilityMcpV2AuthorizationBridge } from '../src/capability-mcp-v2-auth-bridge.mjs';
import { createCapabilityMcpV2Composition } from '../src/capability-mcp-v2-composition.mjs';
import { createCapabilityMcpV2Runtime } from '../src/capability-mcp-v2-runtime.mjs';
import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createCapabilityProviderV2Adapter } from '../src/capability-provider-v2-adapter.mjs';
import { createFabricCapabilityProviderV2Operations } from '../src/fabric-capability-provider-v2-operations.mjs';
import { createSessionContextReferenceStore } from '../src/session-context-reference-store.mjs';

const scopes = [{ tenantId: 'tenant_alpha', type: 'project', scopeId: 'atlas' }];
const context = { contextTags: { room: [`hmac-sha256:test:${'a'.repeat(64)}`] } };
const grant = { actor: 'actor', revision: 'grant-v1', context };

function setup({ allowed = true, tamperReference = false, onIssueResource, transcriptTexts = ['Synthetic peer session context.'], searchItems = [{ id: 'ccon_context0001', firstOccurredAt: '2026-09-01T08:00:00Z', lastOccurredAt: '2026-09-01T09:00:00Z' }] } = {}) {
  const calls = []; let now = Date.parse('2026-09-01T10:00:00.000Z'); let sequence = 0;
  let texts = [...transcriptTexts];
  const reader = {
    configured: true,
    async search(request) {
      calls.push(['search', request]);
      return { items: searchItems, total: searchItems.length, nextCursor: request.cursor === null ? 'private-next' : null };
    },
    async transcript(request) {
      calls.push(['transcript', request]);
      return { id: request.id, view: 'redacted', items: texts.map((text, index) => ({ eventId: `cevt_context${String(index + 1).padStart(4, '0')}`, occurredAt: `2026-09-01T09:00:0${index}Z`, role: 'assistant', content: { redacted: true, contentType: 'text', parts: 1, text } })), nextCursor: null };
    }
  };
  const opaque = new MemoryOpaqueReferenceStore({ now: () => now, idFactory: prefix => `${prefix}${String(++sequence).padStart(24, 'x')}` });
  const referenceOpaqueStore = onIssueResource ? {
    async issueResource(input) { onIssueResource(input); return opaque.issueResource(input); },
    resolveResource: input => opaque.resolveResource(input),
    issueCursor: input => opaque.issueCursor(input),
    resolveCursor: input => opaque.resolveCursor(input)
  } : opaque;
  const references = createSessionContextReferenceStore({ opaqueReferenceStore: referenceOpaqueStore, now: () => now });
  const referenceStore = tamperReference ? {
    issueExpansion: (...args) => references.issueExpansion(...args),
    resolveExpansion: async args => ({ ...(await references.resolveExpansion(args)), capsuleId: 'csc_mismatched0001' }),
    assertExpansionSnapshot: (...args) => references.assertExpansionSnapshot(...args),
    issueCursor: (...args) => references.issueCursor(...args),
    resolveCursor: (...args) => references.resolveCursor(...args)
  } : references;
  const operations = createFabricCapabilityProviderV2Operations({ conversationReader: reader, referenceStore, now: () => now });
  const authorizationBridge = createCapabilityMcpV2AuthorizationBridge({ authorize: async request => { calls.push(['authorize', request]); return allowed ? grant : null; } });
  return { calls, opaque, adapter: createCapabilityProviderV2Adapter({ authorizationBridge, operations }), setTranscriptText(value) { texts[0] = value; }, advance(ms) { now += ms; } };
}

function search(overrides = {}) { return { query: 'peer context', kinds: ['conversation'], scopes, purpose: 'context_recall', limit: 2, ...overrides }; }

test('manual recall returns bounded capsule resources and explicit read reauthorizes expansion', async () => {
  const { adapter, calls } = setup();
  const found = await adapter.call('search', search()); assert.equal(found.outcome, 'found'); assert.equal(found.items.length, 1); assert.match(found.items[0].id, /^rid_/); assert.equal(found.items[0].kind, 'conversation'); assert.equal(found.items[0].text, 'Synthetic peer session context.'); assert.match(found.nextCursor, /^cur_/);
  const expanded = await adapter.call('read', { id: found.items[0].id, scopes, purpose: 'context_recall' }); assert.equal(expanded.outcome, 'found'); assert.equal(expanded.resource.id, found.items[0].id); assert.equal(expanded.resource.text, 'Synthetic peer session context.');
  assert.equal(calls.filter(call => call[0] === 'authorize').length, 2); assert.ok(calls.filter(call => call[0] === 'transcript').every(call => call[1].view === 'redacted' && call[1].limit <= 5));
});

test('notice delivery returns no payload or opaque identifiers', async () => {
  const { adapter, calls } = setup();
  const request = search({ delivery: 'notice' }); delete request.limit;
  const notice = await adapter.call('search', request);
  assert.deepEqual(notice, { ok: true, outcome: 'notice', notice: { mode: 'notice_only', state: 'available', candidateCount: 1, expansionRequired: true } });
  assert.equal(JSON.stringify(notice).includes('rid_'), false); assert.equal(calls.some(call => call[0] === 'transcript'), false);
  const denied = setup({ allowed: false }).adapter;
  assert.deepEqual(await denied.call('search', request), { ok: false, outcome: 'not_found' });
});

test('cursor pages are opaque, request-bound, and reauthorized', async () => {
  const { adapter, calls } = setup();
  const first = await adapter.call('search', search()); const second = await adapter.call('search', search({ cursor: first.nextCursor })); assert.equal(second.outcome, 'found'); assert.equal(second.nextCursor, null);
  const wrongQuery = await adapter.call('search', search({ query: 'other', cursor: first.nextCursor })); assert.equal(wrongQuery.outcome, 'invalid_request');
  assert.equal((await adapter.call('search', search({ cursor: 'cur_short' }))).outcome, 'invalid_request');
  assert.equal(calls.filter(call => call[0] === 'authorize').length, 3); assert.equal(calls.filter(call => call[0] === 'search').at(-1)[1].cursor, 'private-next');
});

test('five-row snapshots expand unchanged and one-row drift remains non-disclosing', async () => {
  const drift = setup({ transcriptTexts: ['Stable row one.', 'Stable row two.', 'Stable row three.', 'Stable row four.', 'Stable row five.'] }); const found = await drift.adapter.call('search', search());
  const unchanged = await drift.adapter.call('read', { id: found.items[0].id, scopes, purpose: 'context_recall' });
  assert.equal(unchanged.outcome, 'found'); assert.equal(unchanged.resource.text, 'Stable row one.\nStable row two.\nStable row three.\nStable row four.\nStable row five.');
  drift.setTranscriptText('Changed live transcript.');
  assert.deepEqual(await drift.adapter.call('read', { id: found.items[0].id, scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
});

test('capsule mismatch remains non-disclosing', async () => {
  const mismatch = setup({ tamperReference: true }); const mismatchFound = await mismatch.adapter.call('search', search());
  assert.deepEqual(await mismatch.adapter.call('read', { id: mismatchFound.items[0].id, scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
});

test('invalid later candidates are validated before their expansion reference is issued', async () => {
  let issued = 0;
  const { adapter } = setup({ onIssueResource() { issued += 1; }, searchItems: [
    { id: 'ccon_context0001', firstOccurredAt: '2026-09-01T08:00:00Z', lastOccurredAt: '2026-09-01T09:00:00Z' },
    { id: 'ccon_context0002', firstOccurredAt: '2026-09-01T08:00:00Z', lastOccurredAt: '2026-09-02T09:00:00Z' }
  ] });
  const result = await adapter.call('search', search());
  assert.equal(result.outcome, 'found'); assert.equal(result.items.length, 1); assert.equal(issued, 1);
});

test('denial, malformed scopes, and revoked reads are non-disclosing', async () => {
  const denied = setup({ allowed: false }).adapter;
  assert.deepEqual(await denied.call('search', search()), { ok: false, outcome: 'forbidden' });
  assert.deepEqual(await denied.call('read', { id: 'rid_reference0001', scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
  const { adapter } = setup();
  assert.deepEqual(await adapter.call('search', search({ scopes: [...scopes, { tenantId: 'tenant_beta', type: 'project', scopeId: 'atlas' }] })), { ok: false, outcome: 'invalid_request' });
  assert.deepEqual(await adapter.call('search', search({ scopes: [...scopes, { ...scopes[0], type: 'room' }] })), { ok: false, outcome: 'invalid_request' });
  assert.deepEqual(await adapter.call('search', search({ purpose: 'memory_recall' })), { ok: false, outcome: 'invalid_request' });
  assert.deepEqual(await adapter.call('read', { id: 'rid_missing0001', scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
});

test('v2 composition retains exactly five tools and keeps proposal/status behavior delegated', async () => {
  const { adapter } = setup(); const retained = [];
  const composition = createCapabilityMcpV2Composition({ adapter, retainedCapabilities: {
    async search(args) { retained.push(['search', args]); return { ok: true, outcome: 'found', items: [], nextCursor: null, coverage: { state: 'complete', requestedKinds: ['canonical_memory', 'document'], coveredKinds: ['canonical_memory', 'document'], uncoveredKinds: [], reasons: [] } }; },
    async read(args) { retained.push(['read', args]); return args.id === 'rid_canonical0001' ? { ok: true, outcome: 'found', resource: { id: args.id, kind: 'canonical_memory', text: 'Retained canonical read.', admission: 'authorized', ranking: { position: 1, reasons: ['freshness'] }, contradiction: 'none' } } : { ok: false, outcome: 'not_found' }; },
    async propose(args) { retained.push(['propose', args]); return { ok: true, outcome: 'queued', id: 'rid_proposal001' }; },
    async proposal_status(args) { retained.push(['proposal_status', args]); return { ok: true, outcome: 'pending', proposal: { id: args.id, state: 'review_required' } }; },
    async status() { retained.push(['status']); return { ok: true, outcome: 'ready', capabilities: ['search', 'read', 'propose', 'proposal_status', 'status'].map(name => ({ name, state: 'ready' })) }; }
  } });
  const runtime = createCapabilityMcpV2Runtime({ composition }); assert.deepEqual(runtime.listTools().map(tool => tool.name), ['search', 'read', 'propose', 'proposal_status', 'status']);
  const omittedKinds = { query: 'canonical default', scopes, purpose: 'context_recall' };
  assert.equal((await runtime.callTool('search', omittedKinds)).outcome, 'found');
  assert.equal((await runtime.callTool('read', { id: 'rid_canonical0001', scopes, purpose: 'context_recall' })).resource.text, 'Retained canonical read.');
  const capsuleSearch = await runtime.callTool('search', search()); assert.equal(capsuleSearch.outcome, 'found');
  assert.equal((await runtime.callTool('read', { id: capsuleSearch.items[0].id, scopes, purpose: 'context_recall' })).resource.text, 'Synthetic peer session context.');
  assert.equal((await runtime.callTool('propose', { synthetic: true })).outcome, 'queued'); assert.equal((await runtime.callTool('status', {})).outcome, 'ready'); assert.equal((await runtime.callTool('sixth_tool', {})).outcome, 'invalid_request'); assert.deepEqual(retained.map(call => call[0]), ['search', 'read', 'read', 'propose', 'status']);
  runtime.close(); const closed = await runtime.callTool('search', search()); assert.equal(closed.outcome, 'unavailable'); assert.deepEqual(closed.capabilities.map(item => item.state), Array(5).fill('unavailable'));
});

test('context ownership fallback preserves denied and missing non-disclosure', async () => {
  const denied = setup({ allowed: false }).adapter;
  const retained = {
    async search() { return { ok: false, outcome: 'not_found' }; },
    async read() { return { ok: false, outcome: 'not_found' }; },
    async propose() { return { ok: false, outcome: 'forbidden' }; },
    async proposal_status() { return { ok: false, outcome: 'not_found' }; },
    async status() { return { ok: true, outcome: 'ready', capabilities: [] }; }
  };
  const runtime = createCapabilityMcpV2Runtime({ composition: createCapabilityMcpV2Composition({ adapter: denied, retainedCapabilities: retained }) });
  assert.deepEqual(await runtime.callTool('search', search()), { ok: false, outcome: 'forbidden' });
  assert.deepEqual(await runtime.callTool('read', { id: 'rid_missing0001', scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
});

test('retained-first ownership cannot bypass a drifted capsule', async () => {
  const drift = setup(); let retainedReads = 0;
  const retained = {
    async search() { return { ok: false, outcome: 'not_found' }; },
    async read(args) { retainedReads += 1; assert.match(args.id, /^rid_/); return { ok: false, outcome: 'not_found' }; },
    async propose() { return { ok: false, outcome: 'forbidden' }; },
    async proposal_status() { return { ok: false, outcome: 'not_found' }; },
    async status() { return { ok: true, outcome: 'ready', capabilities: [] }; }
  };
  const runtime = createCapabilityMcpV2Runtime({ composition: createCapabilityMcpV2Composition({ adapter: drift.adapter, retainedCapabilities: retained }) });
  const capsule = await runtime.callTool('search', search());
  drift.setTranscriptText('Changed after capsule issuance.');
  assert.deepEqual(await runtime.callTool('read', { id: capsule.items[0].id, scopes, purpose: 'context_recall' }), { ok: false, outcome: 'not_found' });
  assert.equal(retainedReads, 1);
});
