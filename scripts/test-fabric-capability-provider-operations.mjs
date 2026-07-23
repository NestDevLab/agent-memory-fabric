import assert from 'node:assert/strict';
import test from 'node:test';

import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createCapabilityProviderAdapter } from '../src/capability-provider-adapter.mjs';
import { createFabricCapabilityProviderOperations } from '../src/fabric-capability-provider-operations.mjs';

const TAG = `hmac-sha256:routing-v1:${'a'.repeat(64)}`;
const CONTEXT = Object.freeze({ conversationKind: 'direct', contextTags: Object.freeze({ room: Object.freeze([TAG]) }) });
const GRANT = Object.freeze({ id: 'synthetic-grant' });
const PROJECTION = Object.freeze({
  actor: 'synthetic-actor',
  allowedScopes: Object.freeze(['room:synthetic', 'team:synthetic']),
  documentVaultIds: Object.freeze(['vault-synthetic']),
  sessionOwnerActors: Object.freeze(['synthetic-actor']),
  context: CONTEXT
});

function memory(id, text, overrides = {}) {
  return {
    id,
    revision: 1,
    scope: { id: 'team:synthetic' },
    visibility: 'shared',
    claim: { encoding: 'plain', text },
    lifecycle: { status: 'active', validFrom: '2020-01-01T00:00:00Z', validTo: '2099-01-01T00:00:00Z' },
    ...overrides
  };
}

function document(documentId, text, overrides = {}) {
  return { documentId, vaultId: 'vault-synthetic', revision: 1, tombstone: false, text, ...overrides };
}

function transcript(id, text = `Conversation ${id}`) {
  return {
    id,
    view: 'redacted',
    items: [{
      eventId: `cevt_${id.padEnd(8, 'x')}`,
      occurredAt: '2026-07-20T10:00:00Z',
      role: 'user',
      content: { redacted: true, contentType: 'text', parts: 1, text }
    }],
    nextCursor: null
  };
}

function setup(overrides = {}) {
  const calls = [];
  const canonicalStore = overrides.canonicalStore || {
    configured: true,
    routingContext: () => null,
    async search(request) {
      calls.push(['canonical.search', request]);
      return { items: [memory('mem_alpha', 'Memory alpha'), memory('mem_beta', 'Memory beta')], nextCursor: null };
    },
    async read(request) {
      calls.push(['canonical.read', request]);
      return memory(request.id, 'Memory read');
    }
  };
  const documentStore = overrides.documentStore || {
    configured: true,
    async search(request) {
      calls.push(['document.search', request]);
      return [document('doc_alpha', 'Document alpha'), document('doc_beta', 'Document beta')];
    },
    async read(request) {
      calls.push(['document.read', request]);
      return document(request.documentId, 'Document read', { revision: request.revision ?? 1 });
    }
  };
  const conversationReader = overrides.conversationReader || {
    configured: true,
    async search(request) {
      calls.push(['conversation.search', request]);
      return { items: [{ id: 'conversation-alpha' }, { id: 'conversation-beta' }], total: 2, nextCursor: null };
    },
    async transcript(request) {
      calls.push(['conversation.transcript', request]);
      return transcript(request.id);
    }
  };
  const fabricStore = overrides.fabricStore || {
    configured: true,
    async propose(request) {
      calls.push(['fabric.propose', request]);
      return { id: 'proposal-synthetic', status: 'queued' };
    },
    async getProposalStatusAuthorized(id, authorization) {
      calls.push(['fabric.proposal_status', id, authorization]);
      return { id, status: 'review' };
    }
  };
  const resolveGrant = overrides.resolveGrant || (async (grant, request) => {
    calls.push(['grant', grant, request]);
    return PROJECTION;
  });
  return {
    calls,
    operations: createFabricCapabilityProviderOperations({
      canonicalStore, documentStore, conversationReader, fabricStore, resolveGrant
    })
  };
}

function searchRequest(overrides = {}) {
  return {
    query: 'synthetic',
    kinds: ['canonical_memory', 'document', 'conversation'],
    scopes: ['team:synthetic'],
    purpose: 'conversation_recall',
    limit: 6,
    continuation: null,
    ...overrides
  };
}

test('mixed search round-robins the requested kinds deterministically', async () => {
  const { operations } = setup();
  const result = await operations.search(searchRequest(), { grant: GRANT });
  assert.deepEqual(result.items.map(item => `${item.kind}:${item.locator}`), [
    'canonical_memory:mem_alpha',
    'document:doc_alpha',
    'conversation:conversation-alpha',
    'canonical_memory:mem_beta',
    'document:doc_beta',
    'conversation:conversation-beta'
  ]);
  assert.equal(result.continuation, null);
});

test('search passes exact bounded requests to all real store interfaces', async () => {
  const { operations, calls } = setup();
  const request = searchRequest({ limit: 6 });
  await operations.search(request, { grant: GRANT });
  assert.deepEqual(calls.find(call => call[0] === 'canonical.search')[1], {
    query: 'synthetic', scopes: ['team:synthetic'], limit: 2, cursor: null,
    actor: 'synthetic-actor', context: CONTEXT
  });
  assert.deepEqual(calls.find(call => call[0] === 'document.search')[1], {
    query: 'synthetic', vaultIds: ['vault-synthetic'], limit: 3
  });
  assert.equal(calls.find(call => call[0] === 'conversation.transcript')[1].view, 'redacted');
});

test('omitted limit defaults to twenty and malformed continuations fail closed', async () => {
  const { operations, calls } = setup();
  const request = searchRequest({ kinds: ['canonical_memory'], purpose: 'memory_recall' });
  delete request.limit;
  await operations.search(request, { grant: GRANT });
  assert.equal(calls.find(call => call[0] === 'canonical.search')[1].limit, 20);
  const base = {
    version: 1,
    kinds: ['canonical_memory'],
    chunk: 20,
    nextKindIndex: 0,
    sources: { canonical_memory: { cursor: null, done: false } }
  };
  for (const continuation of [
    { private: true },
    { ...base, version: 2 },
    { ...base, kinds: ['document'] },
    { ...base, chunk: 19 },
    { ...base, nextKindIndex: 1 },
    { ...base, sources: { canonical_memory: { cursor: 'x'.repeat(4097), done: false } } },
    { ...base, sources: { canonical_memory: { cursor: null, done: 'false' } } }
  ]) {
    await assert.rejects(operations.search({ ...request, continuation }, { grant: GRANT }), {
      code: 'fabric_capability_provider_operations_failed'
    });
  }
});

test('multi-source continuation advances every source without truncation', async () => {
  const calls = [];
  const canonicalRows = [memory('mem_alpha', 'Memory alpha'), memory('mem_beta', 'Memory beta')];
  const conversationRows = [{ id: 'conversation-alpha' }, { id: 'conversation-beta' }];
  const documents = [document('doc_alpha', 'Document alpha'), document('doc_beta', 'Document beta')];
  const { operations } = setup({
    canonicalStore: {
      configured: true,
      routingContext: () => null,
      async search(request) {
        calls.push(['canonical', request]);
        const offset = request.cursor === null ? 0 : 1;
        return { items: canonicalRows.slice(offset, offset + request.limit), nextCursor: offset === 0 ? 'pam_next' : null };
      },
      async read() { throw new Error('unused'); }
    },
    documentStore: {
      configured: true,
      async search(request) {
        calls.push(['document', request]);
        return documents.slice(0, request.limit);
      },
      async read() { throw new Error('unused'); }
    },
    conversationReader: {
      configured: true,
      async search(request) {
        calls.push(['conversation', request]);
        const offset = request.cursor === null ? 0 : 1;
        return { items: conversationRows.slice(offset, offset + request.limit), total: 2, nextCursor: offset === 0 ? 'conversation_next' : null };
      },
      async transcript(request) { return transcript(request.id); }
    }
  });
  const request = searchRequest({ limit: 3 });
  const first = await operations.search(request, { grant: GRANT });
  assert.deepEqual(first.items.map(item => item.locator), ['mem_alpha', 'doc_alpha', 'conversation-alpha']);
  assert.notEqual(first.continuation, null);
  const second = await operations.search({ ...request, continuation: first.continuation }, { grant: GRANT });
  assert.deepEqual(second.items.map(item => item.locator), ['mem_beta', 'doc_beta', 'conversation-beta']);
  assert.equal(second.continuation, null);
  assert.deepEqual(calls.filter(call => call[0] === 'canonical').map(call => [call[1].limit, call[1].cursor]), [[1, null], [1, 'pam_next']]);
  assert.deepEqual(calls.filter(call => call[0] === 'document').map(call => call[1].limit), [2, 3]);
  assert.deepEqual(calls.filter(call => call[0] === 'conversation').map(call => [call[1].limit, call[1].cursor]), [[1, null], [1, 'conversation_next']]);
});

test('search rotates sources fairly when the public limit is smaller than the kind count', async () => {
  const calls = [];
  const { operations } = setup({
    canonicalStore: {
      configured: true,
      routingContext: () => null,
      async search() { calls.push('canonical_memory'); return { items: [memory('mem_alpha', 'Memory alpha')], nextCursor: null }; },
      async read() { throw new Error('unused'); }
    },
    documentStore: {
      configured: true,
      async search() { calls.push('document'); return [document('doc_alpha', 'Document alpha')]; },
      async read() { throw new Error('unused'); }
    },
    conversationReader: {
      configured: true,
      async search() { calls.push('conversation'); return { items: [{ id: 'conversation-alpha' }], total: 1, nextCursor: null }; },
      async transcript(request) { return transcript(request.id); }
    }
  });
  const request = searchRequest({ limit: 1 });
  const first = await operations.search(request, { grant: GRANT });
  const second = await operations.search({ ...request, continuation: first.continuation }, { grant: GRANT });
  const third = await operations.search({ ...request, continuation: second.continuation }, { grant: GRANT });
  assert.deepEqual(calls, ['canonical_memory', 'document', 'conversation']);
  assert.deepEqual([first.items[0].kind, second.items[0].kind, third.items[0].kind], [
    'canonical_memory', 'document', 'conversation'
  ]);
  assert.notEqual(first.continuation, null);
  assert.notEqual(second.continuation, null);
  assert.equal(third.continuation, null);
});

test('canonical search excludes sealed inactive expired and unauthorized records', async () => {
  const canonicalStore = {
    configured: true,
    routingContext: () => null,
    async search() {
      return {
        items: [
          memory('mem_visible', 'Visible'),
          memory('mem_sealed', '', { claim: { encoding: 'sealed', ciphertext: 'opaque' } }),
          memory('mem_inactive', 'Inactive', { lifecycle: { status: 'revoked', validFrom: null, validTo: null } }),
          memory('mem_expired', 'Expired', { lifecycle: { status: 'active', validFrom: null, validTo: '2020-01-01T00:00:00Z' } }),
          memory('mem_other', 'Other', { scope: { id: 'team:other' } })
        ],
        nextCursor: null
      };
    },
    async read() { throw new Error('unused'); }
  };
  const { operations } = setup({ canonicalStore });
  const result = await operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 5 }), { grant: GRANT });
  assert.deepEqual(result.items.map(item => item.locator), ['mem_visible']);
});

test('sensitive canonical scopes require matching routing context', async () => {
  let routing = { room: [TAG] };
  const canonicalStore = {
    configured: true,
    routingContext: () => routing,
    async search() { return { items: [memory('mem_room', 'Room', { scope: { id: 'room:synthetic' } })], nextCursor: null }; },
    async read(request) { return memory(request.id, 'Room', { scope: { id: 'room:synthetic' } }); }
  };
  const { operations } = setup({ canonicalStore });
  const visible = await operations.search(searchRequest({ kinds: ['canonical_memory'], scopes: ['room:synthetic'], limit: 1 }), { grant: GRANT });
  assert.equal(visible.items.length, 1);
  routing = { room: [`hmac-sha256:routing-v1:${'b'.repeat(64)}`] };
  const hidden = await operations.search(searchRequest({ kinds: ['canonical_memory'], scopes: ['room:synthetic'], limit: 1 }), { grant: GRANT });
  assert.equal(hidden.items.length, 0);
});

test('group context excludes non-shared canonical records', async () => {
  const canonicalStore = {
    configured: true,
    routingContext: () => null,
    async search() { return { items: [memory('mem_private', 'Private', { visibility: 'private' })], nextCursor: null }; },
    async read() { throw new Error('unused'); }
  };
  const resolveGrant = async () => ({ ...PROJECTION, context: { conversationKind: 'group', contextTags: { room: [TAG] } } });
  const { operations } = setup({ canonicalStore, resolveGrant });
  assert.equal((await operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT })).items.length, 0);
});

test('document search excludes tombstones disallowed vaults and textless rows', async () => {
  const documentStore = {
    configured: true,
    async search() {
      return [
        document('doc_visible', 'Visible'),
        document('doc_deleted', 'Deleted', { tombstone: true }),
        document('doc_other', 'Other', { vaultId: 'vault-other' }),
        document('doc_empty', null)
      ];
    },
    async read() { throw new Error('unused'); }
  };
  const { operations } = setup({ documentStore });
  const result = await operations.search(searchRequest({ kinds: ['document'], limit: 4 }), { grant: GRANT });
  assert.deepEqual(result.items.map(item => item.locator), ['doc_visible']);
});

test('conversation search requires context and accepts only nested redacted text', async () => {
  let calls = 0;
  const conversationReader = {
    configured: true,
    async search() { calls += 1; return { items: [{ id: 'conversation-alpha' }], total: 1, nextCursor: null }; },
    async transcript() { return transcript('conversation-alpha', 'Visible redacted'); }
  };
  const { operations } = setup({ conversationReader });
  assert.equal((await operations.search(searchRequest({ kinds: ['conversation'], limit: 1 }), { grant: GRANT })).items[0].text, 'Visible redacted');
  const missingContext = setup({ conversationReader, resolveGrant: async () => ({ ...PROJECTION, context: null }) });
  await assert.rejects(missingContext.operations.search(searchRequest({ kinds: ['conversation'], limit: 1 }), { grant: GRANT }), {
    code: 'fabric_capability_provider_operations_failed'
  });
  assert.equal(calls, 1);
});

test('malformed conversation content fails without releasing source fields', async () => {
  const conversationReader = {
    configured: true,
    async search() { return { items: [{ id: 'conversation-alpha' }], total: 1, nextCursor: null }; },
    async transcript() {
      return { id: 'conversation-alpha', view: 'original', items: [{ raw: 'private' }], nextCursor: null };
    }
  };
  const { operations } = setup({ conversationReader });
  await assert.rejects(operations.search(searchRequest({ kinds: ['conversation'], limit: 1 }), { grant: GRANT }), error => {
    assert.equal(error.code, 'fabric_capability_provider_operations_failed');
    assert.equal(error.message.includes('private'), false);
    return true;
  });
});

test('canonical read rechecks scope lifecycle encoding and revision', async () => {
  const { operations } = setup();
  assert.deepEqual(await operations.read({ kind: 'canonical_memory', locator: 'mem_alpha', revision: 1 }, { grant: GRANT }), {
    kind: 'canonical_memory', text: 'Memory read'
  });
  assert.equal(await operations.read({ kind: 'canonical_memory', locator: 'mem_alpha', revision: 2 }, { grant: GRANT }), null);
  const sealed = setup({ canonicalStore: {
    configured: true,
    routingContext: () => null,
    async search() { return { items: [], nextCursor: null }; },
    async read() { return memory('mem_alpha', '', { claim: { encoding: 'sealed', ciphertext: 'opaque' } }); }
  } });
  assert.equal(await sealed.operations.read({ kind: 'canonical_memory', locator: 'mem_alpha', revision: 1 }, { grant: GRANT }), null);
});

test('document read rechecks vault tombstone and not-found without an oracle', async () => {
  let mode = 'visible';
  const documentStore = {
    configured: true,
    async search() { return []; },
    async read(request) {
      if (mode === 'missing') throw Object.assign(new Error('document_not_found'), { status: 404 });
      return document(request.documentId, 'Document', { vaultId: mode === 'other' ? 'vault-other' : 'vault-synthetic' });
    }
  };
  const { operations } = setup({ documentStore });
  assert.equal((await operations.read({ kind: 'document', locator: 'doc_alpha', revision: 1 }, { grant: GRANT })).text, 'Document');
  mode = 'other';
  assert.equal(await operations.read({ kind: 'document', locator: 'doc_alpha', revision: 1 }, { grant: GRANT }), null);
  mode = 'missing';
  assert.equal(await operations.read({ kind: 'document', locator: 'doc_alpha', revision: 1 }, { grant: GRANT }), null);
});

test('conversation read is redacted while outages remain fixed failures', async () => {
  let mode = 'visible';
  const conversationReader = {
    configured: true,
    async search() { return { items: [], total: 0, nextCursor: null }; },
    async transcript(request) {
      if (mode === 'missing') throw Object.assign(new Error('session_not_found'), { status: 404 });
      if (mode === 'outage') throw new Error('private database address');
      return transcript(request.id, 'Conversation read');
    }
  };
  const { operations } = setup({ conversationReader });
  assert.equal((await operations.read({ kind: 'conversation', locator: 'conversation-alpha', revision: null }, { grant: GRANT })).text, 'Conversation read');
  mode = 'missing';
  assert.equal(await operations.read({ kind: 'conversation', locator: 'conversation-alpha', revision: null }, { grant: GRANT }), null);
  mode = 'outage';
  await assert.rejects(operations.read({ kind: 'conversation', locator: 'conversation-alpha', revision: null }, { grant: GRANT }), {
    code: 'fabric_capability_provider_operations_failed'
  });
});

test('proposal queues only the bounded proposal operation', async () => {
  const { operations, calls } = setup();
  const result = await operations.propose({
    scope: 'team:synthetic', claim: 'Synthetic claim', purpose: 'memory_curation', idempotencyKey: 'req_synthetic0001'
  }, { grant: GRANT });
  assert.deepEqual(result, { locator: 'proposal-synthetic', revision: null });
  assert.deepEqual(calls.find(call => call[0] === 'fabric.propose')[1], {
    actor: 'synthetic-actor', scope: 'team:synthetic', text: 'Synthetic claim', metadata: {}, infer: false,
    source: 'capability-mcp', idempotencyKey: 'req_synthetic0001'
  });
  assert.deepEqual(Object.keys(operations).sort(), ['proposal_status', 'propose', 'read', 'search', 'status']);
});

test('proposal status maps lifecycle and forwards exact allowed scopes', async () => {
  const statuses = { queued: 'queued', review: 'review_required', promoted: 'applied', rejected: 'rejected', revoked: 'rejected' };
  for (const [sourceStatus, expected] of Object.entries(statuses)) {
    const fabricStore = {
      configured: true,
      async propose() { return { id: 'unused' }; },
      async getProposalStatusAuthorized(id, authorization) {
        assert.equal(id, 'proposal-synthetic');
        assert.deepEqual(authorization, { actor: 'synthetic-actor', allowedScopes: ['room:synthetic', 'team:synthetic'], allowAll: false });
        return { status: sourceStatus };
      }
    };
    const { operations } = setup({ fabricStore });
    assert.deepEqual(await operations.proposal_status({ locator: 'proposal-synthetic', revision: null }, { grant: GRANT }), { state: expected });
  }
});

test('proposal status distinguishes missing from malformed or unavailable sources', async () => {
  let mode = 'missing';
  const fabricStore = {
    configured: true,
    async propose() { return { id: 'unused' }; },
    async getProposalStatusAuthorized() {
      if (mode === 'missing') throw Object.assign(new Error('memory_not_found'), { status: 404 });
      if (mode === 'outage') throw new Error('private catalog');
      return { status: 'unknown' };
    }
  };
  const { operations } = setup({ fabricStore });
  assert.equal(await operations.proposal_status({ locator: 'proposal-synthetic', revision: null }, { grant: GRANT }), null);
  mode = 'unknown';
  await assert.rejects(operations.proposal_status({ locator: 'proposal-synthetic', revision: null }, { grant: GRANT }), { code: 'fabric_capability_provider_operations_failed' });
  mode = 'outage';
  await assert.rejects(operations.proposal_status({ locator: 'proposal-synthetic', revision: null }, { grant: GRANT }), { code: 'fabric_capability_provider_operations_failed' });
});

test('status derives five redacted rows from captured configured booleans', async () => {
  let healthCalls = 0;
  const canonicalStore = { configured: false, routingContext() {}, async search() {}, async read() {}, health() { healthCalls += 1; } };
  const { operations } = setup({ canonicalStore });
  canonicalStore.configured = true;
  assert.deepEqual(await operations.status(), {
    capabilities: [
      { name: 'search', state: 'unavailable' },
      { name: 'read', state: 'unavailable' },
      { name: 'propose', state: 'ready' },
      { name: 'proposal_status', state: 'ready' },
      { name: 'status', state: 'ready' }
    ]
  });
  assert.equal(healthCalls, 0);
});

test('grant projection cannot widen requested scopes', async () => {
  const { operations, calls } = setup({ resolveGrant: async () => ({ ...PROJECTION, allowedScopes: ['room:synthetic'] }) });
  await assert.rejects(operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT }), {
    code: 'fabric_capability_provider_operations_failed'
  });
  assert.equal(calls.some(call => call[0].endsWith('.search')), false);
});

test('search bounds kinds scopes limit and extras before source calls', async () => {
  const { operations, calls } = setup();
  for (const request of [
    searchRequest({ limit: 51 }),
    searchRequest({ kinds: ['proposal'] }),
    searchRequest({ scopes: [] }),
    { ...searchRequest(), extra: true }
  ]) await assert.rejects(operations.search(request, { grant: GRANT }), { code: 'fabric_capability_provider_operations_failed' });
  assert.equal(calls.length, 0);
});

test('grant context enforces depth key string and canonical byte bounds', async () => {
  for (const context of [
    { value: 'x'.repeat(4097) },
    Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`key${index}`, true])),
    { value: 'x'.repeat(4096), second: 'y'.repeat(4096), third: 'z'.repeat(4096), fourth: 'w'.repeat(4096) }
  ]) {
    const { operations } = setup({ resolveGrant: async () => ({ ...PROJECTION, context }) });
    await assert.rejects(operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT }), {
      code: 'fabric_capability_provider_operations_failed'
    });
  }
});

test('accessor-backed dependencies and hostile provider results fail closed', async () => {
  const canonicalStore = { configured: true, routingContext: () => null, async read() {} };
  Object.defineProperty(canonicalStore, 'search', { get() { throw new Error('private getter'); } });
  assert.throws(() => setup({ canonicalStore }), { code: 'fabric_capability_provider_operations_config_invalid' });

  const hostile = {};
  Object.defineProperty(hostile, 'items', { enumerable: true, get() { throw new Error('private row'); } });
  const bad = setup({ canonicalStore: {
    configured: true,
    routingContext: () => null,
    async search() { return hostile; },
    async read() { return memory('mem_alpha', 'Memory'); }
  } });
  await assert.rejects(bad.operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT }), error => {
    assert.equal(error.code, 'fabric_capability_provider_operations_failed');
    assert.equal(error.message.includes('private'), false);
    return true;
  });
});

test('requests results and grant projections are mutation isolated and frozen', async () => {
  const mutableProjection = structuredClone(PROJECTION);
  const mutableMemory = memory('mem_alpha', 'Original');
  const canonicalStore = {
    configured: true,
    routingContext: () => null,
    async search(request) {
      assert.equal(Object.isFrozen(request), true);
      return { items: [mutableMemory], nextCursor: null };
    },
    async read() { return mutableMemory; }
  };
  const { operations } = setup({ canonicalStore, resolveGrant: async () => mutableProjection });
  const result = await operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT });
  mutableProjection.actor = 'changed';
  mutableMemory.claim.text = 'Changed';
  assert.equal(result.items[0].text, 'Original');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.items), true);
  assert.throws(() => result.items.push({}), TypeError);
});

test('source errors always become one content-free fixed error', async () => {
  const canonicalStore = {
    configured: true,
    routingContext: () => null,
    async search() { throw new Error('private host and record'); },
    async read() { throw new Error('private host and record'); }
  };
  const { operations } = setup({ canonicalStore });
  await assert.rejects(operations.search(searchRequest({ kinds: ['canonical_memory'], limit: 1 }), { grant: GRANT }), error => {
    assert.equal(error.code, 'fabric_capability_provider_operations_failed');
    assert.equal(error.message, 'fabric_capability_provider_operations_failed');
    return true;
  });
});

test('real adapter composition releases opaque results and supports every capability', async () => {
  const { operations } = setup();
  const provider = createCapabilityProviderAdapter({
    operations,
    opaqueReferenceStore: new MemoryOpaqueReferenceStore(),
    now: () => Date.parse('2030-01-01T00:00:00Z')
  });
  const found = await provider({
    query: 'synthetic', kinds: ['canonical_memory', 'document'], scopes: ['team:synthetic'],
    purpose: 'memory_recall', limit: 4, cursor: null
  }, { capability: 'search', grant: GRANT });
  assert.equal(found.items.length, 4);
  assert.equal(JSON.stringify(found).includes('mem_alpha'), false);
  assert.deepEqual(await provider({
    id: found.items[0].id, scopes: ['team:synthetic'], purpose: 'memory_recall'
  }, { capability: 'read', grant: GRANT }), {
    ok: true,
    outcome: 'found',
    resource: { id: found.items[0].id, kind: 'canonical_memory', text: 'Memory read' }
  });
  const proposed = await provider({
    scope: 'team:synthetic', claim: 'Synthetic claim', purpose: 'memory_curation',
    idempotencyKey: 'req_synthetic0003'
  }, { capability: 'propose', grant: GRANT });
  assert.equal(proposed.outcome, 'queued');
  assert.equal((await provider({
    id: proposed.id, scopes: ['team:synthetic'], purpose: 'memory_curation'
  }, { capability: 'proposal_status', grant: GRANT })).proposal.state, 'review_required');
  assert.equal((await provider({}, { capability: 'status', grant: GRANT })).outcome, 'ready');
});

test('real adapter keeps provider continuation opaque across pages', async () => {
  const rows = [memory('mem_alpha', 'Memory alpha'), memory('mem_beta', 'Memory beta')];
  const { operations } = setup({
    canonicalStore: {
      configured: true,
      routingContext: () => null,
      async search(request) {
        const offset = request.cursor === null ? 0 : 1;
        return { items: rows.slice(offset, offset + request.limit), nextCursor: offset === 0 ? 'pam_next' : null };
      },
      async read(request) { return rows.find(row => row.id === request.id); }
    }
  });
  const provider = createCapabilityProviderAdapter({
    operations,
    opaqueReferenceStore: new MemoryOpaqueReferenceStore(),
    now: () => Date.parse('2030-01-01T00:00:00Z')
  });
  const request = {
    query: 'synthetic', kinds: ['canonical_memory'], scopes: ['team:synthetic'],
    purpose: 'memory_recall', limit: 1, cursor: null
  };
  const first = await provider(request, { capability: 'search', grant: GRANT });
  assert.equal(first.items[0].text, 'Memory alpha');
  assert.match(first.nextCursor, /^cur_/);
  assert.equal(JSON.stringify(first).includes('pam_next'), false);
  const second = await provider({ ...request, cursor: first.nextCursor }, { capability: 'search', grant: GRANT });
  assert.equal(second.items[0].text, 'Memory beta');
  assert.equal(second.nextCursor, null);
  assert.equal(JSON.stringify(second).includes('mem_beta'), false);
});
