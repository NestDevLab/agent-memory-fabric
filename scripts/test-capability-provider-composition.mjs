import assert from 'node:assert/strict';
import test from 'node:test';
import { createCapabilityProviderAdapter } from '../src/capability-provider-adapter.mjs';
import { MemoryOpaqueReferenceStore } from '../src/capability-opaque-reference-store.mjs';
import { createCapabilityProviderRegistry } from '../src/capability-provider-registry.mjs';

const grant = Object.freeze({ actor: Object.freeze({ id: 'actor_synthetic', scopes: Object.freeze(['team:synthetic']) }) });
const allReady = () => ({ capabilities: ['search', 'read', 'propose', 'proposal_status', 'status'].map(name => ({ name, state: 'ready' })) });

test('two composed providers share opaque state without cross-provider scope or purpose widening', async () => {
  const store = new MemoryOpaqueReferenceStore(); const calls = { alpha: [], beta: [] };
  const alpha = createCapabilityProviderAdapter({ opaqueReferenceStore: store, operations: {
    search: async () => { calls.alpha.push('search'); return { items: [{ kind: 'canonical_memory', locator: 'private-alpha-resource', revision: 1, text: 'Synthetic alpha text' }], continuation: null }; },
    read: async () => null,
    propose: async () => { calls.alpha.push('propose'); return { locator: 'private-alpha-proposal', revision: 1 }; },
    proposal_status: async () => null,
    status: async () => allReady()
  } });
  const beta = createCapabilityProviderAdapter({ opaqueReferenceStore: store, operations: {
    search: async () => ({ items: [], continuation: null }),
    read: async request => { calls.beta.push(['read', request]); return { kind: request.kind, text: 'Synthetic beta read' }; },
    propose: async () => ({ locator: 'unused', revision: 1 }),
    proposal_status: async request => { calls.beta.push(['proposal_status', request]); return { state: 'pending' }; },
    status: async () => allReady()
  } });
  const registry = createCapabilityProviderRegistry({
    enabledCapabilities: ['search', 'read', 'propose', 'proposal_status', 'status'],
    providerAssignments: [
      { capability: 'search', providerId: 'provider_alpha' }, { capability: 'read', providerId: 'provider_beta' },
      { capability: 'propose', providerId: 'provider_alpha' }, { capability: 'proposal_status', providerId: 'provider_beta' }, { capability: 'status', providerId: 'provider_alpha' }
    ],
    providers: [{ providerId: 'provider_alpha', handle: alpha }, { providerId: 'provider_beta', handle: beta }]
  });
  const found = await registry.call('search', { query: 'synthetic', kinds: ['canonical_memory'], scopes: ['team:synthetic'], purpose: 'memory_recall', limit: 10, cursor: null }, grant);
  const resourceId = found.items[0].id; const beforeRead = calls.beta.length;
  assert.deepEqual(await registry.call('read', { id: resourceId, scopes: ['team:synthetic', 'team:expanded'], purpose: 'memory_recall' }, grant), { ok: false, outcome: 'not_found' });
  assert.deepEqual(await registry.call('read', { id: resourceId, scopes: ['team:synthetic'], purpose: 'conversation_recall' }, grant), { ok: false, outcome: 'not_found' });
  assert.equal(calls.beta.length, beforeRead);
  const read = await registry.call('read', { id: resourceId, scopes: ['team:synthetic'], purpose: 'memory_recall' }, grant);
  assert.equal(read.ok, true); assert.equal(calls.beta.length, beforeRead + 1);
  const proposed = await registry.call('propose', { scope: 'team:synthetic', claim: 'Synthetic claim', purpose: 'memory_curation', idempotencyKey: 'req_synthetic0001' }, grant);
  const beforeStatus = calls.beta.length;
  assert.deepEqual(await registry.call('proposal_status', { id: proposed.id, scopes: ['team:synthetic', 'team:expanded'], purpose: 'memory_curation' }, grant), { ok: false, outcome: 'not_found' });
  assert.equal(calls.beta.length, beforeStatus);
  const status = await registry.call('proposal_status', { id: proposed.id, scopes: ['team:synthetic'], purpose: 'memory_curation' }, grant);
  assert.equal(status.ok, true); assert.equal(calls.beta.length, beforeStatus + 1);
  const publicValues = JSON.stringify([found, read, proposed, status, registry.snapshot()]);
  for (const privateValue of ['private-alpha-resource', 'private-alpha-proposal', 'provider_alpha', 'provider_beta']) assert.equal(publicValues.includes(privateValue), false);
});
