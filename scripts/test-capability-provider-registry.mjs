import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  CAPABILITY_PROVIDER_REGISTRY_CAPABILITIES,
  createCapabilityProviderRegistry
} from '../src/capability-provider-registry.mjs';

function validConfig(overrides = {}) {
  const calls = [];
  const config = {
    enabledCapabilities: ['search', 'read', 'status'],
    providerAssignments: [
      { capability: 'search', providerId: 'memory_core' },
      { capability: 'read', providerId: 'memory_core' },
      { capability: 'status', providerId: 'status_source' }
    ],
    providers: [
      { providerId: 'memory_core', handle: (request, context) => { calls.push(['memory', request, context]); return { ok: true, request }; } },
      { providerId: 'status_source', handle: (request, context) => { calls.push(['status', request, context]); return { ok: true, request }; } }
    ]
  };
  return { config: { ...config, ...overrides }, calls };
}

function invalid(action) {
  assert.throws(action, { code: 'capability_provider_registry_config_invalid' });
}

test('routes each enabled capability to its sole assigned provider without provider identity exposure', async () => {
  const value = validConfig();
  const registry = createCapabilityProviderRegistry(value.config);

  assert.deepEqual(CAPABILITY_PROVIDER_REGISTRY_CAPABILITIES, ['search', 'read', 'propose', 'proposal_status', 'status']);
  assert.deepEqual(await registry.call('search', { query: 'synthetic' }), { ok: true, request: { query: 'synthetic' } });
  assert.deepEqual(await registry.lookup('read').call({ id: 'rid_synthetic' }), { ok: true, request: { id: 'rid_synthetic' } });
  assert.deepEqual(value.calls, [
    ['memory', { query: 'synthetic' }, { capability: 'search' }],
    ['memory', { id: 'rid_synthetic' }, { capability: 'read' }]
  ]);
  assert.equal(Object.isFrozen(value.calls[0][2]), true);
  assert.equal(JSON.stringify(value.calls).includes('memory_core'), false);

  const snapshot = registry.snapshot();
  assert.deepEqual(snapshot, {
    enabledCapabilities: ['search', 'read', 'status'],
    capabilities: [{ name: 'search', state: 'ready' }, { name: 'read', state: 'ready' }, { name: 'status', state: 'ready' }]
  });
  assert.equal(JSON.stringify(snapshot).includes('memory_core'), false);
  assert.equal(JSON.stringify(snapshot).includes('status_source'), false);
  assert.equal(JSON.stringify(registry.lookup('search')).includes('memory_core'), false);
});

test('strictly rejects malformed, unknown, disabled, missing, duplicate and unusable routing configuration', () => {
  invalid(() => createCapabilityProviderRegistry());
  invalid(() => createCapabilityProviderRegistry({ ...validConfig().config, extra: true }));
  invalid(() => createCapabilityProviderRegistry(validConfig({ enabledCapabilities: [] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ enabledCapabilities: ['search', 'search'] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ enabledCapabilities: ['legacy_search'] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providerAssignments: [{ capability: 'search', providerId: 'memory_core' }] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providerAssignments: [
    { capability: 'search', providerId: 'memory_core' }, { capability: 'search', providerId: 'status_source' }, { capability: 'read', providerId: 'memory_core' }, { capability: 'status', providerId: 'status_source' }
  ] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providerAssignments: [
    { capability: 'search', providerId: 'memory_core' }, { capability: 'read', providerId: 'memory_core' }, { capability: 'status', providerId: 'status_source' }, { capability: 'propose', providerId: 'memory_core' }
  ] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providerAssignments: [
    { capability: 'search', providerId: 'bad provider' }, { capability: 'read', providerId: 'memory_core' }, { capability: 'status', providerId: 'status_source' }
  ] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providers: [
    { providerId: 'memory_core', handle: () => ({}) }, { providerId: 'memory_core', handle: () => ({}) }, { providerId: 'status_source', handle: () => ({}) }
  ] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providers: [
    { providerId: 'memory_core', handle: null }, { providerId: 'status_source', handle: () => ({}) }
  ] }).config));
  invalid(() => createCapabilityProviderRegistry(validConfig({ providers: [
    { providerId: 'memory_core', handle: () => ({}) }
  ] }).config));
});

test('rejects symbol and non-enumerable extras at every configuration boundary', () => {
  const topLevelExtra = validConfig().config;
  Object.defineProperty(topLevelExtra, 'hidden', { value: true });
  invalid(() => createCapabilityProviderRegistry(topLevelExtra));

  const topLevelSymbol = validConfig().config;
  topLevelSymbol[Symbol('hidden')] = true;
  invalid(() => createCapabilityProviderRegistry(topLevelSymbol));

  const assignmentExtra = validConfig().config;
  Object.defineProperty(assignmentExtra.providerAssignments[0], 'hidden', { value: true });
  invalid(() => createCapabilityProviderRegistry(assignmentExtra));

  const assignmentSymbol = validConfig().config;
  assignmentSymbol.providerAssignments[0][Symbol('hidden')] = true;
  invalid(() => createCapabilityProviderRegistry(assignmentSymbol));

  const providerExtra = validConfig().config;
  Object.defineProperty(providerExtra.providers[0], 'hidden', { value: true });
  invalid(() => createCapabilityProviderRegistry(providerExtra));

  const providerSymbol = validConfig().config;
  providerSymbol.providers[0][Symbol('hidden')] = true;
  invalid(() => createCapabilityProviderRegistry(providerSymbol));
});

test('rejects accessor-backed configuration values before they can drift or throw', () => {
  const topLevel = validConfig().config;
  Object.defineProperty(topLevel, 'enabledCapabilities', { enumerable: true, get: () => ['search'] });
  invalid(() => createCapabilityProviderRegistry(topLevel));
  const assignment = validConfig().config;
  Object.defineProperty(assignment.providerAssignments[0], 'providerId', { enumerable: true, get: () => 'memory_core' });
  invalid(() => createCapabilityProviderRegistry(assignment));
  const provider = validConfig().config;
  Object.defineProperty(provider.providers[0], 'handle', { enumerable: true, get: () => () => ({}) });
  invalid(() => createCapabilityProviderRegistry(provider));
  const list = validConfig().config;
  Object.defineProperty(list.enabledCapabilities, '0', { enumerable: true, get: () => 'search' });
  invalid(() => createCapabilityProviderRegistry(list));
});

test('executes the three published invalid startup registry rows', () => {
  const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/capability-mcp-v1.conformance.json', import.meta.url), 'utf8'));
  for (const id of ['missing_provider_startup', 'ambiguous_provider_startup', 'disabled_provider_assignment']) {
    const registry = fixture.scenarios.find(item => item.id === id).registry;
    const providerIds = [...new Set(registry.providerAssignments.map(item => item.providerId))];
    invalid(() => createCapabilityProviderRegistry({ ...registry, providers: providerIds.map(providerId => ({ providerId, handle: () => ({}) })) }));
  }
});

test('configuration mutations and returned snapshots cannot alter routing state', async () => {
  const value = validConfig();
  const registry = createCapabilityProviderRegistry(value.config);
  value.config.enabledCapabilities.splice(0, value.config.enabledCapabilities.length, 'propose');
  value.config.providerAssignments[0].providerId = 'status_source';
  value.config.providers[0].handle = () => ({ changed: true });

  assert.deepEqual(await registry.call('search', { stable: true }), { ok: true, request: { stable: true } });
  const snapshot = registry.snapshot();
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.enabledCapabilities), true);
  assert.equal(Object.isFrozen(snapshot.capabilities), true);
  assert.equal(Object.isFrozen(snapshot.capabilities[0]), true);
  assert.throws(() => snapshot.enabledCapabilities.push('propose'), TypeError);
  assert.throws(() => { snapshot.capabilities[0].state = 'unavailable'; }, TypeError);
  assert.deepEqual(registry.snapshot().enabledCapabilities, ['search', 'read', 'status']);
});

test('does not fall back, and public errors stay provider-neutral', async () => {
  const registry = createCapabilityProviderRegistry(validConfig({
    providers: [
      { providerId: 'memory_core', handle: () => { throw new Error('memory_core should never escape'); } },
      { providerId: 'status_source', handle: () => ({ ok: true }) }
    ]
  }).config);

  await assert.rejects(registry.call('search', {}), error => error.code === 'capability_provider_registry_call_failed' && !error.message.includes('memory_core'));
  assert.throws(() => registry.lookup('propose'), error => error.code === 'capability_provider_registry_unavailable' && !error.message.includes('memory_core'));
  await assert.rejects(registry.call('propose', {}), error => error.code === 'capability_provider_registry_unavailable');
});
