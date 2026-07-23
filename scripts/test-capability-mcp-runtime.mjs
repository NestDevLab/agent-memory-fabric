import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { createCapabilityMcpRuntime, CAPABILITY_MCP_TOOL_DEFINITIONS } from '../src/capability-mcp-runtime.mjs';
import { createCapabilityProviderRegistry } from '../src/capability-provider-registry.mjs';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/capability-mcp-v1.conformance.json', import.meta.url), 'utf8'));
const ALL_TOOLS = ['search', 'read', 'propose', 'proposal_status', 'status'];
const clone = value => JSON.parse(JSON.stringify(value));

function registryFor(handler) {
  return createCapabilityProviderRegistry({
    enabledCapabilities: ALL_TOOLS,
    providerAssignments: ALL_TOOLS.map(capability => ({ capability, providerId: 'source_main' })),
    providers: [{ providerId: 'source_main', handle: handler }]
  });
}

function runtimeFor({ handler, authorize = () => true, aliases } = {}) {
  const calls = [];
  const registry = registryFor(async (request) => {
    calls.push(request);
    return handler ? handler(request) : { ok: true, outcome: 'found', items: [], nextCursor: null };
  });
  const authorizations = [];
  const runtime = createCapabilityMcpRuntime({ registry, aliases, authorize: async value => {
    authorizations.push(value);
    return authorize(value);
  } });
  return { runtime, calls, authorizations };
}

function scenario(id) { return fixture.scenarios.find(item => item.id === id); }

test('lists exactly the five frozen canonical typed tools', () => {
  const { runtime } = runtimeFor();
  assert.deepEqual(runtime.listTools(), CAPABILITY_MCP_TOOL_DEFINITIONS);
  assert.deepEqual(runtime.listTools().map(tool => tool.name), ALL_TOOLS);
  assert.equal(Object.isFrozen(runtime.listTools()), true);
  assert.equal(Object.isFrozen(runtime.listTools()[0]), true);
  for (const tool of runtime.listTools()) assert.deepEqual(Object.keys(tool).sort(), ['description', 'inputSchema', 'name']);
});

test('executes the fixture defaults, explicit conversation, read, proposal lifecycle and redacted status paths', async () => {
  for (const id of ['valid_defaults', 'explicit_conversation', 'read_found', 'proposal_queued', 'proposal_lifecycle', 'status_redaction']) {
    const item = scenario(id);
    const { runtime, calls, authorizations } = runtimeFor({ handler: () => clone(item.expected) });
    assert.deepEqual(await runtime.callTool(item.request.name, item.request.arguments), item.expected, id);
    assert.equal(calls.length, 1, id);
    assert.equal(authorizations.length, 1, id);
  }
});

test('denials and malformed requests never call a provider, with no-existence-oracle behavior', async () => {
  for (const id of ['denied_conversation_purpose', 'denied_conversation_scope']) {
    const item = scenario(id);
    const { runtime, calls } = runtimeFor({ authorize: () => false });
    assert.deepEqual(await runtime.callTool(item.request.name, item.request.arguments), item.expected, id);
    assert.equal(calls.length, 0, id);
  }
  const read = scenario('read_no_existence_oracle');
  const deniedRead = runtimeFor({ authorize: () => false });
  assert.deepEqual(await deniedRead.runtime.callTool(read.request.name, read.request.arguments), read.expected);
  assert.equal(deniedRead.calls.length, 0);

  const invalid = runtimeFor();
  assert.deepEqual(await invalid.runtime.callTool('search', { query: 'x', scopes: ['team:synthetic'], purpose: 'memory_recall', extra: true }), { ok: false, outcome: 'invalid_request' });
  assert.equal(invalid.calls.length, 0);
  const accessorInput = { query: 'x', scopes: ['team:synthetic'], purpose: 'memory_recall' };
  Object.defineProperty(accessorInput, 'query', { enumerable: true, get: () => 'x' });
  assert.deepEqual(await invalid.runtime.callTool('search', accessorInput), { ok: false, outcome: 'invalid_request' });
  assert.equal(invalid.calls.length, 0);
});

test('aliases retain the canonical path, are never advertised, and every cursor page is re-authorized', async () => {
  const item = scenario('alias_non_advertisement');
  let grants = 0;
  const value = runtimeFor({ aliases: { legacy_search: 'search' }, authorize: () => ++grants === 1,
    handler: () => clone(item.expected) });
  assert.equal(value.runtime.listTools().some(tool => tool.name === 'legacy_search'), false);
  assert.deepEqual(await value.runtime.callTool('legacy_search', item.request.arguments), item.expected);
  assert.equal(value.authorizations[0].capability, 'search');
  assert.deepEqual(await value.runtime.callTool('legacy_search', { ...item.request.arguments, cursor: 'cur_abcdefghijklmnop' }), { ok: false, outcome: 'forbidden' });
  assert.equal(value.calls.length, 1);
  assert.throws(() => createCapabilityMcpRuntime({ registry: registryFor(() => ({})), authorize: () => true, aliases: { search: 'read' } }), { code: 'capability_mcp_runtime_config_invalid' });
});

test('rejects provider leakage or malformed content and makes provider errors content-free', async () => {
  const request = scenario('valid_defaults').request.arguments;
  for (const result of [
    { ok: true, outcome: 'found', items: [], nextCursor: null, providerId: 'source_main' },
    { ok: true, outcome: 'found', items: [], nextCursor: null, backend: 'synthetic' },
    { ok: true, outcome: 'found', items: [], nextCursor: null, capabilities: [] }
  ]) {
    await assert.rejects(runtimeFor({ handler: () => result }).runtime.callTool('search', request), { code: 'capability_mcp_runtime_provider_invalid' });
  }
  const hidden = { ok: true, outcome: 'found', items: [], nextCursor: null };
  Object.defineProperty(hidden, 'providerId', { value: 'source_main' });
  await assert.rejects(runtimeFor({ handler: () => hidden }).runtime.callTool('search', request), { code: 'capability_mcp_runtime_provider_invalid' });
  const symbol = { ok: true, outcome: 'found', items: [], nextCursor: null };
  symbol[Symbol('backend')] = 'synthetic';
  await assert.rejects(runtimeFor({ handler: () => symbol }).runtime.callTool('search', request), { code: 'capability_mcp_runtime_provider_invalid' });
  const arraySymbol = { ok: true, outcome: 'found', items: [], nextCursor: null };
  arraySymbol.items[Symbol('backend')] = 'synthetic';
  await assert.rejects(runtimeFor({ handler: () => arraySymbol }).runtime.callTool('search', request), { code: 'capability_mcp_runtime_provider_invalid' });
  await assert.rejects(runtimeFor({ handler: () => { throw new Error('source_main secret'); } }).runtime.callTool('search', request), error => error.code === 'capability_mcp_runtime_provider_invalid' && !error.message.includes('source_main'));
});

test('allows exact provider invalid-request results but rejects hidden fields and provider widening', async () => {
  const inputs = {
    search: scenario('valid_defaults').request.arguments,
    read: scenario('read_found').request.arguments,
    propose: scenario('proposal_queued').request.arguments,
    proposal_status: scenario('proposal_lifecycle').request.arguments,
    status: {}
  };
  for (const [name, input] of Object.entries(inputs)) {
    assert.deepEqual(await runtimeFor({ handler: () => ({ ok: false, outcome: 'invalid_request' }) }).runtime.callTool(name, input), { ok: false, outcome: 'invalid_request' });
  }
  const hiddenRequired = { ok: true, outcome: 'found', items: [], nextCursor: null };
  Object.defineProperty(hiddenRequired, 'ok', { value: true, enumerable: false });
  await assert.rejects(runtimeFor({ handler: () => hiddenRequired }).runtime.callTool('search', inputs.search), { code: 'capability_mcp_runtime_provider_invalid' });
  await assert.rejects(runtimeFor({ handler: () => ({ ok: true, outcome: 'found', items: [{ id: 'rid_gamma0003', kind: 'conversation', text: 'Synthetic.' }], nextCursor: null }) }).runtime.callTool('search', inputs.search), { code: 'capability_mcp_runtime_provider_invalid' });
  await assert.rejects(runtimeFor({ handler: () => ({ ok: true, outcome: 'found', resource: { id: 'rid_gamma0003', kind: 'conversation', text: 'Synthetic.' } }) }).runtime.callTool('read', inputs.read), { code: 'capability_mcp_runtime_provider_invalid' });
  await assert.rejects(runtimeFor({ handler: () => ({ ok: true, outcome: 'ready', capabilities: [{ name: 'search', state: 'ready' }] }) }).runtime.callTool('status', {}), { code: 'capability_mcp_runtime_provider_invalid' });
});

test('rejects accessor-backed runtime config, aliases, provider results, and result arrays', async () => {
  const registry = registryFor(() => ({ ok: true, outcome: 'found', items: [], nextCursor: null }));
  const config = { registry, authorize: () => true };
  Object.defineProperty(config, 'authorize', { enumerable: true, get: () => () => true });
  assert.throws(() => createCapabilityMcpRuntime(config), { code: 'capability_mcp_runtime_config_invalid' });
  const aliases = {};
  Object.defineProperty(aliases, 'legacy_search', { enumerable: true, get: () => 'search' });
  assert.throws(() => createCapabilityMcpRuntime({ registry, authorize: () => true, aliases }), { code: 'capability_mcp_runtime_config_invalid' });
  const result = { ok: true, outcome: 'found', items: [], nextCursor: null };
  Object.defineProperty(result, 'items', { enumerable: true, get: () => [] });
  await assert.rejects(runtimeFor({ handler: () => result }).runtime.callTool('search', scenario('valid_defaults').request.arguments), { code: 'capability_mcp_runtime_provider_invalid' });
  const arrayResult = { ok: true, outcome: 'found', items: [], nextCursor: null };
  Object.defineProperty(arrayResult.items, '0', { enumerable: true, get: () => ({}) });
  await assert.rejects(runtimeFor({ handler: () => arrayResult }).runtime.callTool('search', scenario('valid_defaults').request.arguments), { code: 'capability_mcp_runtime_provider_invalid' });
});
