import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { createCapabilityMcpJsonRpc, CAPABILITY_MCP_PROTOCOL_VERSION, encodeCapabilityMcpSse, encodeCapabilityMcpStreamableHttp } from '../src/capability-mcp-jsonrpc.mjs';
import { createCapabilityMcpRuntime } from '../src/capability-mcp-runtime.mjs';
import { createCapabilityProviderRegistry } from '../src/capability-provider-registry.mjs';

const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/capability-mcp-v1.conformance.json', import.meta.url), 'utf8'));
const tools = ['search', 'read', 'propose', 'proposal_status', 'status'];
const grant = () => ({ actor: { id: 'actor_synthetic', scopes: ['team:synthetic'] } });
const clone = value => JSON.parse(JSON.stringify(value));
const scenario = id => fixture.scenarios.find(item => item.id === id);
function registry(handler) { return createCapabilityProviderRegistry({ enabledCapabilities: tools, providerAssignments: tools.map(capability => ({ capability, providerId: 'source_main' })), providers: [{ providerId: 'source_main', handle: handler }] }); }
function kernelFor(item, { crash = false } = {}) {
  const authorizations = [];
  const runtime = createCapabilityMcpRuntime({ registry: registry(() => { if (crash) throw Error('private-runtime-secret'); return clone(item.expected); }), aliases: item?.alias ? { [item.alias]: item.request.name } : undefined, authorize: async authorization => {
    authorizations.push(authorization);
    return authorization.scopes.includes('team:outside') ? false : grant();
  } });
  return { kernel: createCapabilityMcpJsonRpc({ runtime }), authorizations };
}
async function roundTrip(kind, kernel, request) {
  const reply = await kernel.handle(request);
  if (reply === null) return null;
  const encoded = kind === 'http' ? encodeCapabilityMcpStreamableHttp(reply) : encodeCapabilityMcpSse(reply);
  assert.equal(Object.isFrozen(encoded), true);
  return JSON.parse(kind === 'http' ? encoded.body : encoded.data);
}
function toolReply(value) { return JSON.parse(value.result.content[0].text); }
function expectedAuthorization(item) {
  const name = item.request.name; const args = item.request.arguments;
  return { capability: name, permission: `fabric:${name}`, purpose: name === 'status' ? null : args.purpose,
    scopes: name === 'propose' ? [args.scope] : (args.scopes || []) };
}

test('every applicable fixture scenario has an identical HTTP and SSE capability round trip', async () => {
  for (const item of fixture.scenarios.filter(value => !value.registry)) {
    const replies = [];
    for (const kind of ['http', 'sse']) {
      const { kernel, authorizations } = kernelFor(item); const initialized = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION } });
      assert.equal(initialized.result.protocolVersion, CAPABILITY_MCP_PROTOCOL_VERSION, item.id);
      const name = item.alias || item.request.name;
      const reply = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: item.request.arguments } });
      assert.deepEqual(toolReply(reply), item.expected, item.id);
      assert.equal(reply.result.isError, item.expected.ok === false, item.id);
      replies.push(reply);
      assert.deepEqual(authorizations, item.id === 'denied_conversation_purpose' ? [] : [expectedAuthorization(item)], item.id);
      const listed = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
      assert.deepEqual(listed.result.tools.map(tool => tool.name), fixture.advertisedTools);
      assert.equal(listed.result.tools.some(tool => tool.name === item.alias), false);
    }
    assert.deepEqual(replies[0], replies[1], item.id);
  }
});

test('invalid registry fixtures prevent both transports from starting before encoding', () => {
  for (const item of fixture.scenarios.filter(value => value.registry)) for (const kind of ['http', 'sse']) {
    const ids = [...new Set(item.registry.providerAssignments.map(row => row.providerId))];
    let transportConstructed = false;
    assert.throws(() => {
      const configured = createCapabilityProviderRegistry({ ...item.registry, providers: ids.map(providerId => ({ providerId, handle: () => ({}) })) });
      createCapabilityMcpJsonRpc({ runtime: createCapabilityMcpRuntime({ registry: configured, authorize: grant }) });
      transportConstructed = true;
    }, { code: 'capability_provider_registry_config_invalid' }, `${kind}:${item.id}`);
    assert.equal(transportConstructed, false, `${kind}:${item.id}`);
  }
});

test('notifications produce no response and malformed, hostile, and unknown RPCs fail closed identically', async () => {
  const { kernel } = kernelFor(scenario('valid_defaults'));
  assert.deepEqual(encodeCapabilityMcpStreamableHttp(null), { status: 202, headers: {}, body: '' });
  for (const kind of ['http', 'sse']) {
    assert.equal(await roundTrip(kind, kernel, { jsonrpc: '2.0', method: 'notifications/initialized' }), null);
    const privateText = 'private-rpc-secret'; const hostile = { jsonrpc: '2.0', id: 4, method: 'tools/list' }; Object.defineProperty(hostile, 'secret', { enumerable: true, get() { throw Error(privateText); } });
    for (const request of [hostile, { jsonrpc: '2.0', id: 4, method: 'unknown' }, { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'search' } }]) {
      const reply = await roundTrip(kind, kernel, request); assert.ok(reply.error); assert.equal(JSON.stringify(reply).includes(privateText), false);
    }
  }
});

test('initialize accepts bounded standard client fields while rejecting unknown and hostile fields', async () => {
  const { kernel } = kernelFor(scenario('valid_defaults'));
  for (const kind of ['http', 'sse']) {
    const standard = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 8, method: 'initialize', params: { protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION, capabilities: { roots: { listChanged: true } }, clientInfo: { name: 'synthetic-client', version: '1' } } });
    assert.equal(standard.result.protocolVersion, CAPABILITY_MCP_PROTOCOL_VERSION);
    const hostile = { protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION }; Object.defineProperty(hostile, 'clientInfo', { enumerable: true, get() { throw Error('private-initialize-secret'); } });
    const unknown = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 9, method: 'initialize', params: { protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION, unknown: true } }); assert.deepEqual(unknown.error, { code: -32602, message: 'Invalid params' });
    const malformedClient = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 9, method: 'initialize', params: { protocolVersion: CAPABILITY_MCP_PROTOCOL_VERSION, clientInfo: 'synthetic-client' } }); assert.deepEqual(malformedClient.error, { code: -32602, message: 'Invalid params' });
    const rejected = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 9, method: 'initialize', params: hostile }); assert.deepEqual(rejected.error, { code: -32600, message: 'Invalid request' });
  }
});

test('runtime exceptions become fixed content-free errors and encoders reject injection-shaped values', async () => {
  for (const kind of ['http', 'sse']) {
    const { kernel } = kernelFor(scenario('valid_defaults'), { crash: true });
    const reply = await roundTrip(kind, kernel, { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'search', arguments: scenario('valid_defaults').request.arguments } });
    assert.deepEqual(reply, { jsonrpc: '2.0', id: 7, error: { code: -32000, message: 'Internal error' } });
  }
  const privateText = 'private-sse-injection\nevent: private';
  const sse = encodeCapabilityMcpSse({ jsonrpc: '2.0', id: 1, result: { value: privateText } }); assert.equal(sse.body.includes('\nevent: private'), false);
  assert.throws(() => encodeCapabilityMcpStreamableHttp({ jsonrpc: '2.0', id: 1, error: { code: -1, message: privateText } }), { code: 'capability_mcp_jsonrpc_encode_invalid' });
});
