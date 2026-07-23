import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCapabilityMcpServerRuntime } from '../src/capability-mcp-server-runtime.mjs';
const env = { AMF_CAPABILITY_MCP_ENABLED: 'true', AMF_CAPABILITY_MCP_HOST: '127.0.0.1', AMF_CAPABILITY_MCP_PORT: '31337', AMF_POLICY_PATH: '/missing' };
const deps = { createFabricStore() {}, createCanonicalStore() {}, createDocumentStore() {}, createContextVerifier() {}, createConversationRuntime() {}, createOpaqueStore() {}, createHttpServer() {}, authenticateRequest() {}, validateContextActorBinding() {}, createBridge() {}, createComposition() {} };
test('disabled and invalid startup fail before constructing resources', () => { assert.throws(() => createCapabilityMcpServerRuntime({ env: {}, dependencies: deps }), { code: 'capability_mcp_server_runtime_invalid' }); assert.throws(() => createCapabilityMcpServerRuntime({ env: { ...env, AMF_CAPABILITY_MCP_HOST: '0.0.0.0' }, dependencies: deps }), { code: 'capability_mcp_server_runtime_invalid' }); });
test('missing policy fails before resource construction', async () => { const runtime = createCapabilityMcpServerRuntime({ env, dependencies: deps }); await assert.rejects(runtime.start(), { code: 'capability_mcp_server_runtime_invalid' }); });
test('strict optional aliases reject before construction', () => { const tooMany = JSON.stringify(Object.fromEntries(Array.from({ length: 17 }, (_, index) => [`legacy_${index}`, 'search']))); for (const aliases of ['not-json', '{"search":"read"}', '{"legacy_search":"unknown"}', '[]', {}, tooMany]) assert.throws(() => createCapabilityMcpServerRuntime({ env: { ...env, AMF_CAPABILITY_MCP_ALIASES_JSON: aliases }, dependencies: deps }), { code: 'capability_mcp_server_runtime_invalid' }); });

function policyFile(value = { actors: { actor: { mode: 'allow_all' } }, scopes: { 'team:synthetic': {} } }) { const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'amf-capability-')), 'policy.json'); fs.writeFileSync(file, JSON.stringify(value)); return file; }
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function waitFor(predicate) { for (let index = 0; index < 100; index += 1) { if (predicate()) return; await new Promise(resolve => setImmediate(resolve)); } assert.fail('condition_not_reached'); }
function harness({ failing = null, unconfigured = null, factoryGate = null, readyGate = null, httpMode = 'ready' } = {}) {
  const events = []; let http;
  const make = name => async () => {
    events.push(`create:${name}`);
    if (factoryGate?.name === name) await factoryGate.gate.promise;
    if (failing === `create:${name}`) throw Error();
    const configured = unconfigured !== name;
    const value = { configured, async ready() { events.push(`ready:${name}`); if (readyGate?.name === name) await readyGate.gate.promise; if (failing === `ready:${name}`) throw Error(); }, async close() { events.push(`close:${name}`); } };
    if (name === 'fabric') value.createSessionReader = () => ({ configured: true });
    if (name === 'conversation') value.reader = { configured };
    return value;
  };
  const dependencies = {
    createFabricStore: make('fabric'), createCanonicalStore: make('canonical'), createDocumentStore: make('document'), createContextVerifier: make('context'), createConversationRuntime: make('conversation'), createOpaqueStore: make('opaque'),
    authenticateRequest: async () => ({ actor: 'actor', policy: {} }),
    validateContextActorBinding(...args) { events.push(`binding:${args[0]}`); },
    createBridge(value) { events.push(`bridge:${Object.hasOwn(value.policies.scopes, 'team:changed') ? 'changed' : 'initial'}`); return { authorize() {}, resolveGrant() {} }; },
    createComposition(value) { events.push(`compose:${Object.hasOwn(value, 'aliases') ? 'aliases' : 'none'}`); return { handle() {}, tools() {} }; },
    createHttpServer(options) {
      if (httpMode === 'malformed') return {};
      let errorListener;
      http = { options, close(callback) { events.push('close:http'); callback?.(); }, listen(port, host, callback) { events.push(`listen:${host}:${port}`); if (httpMode === 'ready') callback(); else if (httpMode === 'error') errorListener?.(Error()); }, once(name, listener) { if (name === 'error') errorListener = listener; }, off(name, listener) { if (name === 'error' && errorListener === listener) errorListener = undefined; } };
      return http;
    }
  };
  return { events, dependencies, get http() { return http; } };
}

test('readiness completes before loopback listen and graceful close is reverse ordered', async () => { const file = policyFile(); const value = harness(); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: file }, dependencies: value.dependencies }); await runtime.start(); assert.equal(value.events.indexOf('listen:127.0.0.1:31337') > value.events.indexOf('ready:opaque'), true); await runtime.close(); assert.deepEqual(value.events.slice(-7), ['close:http', 'close:opaque', 'close:conversation', 'close:context', 'close:document', 'close:canonical', 'close:fabric']); });

test('readiness failure and unconfigured context or conversation never listen and clean up', async () => { for (const options of [{ failing: 'ready:document' }, { unconfigured: 'context' }, { unconfigured: 'conversation' }]) { const file = policyFile(); const value = harness(options); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: file }, dependencies: value.dependencies }); await assert.rejects(runtime.start(), { code: 'capability_mcp_server_runtime_invalid' }); assert.equal(value.events.some(event => event.startsWith('listen:')), false); assert.equal(value.events.includes('close:fabric'), true); } });

test('policy reload is per request and bridge/composition receive no aliases', async () => { const file = policyFile(); const value = harness(); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: file }, dependencies: value.dependencies }); await runtime.start(); await value.http.options.createComposition({ authContext: { actor: 'actor', policy: {} }, request: {}, requestArguments: {}, contextToken: undefined, transport: 'streamable-http' }); fs.writeFileSync(file, JSON.stringify({ actors: { actor: { mode: 'allow_all' } }, scopes: { 'team:synthetic': {}, 'team:changed': {} } })); await value.http.options.createComposition({ authContext: { actor: 'actor', policy: {} }, request: {}, requestArguments: {}, contextToken: undefined, transport: 'sse' }); assert.deepEqual(value.events.filter(event => event.startsWith('binding:')), ['binding:actor', 'binding:actor']); assert.deepEqual(value.events.filter(event => event.startsWith('bridge:')), ['bridge:initial', 'bridge:changed']); assert.deepEqual(value.events.filter(event => event.startsWith('compose:')), ['compose:none', 'compose:none']); await runtime.close(); });

test('valid migration aliases are forwarded without becoming a default', async () => {
  const value = harness(); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile(), AMF_CAPABILITY_MCP_ALIASES_JSON: '{"legacy_search":"search"}' }, dependencies: value.dependencies }); await runtime.start(); await value.http.options.createComposition({ authContext: { actor: 'actor', policy: {} }, requestArguments: {}, contextToken: undefined }); assert.deepEqual(value.events.filter(event => event.startsWith('compose:')), ['compose:aliases']); await runtime.close();
});

test('partial construction and malformed HTTP server failures close every owned resource', async () => {
  for (const options of [{ failing: 'create:document' }, { httpMode: 'malformed' }]) {
    const value = harness(options); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile() }, dependencies: value.dependencies });
    await assert.rejects(runtime.start(), { code: 'capability_mcp_server_runtime_invalid' });
    assert.equal(value.events.includes('close:fabric'), true);
    if (options.failing) assert.deepEqual(value.events.slice(-2), ['close:canonical', 'close:fabric']);
    assert.equal(value.events.some(event => event.startsWith('listen:')), false);
  }
});

test('close serializes with pending construction and readiness without a late listener', async () => {
  for (const mode of ['factory', 'ready']) {
    const gate = deferred(); const options = mode === 'factory' ? { factoryGate: { name: 'fabric', gate } } : { readyGate: { name: 'document', gate } };
    const value = harness(options); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile() }, dependencies: value.dependencies }); const starting = runtime.start();
    await waitFor(() => value.events.includes(mode === 'factory' ? 'create:fabric' : 'ready:document'));
    const closing = runtime.close(); gate.resolve();
    await assert.rejects(starting, { code: 'capability_mcp_server_runtime_invalid' }); await closing;
    assert.equal(value.events.some(event => event.startsWith('listen:')), false);
    assert.equal(value.events.filter(event => event === 'close:fabric').length, 1);
    assert.equal(runtime.server, null);
  }
});

test('concurrent starts reject and a completed close permits a clean restart', async () => {
  const gate = deferred(); const value = harness({ factoryGate: { name: 'fabric', gate } }); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile() }, dependencies: value.dependencies }); const first = runtime.start();
  await waitFor(() => value.events.includes('create:fabric')); await assert.rejects(runtime.start(), { code: 'capability_mcp_server_runtime_invalid' }); gate.resolve(); await first; await runtime.close(); await runtime.start(); assert.equal(value.events.filter(event => event.startsWith('listen:')).length, 2); await runtime.close();
});

test('listen errors and close during listen leave no server or resources', async () => {
  for (const httpMode of ['error', 'pending']) {
    const value = harness({ httpMode }); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile() }, dependencies: value.dependencies }); const starting = runtime.start();
    if (httpMode === 'pending') { await waitFor(() => value.events.some(event => event.startsWith('listen:'))); const closing = runtime.close(); await assert.rejects(starting, { code: 'capability_mcp_server_runtime_invalid' }); await closing; }
    else await assert.rejects(starting, { code: 'capability_mcp_server_runtime_invalid' });
    assert.equal(runtime.server, null); assert.equal(value.events.includes('close:http'), true); assert.equal(value.events.includes('close:fabric'), true);
  }
});

test('signal listeners are installed only while started and removed by close', async () => {
  const before = ['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)); const value = harness(); const runtime = createCapabilityMcpServerRuntime({ env: { ...env, AMF_POLICY_PATH: policyFile() }, dependencies: value.dependencies, installSignals: true }); await runtime.start();
  assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), before.map(count => count + 1)); await runtime.close(); assert.deepEqual(['SIGINT', 'SIGTERM'].map(signal => process.listenerCount(signal)), before);
});

test('disabled executable emits one fixed error and exits with code 78', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'); const result = spawnSync(process.execPath, ['scripts/amf-capability-mcp-server.mjs'], { cwd: root, env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 });
  assert.equal(result.status, 78); assert.equal(result.stdout, ''); assert.equal(result.stderr, 'capability_mcp_server_startup_failed\n');
});
