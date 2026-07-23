import { createFabricCapabilityProviderOperations } from './fabric-capability-provider-operations.mjs';
import { createCapabilityProviderAdapter } from './capability-provider-adapter.mjs';
import { createCapabilityProviderRegistry } from './capability-provider-registry.mjs';
import { createCapabilityMcpRuntime } from './capability-mcp-runtime.mjs';
import { createCapabilityMcpJsonRpc } from './capability-mcp-jsonrpc.mjs';

const CAPABILITIES = Object.freeze(['search', 'read', 'propose', 'proposal_status', 'status']);
const ALIAS = /^[a-z][a-z0-9_-]{2,63}$/;

function fail() { const error = new Error('capability_mcp_composition_config_invalid'); error.code = error.message; throw error; }
function record(value, keys) {
  try { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null; const own = Reflect.ownKeys(value); if (own.some(key => typeof key !== 'string') || own.some(key => !keys.includes(key))) return null; const out = {}; for (const key of own) { const descriptor = Object.getOwnPropertyDescriptor(value, key); if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null; Object.defineProperty(out, key, { value: descriptor.value, enumerable: true }); } return out; } catch { return null; }
}
function aliases(value) {
  try {
    if (value === undefined) return undefined; const source = record(value, Reflect.ownKeys(value).filter(key => typeof key === 'string'));
    if (!source || Object.keys(source).length > 16) fail(); const out = {};
    for (const [name, target] of Object.entries(source)) { if (!ALIAS.test(name) || CAPABILITIES.includes(name) || !CAPABILITIES.includes(target)) fail(); Object.defineProperty(out, name, { value: target, enumerable: true }); }
    return Object.freeze(out);
  } catch { fail(); }
}

/** Compose the public capability MCP protocol from the existing real modules. */
export function createCapabilityMcpComposition(config) {
  const input = record(config, ['canonicalStore', 'documentStore', 'conversationReader', 'fabricStore', 'resolveGrant', 'authorize', 'opaqueReferenceStore', 'aliases', 'cursorTtlMs', 'now']);
  if (!input || !['canonicalStore', 'documentStore', 'conversationReader', 'fabricStore', 'resolveGrant', 'authorize', 'opaqueReferenceStore'].every(key => Object.hasOwn(input, key)) || typeof input.resolveGrant !== 'function' || typeof input.authorize !== 'function' || (input.now !== undefined && typeof input.now !== 'function') || (input.cursorTtlMs !== undefined && (!Number.isSafeInteger(input.cursorTtlMs) || input.cursorTtlMs < 1000 || input.cursorTtlMs > 3600000))) fail();
  const safeAliases = aliases(input.aliases);
  try {
    const operations = createFabricCapabilityProviderOperations({ canonicalStore: input.canonicalStore, documentStore: input.documentStore, conversationReader: input.conversationReader, fabricStore: input.fabricStore, resolveGrant: input.resolveGrant });
    const provider = createCapabilityProviderAdapter({ operations, opaqueReferenceStore: input.opaqueReferenceStore, ...(input.now === undefined ? {} : { now: input.now }), ...(input.cursorTtlMs === undefined ? {} : { cursorTtlMs: input.cursorTtlMs }) });
    const registry = createCapabilityProviderRegistry({ enabledCapabilities: [...CAPABILITIES], providerAssignments: CAPABILITIES.map(capability => ({ capability, providerId: 'capability_core' })), providers: [{ providerId: 'capability_core', handle: provider }] });
    const runtime = createCapabilityMcpRuntime({ registry, authorize: input.authorize, ...(safeAliases === undefined ? {} : { aliases: safeAliases }) });
    const kernel = createCapabilityMcpJsonRpc({ runtime });
    return Object.freeze({ handle: kernel.handle, tools: kernel.tools });
  } catch { fail(); }
}
