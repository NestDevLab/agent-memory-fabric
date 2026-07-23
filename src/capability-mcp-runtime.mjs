const TOOL_NAMES = Object.freeze(['search', 'read', 'propose', 'proposal_status', 'status']);
const TOOL_SET = new Set(TOOL_NAMES);
const KINDS = new Set(['canonical_memory', 'document', 'conversation']);
const PROPOSAL_STATES = new Set(['queued', 'pending', 'review_required', 'approved', 'rejected', 'applied', 'failed']);
const RESOURCE_ID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const CURSOR = /^cur_[A-Za-z0-9_-]{16,256}$/;
const REQUEST_ID = /^req_[A-Za-z0-9_-]{8,128}$/;
const SCOPE = /^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$/;
const ALIAS = /^[a-z][a-z0-9_-]{2,63}$/;

export const CAPABILITY_MCP_TOOL_DEFINITIONS = deepFreeze([
  { name: 'search', description: 'Search authorized memory resources.', inputSchema: { type: 'object', additionalProperties: false, required: ['query', 'scopes', 'purpose'], properties: { query: { type: 'string', minLength: 1, maxLength: 512, pattern: '\\S' }, kinds: { type: 'array', minItems: 1, maxItems: 3, uniqueItems: true, items: { enum: ['canonical_memory', 'document', 'conversation'] } }, scopes: { type: 'array', minItems: 1, maxItems: 16, uniqueItems: true, items: { type: 'string', pattern: '^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$' } }, purpose: { enum: ['memory_recall', 'conversation_recall'] }, limit: { type: 'integer', minimum: 1, maximum: 50 }, cursor: { type: ['string', 'null'], pattern: '^cur_[A-Za-z0-9_-]{16,256}$' } } } },
  { name: 'read', description: 'Read an authorized memory resource.', inputSchema: { type: 'object', additionalProperties: false, required: ['id', 'scopes', 'purpose'], properties: { id: { type: 'string', pattern: '^rid_[A-Za-z0-9_-]{8,128}$' }, scopes: { type: 'array', minItems: 1, maxItems: 16, uniqueItems: true, items: { type: 'string', pattern: '^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$' } }, purpose: { enum: ['memory_recall', 'conversation_recall'] } } } },
  { name: 'propose', description: 'Queue a memory curation proposal.', inputSchema: { type: 'object', additionalProperties: false, required: ['scope', 'claim', 'purpose', 'idempotencyKey'], properties: { scope: { type: 'string', pattern: '^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$' }, claim: { type: 'string', minLength: 1, maxLength: 4096, pattern: '\\S' }, purpose: { const: 'memory_curation' }, idempotencyKey: { type: 'string', pattern: '^req_[A-Za-z0-9_-]{8,128}$' } } } },
  { name: 'proposal_status', description: 'Read an authorized proposal status.', inputSchema: { type: 'object', additionalProperties: false, required: ['id', 'scopes', 'purpose'], properties: { id: { type: 'string', pattern: '^rid_[A-Za-z0-9_-]{8,128}$' }, scopes: { type: 'array', minItems: 1, maxItems: 16, uniqueItems: true, items: { type: 'string', pattern: '^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$' } }, purpose: { const: 'memory_curation' } } } },
  { name: 'status', description: 'Read public capability readiness.', inputSchema: { type: 'object', additionalProperties: false, maxProperties: 0, properties: {} } }
]);

function error(code) {
  const value = new Error(code);
  value.code = code;
  return value;
}

function configInvalid() { throw error('capability_mcp_runtime_config_invalid'); }
function providerInvalid() { throw error('capability_mcp_runtime_provider_invalid'); }
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function exactKeys(value, keys) {
  return isPlainObject(value) && Reflect.ownKeys(value).every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string' && keys.includes(key) && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function cleanArray(value) {
  return Array.isArray(value) && Reflect.ownKeys(value).every(key => {
    if (key === 'length') return true;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === 'string' && /^(?:0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length
      && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
function cloneFrozen(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
  if (isPlainObject(value)) return deepFreeze(Object.fromEntries(Object.keys(value).map(key => [key, cloneFrozen(value[key])] )));
  return value;
}
function uniqueStrings(value, { min, max, valid }) {
  if (!cleanArray(value) || value.length < min || value.length > max) return null;
  const seen = new Set();
  for (const item of value) if (typeof item !== 'string' || !valid(item) || seen.has(item)) return null; else seen.add(item);
  return [...value];
}
function validText(value, max) { return typeof value === 'string' && value.length >= 1 && value.length <= max && /\S/.test(value); }
function invalidResult() { return deepFreeze({ ok: false, outcome: 'invalid_request' }); }
function deniedResult(name) { return deepFreeze({ ok: false, outcome: ['read', 'proposal_status'].includes(name) ? 'not_found' : 'forbidden' }); }

function normalizeArguments(name, input) {
  if (!isPlainObject(input)) return null;
  if (name === 'search') {
    if (!exactKeys(input, ['query', 'kinds', 'scopes', 'purpose', 'limit', 'cursor']) || !Object.hasOwn(input, 'query') || !Object.hasOwn(input, 'scopes') || !Object.hasOwn(input, 'purpose')) return null;
    const kinds = input.kinds === undefined ? ['canonical_memory', 'document'] : uniqueStrings(input.kinds, { min: 1, max: 3, valid: item => KINDS.has(item) });
    const scopes = uniqueStrings(input.scopes, { min: 1, max: 16, valid: item => SCOPE.test(item) });
    const limit = input.limit === undefined ? undefined : input.limit;
    const cursor = input.cursor === undefined ? null : input.cursor;
    if (!validText(input.query, 512) || !kinds || !scopes || !['memory_recall', 'conversation_recall'].includes(input.purpose)
      || (limit !== undefined && (!Number.isInteger(limit) || limit < 1 || limit > 50))
      || (cursor !== null && (typeof cursor !== 'string' || !CURSOR.test(cursor)))) return null;
    return deepFreeze({ query: input.query, kinds, scopes, purpose: input.purpose, ...(limit === undefined ? {} : { limit }), cursor });
  }
  if (name === 'read' || name === 'proposal_status') {
    if (!exactKeys(input, ['id', 'scopes', 'purpose']) || !Object.hasOwn(input, 'id') || !Object.hasOwn(input, 'scopes') || !Object.hasOwn(input, 'purpose')) return null;
    const scopes = uniqueStrings(input.scopes, { min: 1, max: 16, valid: item => SCOPE.test(item) });
    const purposeValid = name === 'proposal_status' ? input.purpose === 'memory_curation' : (input.purpose === 'memory_recall' || input.purpose === 'conversation_recall');
    return RESOURCE_ID.test(input.id) && scopes && purposeValid ? deepFreeze({ id: input.id, scopes, purpose: input.purpose }) : null;
  }
  if (name === 'propose') {
    if (!exactKeys(input, ['scope', 'claim', 'purpose', 'idempotencyKey']) || !Object.hasOwn(input, 'scope') || !Object.hasOwn(input, 'claim') || !Object.hasOwn(input, 'purpose') || !Object.hasOwn(input, 'idempotencyKey')) return null;
    return typeof input.scope === 'string' && SCOPE.test(input.scope) && validText(input.claim, 4096) && input.purpose === 'memory_curation' && typeof input.idempotencyKey === 'string' && REQUEST_ID.test(input.idempotencyKey)
      ? deepFreeze({ scope: input.scope, claim: input.claim, purpose: input.purpose, idempotencyKey: input.idempotencyKey }) : null;
  }
  if (name === 'status') return exactKeys(input, []) ? deepFreeze({}) : null;
  return null;
}

function validateResource(value) {
  return exactKeys(value, ['id', 'kind', 'text']) && RESOURCE_ID.test(value.id) && KINDS.has(value.kind) && validText(value.text, 65536);
}
function validateProposal(value) {
  return exactKeys(value, ['id', 'state']) && RESOURCE_ID.test(value.id) && PROPOSAL_STATES.has(value.state);
}
function validateReadiness(value) {
  return exactKeys(value, ['name', 'state']) && TOOL_SET.has(value.name) && ['ready', 'unavailable'].includes(value.state);
}
function only(value, keys) { return exactKeys(value, keys); }
function resultValidFor(name, value, request) {
  if (!exactKeys(value, ['ok', 'outcome', 'id', 'items', 'resource', 'proposal', 'nextCursor', 'capabilities']) || typeof value.ok !== 'boolean' || typeof value.outcome !== 'string') return false;
  const outcome = value.outcome;
  const has = key => Object.hasOwn(value, key);
  const noExtras = keys => Reflect.ownKeys(value).length === keys.length && keys.every(key => has(key));
  if (outcome === 'found') {
    if (value.ok !== true) return false;
    if (name === 'search') return noExtras(['ok', 'outcome', 'items', 'nextCursor']) && cleanArray(value.items) && value.items.length <= 50 && value.items.every(item => validateResource(item) && request.kinds.includes(item.kind))
      && (value.nextCursor === null || (typeof value.nextCursor === 'string' && CURSOR.test(value.nextCursor)));
    return name === 'read' && noExtras(['ok', 'outcome', 'resource']) && validateResource(value.resource)
      && (value.resource.kind !== 'conversation' || request.purpose === 'conversation_recall');
  }
  if (outcome === 'queued') return name === 'propose' && value.ok === true && noExtras(['ok', 'outcome', 'id']) && typeof value.id === 'string' && RESOURCE_ID.test(value.id);
  if (outcome === 'pending') return name === 'proposal_status' && value.ok === true && noExtras(['ok', 'outcome', 'proposal']) && validateProposal(value.proposal);
  if (outcome === 'not_found') return ['read', 'proposal_status'].includes(name) && value.ok === false && noExtras(['ok', 'outcome']);
  if (outcome === 'forbidden') return ['search', 'propose', 'status'].includes(name) && value.ok === false && noExtras(['ok', 'outcome']);
  if (outcome === 'invalid_request') return value.ok === false && noExtras(['ok', 'outcome']);
  if (outcome === 'ready' || outcome === 'unavailable') {
    if (name !== 'status' || value.ok !== (outcome === 'ready') || !noExtras(['ok', 'outcome', 'capabilities']) || !cleanArray(value.capabilities) || value.capabilities.length < 1 || value.capabilities.length > 5 || !value.capabilities.every(validateReadiness)) return false;
    return new Set(value.capabilities.map(item => item.name)).size === TOOL_NAMES.length
      && TOOL_NAMES.every(name => value.capabilities.some(item => item.name === name));
  }
  return false;
}

function normalizeAliases(value) {
  if (value === undefined) return new Map();
  if (!isPlainObject(value) || Reflect.ownKeys(value).some(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return typeof key !== 'string' || descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value');
  })) configInvalid();
  const aliases = new Map();
  for (const [alias, target] of Object.entries(value)) {
    if (!ALIAS.test(alias) || TOOL_SET.has(alias) || !TOOL_SET.has(target) || aliases.has(alias)) configInvalid();
    aliases.set(alias, target);
  }
  return aliases;
}

function validateRegistry(registry) {
  if (!registry || typeof registry.snapshot !== 'function' || typeof registry.call !== 'function') configInvalid();
  let snapshot;
  try { snapshot = registry.snapshot(); } catch { configInvalid(); }
  if (!exactKeys(snapshot, ['enabledCapabilities', 'capabilities']) || !Array.isArray(snapshot.enabledCapabilities)
    || snapshot.enabledCapabilities.length !== TOOL_NAMES.length || new Set(snapshot.enabledCapabilities).size !== TOOL_NAMES.length
    || snapshot.enabledCapabilities.some(name => !TOOL_SET.has(name)) || !cleanArray(snapshot.capabilities)
    || snapshot.capabilities.length !== TOOL_NAMES.length || !snapshot.capabilities.every(item => validateReadiness(item) && item.state === 'ready')
    || new Set(snapshot.capabilities.map(item => item.name)).size !== TOOL_NAMES.length) configInvalid();
}

/** A transport-neutral MCP dispatcher; all provider output is validated before release. */
export function createCapabilityMcpRuntime(config) {
  if (!exactKeys(config, ['registry', 'authorize', 'aliases']) || typeof config.authorize !== 'function') configInvalid();
  validateRegistry(config.registry);
  const aliases = normalizeAliases(config.aliases);
  const registry = config.registry;

  const callTool = async (name, input) => {
    const canonical = TOOL_SET.has(name) ? name : aliases.get(name);
    if (!canonical) return invalidResult();
    const argumentsValue = normalizeArguments(canonical, input);
    if (!argumentsValue) return invalidResult();
    if (canonical === 'search' && argumentsValue.kinds.includes('conversation') && argumentsValue.purpose !== 'conversation_recall') return deniedResult(canonical);
    const authorization = deepFreeze({ capability: canonical, permission: `fabric:${canonical}`,
      purpose: canonical === 'status' ? null : argumentsValue.purpose,
      scopes: canonical === 'propose' ? [argumentsValue.scope] : (argumentsValue.scopes || []) });
    let granted = false;
    try { granted = await config.authorize(authorization) === true; } catch { granted = false; }
    if (!granted) return deniedResult(canonical);
    try {
      const result = await registry.call(canonical, argumentsValue);
      if (!resultValidFor(canonical, result, argumentsValue)) providerInvalid();
      return cloneFrozen(result);
    } catch { providerInvalid(); }
  };

  return Object.freeze({
    listTools: () => CAPABILITY_MCP_TOOL_DEFINITIONS,
    callTool
  });
}
