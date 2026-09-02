import { normalizeScopeRef, scopeRefIdentity } from './scope-substrate.mjs';

const RID = /^rid_[A-Za-z0-9_-]{8,128}$/;
const CURSOR = /^cur_[A-Za-z0-9_-]{16,256}$/;
const KINDS = new Set(['canonical_memory', 'document', 'conversation', 'resource']);
const PURPOSES = new Set(['memory_recall', 'conversation_recall', 'context_recall']);

function invalid() {
  throw Object.assign(new Error('capability_mcp_v2_invalid_request'), { code: 'capability_mcp_v2_invalid_request' });
}

function plain(value) {
  try { return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; } catch { return false; }
}

function freeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function exactRecord(value, allowed, required) {
  if (!plain(value)) invalid();
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string' || !allowed.includes(key))) invalid();
  if (required.some(key => !Object.hasOwn(value, key))) invalid();
  const output = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) invalid();
    output[key] = descriptor.value;
  }
  return output;
}

export function normalizeScopeRefs(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 16 || Reflect.ownKeys(value).length !== value.length + 1) invalid();
  let scopes;
  try {
    scopes = value.map(scope => normalizeScopeRef(
      exactRecord(scope, ['tenantId', 'type', 'scopeId'], ['tenantId', 'type', 'scopeId'])
    ));
  } catch { invalid(); }
  if (new Set(scopes.map(scope => scope.tenantId)).size !== 1) invalid();
  const identities = scopes.map(scopeRefIdentity);
  if (new Set(identities).size !== identities.length) invalid();
  return freeze(scopes);
}

export function canonicalScopeIdentities(scopes) {
  return freeze(normalizeScopeRefs(scopes).map(scope => ({ tenantId: scope.tenantId, scopeId: scope.scopeId }))
    .sort((left, right) => left.tenantId.localeCompare(right.tenantId) || left.scopeId.localeCompare(right.scopeId)));
}

function normalizeKinds(value) {
  if (value === undefined) return freeze(['canonical_memory', 'document']);
  if (!Array.isArray(value) || value.length < 1 || value.length > 4 || Reflect.ownKeys(value).length !== value.length + 1 ||
    new Set(value).size !== value.length || value.some(kind => typeof kind !== 'string' || !KINDS.has(kind))) invalid();
  return freeze([...value]);
}

export function normalizeCapabilityMcpV2Request(capability, requestArguments) {
  if (capability === 'search') {
    const args = exactRecord(requestArguments, ['query', 'kinds', 'scopes', 'purpose', 'delivery', 'limit', 'cursor'], ['query', 'scopes', 'purpose']);
    const scopes = normalizeScopeRefs(args.scopes);
    const kinds = normalizeKinds(args.kinds);
    const delivery = args.delivery ?? 'results';
    const limit = args.limit ?? 20;
    const cursor = args.cursor ?? null;
    if (typeof args.query !== 'string' || Array.from(args.query).length < 1 || Array.from(args.query).length > 512 || !/\S/u.test(args.query) ||
      !PURPOSES.has(args.purpose) || !['results', 'notice'].includes(delivery) || !Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
      (cursor !== null && (typeof cursor !== 'string' || !CURSOR.test(cursor)))) invalid();
    if (kinds.includes('conversation') && !['conversation_recall', 'context_recall'].includes(args.purpose)) invalid();
    if (kinds.includes('resource') && args.purpose !== 'context_recall') invalid();
    if (delivery === 'notice' && (args.purpose !== 'context_recall' || Object.hasOwn(args, 'limit') || Object.hasOwn(args, 'cursor'))) invalid();
    return freeze({ capability, query: args.query, kinds, scopes, purpose: args.purpose, delivery, limit, cursor });
  }
  if (capability === 'read') {
    const args = exactRecord(requestArguments, ['id', 'scopes', 'purpose'], ['id', 'scopes', 'purpose']);
    const scopes = normalizeScopeRefs(args.scopes);
    if (typeof args.id !== 'string' || !RID.test(args.id) || !PURPOSES.has(args.purpose)) invalid();
    return freeze({ capability, id: args.id, scopes, purpose: args.purpose });
  }
  invalid();
}

export function createCapabilityMcpV2AuthorizationBridge({ authorize } = {}) {
  if (typeof authorize !== 'function') throw new TypeError('capability_mcp_v2_authorize_invalid');
  return freeze({
    async authorize(request) {
      const normalized = normalizeCapabilityMcpV2Request(request?.capability, request?.arguments);
      let grant = null;
      try {
        grant = await authorize({
          capability: normalized.capability,
          permission: `fabric:${normalized.capability}`,
          purpose: normalized.purpose,
          scopes: normalized.scopes
        });
      } catch { grant = null; }
      return freeze({ normalized, grant });
    }
  });
}
