const CAPS = new Set(['search', 'read', 'propose', 'proposal_status', 'status']);
const SCOPE = /^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$/;
function fail() { const error = new Error('capability_mcp_auth_bridge_invalid'); error.code = error.message; throw error; }
function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function plain(value) { try { return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; } catch { return false; } }
function record(value, keys = null) { try { if (!plain(value)) return null; const own = Reflect.ownKeys(value); if (own.some(key => typeof key !== 'string') || (keys && (own.length !== keys.length || !keys.every(key => own.includes(key))))) return null; const out = {}; for (const key of own) { const d = Object.getOwnPropertyDescriptor(value, key); if (!d?.enumerable || !Object.hasOwn(d, 'value')) return null; Object.defineProperty(out, key, { value: d.value, enumerable: true }); } return out; } catch { return null; } }
function method(value, name) { try { for (let target = value; target; target = Object.getPrototypeOf(target)) { const descriptor = Object.getOwnPropertyDescriptor(target, name); if (descriptor) return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function' ? descriptor.value.bind(value) : null; } } catch { /* invalid dependency */ } return null; }
function strings(value, max = 64) { try { if (!Array.isArray(value) || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) return null; const out = []; for (let i = 0; i < value.length; i += 1) { const d = Object.getOwnPropertyDescriptor(value, String(i)); if (!d?.enumerable || !Object.hasOwn(d, 'value') || typeof d.value !== 'string' || d.value.length < 1 || d.value.length > 4096) return null; out.push(d.value); } return [...new Set(out)].sort(); } catch { return null; } }
function requestStrings(value, max = 64) { try { if (!Array.isArray(value) || value.length < 1 || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) return null; const out = []; for (let i = 0; i < value.length; i += 1) { const d = Object.getOwnPropertyDescriptor(value, String(i)); if (!d?.enumerable || !Object.hasOwn(d, 'value') || typeof d.value !== 'string' || d.value.length < 1 || d.value.length > 4096 || out.includes(d.value)) return null; out.push(d.value); } return out; } catch { return null; } }
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`; if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function clone(value, seen = new WeakSet(), depth = 0) { if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value; if (typeof value === 'string') return value.length <= 4096 ? value : null; try { if (!value || typeof value !== 'object' || depth >= 8 || seen.has(value)) return null; seen.add(value); if (Array.isArray(value)) { if (value.length > 128 || Reflect.ownKeys(value).length !== value.length + 1) return null; const out = []; for (let i = 0; i < value.length; i += 1) { const d = Object.getOwnPropertyDescriptor(value, String(i)); const item = d?.enumerable && Object.hasOwn(d, 'value') ? clone(d.value, seen, depth + 1) : null; if (item === null && d?.value !== null) return null; out.push(item); } return out; } if (!plain(value) || Reflect.ownKeys(value).length > 128) return null; const out = {}; for (const key of Object.keys(value).sort()) { const d = Object.getOwnPropertyDescriptor(value, key); const item = d?.enumerable && Object.hasOwn(d, 'value') ? clone(d.value, seen, depth + 1) : null; if (item === null && d?.value !== null) return null; Object.defineProperty(out, key, { value: item, enumerable: true }); } return out; } catch { return null; } finally { try { seen.delete(value); } catch {} } }
function scopesFor(capability, args) { if (capability === 'propose') return strings([args.scope], 1); return capability === 'status' ? [] : strings(args.scopes, 16); }

/** Build the canonical private context-token request without adding a public MCP field. */
export function buildCapabilityContextRequest(capability, requestArguments) {
  const args = record(requestArguments); if (!CAPS.has(capability) || !args) fail();
  if (Object.hasOwn(args, 'contextToken')) fail();
  if (capability === 'search') {
    if (Object.keys(args).some(key => !['query', 'scopes', 'purpose', 'kinds', 'limit', 'cursor'].includes(key)) || !Object.hasOwn(args, 'query') || !Object.hasOwn(args, 'scopes') || !Object.hasOwn(args, 'purpose')) fail();
    const scopes = requestStrings(args.scopes, 16); const kinds = args.kinds === undefined ? ['canonical_memory', 'document'] : requestStrings(args.kinds, 3);
    const limit = args.limit === undefined ? 20 : args.limit; const cursor = args.cursor === undefined ? null : args.cursor;
    if (!scopes || !kinds || !scopes.every(scope => SCOPE.test(scope)) || !kinds.every(kind => ['canonical_memory', 'document', 'conversation'].includes(kind)) || typeof args.query !== 'string' || args.query.length < 1 || args.query.length > 512 || !/\S/.test(args.query) || !['memory_recall', 'conversation_recall'].includes(args.purpose) || !Number.isSafeInteger(limit) || limit < 1 || limit > 50 || (cursor !== null && (typeof cursor !== 'string' || !/^cur_[A-Za-z0-9_-]{16,256}$/.test(cursor)))) fail();
    return freeze({ operation: 'capability_search', query: args.query, kinds, scopes, purpose: args.purpose, limit, cursor });
  }
  if (capability === 'read') { if (Object.keys(args).sort().join('\0') !== 'id\0purpose\0scopes') fail(); const scopes = requestStrings(args.scopes, 16); if (typeof args.id !== 'string' || !/^rid_[A-Za-z0-9_-]{8,128}$/.test(args.id) || !scopes || !scopes.every(scope => SCOPE.test(scope)) || !['memory_recall', 'conversation_recall'].includes(args.purpose)) fail(); return freeze({ operation: 'capability_read', id: args.id, scopes, purpose: args.purpose }); }
  fail();
}

/** Create private authorize/resolveGrant closures for one authenticated capability MCP request. */
export function createCapabilityMcpAuthorizationBridge(config) {
  const input = record(config, ['authContext', 'requestArguments', 'contextToken', 'contextVerifier', 'policies', 'validateContextActorBinding']);
  const auth = input && record(input.authContext); const policy = auth && record(auth.policy); const policies = input && record(input.policies); const actor = auth?.actor; const verifyContext = input && method(input.contextVerifier, 'verify');
  if (!input || !auth || !policy || !policies || typeof actor !== 'string' || actor.length < 1 || actor.length > 192 || /[\0\r\n]/.test(actor) || !verifyContext || typeof input.validateContextActorBinding !== 'function' || (input.contextToken !== undefined && (typeof input.contextToken !== 'string' || input.contextToken.length < 1 || input.contextToken.length > 16384))) fail();
  const baseArgs = record(input.requestArguments); if (!baseArgs) fail();
  const allowedScopes = strings(policy.allowedScopes, 64); const permissions = strings(policy.permissions, 64); const vaults = strings(policy.documentVaultIds ?? policy.allowedVaults ?? [], 64); const sessions = strings(policy.sessionOwnerActors ?? [], 64); const versions = strings(policy.contextKeyVersions ?? [], 32); const owners = sessions && strings([actor, ...sessions], 65); const allowedCapabilities = permissions && [...CAPS].filter(capability => permissions.includes('*') || permissions.includes(`fabric:${capability}`)).sort();
  const mode = policy.mode; if (!['allow_all', 'scoped', 'read_only_scoped', 'deny'].includes(mode)) fail();
  const registeredScopes = record(policies.scopes); if (!registeredScopes || !owners || !allowedScopes || !permissions || !vaults || !versions || !allowedCapabilities) fail();
  const safePolicy = freeze({ mode, allowedScopes, permissions, allowedVaults: vaults, sessionOwnerActors: sessions, contextKeyVersions: versions });
  let stableGrant = null;
  const authorize = async authorization => {
    const request = record(authorization, ['capability', 'permission', 'purpose', 'scopes']); if (!request || !CAPS.has(request.capability) || request.permission !== `fabric:${request.capability}` || !Array.isArray(request.scopes) || request.purpose !== (request.capability === 'status' ? null : baseArgs.purpose)) return null;
    const requestedScopes = strings(request.scopes, 16); const originalScopes = scopesFor(request.capability, baseArgs);
    if (!requestedScopes || !originalScopes || canonical(requestedScopes) !== canonical(originalScopes) || mode === 'deny' || !allowedCapabilities.includes(request.capability)
      || (request.purpose !== null && !permissions.includes('*') && !permissions.includes(`purpose:${request.purpose}`))
      || (request.capability === 'propose' && mode === 'read_only_scoped')) return null;
    if (requestedScopes.some(scope => !SCOPE.test(scope) || !Object.hasOwn(registeredScopes, scope) || ((mode === 'scoped' || mode === 'read_only_scoped') && !allowedScopes.includes('*') && !allowedScopes.includes(scope)))) return null;
    let context = null;
    if (request.purpose === 'conversation_recall') {
      if (typeof input.contextToken !== 'string' || !versions.length || !['search', 'read'].includes(request.capability)) return null;
      let verified; try { input.validateContextActorBinding(actor, safePolicy, policies, input.contextVerifier); verified = verifyContext(input.contextToken, { actor, purpose: request.purpose, request: buildCapabilityContextRequest(request.capability, baseArgs), contextKeyVersions: versions }); } catch { return null; }
      const source = record(verified); if (!source) return null; const fields = ['actor', 'runtime', 'profile', 'conversationKind', 'contextTags', 'purpose', 'policyRevision', 'keyVersion', 'canonicalScopes']; context = {}; for (const field of fields) if (Object.hasOwn(source, field)) { const copied = clone(source[field]); if (copied === null && source[field] !== null) return null; Object.defineProperty(context, field, { value: copied, enumerable: true }); } if (context.actor !== actor || context.purpose !== request.purpose) return null; context = freeze(context);
    }
    stableGrant = freeze({ actor, allowedScopes: requestedScopes, documentVaultIds: vaults, sessionOwnerActors: owners, allowedCapabilities, purpose: request.purpose, context });
    return stableGrant;
  };
  const resolveGrant = async (grant, internal) => {
    const request = record(internal, ['capability', 'scopes', 'purpose']); if (!stableGrant || !request || !CAPS.has(request.capability) || !Array.isArray(request.scopes) || (request.purpose !== null && request.purpose !== stableGrant.purpose) || !allowedCapabilities.includes(request.capability)) return null;
    const scopes = strings(request.scopes, 16); const candidate = record(grant, ['actor', 'allowedScopes', 'documentVaultIds', 'sessionOwnerActors', 'allowedCapabilities', 'purpose', 'context']);
    if (!scopes || !candidate || canonical(candidate) !== canonical(stableGrant) || scopes.some(scope => !stableGrant.allowedScopes.includes(scope))) return null;
    return freeze({ actor, allowedScopes: stableGrant.allowedScopes, documentVaultIds: stableGrant.documentVaultIds, sessionOwnerActors: stableGrant.sessionOwnerActors, context: stableGrant.context });
  };
  return freeze({ authorize, resolveGrant });
}
