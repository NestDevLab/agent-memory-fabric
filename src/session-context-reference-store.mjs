import crypto from 'node:crypto';

import { canonicalScopeIdentities } from './capability-mcp-v2-auth-bridge.mjs';

const CONVERSATION_ID = /^ccon_[A-Za-z0-9_-]{8,128}$/;
const CAPSULE_ID = /^csc_[A-Za-z0-9_-]{8,128}$/;
// Capsule references are a context_recall overlay.  conversation_recall keeps
// the retained v1 read path and must never resolve a capsule reference.
const PURPOSES = new Set(['context_recall']);
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function failure(code) { throw Object.assign(new Error(code), { code }); }
function plain(value) { try { return value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; } catch { return false; } }
function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function canonical(value) { if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`; if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function digest(value) { return `sha256:${crypto.createHash('sha256').update(canonical(value), 'utf8').digest('hex')}`; }

function safeSnapshot(value, depth = 0, seen = new WeakSet()) {
  if (value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isSafeInteger(value)) || (typeof value === 'string' && value.length <= 4096)) return value;
  if (!value || typeof value !== 'object' || depth >= 8 || seen.has(value)) failure('session_context_reference_invalid');
  try {
    seen.add(value);
    if (Array.isArray(value)) {
      if (value.length > 128 || Reflect.ownKeys(value).length !== value.length + 1) failure('session_context_reference_invalid');
      return value.map(item => safeSnapshot(item, depth + 1, seen));
    }
    if (!plain(value) || Reflect.ownKeys(value).some(key => typeof key !== 'string') || Reflect.ownKeys(value).length > 128) failure('session_context_reference_invalid');
    const result = {};
    for (const key of Object.keys(value).sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) failure('session_context_reference_invalid');
      result[key] = safeSnapshot(descriptor.value, depth + 1, seen);
    }
    return result;
  } finally { seen.delete(value); }
}

function timestamp(value) {
  const parsed = typeof value === 'string' ? Date.parse(value) : NaN;
  const normalized = Number.isFinite(parsed) ? new Date(Math.floor(parsed / 1000) * 1000).toISOString().replace('.000Z', 'Z') : null;
  if (!normalized || (value !== new Date(parsed).toISOString() && value !== normalized)) failure('session_context_reference_invalid');
  return normalized;
}

function grantBinding(grant, scopes, purpose) {
  const snapshot = safeSnapshot(grant);
  const binding = digest({ grant: snapshot, purpose, scopes: canonicalScopeIdentities(scopes) });
  if (!DIGEST.test(binding)) failure('session_context_reference_invalid');
  return binding;
}

function locator(payload) {
  const encoded = canonical(payload);
  if (Buffer.byteLength(encoded, 'utf8') > 4096) failure('session_context_reference_invalid');
  return encoded;
}

function decodeLocator(value) {
  try {
    const parsed = JSON.parse(value);
    if (!plain(parsed) || Object.keys(parsed).sort().join('\0') !== 'capsuleId\0conversationId\0expiresAt\0observedAt\0purpose\0query\0redactionPolicy\0scopeIdentities\0sourceSnapshotDigest\0target\0v' || parsed.v !== 1 || parsed.target !== 'expansion' ||
      !CAPSULE_ID.test(parsed.capsuleId) || !CONVERSATION_ID.test(parsed.conversationId) || !PURPOSES.has(parsed.purpose) || typeof parsed.query !== 'string' || Array.from(parsed.query).length > 512 || parsed.redactionPolicy !== 'session-context-capsule/v1' || !Array.isArray(parsed.scopeIdentities) || !DIGEST.test(parsed.sourceSnapshotDigest)) failure('session_context_reference_not_found');
    timestamp(parsed.expiresAt);
    timestamp(parsed.observedAt);
    return parsed;
  } catch (caught) { if (caught?.code === 'session_context_reference_not_found') throw caught; failure('session_context_reference_not_found'); }
}

export function createSessionContextReferenceStore({ opaqueReferenceStore, now = () => Date.now(), cursorTtlMs = 15 * 60_000 } = {}) {
  if (!opaqueReferenceStore || typeof opaqueReferenceStore.issueResource !== 'function' || typeof opaqueReferenceStore.resolveResource !== 'function' ||
    typeof opaqueReferenceStore.issueCursor !== 'function' || typeof opaqueReferenceStore.resolveCursor !== 'function' || typeof now !== 'function' ||
    !Number.isSafeInteger(cursorTtlMs) || cursorTtlMs < 1_000 || cursorTtlMs > 86_400_000) throw new TypeError('session_context_reference_store_invalid');

  return freeze({
    async issueExpansion({ conversationId, capsuleId, query = '', scopes, purpose, grant, expiresAt, observedAt, sourceSnapshot }) {
      if (!CONVERSATION_ID.test(conversationId) || !CAPSULE_ID.test(capsuleId) || !PURPOSES.has(purpose) || typeof query !== 'string' || Array.from(query).length > 512) failure('session_context_reference_invalid');
      const expiry = timestamp(expiresAt);
      const observed = timestamp(observedAt);
      if (Date.parse(expiry) <= Number(now())) failure('session_context_reference_invalid');
      const scopeIdentities = canonicalScopeIdentities(scopes);
      const binding = grantBinding(grant, scopes, purpose);
      const sourceSnapshotDigest = digest(safeSnapshot(sourceSnapshot));
      return opaqueReferenceStore.issueResource({
        kind: 'conversation', revision: null, grantBinding: binding,
        locator: locator({ v: 1, target: 'expansion', capsuleId, conversationId, query, scopeIdentities, purpose, expiresAt: expiry, observedAt: observed, sourceSnapshotDigest, redactionPolicy: 'session-context-capsule/v1' })
      });
    },

    async resolveExpansion({ id, scopes, purpose, grant }) {
      const binding = grantBinding(grant, scopes, purpose);
      let resource;
      try { resource = await opaqueReferenceStore.resolveResource({ id, grantBinding: binding, expectedKind: 'conversation' }); } catch { failure('session_context_reference_not_found'); }
      const payload = decodeLocator(resource.locator);
      if (payload.purpose !== purpose || canonical(payload.scopeIdentities) !== canonical(canonicalScopeIdentities(scopes)) || Date.parse(payload.expiresAt) <= Number(now())) failure('session_context_reference_not_found');
      return freeze(payload);
    },

    assertExpansionSnapshot({ reference, sourceSnapshot }) {
      if (!plain(reference) || !CAPSULE_ID.test(reference.capsuleId) || !DIGEST.test(reference.sourceSnapshotDigest) || digest(safeSnapshot(sourceSnapshot)) !== reference.sourceSnapshotDigest) failure('session_context_reference_not_found');
      return true;
    },

    async issueCursor({ request, scopes, purpose, grant, continuation }) {
      const binding = grantBinding(grant, scopes, purpose);
      const requestBinding = digest(safeSnapshot(request));
      const expiresAt = new Date(Number(now()) + cursorTtlMs).toISOString();
      return opaqueReferenceStore.issueCursor({ requestBinding, grantBinding: binding, continuation: safeSnapshot(continuation), expiresAt });
    },

    async resolveCursor({ id, request, scopes, purpose, grant }) {
      const binding = grantBinding(grant, scopes, purpose);
      const requestBinding = digest(safeSnapshot(request));
      try { return await opaqueReferenceStore.resolveCursor({ id, requestBinding, grantBinding: binding }); } catch { failure('session_context_cursor_invalid'); }
    }
  });
}
