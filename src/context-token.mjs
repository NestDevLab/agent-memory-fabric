import crypto from 'node:crypto';
import fs from 'node:fs';
import { normalizeOpaqueTagMap } from './access-contract.mjs';

const TOKEN_FIELDS = ['actor', 'runtime', 'profile', 'conversationKind', 'contextTags', 'purpose', 'policyRevision', 'issuedAt', 'expiresAt', 'nonce', 'keyVersion', 'requestDigest'];
const OPTIONAL_TOKEN_FIELDS = ['canonicalScopes'];
const CANONICAL_SCOPE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const ROUTE_BINDING_FIELDS = ['actor', 'canonicalScope', 'conversationKind', 'contextTags', 'keyVersion'];

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function parseKey(value) {
  const raw = String(value || '');
  if (/^[a-f0-9]{64}$/i.test(raw)) return Buffer.from(raw, 'hex');
  const decoded = Buffer.from(raw, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== raw) throw new Error('context_key_invalid');
  return decoded;
}

export function requestDigest(value) {
  return crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}

export function normalizeContextKeyRing(value) {
  if (!value?.currentKeyVersion || !value?.keys || typeof value.keys !== 'object') throw new Error('context_keys_unconfigured');
  const keys = new Map(Object.entries(value.keys).map(([version, key]) => {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(version)) throw new Error('context_key_version_invalid');
    return [version, parseKey(key)];
  }));
  if (!keys.has(value.currentKeyVersion)) throw new Error('context_current_key_missing');
  return { currentKeyVersion: value.currentKeyVersion, keys };
}

function sign(encoded, key) {
  return crypto.createHmac('sha256', key).update(encoded, 'utf8').digest('base64url');
}

function tokenFieldsValid(value) {
  const keys = Object.keys(value || {}).sort();
  const required = [...TOKEN_FIELDS].sort();
  return keys.join('\0') === required.join('\0')
    || keys.join('\0') === [...TOKEN_FIELDS, ...OPTIONAL_TOKEN_FIELDS].sort().join('\0');
}

function normalizeCanonicalScopes(value) {
  if (!Array.isArray(value) || !value.length || value.length > 64
    || value.some(scope => typeof scope !== 'string' || !CANONICAL_SCOPE.test(scope) || scope.includes('*'))) {
    throw new Error('context_scopes_invalid');
  }
  return [...new Set(value)].sort();
}

function normalizeRouteBinding(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join('\0') !== [...ROUTE_BINDING_FIELDS].sort().join('\0')
    || typeof value.actor !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/.test(value.actor)
    || typeof value.keyVersion !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.keyVersion)
    || typeof value.canonicalScope !== 'string' || !CANONICAL_SCOPE.test(value.canonicalScope)
    || !['dm', 'group', 'channel', 'thread', 'session'].includes(value.conversationKind)) {
    throw new Error('route_binding_invalid');
  }
  const contextTags = normalizeOpaqueTagMap(value.contextTags);
  if (canonicalJson(contextTags) !== canonicalJson(value.contextTags)) throw new Error('route_binding_invalid');
  return { actor: value.actor, canonicalScope: value.canonicalScope,
    conversationKind: value.conversationKind, contextTags, keyVersion: value.keyVersion };
}

export function issueSessionRouteBinding(payload, keyRing) {
  const normalizedRing = keyRing?.keys instanceof Map ? keyRing : normalizeContextKeyRing(keyRing);
  const unsigned = normalizeRouteBinding({ ...payload, keyVersion: normalizedRing.currentKeyVersion });
  return { ...unsigned, mac: sign(canonicalJson(unsigned), normalizedRing.keys.get(unsigned.keyVersion)) };
}

export function issueContextToken(payload, keyRing) {
  const normalized = keyRing?.keys instanceof Map ? keyRing : normalizeContextKeyRing(keyRing);
  const complete = { ...payload, ...(payload.canonicalScopes === undefined ? {}
    : { canonicalScopes: normalizeCanonicalScopes(payload.canonicalScopes) }), keyVersion: normalized.currentKeyVersion };
  if (!tokenFieldsValid(complete)) throw new Error('context_token_invalid');
  const encoded = Buffer.from(canonicalJson(complete), 'utf8').toString('base64url');
  return `${encoded}.${sign(encoded, normalized.keys.get(complete.keyVersion))}`;
}

export class ContextTokenVerifier {
  constructor({ keyRing, policyRevision, clock = () => Date.now(), maxTtlMs = 300000, maxClockSkewMs = 30000 }) {
    this.configured = true;
    this.keyRing = keyRing?.keys instanceof Map ? keyRing : normalizeContextKeyRing(keyRing);
    this.policyRevision = String(policyRevision || '');
    this.clock = clock;
    this.maxTtlMs = maxTtlMs;
    this.maxClockSkewMs = maxClockSkewMs;
    this.nonces = new Map();
  }
  verify(token, { actor, purpose, request, contextKeyVersions = null }) {
    const [encoded, signature, extra] = String(token || '').split('.');
    if (!encoded || !signature || extra !== undefined) throw Object.assign(new Error('context_invalid'), { status: 403 });
    let payload;
    try { payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); } catch { throw Object.assign(new Error('context_invalid'), { status: 403 }); }
    if (!tokenFieldsValid(payload)) throw Object.assign(new Error('context_invalid'), { status: 403 });
    const key = this.keyRing.keys.get(payload.keyVersion);
    if (!key || signature.length !== 43 || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(sign(encoded, key)))) throw Object.assign(new Error('context_invalid'), { status: 403 });
    if (contextKeyVersions !== null
      && (!Array.isArray(contextKeyVersions) || !contextKeyVersions.includes(payload.keyVersion))) {
      throw Object.assign(new Error('context_invalid'), { status: 403 });
    }
    const now = this.clock();
    const issuedAt = Date.parse(payload.issuedAt);
    const expiresAt = Date.parse(payload.expiresAt);
    if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || issuedAt > now + this.maxClockSkewMs || expiresAt <= now || expiresAt - issuedAt > this.maxTtlMs) throw Object.assign(new Error('context_invalid'), { status: 403 });
    if (payload.actor !== actor || payload.purpose !== purpose || payload.policyRevision !== this.policyRevision || payload.requestDigest !== requestDigest(request)) throw Object.assign(new Error('context_invalid'), { status: 403 });
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(payload.runtime) || !/^[A-Za-z0-9._-]{1,128}$/.test(payload.profile) || !/^[A-Za-z0-9_-]{16,128}$/.test(payload.nonce) || !['dm', 'group', 'channel', 'thread', 'session'].includes(payload.conversationKind)) throw Object.assign(new Error('context_invalid'), { status: 403 });
    try { normalizeOpaqueTagMap(payload.contextTags); } catch { throw Object.assign(new Error('context_invalid'), { status: 403 }); }
    if (payload.canonicalScopes !== undefined) {
      try {
        if (canonicalJson(normalizeCanonicalScopes(payload.canonicalScopes)) !== canonicalJson(payload.canonicalScopes)) {
          throw new Error('context_scopes_invalid');
        }
      } catch { throw Object.assign(new Error('context_invalid'), { status: 403 }); }
    }
    const seen = this.nonces.get(payload.nonce);
    const tokenDigest = crypto.createHash('sha256').update(String(token), 'utf8').digest('hex');
    if (seen && (seen.requestDigest !== payload.requestDigest || seen.expiresAt !== expiresAt || seen.tokenDigest !== tokenDigest)) throw Object.assign(new Error('context_invalid'), { status: 403 });
    this.nonces.set(payload.nonce, { requestDigest: payload.requestDigest, expiresAt, tokenDigest });
    for (const [nonce, record] of this.nonces) if (record.expiresAt <= now) this.nonces.delete(nonce);
    return payload;
  }

  verifySessionRouteBinding(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== [...ROUTE_BINDING_FIELDS, 'mac'].sort().join('\0')
      || typeof value.mac !== 'string') throw new Error('route_binding_invalid');
    const { mac, ...candidate } = value; const unsigned = normalizeRouteBinding(candidate);
    const key = this.keyRing.keys.get(unsigned.keyVersion);
    const expected = key ? sign(canonicalJson(unsigned), key) : '';
    if (!key || mac.length !== expected.length
      || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) throw new Error('route_binding_invalid');
    return unsigned;
  }
}

export function createUnconfiguredContextVerifier() {
  return { configured: false, verify() { throw Object.assign(new Error('context_required'), { status: 403 }); } };
}

export function createContextVerifierFromEnv(env = process.env) {
  let ring;
  if (env.AMF_CONTEXT_KEY_RING_PATH) {
    try { ring = JSON.parse(fs.readFileSync(env.AMF_CONTEXT_KEY_RING_PATH, 'utf8')); } catch { throw new Error('context_key_ring_invalid'); }
  } else if (env.AMF_CONTEXT_KEY_RING_JSON) {
    try { ring = JSON.parse(env.AMF_CONTEXT_KEY_RING_JSON); } catch { throw new Error('context_key_ring_invalid'); }
  }
  if (!ring) return createUnconfiguredContextVerifier();
  return new ContextTokenVerifier({ keyRing: ring, policyRevision: String(env.AMF_POLICY_REVISION || '') });
}
