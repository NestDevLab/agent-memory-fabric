import crypto from 'node:crypto';

import { normalizeOpaqueTagMap } from './access-contract.mjs';
import { normalizeMappingEvidence, normalizeScopeRef, scopeRefIdentity } from './scope-substrate.mjs';

export const SESSION_ROUTE_INPUT_SCHEMA_V3 = 'amf.session-route-input/v3';
export const SESSION_ROUTE_MANIFEST_SCHEMA_V3 = 'amf.session-route-manifest/v3';
const KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session']);
const ACTOR = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const KEY_VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function normalizedTags(value) {
  const tags = normalizeOpaqueTagMap(value);
  if (canonical(tags) !== canonical(value)) throw new Error('session_route_invalid');
  return tags;
}
function normalizedV3Binding(value) {
  if (!exact(value, ['actor', 'scope', 'conversationKind', 'contextTags', 'mappingEvidence', 'keyVersion'])
    || !ACTOR.test(value.actor) || !KINDS.has(value.conversationKind) || !KEY_VERSION.test(value.keyVersion)) {
    throw new Error('session_route_invalid');
  }
  return { actor: value.actor, scope: normalizeScopeRef(value.scope), conversationKind: value.conversationKind,
    contextTags: normalizedTags(value.contextTags), mappingEvidence: normalizeMappingEvidence(value.mappingEvidence),
    keyVersion: value.keyVersion };
}

export function sessionRouteBindingIdentity(value) {
  const candidate = value && typeof value === 'object' && Object.hasOwn(value, 'mac')
    ? (() => { const { mac: _mac, ...unsigned } = value; return unsigned; })() : value;
  const route = normalizedV3Binding(candidate);
  return `${route.actor}\0${route.conversationKind}\0${canonical(route.contextTags)}\0${scopeRefIdentity(route.scope)}`;
}

export function normalizeSessionScopeManifest(value, verifier = null) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Array.isArray(value.bindings)
    || value.bindings.length > 10000) throw new Error('session_route_manifest_invalid');
  // Read-only compatibility for deployed v1/v2 manifests. They are never
  // parsed into ScopeRef values and consequently can never select a v3 route.
  if ((value.schema === 'amf.session-route-manifest/v1' || value.schema === 'amf.session-route-manifest/v2')
    && exact(value, ['schema', 'bindings'])) {
    if (!verifier?.verifySessionRouteBinding) throw new Error('session_route_manifest_invalid');
    return { schema: value.schema, legacy: true, bindings: value.bindings.map(item => verifier.verifySessionRouteBinding(item)) };
  }
  if (value.schema !== SESSION_ROUTE_MANIFEST_SCHEMA_V3 || !exact(value, ['schema', 'bindings'])) {
    throw new Error('session_route_manifest_invalid');
  }
  if (!verifier?.verifySessionRouteBindingV3) throw new Error('session_route_manifest_invalid');
  const seen = new Set();
  const bindings = value.bindings.map(item => {
    const binding = verifier.verifySessionRouteBindingV3(item);
    const identity = sessionRouteBindingIdentity(binding);
    if (seen.has(identity)) throw new Error('session_route_manifest_invalid');
    seen.add(identity);
    return binding;
  });
  return { schema: value.schema, legacy: false, bindings };
}

export function routeSessionScope({ manifest, verifier, actor, conversationKind, contextTags }) {
  if (!ACTOR.test(String(actor || '')) || !KINDS.has(conversationKind)) throw new Error('session_route_input_invalid');
  const tags = normalizedTags(contextTags);
  const normalized = normalizeSessionScopeManifest(manifest, verifier);
  if (normalized.legacy) return { outcome: 'unmapped' };
  const matches = normalized.bindings.filter(item => item.actor === actor && item.conversationKind === conversationKind
    && canonical(item.contextTags) === canonical(tags));
  if (matches.length === 0) return { outcome: 'unmapped' };
  if (matches.length !== 1) return { outcome: 'ambiguous' };
  const route = matches[0];
  const routeBindingDigest = `sha256:${crypto.createHash('sha256').update(canonical(route), 'utf8').digest('hex')}`;
  return { outcome: 'routed', scope: structuredClone(route.scope), routingEvidence: {
    schema: 'amf.session-route-evidence/v1', routeBindingDigest,
    mappingEvidence: structuredClone(route.mappingEvidence)
  } };
}

export function requireSessionScopeRoute(value) {
  if (!value || value.outcome === 'unmapped') throw new Error('session_scope_unmapped');
  if (value.outcome === 'ambiguous') throw new Error('session_scope_ambiguous');
  if (value.outcome !== 'routed') throw new Error('session_scope_route_invalid');
  const scope = normalizeScopeRef(value.scope);
  const routingEvidence = value.routingEvidence;
  if (!exact(routingEvidence, ['schema', 'routeBindingDigest', 'mappingEvidence'])
    || routingEvidence.schema !== 'amf.session-route-evidence/v1'
    || !/^sha256:[a-f0-9]{64}$/.test(routingEvidence.routeBindingDigest)) throw new Error('session_scope_route_invalid');
  return { outcome: 'routed', scope, routingEvidence: { schema: routingEvidence.schema,
    routeBindingDigest: routingEvidence.routeBindingDigest, mappingEvidence: normalizeMappingEvidence(routingEvidence.mappingEvidence) } };
}
