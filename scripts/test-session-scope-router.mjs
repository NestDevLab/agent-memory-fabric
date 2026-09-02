import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ContextTokenVerifier, issueSessionRouteBindingV3 } from '../src/context-token.mjs';
import { buildMemoryRecord } from '../src/conversation-memory-extractor.mjs';
import { requireSessionScopeRoute, routeSessionScope } from '../src/session-scope-router.mjs';

const ring = { currentKeyVersion: 'ctx-v3', keys: { 'ctx-v3': crypto.randomBytes(32).toString('base64') } };
const tags = { conversation: [`hmac-sha256:routing-v3:${'a'.repeat(64)}`], room: [`hmac-sha256:routing-v3:${'b'.repeat(64)}`] };
const binding = { actor: 'service:conversation-extractor', scope: { tenantId: 'tenant_alpha', type: 'project', scopeId: 'atlas' },
  conversationKind: 'group', contextTags: tags, mappingEvidence: { id: 'evidence-route-001', digest: `sha256:${'c'.repeat(64)}` }, keyVersion: 'ctx-v3' };
function manifest(bindings = [binding]) {
  return { schema: 'amf.session-route-manifest/v3', bindings: bindings.map(item => issueSessionRouteBindingV3(item, ring)) };
}
function routed(value = {}) {
  return routeSessionScope({ manifest: manifest(value.bindings), verifier: new ContextTokenVerifier({ keyRing: ring, policyRevision: '' }),
    actor: value.actor ?? binding.actor, conversationKind: value.conversationKind ?? binding.conversationKind,
    contextTags: value.contextTags ?? tags });
}

test('an exact reviewed v3 route returns one ScopeRef and B1.3 mapping evidence', () => {
  const result = routed();
  assert.equal(result.outcome, 'routed');
  assert.deepEqual(result.scope, binding.scope);
  assert.deepEqual(result.routingEvidence.mappingEvidence, binding.mappingEvidence);
  assert.match(result.routingEvidence.routeBindingDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(requireSessionScopeRoute(result), result);
  const candidate = buildMemoryRecord({ sessionId: 'ccon_routecandidate01', extractionIdentity: 'ccon_routecandidate01',
    visibleRevisionDigest: `sha256:${'d'.repeat(64)}`, claim: { claimType: 'decision', claim: 'Keep attributed route evidence through retry.', confidence: 0.8 }, route: result });
  assert.equal(candidate.infer, false); assert.equal(Object.hasOwn(candidate, 'record'), false);
  assert.deepEqual(candidate.scope, binding.scope); assert.deepEqual(candidate.routingEvidence, result.routingEvidence);
});

test('missing, mismatched, legacy, and ambiguous routes fail closed without conversion', () => {
  assert.deepEqual(routed({ actor: 'service:other' }), { outcome: 'unmapped' });
  assert.deepEqual(routed({ contextTags: { conversation: [tags.conversation[0]], room: [`hmac-sha256:routing-v3:${'d'.repeat(64)}`] } }), { outcome: 'unmapped' });
  const verifier = new ContextTokenVerifier({ keyRing: ring, policyRevision: '' });
  const legacy = { schema: 'amf.session-route-manifest/v1', bindings: [] };
  assert.deepEqual(routeSessionScope({ manifest: legacy, verifier, actor: binding.actor, conversationKind: binding.conversationKind, contextTags: tags }), { outcome: 'unmapped' });
  const alternate = { ...binding, scope: { tenantId: 'tenant_alpha', type: 'project', scopeId: 'other' }, mappingEvidence: { id: 'evidence-route-002', digest: `sha256:${'d'.repeat(64)}` } };
  assert.deepEqual(routed({ bindings: [binding, alternate] }), { outcome: 'ambiguous' });
  assert.throws(() => requireSessionScopeRoute({ outcome: 'unmapped' }), /session_scope_unmapped/);
  assert.throws(() => requireSessionScopeRoute({ outcome: 'ambiguous' }), /session_scope_ambiguous/);
});

test('scope strings, prefixes, wildcards, duplicate identities, and implicit normalization are rejected', () => {
  const verifier = new ContextTokenVerifier({ keyRing: ring, policyRevision: '' });
  for (const candidate of [
    { ...binding, scope: 'tenant_alpha:atlas' },
    { ...binding, scope: { ...binding.scope, scopeId: 'atlas*' } },
    { ...binding, scope: { ...binding.scope, scopeId: 'Atlas' } },
    { ...binding, scope: { ...binding.scope, tenantId: 'tenant_alpha ' } },
  ]) {
    assert.throws(() => routeSessionScope({ manifest: manifest([candidate]), verifier, actor: binding.actor, conversationKind: binding.conversationKind, contextTags: tags }), /route_binding_invalid|session_route_manifest_invalid/);
  }
  assert.throws(() => routeSessionScope({ manifest: manifest([binding, binding]), verifier, actor: binding.actor, conversationKind: binding.conversationKind, contextTags: tags }), /session_route_manifest_invalid/);
});
