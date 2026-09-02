import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { ContextTokenVerifier, issueSessionRouteBindingV3 } from '../src/context-token.mjs';
import { buildMemoryRecord, proposalIdempotencyKey } from '../src/conversation-memory-extractor.mjs';
import { createSessionScopeRouteComposer, createStructuredCandidateProposalSink, routeReaderSessionScope } from '../src/scope-route-composition.mjs';
import { legacyHttpProposalSinkUnsupported } from '../src/structured-candidate-proposal-sink.mjs';

const ring = { currentKeyVersion: 'ctx-v3', keys: { 'ctx-v3': crypto.randomBytes(32).toString('base64') } };
const actor = 'service:raw-extractor';
const tags = { conversation: [`hmac-sha256:routing-v3:${'a'.repeat(64)}`], room: [`hmac-sha256:routing-v3:${'b'.repeat(64)}`] };
const session = { id: 'ccon_readerroute01', extractionIdentity: 'ccon_readerroute01', visibleRevisionDigest: `sha256:${'c'.repeat(64)}`,
  conversationKind: 'group', contextTags: tags, firstOccurredAt: '2026-09-01T12:00:00.000Z', lastOccurredAt: '2026-09-01T12:01:00.000Z', eventCount: 2 };
const binding = { actor, conversationKind: 'group', contextTags: tags,
  scope: { tenantId: 'tenant_alpha', type: 'project', scopeId: 'atlas' },
  mappingEvidence: { id: 'evidence-route-001', digest: `sha256:${'d'.repeat(64)}` }, keyVersion: 'ctx-v3' };
const verifier = () => new ContextTokenVerifier({ keyRing: ring, policyRevision: '' });
const manifest = bindings => ({ schema: 'amf.session-route-manifest/v3', bindings: bindings.map(item => issueSessionRouteBindingV3(item, ring)) });

test('reader-shaped session routes exactly and delivers only a structured attributed candidate', async () => {
  const delivered = [];
  const sink = createStructuredCandidateProposalSink({ submit: async value => { delivered.push(value); return { accepted: true }; } });
  const composer = createSessionScopeRouteComposer({ manifest: manifest([binding]), verifier: verifier(), actor, candidateSink: sink });
  const route = composer.routeSession(session);
  const candidate = buildMemoryRecord({ sessionId: session.id, extractionIdentity: session.extractionIdentity,
    visibleRevisionDigest: session.visibleRevisionDigest, claim: { claimType: 'decision', claim: 'Keep route evidence on every candidate proposal.', confidence: 0.8 }, route });
  const idempotencyKey = proposalIdempotencyKey({ sessionId: session.id, extractionIdentity: session.extractionIdentity,
    visibleRevisionDigest: session.visibleRevisionDigest, claim: candidate.text, route });
  assert.deepEqual(await composer.proposeCandidate({ session, candidate, idempotencyKey }), { accepted: true });
  assert.equal(delivered.length, 1); assert.strictEqual(delivered[0].scope, candidate.scope);
  assert.strictEqual(delivered[0].routingEvidence, candidate.routingEvidence); assert.strictEqual(delivered[0].candidate, candidate);
  assert.equal(delivered[0].candidate.infer, false); assert.match(delivered[0].idempotencyKey, /^raw-extractor:/);
});

test('unmapped, ambiguous, and legacy routes remain fail-closed for reader-shaped sessions', () => {
  const sink = createStructuredCandidateProposalSink({ submit: async () => ({ accepted: true }) });
  const make = bindings => createSessionScopeRouteComposer({ manifest: bindings, verifier: verifier(), actor, candidateSink: sink });
  assert.throws(() => make(manifest([binding])).routeSession({ ...session, contextTags: { ...tags, room: [`hmac-sha256:routing-v3:${'e'.repeat(64)}`] } }), /session_scope_unmapped/);
  const alternate = { ...binding, scope: { ...binding.scope, scopeId: 'other' }, mappingEvidence: { id: 'evidence-route-002', digest: `sha256:${'e'.repeat(64)}` } };
  assert.throws(() => make(manifest([binding, alternate])).routeSession(session), /session_scope_ambiguous/);
  assert.throws(() => routeReaderSessionScope({ session, manifest: { schema: 'amf.session-route-manifest/v1', bindings: [] }, verifier: verifier(), actor }), /session_scope_unmapped/);
});

test('legacy HTTP and incompatible candidate sinks cannot receive a ScopeRef candidate', () => {
  assert.throws(() => legacyHttpProposalSinkUnsupported(), /structured_candidate_legacy_http_unsupported/);
  assert.throws(() => createSessionScopeRouteComposer({ manifest: manifest([binding]), verifier: verifier(), actor,
    candidateSink: { schema: 'amf.legacy-memory-proposal-sink/v1', propose() {} } }), /structured_candidate_sink_required/);
});
