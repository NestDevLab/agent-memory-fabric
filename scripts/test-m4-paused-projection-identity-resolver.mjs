import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { createM4CrossPhaseIdentityRegistry } from '../src/migration/m4-cross-phase-identity-registry.mjs';
import { createM4PausedProjectionIdentityResolver, validateM4PausedProjectionIdentity } from '../src/migration/m4-paused-projection-identity-resolver.mjs';
import { createM4PausedSourceTagAuthority } from '../src/migration/m4-paused-source-tag-authority.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession } from '../src/migration/m4-v2-conversation-projector.mjs';

const registrySecret = Buffer.alloc(32, 6); const sourceTagSecret = Buffer.alloc(32, 7);
const keys = { registrySecret, sourceTagSecret };
const hex = value => crypto.createHash('sha256').update(value).digest('hex');
const sessionId = `ses_${hex('session')}`; const eventId = `evt_${hex('event')}`;
const sourceTags = [`routing:${hex('one')}`, `routing:${hex('two')}`].sort();
const opaque = value => `hmac-sha256:routing-v1:${hex(value)}`;
const binding = { schema: 'amf.m4-paused-projection-binding/v1', runtime: 'hermes', sourceId: 'primary', digest: `sha256:${hex('binding')}` };
function fixture({ mappings = [{ runtime: binding.runtime, sourceId: binding.sourceId, projectionBindingDigest: binding.digest, sourceTags }], sourceAuthority = null } = {}) {
  const registry = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` },
    sessions: [{ legacySessionId: sessionId, conversationId: deriveM4V3ConversationIdFromLegacySessionId(sessionId), conversationKind: 'dm',
      sessionContextTags: { conversation: [opaque('conversation')], room: [opaque('room')] } }],
    events: [{ legacyEventId: eventId, legacySessionId: sessionId, eventId: deriveM4V3EventIdFromLegacyEventId(eventId),
      conversationId: deriveM4V3ConversationIdFromLegacySessionId(sessionId),
      sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(sessionId, sourceTags), sourceTags,
      conversationKind: 'dm', authorizationContextTags: { sender: [opaque('user')], conversation: [opaque('conversation')], room: [opaque('room')] },
      role: 'user', direction: 'inbound', state: 'active', revision: 1, replacesLegacyEventId: null,
      tombstonesLegacyEventId: null, conflictsWithLegacyEventIds: [] }] }, registrySecret);
  const pages = new Map(registry.pages.map(page => [page.pageKey, page]));
  const authority = sourceAuthority ?? createM4PausedSourceTagAuthority({ registryAuthority: registry.authority,
    backfillBinding: registry.authority.backfillBinding, mappings }, keys);
  return { registry, authority, resolver: createM4PausedProjectionIdentityResolver({ registryAuthority: registry.authority,
    loadPage: key => structuredClone(pages.get(key)), loadPostCutoffEvent: null, sourceTagAuthority: authority, ...keys }) };
}
function identity(overrides = {}) { return { schema: 'amf.m4-paused-projection-identity/v1', binding, runtime: 'hermes', sourceId: 'primary', sourceKind: 'hermes',
  observationClass: 'native', authoritativeDeletion: false, occurredAt: '2026-07-21T00:00:00Z', editedAt: null,
  legacy: { sessionId, eventId, priorEventId: null }, routing: { role: 'user', direction: 'inbound', conversationKind: 'dm',
    authorizationContextTags: { sender: [opaque('user')], conversation: [opaque('conversation')], room: [opaque('room')] } },
  lifecycle: { change: 'new', nativeRevision: 1 }, ...overrides }; }

test('constructs its own registry resolver and resolves a signed content-free paused identity', () => {
  const resolved = fixture().resolver.resolve({ identity: identity(), attestation: binding });
  assert.equal(resolved.covered, true); assert.equal(resolved.eventId, deriveM4V3EventIdFromLegacyEventId(eventId));
  assert.doesNotMatch(JSON.stringify(resolved), /visibleText|normalizedPayloadDigest|ciphertext|logicalMessageId/);
  const value = fixture();
  assert.throws(() => createM4PausedProjectionIdentityResolver({ registryResolver: { resolveBinding() { return {}; } },
    registryAuthority: value.registry.authority, loadPage: () => null, loadPostCutoffEvent: null,
    sourceTagAuthority: value.authority, ...keys }), { code: 'm4_paused_projection_identity_resolver_invalid' });
});

test('destroys owned key copies on idempotent close and rejects warmed-cache reuse', () => {
  const resolver = fixture().resolver;
  const input = { identity: identity(), attestation: binding };
  assert.equal(resolver.resolve(input).covered, true);
  resolver.close(); resolver.close();
  assert.throws(() => resolver.resolve(input), {
    code: 'm4_paused_projection_identity_resolver_closed',
  });
});

test('rejects unknown fields at every identity layer plus attestation binding drift', () => {
  const resolver = fixture().resolver;
  for (const mutate of [
    value => { value.extra = true; }, value => { value.binding.extra = true; }, value => { value.legacy.extra = true; },
    value => { value.routing.extra = true; }, value => { value.lifecycle.extra = true; },
  ]) {
    const changed = structuredClone(identity()); mutate(changed);
    assert.throws(() => resolver.resolve({ identity: changed, attestation: binding }), { code: 'm4_paused_projection_identity_invalid' });
  }
  for (const changedBinding of [{ ...binding, runtime: 'claude' }, { ...binding, sourceId: 'other' }, { ...binding, digest: `sha256:${hex('other')}` }]) {
    assert.throws(() => resolver.resolve({ identity: identity(), attestation: changedBinding }), { code: 'm4_paused_projection_identity_attestation_mismatch' });
  }
  const badAttestation = { ...binding, extra: true };
  assert.throws(() => resolver.resolve({ identity: identity(), attestation: badAttestation }), { code: 'm4_paused_projection_identity_attestation_invalid' });
});

test('rejects invalid identity timestamp, context, lifecycle, caller source, and full v2 payloads', () => {
  for (const changed of [
    identity({ occurredAt: 'invalid' }),
    identity({ routing: { ...identity().routing, authorizationContextTags: { sender: ['not-opaque'], conversation: [opaque('conversation')] } } }),
    identity({ lifecycle: { change: 'new', nativeRevision: -1 } }),
    identity({ lifecycle: { change: 'changed', nativeRevision: 1 } }),
    identity({ lifecycle: { change: 'deleted', nativeRevision: 1 }, legacy: { sessionId, eventId, priorEventId: eventId } }),
    { ...identity(), sourceTag: `routing:${hex('caller')}` },
    { schema: 'amf.raw-event-projection/v2' },
  ]) assert.throws(() => validateM4PausedProjectionIdentity(changed), { code: 'm4_paused_projection_identity_invalid' });
});

test('fails closed on missing/tampered mapping authority and independently wrong keys', () => {
  assert.throws(() => fixture({ mappings: [{ runtime: 'hermes', sourceId: 'other', projectionBindingDigest: binding.digest, sourceTags }] }).resolver
    .resolve({ identity: identity(), attestation: binding }), { code: 'm4_paused_source_tag_authority_mapping_missing' });
  const value = fixture(); const tampered = structuredClone(value.authority); tampered.mac = `hmac-sha256:${'a'.repeat(43)}`;
  assert.throws(() => createM4PausedProjectionIdentityResolver({ registryAuthority: value.registry.authority,
    loadPage: key => value.registry.pages.find(page => page.pageKey === key), loadPostCutoffEvent: null,
    sourceTagAuthority: tampered, ...keys }), { code: 'm4_paused_projection_identity_resolver_invalid' });
  assert.throws(() => createM4PausedProjectionIdentityResolver({ registryAuthority: value.registry.authority, loadPage: () => null,
    loadPostCutoffEvent: null, sourceTagAuthority: value.authority, registrySecret: sourceTagSecret, sourceTagSecret }),
  { code: 'm4_paused_projection_identity_resolver_invalid' });
});

test('derives post-cutoff identity from the complete mapped source-tag set', () => {
  const nextId = `evt_${hex('next')}`; const next = identity({ occurredAt: '2026-07-22T00:00:01Z',
    legacy: { sessionId, eventId: nextId, priorEventId: null } });
  const resolved = fixture().resolver.resolve({ identity: next, attestation: binding });
  assert.equal(resolved.covered, false);
  assert.equal(resolved.sourceInstanceId, deriveM4V3SourceInstanceIdFromLegacySession(sessionId, sourceTags));
  assert.deepEqual(resolved.postCutoffBinding.sourceTags, sourceTags);
});
