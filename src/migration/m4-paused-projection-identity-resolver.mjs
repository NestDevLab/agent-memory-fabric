import { isConversationEventUtcTimestamp } from '../conversation-event-v3.mjs';
import { normalizeContextTags } from '../ingest/raw-projection-v2.mjs';
import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4CrossPhaseIdentityResolver } from './m4-cross-phase-identity-registry.mjs';
import { createM4PausedSourceTagResolver } from './m4-paused-source-tag-authority.mjs';
import { createM4CrossPhaseIdentityPublicationReader } from '../operator/m4-cross-phase-identity-publication-reader.mjs';

export const M4_PAUSED_PROJECTION_IDENTITY_SCHEMA = 'amf.m4-paused-projection-identity/v1';

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SESSION = /^ses_[a-f0-9]{64}$/;
const EVENT = /^evt_[a-f0-9]{64}$/;
const RUNTIME = new Set(['codex', 'claude', 'hermes', 'openclaw']);
const ROLES = new Set(['user', 'assistant']);
const DIRECTIONS = new Set(['inbound', 'outbound']);
const KINDS = new Set(['dm', 'group', 'channel', 'thread', 'session', 'unknown']);
const SOURCE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function binding(value, code) {
  if (!exact(value, ['schema', 'runtime', 'sourceId', 'digest']) || value.schema !== 'amf.m4-paused-projection-binding/v1'
    || !RUNTIME.has(value.runtime) || typeof value.sourceId !== 'string' || !SOURCE_ID.test(value.sourceId)
    || typeof value.digest !== 'string' || !DIGEST.test(value.digest)) fail(code);
  return { schema: value.schema, runtime: value.runtime, sourceId: value.sourceId, digest: value.digest };
}

export function createM4PausedProjectionIdentityResolverFromPublication(input = {}) {
  if (!exact(input, ['artifactRoot', 'manifestId', 'revision',
    'traversalCompletionKeyDocument', 'registrySecret', 'sourceTagAuthority',
    'sourceTagSecret', 'loadPostCutoffEvent'])) {
    fail('m4_paused_projection_identity_resolver_invalid');
  }
  const reader = createM4CrossPhaseIdentityPublicationReader({
    artifactRoot: input.artifactRoot,
    manifestId: input.manifestId,
    revision: input.revision,
    traversalCompletionKeyDocument: input.traversalCompletionKeyDocument,
    registrySecret: input.registrySecret,
  });
  try {
    const resolver = createM4PausedProjectionIdentityResolver({
      registryAuthority: reader.authority,
      loadPage: pageKey => reader.loadPage(pageKey),
      loadPostCutoffEvent: input.loadPostCutoffEvent,
      sourceTagAuthority: input.sourceTagAuthority,
      registrySecret: input.registrySecret,
      sourceTagSecret: input.sourceTagSecret,
    });
    let closed = false;
    return Object.freeze({
      kind: resolver.kind,
      resolve(value) {
        if (closed) fail('m4_paused_projection_identity_resolver_closed');
        return resolver.resolve(value);
      },
      close() {
        if (!closed) {
          closed = true;
          try { resolver.close(); }
          finally { reader.close(); }
        }
      },
    });
  } catch (error) {
    reader.close();
    throw error;
  }
}
function same(left, right) { return canonicalJson(left) === canonicalJson(right); }
function copiedKey(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) fail('m4_paused_projection_identity_resolver_invalid');
  return Buffer.from(value);
}

export function validateM4PausedProjectionIdentity(value) {
  if (!exact(value, ['schema', 'binding', 'runtime', 'sourceId', 'sourceKind', 'observationClass', 'authoritativeDeletion',
    'occurredAt', 'editedAt', 'legacy', 'routing', 'lifecycle']) || value.schema !== M4_PAUSED_PROJECTION_IDENTITY_SCHEMA
    || !RUNTIME.has(value.runtime) || typeof value.sourceId !== 'string' || !SOURCE_ID.test(value.sourceId)
    || value.sourceKind !== value.runtime || value.observationClass !== 'native' || typeof value.authoritativeDeletion !== 'boolean'
    || !isConversationEventUtcTimestamp(value.occurredAt) || !(value.editedAt === null || isConversationEventUtcTimestamp(value.editedAt))
    || !plain(value.legacy) || !exact(value.legacy, ['sessionId', 'eventId', 'priorEventId'])
    || !SESSION.test(value.legacy.sessionId) || !EVENT.test(value.legacy.eventId)
    || !(value.legacy.priorEventId === null || EVENT.test(value.legacy.priorEventId))
    || !plain(value.routing) || !exact(value.routing, ['role', 'direction', 'conversationKind', 'authorizationContextTags'])
    || !ROLES.has(value.routing.role) || !DIRECTIONS.has(value.routing.direction) || !KINDS.has(value.routing.conversationKind)
    || !plain(value.lifecycle) || !exact(value.lifecycle, ['change', 'nativeRevision'])
    || !['new', 'changed', 'deleted'].includes(value.lifecycle.change)
    || !(value.lifecycle.nativeRevision === null || (Number.isSafeInteger(value.lifecycle.nativeRevision) && value.lifecycle.nativeRevision >= 0))
    || (value.authoritativeDeletion !== (value.lifecycle.change === 'deleted'))
    || ((value.lifecycle.change === 'new') !== (value.legacy.priorEventId === null))) fail('m4_paused_projection_identity_invalid');
  let safeBinding; let context;
  try { safeBinding = binding(value.binding, 'm4_paused_projection_identity_invalid'); context = normalizeContextTags(value.routing.authorizationContextTags); }
  catch { fail('m4_paused_projection_identity_invalid'); }
  if (safeBinding.runtime !== value.runtime || safeBinding.sourceId !== value.sourceId) fail('m4_paused_projection_identity_invalid');
  return { schema: value.schema, binding: safeBinding, runtime: value.runtime, sourceId: value.sourceId,
    sourceKind: value.sourceKind, observationClass: value.observationClass, authoritativeDeletion: value.authoritativeDeletion,
    occurredAt: value.occurredAt, editedAt: value.editedAt,
    legacy: { ...value.legacy }, routing: { role: value.routing.role, direction: value.routing.direction,
      conversationKind: value.routing.conversationKind, authorizationContextTags: context },
    lifecycle: { ...value.lifecycle } };
}

export function createM4PausedProjectionIdentityResolver(input = {}) {
  if (!exact(input, ['registryAuthority', 'loadPage', 'loadPostCutoffEvent', 'sourceTagAuthority', 'registrySecret', 'sourceTagSecret'])
    || typeof input.loadPage !== 'function' || !(input.loadPostCutoffEvent === null || typeof input.loadPostCutoffEvent === 'function')) {
    fail('m4_paused_projection_identity_resolver_invalid');
  }
  const registrySecret = copiedKey(input.registrySecret); const sourceTagSecret = copiedKey(input.sourceTagSecret);
  if (registrySecret.equals(sourceTagSecret)) {
    registrySecret.fill(0); sourceTagSecret.fill(0);
    fail('m4_paused_projection_identity_resolver_invalid');
  }
  let registryResolver;
  try { registryResolver = createM4CrossPhaseIdentityResolver({ authority: input.registryAuthority,
    loadPage: input.loadPage, loadPostCutoffEvent: input.loadPostCutoffEvent }, registrySecret); }
  catch { registrySecret.fill(0); sourceTagSecret.fill(0); fail('m4_paused_projection_identity_resolver_invalid'); }
  let registryAuthority; let sourceTagAuthority;
  try { registryAuthority = structuredClone(input.registryAuthority); sourceTagAuthority = structuredClone(input.sourceTagAuthority); }
  catch { registrySecret.fill(0); sourceTagSecret.fill(0); fail('m4_paused_projection_identity_resolver_invalid'); }
  let sourceTagResolver;
  try { sourceTagResolver = createM4PausedSourceTagResolver({ authority: sourceTagAuthority,
    registryAuthority, registrySecret, sourceTagSecret }); }
  catch { registrySecret.fill(0); sourceTagSecret.fill(0); fail('m4_paused_projection_identity_resolver_invalid'); }
  let closed = false;
  return Object.freeze({
    kind: 'm4-paused-projection-identity-resolver-v1',
    resolve({ identity, attestation } = {}) {
      if (closed) fail('m4_paused_projection_identity_resolver_closed');
      const safeIdentity = validateM4PausedProjectionIdentity(identity);
      let safeAttestation;
      try { safeAttestation = binding(attestation, 'm4_paused_projection_identity_attestation_invalid'); }
      catch { fail('m4_paused_projection_identity_attestation_invalid'); }
      if (!same(safeIdentity.binding, safeAttestation)) fail('m4_paused_projection_identity_attestation_mismatch');
      let sourceTags;
      try { sourceTags = sourceTagResolver.resolve(safeAttestation); }
      catch (error) { if (error?.code) throw error; fail('m4_paused_projection_identity_authority_invalid'); }
      return registryResolver.resolveBinding({ legacyEventId: safeIdentity.legacy.eventId,
        legacySessionId: safeIdentity.legacy.sessionId, sourceTags,
        conversationKind: safeIdentity.routing.conversationKind,
        authorizationContextTags: safeIdentity.routing.authorizationContextTags,
        role: safeIdentity.routing.role, direction: safeIdentity.routing.direction,
        effectiveTimestamp: safeIdentity.editedAt ?? safeIdentity.occurredAt,
        priorLegacyEventId: safeIdentity.legacy.priorEventId });
    },
    close() {
      if (!closed) {
        closed = true;
        registrySecret.fill(0); sourceTagSecret.fill(0);
      }
    },
  });
}
