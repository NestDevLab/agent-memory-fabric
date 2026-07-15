import crypto from 'node:crypto';

import { provisionScopedConsumer } from './recall-consumer-provisioning.mjs';

export const INTERACTIVE_RECALL_HANDOFF_SCHEMA = 'amf.interactive-recall-handoff/v1';
export const INTERACTIVE_RECALL_PERMISSIONS = Object.freeze([
  'memory:search',
  'memory:read',
  'purpose:conversation_recall'
]);
export const INTERACTIVE_RECALL_SCOPES = Object.freeze(['shared:global']);
export const INTERACTIVE_RECALL_PROFILE_NAMES = Object.freeze(['codex', 'claude']);

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const OPTION_KEYS = new Set([
  'profile', 'authRegistryPath', 'policyPath', 'contextKeyRingPath', 'handoffPath', 'backupRoot',
  'backendUserId', 'serviceOwnerUid', 'policyRevision', 'endpoint', 'dryRun', 'clock', 'randomBytes', 'faultAt'
]);

function fail(code) { throw new Error(code); }

function fixedSessionDescriptor(profile) {
  const digest = crypto.createHash('sha256').update(`amf-interactive-recall:${profile}`, 'utf8').digest('hex');
  return Object.freeze({ conversationKind: 'session', contextTags: Object.freeze({
    conversation: Object.freeze([`hmac-sha256:amf-interactive-recall-v1:${digest}`])
  }) });
}

const PROFILES = Object.freeze({
  codex: Object.freeze({
    actor: 'agent:codex',
    contextKeyVersion: 'ctx-codex-v1',
    runtime: 'codex',
    profile: 'interactive-recall',
    sessionDescriptor: fixedSessionDescriptor('codex')
  }),
  claude: Object.freeze({
    actor: 'agent:claude',
    contextKeyVersion: 'ctx-claude-v1',
    runtime: 'claude',
    profile: 'interactive-recall',
    sessionDescriptor: fixedSessionDescriptor('claude')
  })
});

export function normalizeInteractiveRecallEndpoint(value) {
  if (typeof value !== 'string') fail('interactive_recall_endpoint_invalid');
  let endpoint;
  try { endpoint = new URL(value); } catch { fail('interactive_recall_endpoint_invalid'); }
  if (endpoint.protocol !== 'https:' || !endpoint.hostname || endpoint.username || endpoint.password
    || endpoint.hash || endpoint.search || endpoint.pathname !== '/') {
    fail('interactive_recall_endpoint_invalid');
  }
  return endpoint.toString();
}

function cloneSessionDescriptor(value) {
  return {
    conversationKind: value.conversationKind,
    contextTags: Object.fromEntries(Object.entries(value.contextTags).map(([key, tags]) => [key, [...tags]]))
  };
}

export function interactiveRecallProfile(profileName) {
  if (!INTERACTIVE_RECALL_PROFILE_NAMES.includes(profileName)) fail('interactive_recall_profile_invalid');
  const profile = PROFILES[profileName];
  return {
    actor: profile.actor,
    contextKeyVersion: profile.contextKeyVersion,
    runtime: profile.runtime,
    profile: profile.profile,
    sessionDescriptor: cloneSessionDescriptor(profile.sessionDescriptor),
    permissions: [...INTERACTIVE_RECALL_PERMISSIONS],
    scopes: [...INTERACTIVE_RECALL_SCOPES],
    sessionOwnerActors: [],
    allowedVaults: null,
    mode: 'read_only_scoped',
    purpose: 'conversation_recall',
    handoffSchema: INTERACTIVE_RECALL_HANDOFF_SCHEMA,
    backupSlug: `interactive-recall-${profileName}`
  };
}

export function provisionInteractiveRecall(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('interactive_recall_option_invalid');
  if (Object.keys(options).some(key => !OPTION_KEYS.has(key))) fail('interactive_recall_option_unknown');
  if (typeof options.policyRevision !== 'string' || !SAFE_ID.test(options.policyRevision)) {
    fail('interactive_recall_policy_revision_invalid');
  }
  const profile = interactiveRecallProfile(options.profile);
  return provisionScopedConsumer(options, {
    ...profile,
    policyRevision: options.policyRevision,
    endpoint: normalizeInteractiveRecallEndpoint(options.endpoint)
  });
}
