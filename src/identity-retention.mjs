import crypto from 'node:crypto';

const IDENTITY_KINDS = new Set(['agent', 'person', 'relationship', 'room', 'domain', 'shared']);
const RETENTION_STATES = new Set(['active', 'revoked', 'forgotten', 'expired']);
const EVIDENCE_PROOFS = Object.freeze({
  verified_account: ['provider', 'accountId', 'verificationId'],
  cryptographic_binding: ['algorithm', 'keyFingerprint', 'challengeHash', 'signature'],
  operator_attestation: ['ticketId', 'assertion'],
  weak_observation: ['observation']
});
const UTC_RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;

function fail(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  throw error;
}

function exactKeys(value, keys, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${name}_invalid`);
  for (const key of Object.keys(value)) if (!keys.has(key)) fail(`${name}_invalid`);
}

export function parseUtcRfc3339(value, errorCode = 'timestamp_invalid') {
  if (typeof value !== 'string') fail(errorCode);
  const match = UTC_RFC3339.exec(value);
  if (!match || match[1] === '0000') fail(errorCode);
  const [, year, month, day, hour, minute, second, fraction = ''] = match;
  const millis = Number(fraction.padEnd(3, '0'));
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), millis));
  if (date.getUTCFullYear() !== Number(year) || date.getUTCMonth() !== Number(month) - 1 || date.getUTCDate() !== Number(day) || date.getUTCHours() !== Number(hour) || date.getUTCMinutes() !== Number(minute) || date.getUTCSeconds() !== Number(second) || date.getUTCMilliseconds() !== millis) fail(errorCode);
  return date.toISOString();
}

function validateEvidence(evidence) {
  exactKeys(evidence, new Set(['type', 'issuer', 'observedAt', 'claims']), 'identity_evidence');
  const required = EVIDENCE_PROOFS[evidence.type];
  if (!required) fail('identity_evidence_type_invalid');
  if (typeof evidence.issuer !== 'string' || !evidence.issuer || evidence.issuer.length > 1024) fail('identity_evidence_invalid');
  const observedAt = parseUtcRfc3339(evidence.observedAt, 'identity_evidence_timestamp_invalid');
  exactKeys(evidence.claims, new Set(required), 'identity_evidence');
  for (const key of required) if (typeof evidence.claims[key] !== 'string' || !evidence.claims[key] || evidence.claims[key].length > 8192) fail('identity_evidence_invalid');
  return { ...evidence, observedAt, claims: { ...evidence.claims } };
}

export function validateIdentityCreate(input) {
  exactKeys(input, new Set(['kind', 'externalKey', 'scope', 'evidence', 'idempotencyKey']), 'identity');
  const kind = String(input.kind || '');
  const externalKey = String(input.externalKey || '');
  const scope = String(input.scope || '');
  const idempotencyKey = String(input.idempotencyKey || '');
  if (!IDENTITY_KINDS.has(kind)) fail('identity_kind_invalid');
  if (!externalKey || externalKey.length > 1024) fail('identity_external_key_invalid');
  if (!scope || scope.length > 1024) fail('identity_scope_invalid');
  if (!idempotencyKey || idempotencyKey.length > 200) fail('idempotency_key_required');
  return { kind, externalKey, scope, evidence: validateEvidence(input.evidence), idempotencyKey };
}

export function validateIdentityMutation(input, operation) {
  const allowed = operation === 'merge'
    ? new Set(['targetId', 'expectedRevision', 'evidence', 'automatic', 'idempotencyKey'])
    : new Set(['expectedRevision', 'evidence', 'idempotencyKey']);
  exactKeys(input, allowed, `identity_${operation}`);
  const expectedRevision = Number(input.expectedRevision);
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) fail('revision_invalid');
  const idempotencyKey = String(input.idempotencyKey || '');
  if (!idempotencyKey || idempotencyKey.length > 200) fail('idempotency_key_required');
  const evidence = validateEvidence(input.evidence);
  if (operation === 'merge') {
    const targetId = String(input.targetId || '');
    if (!targetId) fail('identity_target_required');
    if (typeof input.automatic !== 'boolean') fail('identity_evidence_strength_required');
    return { targetId, expectedRevision, evidence, automatic: input.automatic, idempotencyKey };
  }
  return { expectedRevision, evidence, idempotencyKey };
}

export function addCalendarYears(timestamp, years) {
  const date = new Date(parseUtcRfc3339(timestamp, 'original_timestamp_invalid'));
  const month = date.getUTCMonth();
  date.setUTCFullYear(date.getUTCFullYear() + years);
  // JavaScript rolls Feb 29 into March. Retention expires at the last valid day
  // of the same calendar month instead.
  if (date.getUTCMonth() !== month) date.setUTCDate(0);
  return date.toISOString();
}

export function retentionDeadline(originalTimestamp, scope, policy = {}) {
  const override = policy?.scopeDays?.[scope];
  if (override != null) {
    if (!Number.isSafeInteger(override) || override < 1 || override > 36500) fail('retention_scope_override_invalid', 500);
    const date = new Date(parseUtcRfc3339(originalTimestamp, 'original_timestamp_invalid'));
    date.setUTCDate(date.getUTCDate() + override);
    return date.toISOString();
  }
  return addCalendarYears(originalTimestamp, Number.isSafeInteger(policy.defaultYears) ? policy.defaultYears : 3);
}

export function validateRetentionAction(input, action) {
  const allowed = action === 'plan'
    ? new Set(['asOf', 'scope', 'limit'])
    : new Set(['candidateIds', 'expectedPlanAsOf', 'reason', 'idempotencyKey']);
  exactKeys(input, allowed, `retention_${action}`);
  if (action === 'plan') {
    const asOf = String(input.asOf || '');
    const normalizedAsOf = parseUtcRfc3339(asOf, 'retention_as_of_invalid');
    const limit = input.limit == null ? 100 : Number(input.limit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) fail('retention_limit_invalid');
    const scope = input.scope == null ? null : String(input.scope);
    if (scope != null && (!scope || scope.length > 1024)) fail('identity_scope_invalid');
    return { asOf: normalizedAsOf, scope, limit };
  }
  if (!Array.isArray(input.candidateIds) || input.candidateIds.length < 1 || input.candidateIds.length > 1000 || input.candidateIds.some(id => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))) fail('retention_candidates_invalid');
  const expectedPlanAsOf = parseUtcRfc3339(input.expectedPlanAsOf, 'retention_as_of_invalid');
  const reason = String(input.reason || '');
  if (!['retention_expired', 'revoked', 'forgotten'].includes(reason)) fail('retention_reason_invalid');
  const idempotencyKey = String(input.idempotencyKey || '');
  if (!idempotencyKey || idempotencyKey.length > 200) fail('idempotency_key_required');
  return { candidateIds: [...new Set(input.candidateIds)].sort(), expectedPlanAsOf, reason, idempotencyKey };
}

export function retentionTombstone({ id = crypto.randomUUID(), row, reason, createdAt }) {
  if (!RETENTION_STATES.has(reason === 'retention_expired' ? 'expired' : reason)) fail('retention_reason_invalid');
  return {
    id,
    contentId: row.contentId,
    contentChecksum: row.contentChecksum,
    sourcePointerTag: row.sourcePointerTag || null,
    reasonCode: reason,
    originalCreatedAt: row.originalCreatedAt,
    expiredAt: row.expiresAt,
    createdAt
  };
}

export { IDENTITY_KINDS };
