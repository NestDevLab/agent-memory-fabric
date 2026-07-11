import crypto from 'node:crypto';

// JSON transport adapter synchronized with PAM 0.6 amf-memory/v1 validation.
// PAM remains authoritative for file/workspace-only checks such as Markdown body
// rules, graph projection collisions, transitions and supersedes target lookup.

const RECORD_FIELDS = new Set(['schema', 'id', 'revision', 'claimType', 'scope', 'visibility', 'subjects', 'claim', 'lifecycle', 'provenance', 'createdAt', 'updatedAt']);
const CLAIM_TYPES = new Set(['fact', 'preference', 'event', 'decision', 'instruction', 'summary', 'relationship']);
const SCOPE_TYPES = new Set(['agent', 'person', 'relationship', 'room', 'domain', 'shared']);
const VISIBILITIES = new Set(['private', 'restricted', 'shared', 'confidential']);
const SUBJECT_ROLES = new Set(['subject', 'object', 'participant', 'owner']);
const LIFECYCLE_STATUSES = new Set(['active', 'superseded', 'revoked', 'expired']);
const CLAIM_FIELDS = { plain: new Set(['encoding', 'text']), sealed: new Set(['encoding', 'alg', 'kekId', 'keyRef', 'iv', 'ciphertext', 'tag', 'aadSha256']) };
const LIFECYCLE_FIELDS = new Set(['status', 'validFrom', 'validTo', 'supersedes', 'revokedAt', 'revocationReason']);
const PROVENANCE_FIELDS = new Set(['sourceType', 'sourceId', 'eventId', 'contentSha256', 'capturedAt']);
const SUBJECT_FIELDS = new Set(['identityId', 'role']);
const MEMORY_ID_RE = /^mem_[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/;
const OPAQUE_REF_RE = /^(?:agent|person|relationship|room|domain):[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/;
const HASH_RE = /^[0-9a-f]{64}$/i;
const TYPE_RE = /^[a-z][a-z0-9_-]{0,31}:[a-z][a-z0-9._-]{0,63}$/;
const RFC3339_UTC_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function aadObjectFor(record) {
  const aad = { schema: record.schema, id: record.id, revision: record.revision, claimType: record.claimType, scope: record.scope, visibility: record.visibility, subjects: record.subjects };
  if (record.claim?.encoding === 'sealed') aad.envelope = { alg: record.claim.alg, kekId: record.claim.kekId, keyRef: record.claim.keyRef };
  return aad;
}

function aadSha256For(record) {
  return crypto.createHash('sha256').update(canonicalize(aadObjectFor(record)), 'utf8').digest('hex');
}

function isRfc3339Utc(value) {
  if (typeof value !== 'string') return false;
  const match = RFC3339_UTC_RE.exec(value);
  if (!match) return false;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return false;
  const date = new Date(timestamp);
  return date.getUTCFullYear() === Number(match[1]) && date.getUTCMonth() + 1 === Number(match[2]) && date.getUTCDate() === Number(match[3])
    && date.getUTCHours() === Number(match[4]) && date.getUTCMinutes() === Number(match[5]) && date.getUTCSeconds() === Number(match[6]);
}

function exactObject(value, label, fields, errors) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { errors.push(`${label} must be an object`); return false; }
  for (const key of Object.keys(value)) if (!fields.has(key)) errors.push(`${label} contains unknown field: ${key}`);
  for (const key of fields) if (!Object.hasOwn(value, key)) errors.push(`${label} is missing field: ${key}`);
  return true;
}

function decodeBase64(value, label, errors) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) { errors.push(`${label} must be non-empty base64`); return null; }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64url') !== value.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')) { errors.push(`${label} must be canonical base64 or base64url`); return null; }
  return decoded;
}

function isScopeId(type, id) {
  if (type === 'shared') return id === 'shared:global';
  return typeof id === 'string' && id.startsWith(`${type}:`) && OPAQUE_REF_RE.test(id);
}

function validateAmfMemoryRecord(record) {
  const errors = [];
  if (!exactObject(record, 'record', RECORD_FIELDS, errors)) return { ok: false, errors };
  if (record.schema !== 'amf-memory/v1') errors.push('schema must be amf-memory/v1');
  if (!MEMORY_ID_RE.test(String(record.id ?? ''))) errors.push('id must be an opaque mem_<id>');
  if (!Number.isInteger(record.revision) || record.revision < 1) errors.push('revision must be a positive integer');
  if (!CLAIM_TYPES.has(record.claimType) && !TYPE_RE.test(String(record.claimType ?? ''))) errors.push('claimType is invalid');
  if (exactObject(record.scope, 'scope', new Set(['type', 'id']), errors)) {
    if (!SCOPE_TYPES.has(record.scope.type)) errors.push('scope.type is invalid');
    if (!isScopeId(record.scope.type, record.scope.id)) errors.push('scope.id must be canonical and match scope.type');
  }
  if (!VISIBILITIES.has(record.visibility)) errors.push('visibility is invalid');

  if (!Array.isArray(record.subjects) || record.subjects.length === 0) errors.push('subjects must be a non-empty array');
  else {
    const seen = new Set();
    record.subjects.forEach((subject, index) => {
      if (!exactObject(subject, `subjects[${index}]`, SUBJECT_FIELDS, errors)) return;
      if (!/^(?:agent|person|relationship):/.test(String(subject.identityId ?? '')) || !OPAQUE_REF_RE.test(subject.identityId)) errors.push(`subjects[${index}].identityId must be an opaque canonical identity`);
      if (!SUBJECT_ROLES.has(subject.role)) errors.push(`subjects[${index}].role is invalid`);
      const key = `${subject.identityId}\0${subject.role}`; if (seen.has(key)) errors.push('subjects must not contain duplicates'); seen.add(key);
    });
  }

  const claimFields = CLAIM_FIELDS[record.claim?.encoding];
  if (!claimFields) errors.push('claim.encoding must be plain or sealed');
  else {
    exactObject(record.claim, 'claim', claimFields, errors);
    const subjectRequiresSealing = Array.isArray(record.subjects) && record.subjects.some(subject => /^(?:person|relationship):/.test(String(subject?.identityId ?? '')));
    const mustSeal = ['person', 'relationship'].includes(record.scope?.type) || record.claimType === 'relationship' || ['confidential', 'restricted'].includes(record.visibility) || subjectRequiresSealing;
    if (mustSeal && record.claim.encoding !== 'sealed') errors.push('record requires a sealed claim');
    if (record.claim.encoding === 'plain' && (typeof record.claim.text !== 'string' || !record.claim.text.trim())) errors.push('plain claim.text must not be empty');
    if (record.claim.encoding === 'sealed') {
      if (record.claim.alg !== 'AES-256-GCM') errors.push('sealed claim.alg must be AES-256-GCM');
      if (!/^kek:[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(String(record.claim.kekId ?? ''))) errors.push('sealed claim.kekId is invalid');
      if (!/^key:[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(String(record.claim.keyRef ?? ''))) errors.push('sealed claim.keyRef is invalid');
      const iv = decodeBase64(record.claim.iv, 'sealed claim.iv', errors); const ciphertext = decodeBase64(record.claim.ciphertext, 'sealed claim.ciphertext', errors); const tag = decodeBase64(record.claim.tag, 'sealed claim.tag', errors);
      if (iv && iv.length !== 12) errors.push('sealed claim.iv must decode to 12 bytes');
      if (ciphertext && ciphertext.length === 0) errors.push('sealed claim.ciphertext must not be empty');
      if (tag && tag.length !== 16) errors.push('sealed claim.tag must decode to 16 bytes');
      if (!HASH_RE.test(String(record.claim.aadSha256 ?? ''))) errors.push('sealed claim.aadSha256 must be a SHA-256 digest');
      else if (record.claim.aadSha256.toLowerCase() !== aadSha256For(record)) errors.push('sealed claim.aadSha256 must match canonical AAD');
    }
  }

  if (exactObject(record.lifecycle, 'lifecycle', LIFECYCLE_FIELDS, errors)) {
    const lifecycle = record.lifecycle;
    if (!LIFECYCLE_STATUSES.has(lifecycle.status)) errors.push('lifecycle.status is invalid');
    for (const key of ['validFrom', 'validTo', 'revokedAt']) if (lifecycle[key] !== null && !isRfc3339Utc(lifecycle[key])) errors.push(`lifecycle.${key} must be null or RFC 3339 UTC`);
    if (!Array.isArray(lifecycle.supersedes)) errors.push('lifecycle.supersedes must be an array');
    else if (lifecycle.supersedes.some(id => !MEMORY_ID_RE.test(String(id)))) errors.push('lifecycle.supersedes contains an invalid memory id');
    if (Array.isArray(lifecycle.supersedes) && (lifecycle.supersedes.includes(record.id) || new Set(lifecycle.supersedes).size !== lifecycle.supersedes.length)) errors.push('lifecycle.supersedes is invalid');
    if (lifecycle.revocationReason !== null && (typeof lifecycle.revocationReason !== 'string' || !lifecycle.revocationReason.trim() || lifecycle.revocationReason.length > 512)) errors.push('lifecycle.revocationReason is invalid');
    if (lifecycle.status === 'revoked' && (!isRfc3339Utc(lifecycle.revokedAt) || typeof lifecycle.revocationReason !== 'string' || !lifecycle.revocationReason.trim())) errors.push('revoked lifecycle requires revokedAt and revocationReason');
    if (lifecycle.status !== 'revoked' && (lifecycle.revokedAt !== null || lifecycle.revocationReason !== null)) errors.push('only revoked lifecycle may set revocation fields');
    if (lifecycle.status === 'expired' && !isRfc3339Utc(lifecycle.validTo)) errors.push('expired lifecycle requires validTo');
    if (isRfc3339Utc(lifecycle.validFrom) && isRfc3339Utc(lifecycle.validTo) && Date.parse(lifecycle.validTo) < Date.parse(lifecycle.validFrom)) errors.push('lifecycle.validTo must not be earlier than validFrom');
    if (lifecycle.status === 'expired' && isRfc3339Utc(lifecycle.validTo) && isRfc3339Utc(record.updatedAt) && Date.parse(lifecycle.validTo) > Date.parse(record.updatedAt)) errors.push('expired lifecycle.validTo must not be later than updatedAt');
    if (lifecycle.status === 'revoked' && isRfc3339Utc(lifecycle.revokedAt) && isRfc3339Utc(record.updatedAt) && Date.parse(lifecycle.revokedAt) > Date.parse(record.updatedAt)) errors.push('lifecycle.revokedAt must not be later than updatedAt');
  }

  if (!Array.isArray(record.provenance) || record.provenance.length === 0) errors.push('provenance must be a non-empty array');
  else {
    const events = new Set(); let previous = -Infinity;
    record.provenance.forEach((item, index) => {
      if (!exactObject(item, `provenance[${index}]`, PROVENANCE_FIELDS, errors)) return;
      if (!/^[a-z][a-z0-9._-]{1,63}$/.test(String(item.sourceType ?? ''))) errors.push(`provenance[${index}].sourceType is invalid`);
      if (typeof item.sourceId !== 'string' || item.sourceId.length < 1 || item.sourceId.length > 256) errors.push(`provenance[${index}].sourceId is invalid`);
      if (typeof item.eventId !== 'string' || item.eventId.length < 8 || item.eventId.length > 256 || events.has(item.eventId)) errors.push(`provenance[${index}].eventId is invalid`); events.add(item.eventId);
      if (!HASH_RE.test(String(item.contentSha256 ?? ''))) errors.push(`provenance[${index}].contentSha256 is invalid`);
      if (!isRfc3339Utc(item.capturedAt)) errors.push(`provenance[${index}].capturedAt is invalid`);
      else { const captured = Date.parse(item.capturedAt); if (captured < previous || (isRfc3339Utc(record.updatedAt) && captured > Date.parse(record.updatedAt))) errors.push('provenance timestamp ordering is invalid'); previous = captured; }
    });
  }

  if (!isRfc3339Utc(record.createdAt) || !isRfc3339Utc(record.updatedAt)) errors.push('createdAt and updatedAt must be RFC 3339 UTC');
  else if (Date.parse(record.updatedAt) < Date.parse(record.createdAt) || (record.revision === 1 && record.createdAt !== record.updatedAt)) errors.push('record timestamps are inconsistent with revision');
  return { ok: errors.length === 0, errors };
}

export { aadSha256For, canonicalize, validateAmfMemoryRecord };
