const TENANT_ID = /^[a-z][a-z0-9_-]{2,63}$/;
const SCOPE_TYPE = /^[a-z][a-z0-9_-]{2,63}$/;
const SCOPE_ID = /^[a-z][a-z0-9._-]{2,127}$/;
const EVIDENCE_ID = /^evidence-[a-z0-9-]{3,79}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

// ScopeRef is intentionally strict: callers must bring a reviewed value, not
// a string which this module could parse, trim, prefix-match, or infer.
export function normalizeScopeRef(value) {
  if (!exact(value, ['tenantId', 'type', 'scopeId'])
    || !TENANT_ID.test(value.tenantId) || !SCOPE_TYPE.test(value.type)
    || !SCOPE_ID.test(value.scopeId)) throw new Error('scope_ref_invalid');
  return { tenantId: value.tenantId, type: value.type, scopeId: value.scopeId };
}

export function scopeRefIdentity(value) {
  const scope = normalizeScopeRef(value);
  return `${scope.tenantId}\0${scope.scopeId}`;
}

export function sameScopeRef(left, right) {
  return scopeRefIdentity(left) === scopeRefIdentity(right);
}

// B1.3 mapping evidence is deliberately a small immutable reference.  Its
// content is owned by the reviewed mapping inventory, not reconstructed here.
export function normalizeMappingEvidence(value) {
  if (!exact(value, ['id', 'digest']) || !EVIDENCE_ID.test(value.id) || !DIGEST.test(value.digest)) {
    throw new Error('scope_mapping_evidence_invalid');
  }
  return { id: value.id, digest: value.digest };
}
