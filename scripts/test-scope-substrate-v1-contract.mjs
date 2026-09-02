import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const schema = JSON.parse(fs.readFileSync(new URL('../config/contracts/amf.scope-substrate-v1.schema.json', import.meta.url), 'utf8'));
const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/scope-substrate-v1.conformance.json', import.meta.url), 'utf8'));
const document = fs.readFileSync(new URL('../docs/scope-substrate-v1.md', import.meta.url), 'utf8');
const SUPPORTED = new Set(['$schema', '$id', '$defs', 'title', 'type', 'additionalProperties', 'required', 'properties', 'const', 'pattern', 'minItems', 'maxItems', 'uniqueItems', 'items', '$ref']);

function assertKeywords(rule) {
  for (const key of Object.keys(rule)) assert.ok(SUPPORTED.has(key), `unsupported schema keyword: ${key}`);
  for (const child of Object.values(rule.$defs || {})) assertKeywords(child);
  for (const child of Object.values(rule.properties || {})) assertKeywords(child);
  if (rule.items) assertKeywords(rule.items);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function resolve(ref) {
  return ref.split('/').slice(1).reduce((value, key) => value[key], schema);
}

function validate(value, rule = schema) {
  if (rule.$ref) return validate(value, resolve(rule.$ref));
  const errors = [];
  if (rule.const !== undefined && value !== rule.const) errors.push('const');
  if (rule.type === 'object' && (!value || typeof value !== 'object' || Array.isArray(value))) return [...errors, 'type'];
  if (rule.type === 'array' && !Array.isArray(value)) return [...errors, 'type'];
  if (rule.type === 'string' && typeof value !== 'string') return [...errors, 'type'];
  if (typeof value === 'string' && rule.pattern && !(new RegExp(rule.pattern).test(value))) errors.push('pattern');
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) errors.push('minItems');
    if (rule.maxItems !== undefined && value.length > rule.maxItems) errors.push('maxItems');
    if (rule.uniqueItems && new Set(value.map(canonical)).size !== value.length) errors.push('uniqueItems');
    if (rule.items) value.forEach(item => errors.push(...validate(item, rule.items)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of rule.required || []) if (!Object.hasOwn(value, key)) errors.push('required');
    if (rule.additionalProperties === false) for (const key of Object.keys(value)) if (!Object.hasOwn(rule.properties || {}, key)) errors.push('additionalProperties');
    for (const [key, child] of Object.entries(rule.properties || {})) if (Object.hasOwn(value, key)) errors.push(...validate(value[key], child));
  }
  return errors;
}

function scopeKey(scope) {
  return `${scope.tenantId}\0${scope.scopeId}`;
}

function semanticErrors(manifest) {
  const errors = [];
  const scopes = new Set();
  for (const scope of manifest.scopes || []) {
    const key = scopeKey(scope);
    if (scopes.has(key)) errors.push('ambiguous_scope_identity');
    scopes.add(key);
  }
  for (const relation of manifest.relations || []) {
    if (relation.from.tenantId !== relation.to.tenantId) errors.push('cross_tenant_relation');
    if (!scopes.has(scopeKey(relation.from)) || !scopes.has(scopeKey(relation.to))) errors.push('unknown_relation_scope');
  }
  const memberships = new Set();
  for (const membership of manifest.resourceMemberships || []) {
    if (membership.resource.tenantId !== membership.scope.tenantId) errors.push('cross_tenant_membership');
    if (!scopes.has(scopeKey(membership.scope))) errors.push('unknown_membership_scope');
    const key = `${membership.resource.tenantId}\0${membership.resource.resourceId}\0${scopeKey(membership.scope)}`;
    if (memberships.has(key)) errors.push('duplicate_resource_membership');
    memberships.add(key);
  }
  return errors;
}

function validateContract(manifest) {
  return [...validate(manifest), ...semanticErrors(manifest)];
}

function clone() {
  return structuredClone(fixtures);
}

test('bounded schema validates the fixture and only uses supported keywords', () => {
  assertKeywords(schema);
  assert.deepEqual(validate(fixtures), []);
  assert.deepEqual(validateContract(fixtures), []);
});

test('ScopeRef is an object with tenantId, type, and a complete non-wildcard scopeId', () => {
  for (const scope of fixtures.scopes) assert.deepEqual(validate(scope, schema.$defs.scopeRef), []);
  const missingTenant = clone();
  delete missingTenant.scopes[0].tenantId;
  assert.ok(validate(missingTenant).includes('required'));
  const nakedString = clone();
  nakedString.scopes[0] = 'tenant_alpha:atlas';
  assert.ok(validate(nakedString).includes('type'));
  const wildcard = clone();
  wildcard.scopes[0].scopeId = '*';
  assert.ok(validate(wildcard).includes('pattern'));
  const prefix = clone();
  prefix.scopes[0].scopeId = 'project:atlas';
  assert.ok(validate(prefix).includes('pattern'));
});

test('scope identity is tenantId plus scopeId, so competing type aliases are rejected', () => {
  const ambiguous = clone();
  ambiguous.scopes.push({ tenantId: 'tenant_alpha', type: 'workspace', scopeId: 'atlas' });
  assert.deepEqual(validate(ambiguous), []);
  assert.deepEqual(validateContract(ambiguous), ['ambiguous_scope_identity']);
});

test('relations are optional, tenant-local declarations with asserted provenance only', () => {
  const noRelations = clone();
  delete noRelations.relations;
  assert.deepEqual(validate(noRelations), []);
  assert.deepEqual(validateContract(noRelations), []);
  const crossTenant = clone();
  crossTenant.relations[0].to.tenantId = 'tenant_beta';
  assert.deepEqual(validate(crossTenant), []);
  assert.deepEqual(validateContract(crossTenant), ['cross_tenant_relation', 'unknown_relation_scope']);
  const missingAssertion = clone();
  delete missingAssertion.relations[0].provenance.assertion;
  assert.ok(validateContract(missingAssertion).includes('required'));
  const missingMembershipAssertion = clone();
  delete missingMembershipAssertion.resourceMemberships[0].provenance.assertion;
  assert.ok(validateContract(missingMembershipAssertion).includes('required'));
  const grant = clone();
  grant.relations[0].permission = 'fabric:read';
  assert.ok(validate(grant).includes('additionalProperties'));
});

test('resource memberships are tenant-local N:M declarations with provenance only', () => {
  assert.equal(fixtures.resourceMemberships.filter(row => row.resource.resourceId === 'record-alpha').length, 2);
  assert.equal(fixtures.resourceMemberships.filter(row => row.scope.scopeId === 'atlas').length, 2);
  const crossTenant = clone();
  crossTenant.resourceMemberships[0].resource.tenantId = 'tenant_beta';
  assert.deepEqual(validate(crossTenant), []);
  assert.deepEqual(validateContract(crossTenant), ['cross_tenant_membership']);
  const grant = clone();
  grant.resourceMemberships[0].role = 'reader';
  assert.ok(validate(grant).includes('additionalProperties'));
  const duplicate = clone();
  duplicate.resourceMemberships.push(structuredClone(duplicate.resourceMemberships[0]));
  assert.ok(validate(duplicate).includes('uniqueItems'));
  assert.ok(validateContract(duplicate).includes('duplicate_resource_membership'));
});

test('published schema and contract validation retain explicit provenance and cross-row rejections', () => {
  for (const phrase of ['required assertion', 'duplicate logical scope identities with competing types', 'cross-tenant relations', 'cross-tenant memberships', 'explicit contract validation']) assert.match(document, new RegExp(phrase.replace(/ /g, '\\s+'), 'i'));
  const competingType = clone();
  competingType.scopes.push({ tenantId: 'tenant_alpha', type: 'workspace', scopeId: 'atlas' });
  assert.deepEqual(validate(competingType), []);
  assert.ok(validateContract(competingType).includes('ambiguous_scope_identity'));
  const crossRelation = clone();
  crossRelation.relations[0].to.tenantId = 'tenant_beta';
  assert.ok(validateContract(crossRelation).includes('cross_tenant_relation'));
  const crossMembership = clone();
  crossMembership.resourceMemberships[0].resource.tenantId = 'tenant_beta';
  assert.ok(validateContract(crossMembership).includes('cross_tenant_membership'));
});
