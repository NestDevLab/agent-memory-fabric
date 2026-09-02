import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

const schemaPath = new URL('../config/contracts/amf.scope-migration-plan-v1.schema.json', import.meta.url);
const fixturePath = new URL('./fixtures/scope-migration-v1.conformance.json', import.meta.url);
const vectorPath = new URL('./fixtures/scope-migration-v1-jcs-vectors.json', import.meta.url);
const documentPath = new URL('../docs/scope-migration-v1.md', import.meta.url);
const testPath = new URL('./test-scope-migration-v1-contract.mjs', import.meta.url);
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
const fixtures = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
const document = fs.readFileSync(documentPath, 'utf8');
const EXPECTED_DIGEST = 'sha256:078077e81b5d5b5e1eb6ceaa6c64c41fe44b9b97f5266104190f62e3e6903306';
const SUPPORTED = new Set(['$schema', '$id', '$defs', 'title', 'description', 'type', 'additionalProperties', 'required', 'properties', 'const', 'enum', 'pattern', 'minLength', 'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'items', '$ref', 'oneOf', 'anyOf', 'not']);

function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index += 1) {
      const code = value.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff && value.charCodeAt(index + 1) >= 0xdc00 && value.charCodeAt(index + 1) <= 0xdfff) { index += 1; continue; }
      if (code >= 0xd800 && code <= 0xdfff) throw new TypeError('canonical JSON string contains an unpaired surrogate');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('canonical JSON number is outside the safe-integer digest domain');
    return JSON.stringify(value);
  }
  if (value === undefined || typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol') throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) if (!Object.hasOwn(value, index)) throw new TypeError('canonical JSON array is sparse');
    return `[${value.map(canonical).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError('unsupported canonical JSON object type');
    return `{${Object.keys(value).sort((left, right) => {
    const length = Math.min(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
      const difference = left.charCodeAt(index) - right.charCodeAt(index);
      if (difference) return difference;
    }
    return left.length - right.length;
    }).map(key => `${canonical(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}

function assertSupported(rule) {
  for (const key of Object.keys(rule)) assert.ok(SUPPORTED.has(key), `unsupported schema keyword: ${key}`);
  for (const child of Object.values(rule.$defs || {})) assertSupported(child);
  for (const child of Object.values(rule.properties || {})) assertSupported(child);
  if (rule.items && rule.items !== false) assertSupported(rule.items);
  for (const child of rule.oneOf || []) assertSupported(child);
  for (const child of rule.anyOf || []) assertSupported(child);
  if (rule.not) assertSupported(rule.not);
}

function resolve(ref) {
  return ref.split('/').slice(1).reduce((value, key) => value[key], schema);
}

function typeMatches(value, type) {
  return ({ object: value && typeof value === 'object' && !Array.isArray(value), array: Array.isArray(value), string: typeof value === 'string', integer: Number.isInteger(value), number: typeof value === 'number' && Number.isFinite(value), boolean: typeof value === 'boolean', null: value === null })[type];
}

function validate(value, rule = schema) {
  if (rule.$ref) return validate(value, resolve(rule.$ref));
  const errors = [];
  if (rule.const !== undefined && !Object.is(value, rule.const)) errors.push('const');
  if (rule.enum && !rule.enum.some(item => Object.is(item, value))) errors.push('enum');
  if (rule.type && !typeMatches(value, rule.type)) return [...errors, 'type'];
  if (typeof value === 'string') {
    if (rule.minLength !== undefined && [...value].length < rule.minLength) errors.push('minLength');
    if (rule.maxLength !== undefined && [...value].length > rule.maxLength) errors.push('maxLength');
    if (rule.pattern && !(new RegExp(rule.pattern).test(value))) errors.push('pattern');
  }
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) errors.push('minItems');
    if (rule.maxItems !== undefined && value.length > rule.maxItems) errors.push('maxItems');
    if (rule.uniqueItems && new Set(value.map(canonical)).size !== value.length) errors.push('uniqueItems');
    if (rule.items === false && value.length) errors.push('items');
    if (rule.items && rule.items !== false) value.forEach(item => errors.push(...validate(item, rule.items)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of rule.required || []) if (!Object.hasOwn(value, key)) errors.push('required');
    if (rule.additionalProperties === false) for (const key of Object.keys(value)) if (!Object.hasOwn(rule.properties || {}, key)) errors.push('additionalProperties');
    for (const [key, child] of Object.entries(rule.properties || {})) if (Object.hasOwn(value, key)) errors.push(...validate(value[key], child));
  }
  if (rule.not && !validate(value, rule.not).length) errors.push('not');
  if (rule.anyOf && !rule.anyOf.some(branch => !validate(value, branch).length)) errors.push('anyOf');
  if (rule.oneOf && rule.oneOf.filter(branch => !validate(value, branch).length).length !== 1) errors.push('oneOf');
  return errors;
}

function scopeKey(scope) {
  return `${scope.tenantId}\0${scope.scopeId}`;
}

function exactScopeKey(scope) {
  return `${scopeKey(scope)}\0${scope.type}`;
}

function semanticErrors(manifest) {
  const errors = [];
  const tenants = new Set(manifest.knownTenants || []);
  const scopes = new Set();
  const exactScopes = new Set();
  for (const scope of manifest.canonicalScopes || []) {
    if (!tenants.has(scope.tenantId)) errors.push('scope_unknown_tenant');
    const key = scopeKey(scope);
    if (scopes.has(key)) errors.push('ambiguous_scope_identity');
    scopes.add(key);
    exactScopes.add(exactScopeKey(scope));
  }
  const values = manifest.legacyValues || [];
  const valuesById = new Map();
  for (const value of values) {
    if (valuesById.has(value.id)) errors.push('duplicate_legacy_id');
    valuesById.set(value.id, value);
    for (const candidate of value.observedCandidates || []) if (!exactScopes.has(exactScopeKey(candidate))) errors.push('unknown_observed_candidate');
  }
  const rows = new Map();
  for (const row of manifest.plan || []) {
    if (!valuesById.has(row.legacyId)) errors.push('unknown_plan_legacy_id');
    if (rows.has(row.legacyId)) errors.push('duplicate_plan_legacy_id');
    rows.set(row.legacyId, row);
    if (row.disposition === 'map' && !exactScopes.has(exactScopeKey(row.target))) errors.push('map_target_not_in_catalogue');
  }
  for (const legacyId of valuesById.keys()) if (!rows.has(legacyId)) errors.push('unplanned_legacy_value');
  if (rows.size !== valuesById.size) errors.push('plan_inventory_count_mismatch');
  for (const value of values) {
    const row = rows.get(value.id);
    if (!row) continue;
    const parts = value.value.split(':');
    const repeated = values.filter(item => item.value === value.value);
    const expected = value.value.startsWith('opaque_') ? 'stale-opaque-reference'
      : value.value.includes('*') ? 'wildcard'
      : (value.observedCandidates || []).length > 1 ? 'collision'
      : repeated.length > 1 && repeated[0].id !== value.id ? 'duplicate'
      : !value.value.includes(':') ? 'naked'
      : parts.length === 2 && !tenants.has(parts[0]) ? 'unknown-tenant'
      : parts.length === 2 ? 'two-segment'
      : parts[0].startsWith('owner_') ? 'owner-first'
      : ['organization', 'project', 'team', 'workspace'].includes(parts[0]) ? 'type-first'
      : 'prefix';
    if (row.classification !== expected) errors.push(`classification_mismatch:${value.id}`);
    if (row.disposition === 'map') {
      if (!row.mappingEvidence) errors.push('map_without_explicit_evidence');
      if (!exactScopeKey(row.target)) errors.push('invalid_map_target');
    }
    if (row.classification === 'collision' && (value.observedCandidates || []).length < 2) errors.push('collision_without_candidates');
  }
  if ((manifest.writeOperations || []).length !== 0) errors.push('dry_run_has_writes');
  return errors;
}

function dryRun(manifest) {
  const compareUtf8 = (left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
  const compareCanonical = (left, right) => compareUtf8(canonical(left), canonical(right));
  const inventory = manifest.legacyValues.map(value => ({ ...value, ...(value.observedCandidates ? { observedCandidates: value.observedCandidates.map(candidate => ({ ...candidate })).sort(compareCanonical) } : {}) })).sort((left, right) => compareUtf8(left.id, right.id));
  const rows = manifest.plan.map(row => ({ ...row })).sort((left, right) => compareUtf8(left.legacyId, right.legacyId));
  const projection = { schema: 'amf.scope-migration-dry-run/v1', mode: manifest.mode, authorityEvidence: { ...manifest.authorityEvidence }, knownTenants: [...manifest.knownTenants].sort(), canonicalScopes: manifest.canonicalScopes.map(scope => ({ ...scope })).sort(compareCanonical), inventory, plan: rows, writeOperations: [] };
  return { projection, digest: `sha256:${crypto.createHash('sha256').update(Buffer.from(canonical(projection), 'utf8')).digest('hex')}` };
}

function clone() {
  return structuredClone(fixtures);
}

test('bounded evaluator covers every published keyword and validates the fixture', () => {
  assertSupported(schema);
  assert.deepEqual(validate(fixtures), []);
  assert.deepEqual(semanticErrors(fixtures), []);
});

test('every legacy representation is classified once and has exactly one fail-closed disposition', () => {
  const expected = ['naked', 'two-segment', 'owner-first', 'type-first', 'prefix', 'wildcard', 'duplicate', 'unknown-tenant', 'collision', 'stale-opaque-reference'];
  assert.deepEqual(fixtures.plan.map(row => row.classification).sort(), expected.slice().sort());
  assert.equal(fixtures.plan.length, fixtures.legacyValues.length);
  assert.deepEqual(new Set(fixtures.plan.map(row => row.legacyId)).size, fixtures.legacyValues.length);
  for (const row of fixtures.plan) assert.ok(['map', 'block', 'expire-and-reissue'].includes(row.disposition));
  assert.deepEqual(new Set(fixtures.legacyValues.map(row => row.kind)), new Set(['scope', 'grant', 'bundle', 'record', 'route', 'cursor']));
});

test('maps require a reviewed catalogue target while blocks and reissues carry no implicit target', () => {
  const catalogue = new Set(fixtures.canonicalScopes.map(exactScopeKey));
  for (const row of fixtures.plan) {
    if (row.disposition === 'map') {
      assert.ok(catalogue.has(exactScopeKey(row.target)), row.legacyId);
      assert.ok(row.mappingEvidence?.id && row.mappingEvidence?.digest, row.legacyId);
    } else assert.equal(Object.hasOwn(row, 'target'), false, row.legacyId);
  }
  const noEvidence = clone();
  delete noEvidence.plan.find(row => row.disposition === 'map').mappingEvidence;
  assert.ok(validate(noEvidence).includes('oneOf'));
  const inferredTenant = clone();
  inferredTenant.plan.find(row => row.disposition === 'map').target.tenantId = 'tenant_omega';
  assert.deepEqual(validate(inferredTenant), []);
  assert.ok(semanticErrors(inferredTenant).includes('map_target_not_in_catalogue'));
  const competingType = clone();
  competingType.legacyValues.find(row => row.id === 'legacy-two-segment-001').observedCandidates[0].type = 'workspace';
  assert.ok(semanticErrors(competingType).includes('unknown_observed_candidate'));
});

test('legacy forms remain classifications, not tenant or hierarchy inference', () => {
  const byId = new Map(fixtures.plan.map(row => [row.legacyId, row]));
  assert.equal(byId.get('legacy-unknown-tenant-001').disposition, 'block');
  assert.equal(byId.get('legacy-collision-001').disposition, 'block');
  assert.equal(byId.get('legacy-wildcard-001').disposition, 'expire-and-reissue');
  assert.equal(byId.get('legacy-stale-opaque-001').disposition, 'expire-and-reissue');
  assert.equal(fixtures.legacyValues.find(row => row.id === 'legacy-collision-001').observedCandidates.length, 2);
  for (const forbidden of ['hierarchy', 'parentScope', 'membership', 'role']) assert.equal(JSON.stringify(schema).includes(`${JSON.stringify(forbidden)}:`), false, forbidden);
});

test('schema rejects unsafe plan branches and semantic checks reject unresolved references', () => {
  const missingAuthority = clone();
  delete missingAuthority.authorityEvidence;
  assert.ok(validate(missingAuthority).includes('required'));
  const missingKind = clone();
  delete missingKind.legacyValues[0].kind;
  assert.ok(validate(missingKind).includes('required'));
  const write = clone();
  write.writeOperations.push('write');
  assert.ok(validate(write).includes('maxItems'));
  const blockTarget = clone();
  blockTarget.plan.find(row => row.disposition === 'block').target = structuredClone(blockTarget.canonicalScopes[0]);
  assert.ok(validate(blockTarget).includes('oneOf'));
  const reissueTarget = clone();
  reissueTarget.plan.find(row => row.disposition === 'expire-and-reissue').target = structuredClone(reissueTarget.canonicalScopes[0]);
  assert.ok(validate(reissueTarget).includes('oneOf'));
  const missingPlan = clone();
  missingPlan.plan.pop();
  assert.ok(semanticErrors(missingPlan).includes('unplanned_legacy_value'));
  const unknownCandidate = clone();
  unknownCandidate.legacyValues.find(row => row.id === 'legacy-collision-001').observedCandidates[0].scopeId = 'unknown';
  assert.ok(semanticErrors(unknownCandidate).includes('unknown_observed_candidate'));
});

test('repeated dry runs have one digest and leave contract sources unchanged', () => {
  const watched = [schemaPath, fixturePath, documentPath, testPath];
  const before = watched.map(path => fs.readFileSync(path, 'utf8'));
  const first = dryRun(fixtures);
  const second = dryRun(fixtures);
  const after = watched.map(path => fs.readFileSync(path, 'utf8'));
  assert.deepEqual(first, second);
  assert.equal(first.projection.writeOperations.length, 0);
  assert.deepEqual(after, before);
});

test('portable canonical bytes omit absent candidates, preserve present candidates, and ignore object key order', () => {
  const baseline = dryRun(fixtures);
  const absent = baseline.projection.inventory.find(row => row.id === 'legacy-naked-001');
  const present = baseline.projection.inventory.find(row => row.id === 'legacy-two-segment-001');
  assert.equal(Object.hasOwn(absent, 'observedCandidates'), false);
  assert.deepEqual(present.observedCandidates, [{ tenantId: 'tenant_alpha', type: 'project', scopeId: 'atlas' }]);
  const reorder = value => Array.isArray(value) ? value.map(reorder) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).reverse().map(([key, child]) => [key, reorder(child)])) : value;
  const permuted = reorder(fixtures);
  assert.deepEqual(validate(permuted), []);
  assert.deepEqual(semanticErrors(permuted), []);
  assert.deepEqual(dryRun(permuted), baseline);
  assert.throws(() => dryRun({ ...fixtures, legacyValues: [{ ...fixtures.legacyValues[0], value: '\ud800' }, ...fixtures.legacyValues.slice(1)] }), /unpaired surrogate/);
});

test('bounded RFC 8785 JCS vectors preserve ECMAScript escaping and UTF-16 key order', () => {
  assert.equal(vectors.schema, 'amf.scope-migration-jcs-vectors/v1');
  for (const item of vectors.cases) {
    assert.equal(canonical(item.value), item.canonical, item.id);
    assert.equal(`sha256:${crypto.createHash('sha256').update(Buffer.from(item.canonical, 'utf8')).digest('hex')}`, item.digest, item.id);
  }
  assert.throws(() => canonical(1.5), /safe-integer digest domain/);
  assert.throws(() => canonical(Number.NaN), /safe-integer digest domain/);
  assert.throws(() => canonical(Number.POSITIVE_INFINITY), /safe-integer digest domain/);
  assert.throws(() => canonical(Number.MAX_SAFE_INTEGER + 1), /safe-integer digest domain/);
  assert.throws(() => canonical('\udc00'), /unpaired surrogate/);
  assert.throws(() => canonical(new Date()), /unsupported canonical JSON object type/);
  assert.throws(() => canonical([,]), /array is sparse/);
});

test('published digest vector is exact', () => {
  const result = dryRun(fixtures);
  assert.equal(result.digest, EXPECTED_DIGEST);
  assert.ok(document.includes(EXPECTED_DIGEST));
});

test('dry-run digest binds authority, catalogue, candidates, inventory, and decisions', () => {
  const baseline = dryRun(fixtures).digest;
  const changes = [
    ['authority evidence', manifest => { manifest.authorityEvidence.digest = `sha256:${'b'.repeat(64)}`; }],
    ['known tenants', manifest => { manifest.knownTenants.push('tenant_gamma'); }],
    ['canonical scopes', manifest => { manifest.canonicalScopes.push({ tenantId: 'tenant_beta', type: 'team', scopeId: 'dock' }); }],
    ['collision candidates', manifest => { manifest.legacyValues.find(row => row.id === 'legacy-collision-001').observedCandidates[0] = { tenantId: 'tenant_alpha', type: 'organization', scopeId: 'northstar' }; }],
    ['full inventory', manifest => { manifest.legacyValues.find(row => row.id === 'legacy-prefix-001').sourceRef = 'legacy-catalog-z'; }],
    ['plan decision', manifest => { manifest.plan.find(row => row.legacyId === 'legacy-two-segment-001').mappingEvidence.digest = `sha256:${'c'.repeat(64)}`; }]
  ];
  for (const [name, mutate] of changes) {
    const changed = clone();
    mutate(changed);
    assert.deepEqual(validate(changed), [], name);
    assert.deepEqual(semanticErrors(changed), [], name);
    assert.notEqual(dryRun(changed).digest, baseline, name);
  }
});

test('contract document preserves no-write and no-inference guarantees', () => {
  for (const phrase of ['deterministic, no-write inventory and plan', 'scope`, `grant`, `bundle`, `record`, `route`, or `cursor', 'digest binds authority evidence, known tenants, canonical scopes, every observed candidate, full inventory row, and every plan decision', 'JSON Canonicalization Scheme', 'RFC 8785', 'UTF-16 code units', 'ECMAScript `JSON.stringify`', 'safe-integer digest domain', 'Every legacy value receives exactly one disposition', 'never derives a target tenant, scope, type, hierarchy relation, membership, role, or grant', 'Unknown and ambiguous input remains fail-closed', 'unchanged source/fixture content across repeated dry runs']) assert.match(document, new RegExp(phrase.replace(/ /g, '\\s+'), 'i'));
});
