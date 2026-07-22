import assert from 'node:assert/strict';
import test from 'node:test';

import { collectM4SelectorScopeSnapshot } from '../src/migration/m4-authority-snapshots.mjs';
import { createM4CutoverAuthorization, verifyM4CutoverAuthorization } from '../src/migration/m4-cutover-authorization.mjs';
import { createM4CutoverCanaryManifest } from '../src/migration/m4-cutover-canary.mjs';
import { m4CutoverFixture, keyDocument } from './helpers/m4-cutover-fixtures.mjs';

const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });
const authorize = fixture => createM4CutoverAuthorization(fixture.authorizationInput, { selectorScopeKeyDocument: fixture.keys.selectorScope });

test('authorizes only the complete signed M4 evidence chain and exact v3 route revisions', async () => {
  const fixture = await m4CutoverFixture(); const before = structuredClone(fixture.authorizationInput);
  const manifest = authorize(fixture);
  assert.deepEqual(fixture.authorizationInput, before); assert.equal(manifest.state, 'authorized');
  assert.equal(manifest.routeConfiguration.publicReader.mode, 'active'); assert.equal(manifest.routeConfiguration.extractorReader.mode, 'v3');
  assert.equal(manifest.aliasBinding.conversationCount, 0); assert.match(manifest.aliasBinding.manifestDigest, /^sha256:[a-f0-9]{64}$/);
  assert.deepEqual(verifyM4CutoverAuthorization(manifest, fixture.keys.authorization), manifest);
});

test('failed canary, incomplete alias authority, and route drift block authorization', async () => {
  const failed = await m4CutoverFixture();
  failed.authorizationInput.canaryManifest = createM4CutoverCanaryManifest({ manifestId: 'cutover-canary-failed', revision: 1, keyDocument: failed.keys.canary,
    policy: failed.canary.policy, observations: { ...failed.canary.observations, errors: { ...failed.canary.observations.errors, reader: 1 } } });
  assert.throws(() => authorize(failed), /m4_cutover_authorization_evidence_incomplete/);
  const alias = await m4CutoverFixture(); alias.authorizationInput.aliasKeyDocument = keyDocument('cutover-alias-key', 99);
  assert.throws(() => authorize(alias), /m4_cutover_authorization_alias_invalid/);
  for (const mutate of [value => { value.routeConfiguration.publicReader.mode = 'shadow'; }, value => { value.routeConfiguration.extractorReader.mode = 'legacy'; }, value => { value.routeConfiguration.extractorReader.stateGeneration = 'legacy-v2'; }]) {
    const fixture = await m4CutoverFixture(); mutate(fixture.authorizationInput); assert.throws(() => authorize(fixture), /m4_cutover_authorization_input_invalid/);
  }
  const rollback = await m4CutoverFixture(); rollback.authorizationInput.rollbackRevision.digest = `sha256:${'e'.repeat(64)}`;
  assert.throws(() => authorize(rollback), /m4_cutover_authorization_rollback_mismatch/);
});

test('tamper, wrong authority, extras, and hostile inputs fail closed', async () => {
  const fixture = await m4CutoverFixture(); const manifest = authorize(fixture);
  manifest.rollbackRevision.digest = `sha256:${'f'.repeat(64)}`;
  assert.throws(() => verifyM4CutoverAuthorization(manifest, fixture.keys.authorization), /m4_cutover_authorization_digest_mismatch/);
  assert.throws(() => verifyM4CutoverAuthorization(authorize(fixture), keyDocument('other-authorization-key', 8)), /m4_cutover_authorization_key_id_mismatch/);
  const extra = structuredClone(fixture.authorizationInput); extra.path = '/forbidden'; assert.throws(() => createM4CutoverAuthorization(extra, { selectorScopeKeyDocument: fixture.keys.selectorScope }), /m4_cutover_authorization_input_invalid/);
  assert.throws(() => createM4CutoverAuthorization(new Proxy({}, { get() { throw new Error('private'); } }), { selectorScopeKeyDocument: fixture.keys.selectorScope }), /m4_cutover_authorization_input_invalid/);
  assert.throws(() => verifyM4CutoverAuthorization({ uncloneable: () => 'private' }, fixture.keys.authorization), error => error.code === 'm4_cutover_authorization_manifest_invalid');
});

test('authorization re-verifies the exact authoritative selector scope and freshness', async () => {
  const changed = await m4CutoverFixture();
  changed.authorizationInput.selectorScopeManifest = await collectM4SelectorScopeSnapshot({ snapshotId: 'cutover-selector-scope-other', revision: 2,
    policy: changed.policy, observedAt: '2026-01-01T23:59:00Z', validThrough: '2026-01-03T00:00:00Z',
    selectorSource: iterable(changed.selectorScope.selectors), keyDocument: changed.keys.selectorScope });
  assert.throws(() => authorize(changed), /m4_cutover_authorization_scope_mismatch/);
  const stale = await m4CutoverFixture(); stale.authorizationInput.authorizedAt = '2026-01-04T00:00:00Z';
  assert.throws(() => authorize(stale), /m4_cutover_authorization_scope_stale/);
});

test('selector trust anchor is external and cannot reuse claimant authority', async () => {
  const injected = await m4CutoverFixture(); injected.authorizationInput.selectorScopeKeyDocument = injected.keys.selectorScope;
  assert.throws(() => authorize(injected), /m4_cutover_authorization_input_invalid/);
  const sameId = await m4CutoverFixture();
  assert.throws(() => createM4CutoverAuthorization(sameId.authorizationInput, { selectorScopeKeyDocument: sameId.keys.authorization }), /m4_cutover_authorization_authority_invalid/);
  const sameMaterial = await m4CutoverFixture();
  assert.throws(() => createM4CutoverAuthorization(sameMaterial.authorizationInput,
    { selectorScopeKeyDocument: keyDocument('different-scope-id', 8) }), /m4_cutover_authorization_authority_invalid/);
});
