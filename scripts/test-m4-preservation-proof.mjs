import assert from 'node:assert/strict';
import test from 'node:test';

import { collectM4SelectorScopeSnapshot } from '../src/migration/m4-authority-snapshots.mjs';
import { createM4PreservationProof, verifyM4PreservationProof } from '../src/migration/m4-preservation-proof.mjs';

const digest = value => `sha256:${value.repeat(64)}`;
const key = (id = 'preservation-key', byte = 1) => ({ schema: 'amf.migration-signing-key/v1', keyId: id, key: Buffer.alloc(32, byte).toString('base64') });
const checkpoint = (id, byte) => ({ id, digest: digest(byte) });
const source = 'src_preservation01';
const iterable = values => ({ async *[Symbol.asyncIterator]() { yield* values; } });
const authorities = () => ({ selectorScopeKeyDocument: key('selector-scope-key', 2) });
async function input() {
  const policy = { schema: 'amf.content-protection-policy/v1', revision: 'policy-v2', defaults: { conversation: 'plaintext', proposal: 'plaintext', 'canonical-memory': 'plaintext', document: 'plaintext' }, rules: [
    { sourceInstanceId: source, contentClass: 'conversation', enabled: true, codec: 'aes-256-gcm', writeKeyRef: 'key:conversation-v2', readKeyRefs: ['key:conversation-v2'], compression: 'deflate-raw', readPlaintext: false },
  ] };
  const scopeKey = key('selector-scope-key', 2);
  const selectorScopeManifest = await collectM4SelectorScopeSnapshot({ snapshotId: 'selector-scope-one', revision: 1, policy,
    observedAt: '2026-01-01T00:00:00Z', validThrough: '2026-01-02T00:00:00Z',
    selectorSource: iterable([{ sourceInstanceId: source, contentClass: 'conversation' }]), keyDocument: scopeKey });
  return {
    manifestId: 'preservation-proof-one', revision: 1, provedAt: '2026-01-01T12:00:00Z', policy,
    selectorScopeManifest,
    dispositions: [{ sourceInstanceId: source, contentClass: 'conversation', scannedPlaintextCount: 8, retainedEncryptedCount: 5, cleanupTargetCount: 3, binding: checkpoint('conversation-disposition', '1') }],
    preservedSharedData: [
      { contentClass: 'proposal', count: 2, binding: checkpoint('proposal-preserved', '2') },
      { contentClass: 'canonical-memory', count: 3, binding: checkpoint('memory-preserved', '3') },
      { contentClass: 'document', count: 4, binding: checkpoint('document-preserved', '4') },
    ],
    rollbackPolicyBinding: { revision: 'policy-v1', digest: digest('5') },
    restoreTest: { state: 'passed', evidence: checkpoint('policy-restore-test', '6') }, signingKeyDocument: key(),
  };
}

test('signs exact selector closure, full disposition, and shared-data preservation evidence', async () => {
  const value = await input(); const before = structuredClone(value); const manifest = createM4PreservationProof(value, authorities());
  assert.deepEqual(value, before); assert.equal(manifest.state, 'passed'); assert.equal(manifest.policyBinding.revision, 'policy-v2');
  assert.equal(manifest.dispositions[0].scannedPlaintextCount, 8);
  assert.deepEqual(manifest.preservedSharedData.map(item => item.contentClass), ['proposal', 'canonical-memory', 'document']);
  assert.deepEqual(verifyM4PreservationProof(manifest, key()), manifest);
});

test('requires encrypted conversation selectors with plaintext reads closed', async () => {
  for (const mutation of [
    value => { value.policy.rules[0].readPlaintext = true; },
    value => { value.policy.rules[0].codec = 'plaintext'; delete value.policy.rules[0].writeKeyRef; delete value.policy.rules[0].readKeyRefs; delete value.policy.rules[0].compression; delete value.policy.rules[0].readPlaintext; },
    value => { value.selectorScopeManifest.selectors[0].contentClass = 'proposal'; value.dispositions[0].contentClass = 'proposal'; },
  ]) { const value = await input(); mutation(value); assert.throws(() => createM4PreservationProof(value, authorities()), /m4_preservation_proof_(?:plaintext_open|scope_invalid|policy_mismatch)/); }
});

test('rejects incomplete dispositions, reordered protected classes, and reused evidence', async () => {
  const incomplete = await input(); incomplete.dispositions[0].scannedPlaintextCount = 9;
  assert.throws(() => createM4PreservationProof(incomplete, authorities()), /m4_preservation_proof_input_invalid/);
  const reordered = await input(); reordered.preservedSharedData.reverse();
  assert.throws(() => createM4PreservationProof(reordered, authorities()), /m4_preservation_proof_input_invalid/);
  const reused = await input(); reused.restoreTest.evidence = structuredClone(reused.preservedSharedData[0].binding);
  assert.throws(() => createM4PreservationProof(reused, authorities()), /m4_preservation_proof_input_invalid/);
});

test('authoritative scope rejects omitted, extra, changed-policy, and stale selector closure', async () => {
  const omitted = await input(); const secondSource = 'src_preservation02';
  omitted.policy.rules.push({ ...omitted.policy.rules[0], sourceInstanceId: secondSource });
  omitted.selectorScopeManifest = await collectM4SelectorScopeSnapshot({ snapshotId: 'selector-scope-two', revision: 2, policy: omitted.policy,
    observedAt: '2026-01-01T00:00:00Z', validThrough: '2026-01-02T00:00:00Z', selectorSource: iterable([
      { sourceInstanceId: source, contentClass: 'conversation' }, { sourceInstanceId: secondSource, contentClass: 'conversation' },
    ]), keyDocument: authorities().selectorScopeKeyDocument });
  assert.throws(() => createM4PreservationProof(omitted, authorities()), /m4_preservation_proof_input_invalid/);
  const extra = await input(); extra.dispositions.push({ ...extra.dispositions[0], sourceInstanceId: secondSource, binding: checkpoint('extra-disposition', '7') });
  assert.throws(() => createM4PreservationProof(extra, authorities()), /m4_preservation_proof_input_invalid/);
  const changed = await input(); changed.policy.revision = 'policy-v3';
  assert.throws(() => createM4PreservationProof(changed, authorities()), /m4_preservation_proof_policy_mismatch/);
  const stale = await input(); stale.provedAt = '2026-01-03T00:00:00Z';
  assert.throws(() => createM4PreservationProof(stale, authorities()), /m4_preservation_proof_scope_stale/);
});

test('tamper, wrong authority, extras, and hostile values fail closed', async () => {
  const first = await input(); const manifest = createM4PreservationProof(first, authorities()); manifest.dispositions[0].cleanupTargetCount += 1;
  assert.throws(() => verifyM4PreservationProof(manifest, key()), /m4_preservation_proof_manifest_invalid|m4_preservation_proof_digest_mismatch/);
  const second = await input(); assert.throws(() => verifyM4PreservationProof(createM4PreservationProof(second, authorities()), key('other-key', 2)), /m4_preservation_proof_key_id_mismatch/);
  const extra = await input(); extra.command = 'never'; assert.throws(() => createM4PreservationProof(extra, authorities()), /m4_preservation_proof_input_invalid/);
  assert.throws(() => createM4PreservationProof(new Proxy({}, { get() { throw new Error('private'); } }), authorities()), /m4_preservation_proof_input_invalid/);
});

test('scope trust anchor cannot be supplied by the claimant or reuse preservation authority', async () => {
  const value = await input(); value.selectorScopeKeyDocument = authorities().selectorScopeKeyDocument;
  assert.throws(() => createM4PreservationProof(value, authorities()), /m4_preservation_proof_input_invalid/);
  const reused = await input();
  assert.throws(() => createM4PreservationProof(reused, { selectorScopeKeyDocument: reused.signingKeyDocument }), /m4_preservation_proof_authority_invalid/);
  const sameMaterial = await input();
  assert.throws(() => createM4PreservationProof(sameMaterial, { selectorScopeKeyDocument: key('different-scope-id', 1) }), /m4_preservation_proof_authority_invalid/);
});
