import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { createM4CrossPhaseIdentityRegistry } from '../src/migration/m4-cross-phase-identity-registry.mjs';
import { createM4PausedSourceTagAuthority, resolveM4PausedSourceTags,
  verifyM4PausedSourceTagAuthority, createM4PausedSourceTagResolver } from '../src/migration/m4-paused-source-tag-authority.mjs';

const registrySecret = Buffer.alloc(32, 4); const sourceTagSecret = Buffer.alloc(32, 5);
const keys = { registrySecret, sourceTagSecret };
const hex = value => crypto.createHash('sha256').update(value).digest('hex');
const binding = { schema: 'amf.m4-paused-projection-binding/v1', runtime: 'hermes', sourceId: 'primary', digest: `sha256:${hex('binding')}` };
const tags = [`routing:${hex('one')}`, `routing:${hex('two')}`].sort();
function fixture() {
  const registry = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-22T00:00:00Z',
    backfillBinding: { completionDigest: `sha256:${hex('completion')}`, catalogRevisionDigest: `sha256:${hex('catalog')}` }, sessions: [], events: [] }, registrySecret);
  const authority = createM4PausedSourceTagAuthority({ registryAuthority: registry.authority,
    backfillBinding: registry.authority.backfillBinding,
    mappings: [{ runtime: binding.runtime, sourceId: binding.sourceId, projectionBindingDigest: binding.digest, sourceTags: tags }] }, keys);
  return { registry, authority };
}
function resolve(value, override = {}) {
  return resolveM4PausedSourceTags({ authority: value.authority, registryAuthority: value.registry.authority, binding, ...override }, keys);
}

test('signs canonical mappings under a dedicated source-tag key bound to the exact registry authority', () => {
  const value = fixture();
  assert.deepEqual(verifyM4PausedSourceTagAuthority(value.authority, { sourceTagSecret }).mappings[0].sourceTags, tags);
  assert.deepEqual(resolve(value), tags);
  assert.throws(() => createM4PausedSourceTagAuthority({ registryAuthority: value.registry.authority,
    backfillBinding: value.registry.authority.backfillBinding, mappings: value.authority.mappings },
  { registrySecret, sourceTagSecret: registrySecret }), { code: 'm4_paused_source_tag_authority_key_invalid' });
});

test('builds one verified bounded resolver with exact input and cloned outputs', () => {
  const value = fixture(); const resolver = createM4PausedSourceTagResolver({ authority: value.authority,
    registryAuthority: value.registry.authority, ...keys });
  const first = resolver.resolve(binding); first.push(`routing:${hex('mutated')}`);
  assert.deepEqual(resolver.resolve(binding), tags);
  assert.deepEqual(resolver.resolve(structuredClone(binding)), tags);
  assert.throws(() => resolver.resolve({ ...binding, extra: true }), { code: 'm4_paused_source_tag_authority_input_invalid' });
  assert.throws(() => resolver.resolve({ ...binding, digest: `sha256:${hex('missing')}` }), { code: 'm4_paused_source_tag_authority_mapping_missing' });
  assert.throws(() => createM4PausedSourceTagResolver({ authority: value.authority, registryAuthority: value.registry.authority,
    registrySecret, sourceTagSecret, extra: true }), { code: 'm4_paused_source_tag_authority_input_invalid' });
});

test('rejects tuple/tag canonicalization errors before signing', () => {
  const value = fixture(); const base = value.authority.mappings[0];
  for (const mappings of [
    [base, structuredClone(base)],
    [structuredClone(base), { ...base, sourceId: 'aaa' }],
    [{ ...base, sourceTags: [] }],
    [{ ...base, sourceTags: [...tags].reverse() }],
    [{ ...base, sourceTags: [tags[0], tags[0]] }],
  ]) {
    assert.throws(() => createM4PausedSourceTagAuthority({ registryAuthority: value.registry.authority,
      backfillBinding: value.registry.authority.backfillBinding, mappings }, keys), { code: 'm4_paused_source_tag_authority_invalid' });
  }
});

test('fails closed on MAC, root, backfill, mapping, and independent key drift', () => {
  const value = fixture();
  const tampered = structuredClone(value.authority); tampered.mac = `hmac-sha256:${'a'.repeat(43)}`;
  assert.throws(() => verifyM4PausedSourceTagAuthority(tampered, { sourceTagSecret }), { code: 'm4_paused_source_tag_authority_invalid' });
  const otherRegistry = createM4CrossPhaseIdentityRegistry({ coveredThrough: '2026-07-23T00:00:00Z',
    backfillBinding: value.registry.authority.backfillBinding, sessions: [], events: [] }, registrySecret);
  assert.throws(() => resolveM4PausedSourceTags({ authority: value.authority, registryAuthority: otherRegistry.authority, binding }, keys),
  { code: 'm4_paused_source_tag_authority_binding_mismatch' });
  const swapped = structuredClone(value.authority); swapped.backfillBinding.completionDigest = `sha256:${hex('other')}`;
  assert.throws(() => verifyM4PausedSourceTagAuthority(swapped, { sourceTagSecret }), { code: 'm4_paused_source_tag_authority_invalid' });
  assert.throws(() => resolve(value, { binding: { ...binding, digest: `sha256:${hex('other')}` } }), { code: 'm4_paused_source_tag_authority_mapping_missing' });
  assert.throws(() => resolveM4PausedSourceTags({ authority: value.authority, registryAuthority: value.registry.authority, binding },
    { registrySecret: Buffer.alloc(32, 9), sourceTagSecret }), { code: 'm4_paused_source_tag_authority_binding_mismatch' });
  assert.throws(() => verifyM4PausedSourceTagAuthority(value.authority, { sourceTagSecret: Buffer.alloc(32, 9) }),
    { code: 'm4_paused_source_tag_authority_invalid' });
});
