import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createM4LegacyReconciliationSource } from '../src/migration/m4-legacy-reconciliation-source.mjs';

const digest = char => `sha256:${char.repeat(64)}`;
const authority = { schema: 'amf.m4-group-replay-authority/v1', authorityDigest: digest('a') };
const full = id => ({ eventId: id, logicalDigest: digest('b'), integrity: { payloadDigest: digest('c') }, sourceOccurredAt: '2026-07-22T00:00:00Z', occurredAt: '2026-07-22T00:00:01Z', state: 'active', visibleText: 'never spool this' });
function dependencies(events) { return { async prepareM4V2UnifiedIndex() { return { index: { origin: 'v2-archive' }, materializer() {}, attestation: { archiveDigest: digest('d'), totalEntries: 1, totalBytes: 1 } }; }, async prepareM4PreservedUnifiedIndex() { return { indexes: { 'preserved-outbox': { origin: 'preserved-outbox', entries: [] }, 'preserved-deadletter': { origin: 'preserved-deadletter', entries: [] } }, materializers: { 'preserved-outbox'() {}, 'preserved-deadletter'() {} }, totalEntries: 0, totalBytes: 0 }; }, async prepareM4UnifiedLogicalGroupSource() { return { async open() { return { groups: (async function* () { yield { descriptor: { groupDigest: digest('e') }, logical: {}, observations: [] }; })(), completion: async () => ({ complete: true }) }; } }; }, async projectM4V2LogicalGroup() { return { events }; } }; }
function anonymousFilesUnder(root) {
  const prefix = `${fs.realpathSync(root)}${path.sep}#`;
  return fs.readdirSync('/proc/self/fd').flatMap(name => {
    try { return fs.readlinkSync(`/proc/self/fd/${name}`).startsWith(prefix) ? [Number(name)] : []; }
    catch { return []; }
  });
}
test('legacy source composes v2 plus both preserved indexes into an owner-only anonymous content-free snapshot', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-sort-')); fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {}, resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}), sortRoot: root, chunkMaxEvents: 1, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 1 }, dependencies: dependencies([full('cevt_legacy0002'), full('cevt_legacy0001')]) });
  const revision = await source.revisionSource(); const descriptors = anonymousFilesUnder(root);
  assert.equal(descriptors.length, 1); assert.equal(fs.fstatSync(descriptors[0]).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(`/proc/self/fd/${descriptors[0]}`, 'utf8').includes('never spool this'), false);
  const rows = []; for await (const row of source.events) rows.push(row); assert.equal(revision.state, 'complete'); assert.deepEqual(rows.map(row => row.eventId), ['cevt_legacy0001', 'cevt_legacy0002']); assert.equal(JSON.stringify(rows).includes('never spool this'), false); assert.equal(fs.readdirSync(root).length, 0); await source.close(); assert.equal(anonymousFilesUnder(root).length, 0);
});

test('early iteration cleanup removes only this source directory', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-clean-')); fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {}, resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}), sortRoot: root, chunkMaxEvents: 2, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 1 }, dependencies: dependencies([full('cevt_legacy0002'), full('cevt_legacy0001')]) });
  await source.revisionSource(); const iterator = source.events[Symbol.asyncIterator](); await iterator.next(); await iterator.return(); assert.equal(fs.readdirSync(root).length, 0); await source.close();
});

test('multiple chunks reject duplicate event ids and source stays structurally streaming', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-dupe-')); fs.chmodSync(root, 0o700); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {}, resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}), sortRoot: root, chunkMaxEvents: 1, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 1 }, dependencies: dependencies([full('cevt_legacy0001'), full('cevt_legacy0001')]) });
  await assert.rejects(() => source.revisionSource(), { code: 'm4_legacy_reconciliation_source_invalid' }); assert.equal(fs.readdirSync(root).length, 0);
  const sourceText = fs.readFileSync(new URL('../src/migration/m4-legacy-reconciliation-source.mjs', import.meta.url), 'utf8'); assert.equal(sourceText.includes('readFileSync('), false); assert.equal(sourceText.includes('.flatMap('), false);
  assert.equal(sourceText.includes('recursive: true'), false);
});

test('sort-root replacement cannot redirect anonymous files or cleanup into unrelated content', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-swap-')); fs.chmodSync(root, 0o700);
  const moved = `${root}-moved`; t.after(() => { fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(moved, { recursive: true, force: true }); });
  const deps = dependencies([full('cevt_swap0001'), full('cevt_swap0002')]);
  const project = deps.projectM4V2LogicalGroup; deps.projectM4V2LogicalGroup = async input => {
    fs.renameSync(root, moved); fs.mkdirSync(root, { mode: 0o700 });
    fs.writeFileSync(path.join(root, 'unrelated'), 'unrelated\n', { mode: 0o600 });
    return project(input);
  };
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {},
    resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}),
    sortRoot: root, chunkMaxEvents: 2, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 2 },
    dependencies: deps });
  await source.revisionSource();
  const rows = []; for await (const row of source.events) rows.push(row);
  await source.close(); assert.equal(fs.readFileSync(path.join(root, 'unrelated'), 'utf8'), 'unrelated\n');
  assert.equal(fs.readdirSync(moved).length, 0); assert.equal(rows.length, 2);
});

test('anonymous temp files expose no replaceable child and cleanup preserves foreign content', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-child-swap-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {},
    resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}),
    sortRoot: root, chunkMaxEvents: 2, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 2 },
    dependencies: dependencies([full('cevt_child0001'), full('cevt_child0002')]) });
  await source.revisionSource(); assert.equal(fs.readdirSync(root).length, 0);
  const foreign = path.join(root, 'foreign'); fs.writeFileSync(foreign, 'foreign regular content\n', { mode: 0o600 });
  const rows = []; for await (const row of source.events) rows.push(row.eventId); await source.close();
  assert.deepEqual(rows, ['cevt_child0001', 'cevt_child0002']);
  assert.equal(fs.readFileSync(foreign, 'utf8'), 'foreign regular content\n');
  const sourceText = fs.readFileSync(new URL('../src/migration/m4-legacy-reconciliation-source.mjs', import.meta.url), 'utf8');
  assert.equal(sourceText.includes('unlinkSync('), false); assert.equal(sourceText.includes('renameSync('), false);
});

test('bounded fan-in sorts more chunks than one merge group within the descriptor budget', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-fanin-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const events = Array.from({ length: 65 }, (_, index) => full(`cevt_fanin${String(65 - index).padStart(4, '0')}`));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {},
    resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}),
    sortRoot: root, chunkMaxEvents: 1, maxEvents: 65, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 100 },
    dependencies: dependencies(events) });
  await source.revisionSource(); const rows = []; for await (const row of source.events) rows.push(row.eventId);
  assert.deepEqual(rows, [...rows].sort()); await source.close(); assert.equal(fs.readdirSync(root).length, 0);
});

test('descriptor budget and actual event bound fail closed without leaked anonymous files', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-bounds-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const base = { authority, v2IndexInput: {}, preservedIndexInput: {},
    resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}),
    sortRoot: root, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 2 } };
  assert.throws(() => createM4LegacyReconciliationSource({ ...base, chunkMaxEvents: 1, maxEvents: 96,
    dependencies: dependencies([]) }), { code: 'm4_legacy_reconciliation_source_bound_exceeded' });
  const source = createM4LegacyReconciliationSource({ ...base, chunkMaxEvents: 2, maxEvents: 1,
    dependencies: dependencies([full('cevt_bound0001'), full('cevt_bound0002')]) });
  await assert.rejects(() => source.revisionSource(),
    { code: 'm4_legacy_reconciliation_source_bound_exceeded' });
  assert.equal(fs.readdirSync(root).length, 0); assert.equal(anonymousFilesUnder(root).length, 0);
});

test('same-inode snapshot mutation is rejected before iteration completes', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'm4-legacy-mutate-')); fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = createM4LegacyReconciliationSource({ authority, v2IndexInput: {}, preservedIndexInput: {},
    resolveCanonicalLogicalId: async () => `lmsg_${'a'.repeat(64)}`, integrityFor: async () => ({}),
    sortRoot: root, chunkMaxEvents: 2, maxEvents: 2, pageLimits: { maxGroups: 1, maxObservations: 1, maxOutputEvents: 2 },
    dependencies: dependencies([full('cevt_mutate0001'), full('cevt_mutate0002')]) });
  await source.revisionSource(); const [descriptor] = anonymousFilesUnder(root); assert.equal(Number.isInteger(descriptor), true);
  const iterator = source.events[Symbol.asyncIterator](); await iterator.next();
  fs.appendFileSync(`/proc/self/fd/${descriptor}`, '{}\n');
  await assert.rejects(async () => { for (;;) { const step = await iterator.next(); if (step.done) break; } },
    { code: 'm4_legacy_reconciliation_source_changed' });
  await source.close(); assert.equal(fs.readdirSync(root).length, 0); assert.equal(anonymousFilesUnder(root).length, 0);
});
