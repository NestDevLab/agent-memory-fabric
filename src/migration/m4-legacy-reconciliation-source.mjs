import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { TextDecoder } from 'node:util';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { createM4ReconciliationEventAccumulator } from './m4-reconciliation-snapshot.mjs';
import { prepareM4PreservedUnifiedIndex } from './m4-preserved-unified-index.mjs';
import { prepareM4UnifiedLogicalGroupSource } from './m4-unified-logical-group-source.mjs';
import { projectM4V2LogicalGroup } from './m4-v2-conversation-projector.mjs';
import { prepareM4V2UnifiedIndex } from './m4-v2-unified-index.mjs';

const MERGE_FAN_IN = 32;
const MAX_INITIAL_CHUNKS = 95;
const O_TMPFILE = 0o20000000 | fs.constants.O_DIRECTORY;

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.getPrototypeOf(value) === Object.prototype; }
function exact(value, keys) { return plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)); }
function noLinks(target, code) {
  let current = path.parse(target).root;
  for (const part of target.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try { if (fs.lstatSync(current).isSymbolicLink()) fail(code); }
    catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}
function compact(event, code) {
  if (!plain(event) || typeof event.eventId !== 'string' || !plain(event.integrity)
    || typeof event.integrity.payloadDigest !== 'string' || typeof event.logicalDigest !== 'string') fail(code);
  const value = { eventId: event.eventId, payloadDigest: event.integrity.payloadDigest,
    logicalDigest: event.logicalDigest, sourceOccurredAt: event.sourceOccurredAt,
    occurredAt: event.occurredAt, state: event.state };
  for (const name of ['replacesEventId', 'tombstonesEventId', 'conflictsWithEventIds']) {
    if (Object.hasOwn(event, name)) value[name] = structuredClone(event[name]);
  }
  return value;
}
function fileIdentityFromStat(stat) {
  return { dev: stat.dev.toString(), ino: stat.ino.toString(), size: stat.size.toString(),
    mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString() };
}
function sameIdentity(left, right) { return Object.keys(left).every(name => left[name] === right[name]); }
function openAnonymousFile(rootDescriptor, ownedDescriptors) {
  let descriptor;
  try {
    descriptor = fs.openSync(`/proc/self/fd/${rootDescriptor}`,
      fs.constants.O_RDWR | O_TMPFILE, 0o600);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || Number(stat.uid) !== process.getuid() || (Number(stat.mode) & 0o077) !== 0) {
      fail('m4_legacy_reconciliation_source_invalid');
    }
    const file = { descriptor, identity: fileIdentityFromStat(stat) };
    ownedDescriptors.add(descriptor); return file;
  } catch (error) {
    if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
    if (error?.code?.startsWith?.('m4_')) throw error;
    fail('m4_legacy_reconciliation_source_invalid');
  }
}
function refreshIdentity(file) { file.identity = fileIdentityFromStat(fs.fstatSync(file.descriptor, { bigint: true })); }
function closeAnonymousFile(file, ownedDescriptors) {
  if (!ownedDescriptors.delete(file.descriptor)) return;
  fs.closeSync(file.descriptor);
}
function writeRows(file, rows) {
  for (const row of rows) fs.writeSync(file.descriptor, `${canonicalJson(row)}\n`);
  fs.fsyncSync(file.descriptor); refreshIdentity(file);
}
function descriptorLines(descriptor) {
  let closed = false;
  return { async *[Symbol.asyncIterator]() {
    const decoder = new TextDecoder(); const buffer = Buffer.allocUnsafe(64 * 1024);
    let pending = ''; let position = 0;
    while (!closed) {
      const size = fs.readSync(descriptor, buffer, 0, buffer.length, position);
      if (size === 0) break;
      position += size; pending += decoder.decode(buffer.subarray(0, size), { stream: true });
      for (;;) {
        const end = pending.indexOf('\n'); if (end < 0) break;
        const line = pending.slice(0, end); pending = pending.slice(end + 1);
        yield line.endsWith('\r') ? line.slice(0, -1) : line;
      }
    }
    pending += decoder.decode();
    if (!closed && pending.length > 0) yield pending.endsWith('\r') ? pending.slice(0, -1) : pending;
  }, close() { closed = true; } };
}
function openDescriptorLines(descriptor) {
  const lines = descriptorLines(descriptor);
  return { iterator: lines[Symbol.asyncIterator](), close: () => lines.close() };
}
function descriptorIdentity(descriptor) {
  const stat = fs.fstatSync(descriptor, { bigint: true });
  return { dev: stat.dev.toString(), ino: stat.ino.toString(), size: stat.size.toString(),
    mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString() };
}
function assertDescriptorIdentity(descriptor, expected) {
  const current = descriptorIdentity(descriptor);
  if (Object.keys(current).some(name => current[name] !== expected[name])) {
    fail('m4_legacy_reconciliation_source_changed');
  }
}
async function mergeGroup(files, target) {
  const sources = files.map(file => {
    assertDescriptorIdentity(file.descriptor, file.identity);
    const lines = openDescriptorLines(file.descriptor);
    return { file, lines, iterator: lines.iterator };
  });
  const heads = [];
  try {
    for (const source of sources) { const item = await source.iterator.next(); heads.push(item.done ? null : JSON.parse(item.value)); }
    let previous = null;
    for (;;) {
      let selected = -1;
      for (let index = 0; index < heads.length; index += 1) {
        if (heads[index] && (selected < 0 || heads[index].eventId < heads[selected].eventId)) selected = index;
      }
      if (selected < 0) break;
      const row = heads[selected];
      if (previous !== null && previous >= row.eventId) fail('m4_legacy_reconciliation_source_invalid');
      fs.writeSync(target.descriptor, `${canonicalJson(row)}\n`); previous = row.eventId;
      const next = await sources[selected].iterator.next(); heads[selected] = next.done ? null : JSON.parse(next.value);
    }
    for (const source of sources) assertDescriptorIdentity(source.file.descriptor, source.file.identity);
    fs.fsyncSync(target.descriptor); refreshIdentity(target);
  } finally { for (const source of sources) source.lines.close(); }
}
async function mergePasses(rootDescriptor, initial, ownedDescriptors) {
  if (initial.length === 0) {
    const empty = openAnonymousFile(rootDescriptor, ownedDescriptors); writeRows(empty, []);
    return empty;
  }
  let files = [...initial];
  while (files.length > 1) {
    const next = [];
    for (let start = 0; start < files.length; start += MERGE_FAN_IN) {
      const group = files.slice(start, start + MERGE_FAN_IN);
      const target = openAnonymousFile(rootDescriptor, ownedDescriptors);
      try { await mergeGroup(group, target); }
      catch (error) { closeAnonymousFile(target, ownedDescriptors); throw error; }
      next.push(target);
      for (const file of group) closeAnonymousFile(file, ownedDescriptors);
    }
    files = next;
  }
  return files[0];
}
async function attestEvents(descriptor) {
  const accumulator = createM4ReconciliationEventAccumulator(); const source = openDescriptorLines(descriptor);
  try { for await (const line of { [Symbol.asyncIterator]: () => source.iterator }) if (line) accumulator.add(JSON.parse(line)); }
  finally { source.close(); }
  return accumulator.finish();
}
function preservedDigest(preserved) {
  const hash = crypto.createHash('sha256'); hash.update('amf.m4-preserved-index-attestation/v1\0', 'utf8');
  for (const origin of ['preserved-outbox', 'preserved-deadletter']) {
    const index = preserved.indexes[origin];
    if (!plain(index) || !Array.isArray(index.entries)) fail('m4_legacy_reconciliation_source_invalid');
    hash.update(`${origin}\0${index.entries.length}\0`, 'utf8');
    for (const entry of index.entries) {
      const encoded = canonicalJson(entry); hash.update(`${Buffer.byteLength(encoded, 'utf8')}\0`, 'utf8'); hash.update(encoded, 'utf8');
    }
  }
  hash.update(canonicalJson([preserved.totalEntries, preserved.totalBytes]), 'utf8');
  return `sha256:${hash.digest('hex')}`;
}

export function createM4LegacyReconciliationSource(input = {}) {
  const required = ['authority', 'v2IndexInput', 'preservedIndexInput', 'resolveCanonicalLogicalId',
    'integrityFor', 'sortRoot', 'chunkMaxEvents', 'maxEvents', 'pageLimits'];
  if (!plain(input) || Object.keys(input).some(key => ![...required, 'dependencies'].includes(key))
    || !required.every(key => Object.hasOwn(input, key)) || !plain(input.authority)
    || !plain(input.v2IndexInput) || !plain(input.preservedIndexInput)
    || Object.hasOwn(input.v2IndexInput, 'authority') || Object.hasOwn(input.preservedIndexInput, 'authority')
    || !exact(input.pageLimits, ['maxGroups', 'maxObservations', 'maxOutputEvents'])
    || !Object.values(input.pageLimits).every(value => Number.isSafeInteger(value) && value >= 1)
    || typeof input.resolveCanonicalLogicalId !== 'function' || typeof input.integrityFor !== 'function'
    || typeof input.sortRoot !== 'string' || !path.isAbsolute(input.sortRoot)
    || !Number.isSafeInteger(input.chunkMaxEvents) || input.chunkMaxEvents < 1 || input.chunkMaxEvents > 100_000
    || !Number.isSafeInteger(input.maxEvents) || input.maxEvents < 1 || input.maxEvents > 5_000_000) {
    fail('m4_legacy_reconciliation_source_invalid');
  }
  if (Math.ceil(input.maxEvents / input.chunkMaxEvents) > MAX_INITIAL_CHUNKS) {
    fail('m4_legacy_reconciliation_source_bound_exceeded');
  }
  const deps = input.dependencies ?? { prepareM4V2UnifiedIndex, prepareM4PreservedUnifiedIndex,
    prepareM4UnifiedLogicalGroupSource, projectM4V2LogicalGroup };
  if (!exact(deps, ['prepareM4V2UnifiedIndex', 'prepareM4PreservedUnifiedIndex',
    'prepareM4UnifiedLogicalGroupSource', 'projectM4V2LogicalGroup'])
    || Object.values(deps).some(value => typeof value !== 'function')) fail('m4_legacy_reconciliation_source_invalid');
  noLinks(input.sortRoot, 'm4_legacy_reconciliation_source_invalid');
  const rootStat = fs.statSync(input.sortRoot);
  if (!rootStat.isDirectory() || rootStat.uid !== process.getuid() || (rootStat.mode & 0o077) !== 0) {
    fail('m4_legacy_reconciliation_source_invalid');
  }
  let state = 'new'; let rootDescriptor; let snapshotDescriptor; let snapshotIdentity;
  const ownedDescriptors = new Set();
  let read = false; let complete = false;
  const cleanup = () => {
    let safe = true;
    for (const descriptor of ownedDescriptors) try { fs.closeSync(descriptor); } catch { safe = false; }
    ownedDescriptors.clear(); snapshotDescriptor = undefined; snapshotIdentity = undefined;
    if (rootDescriptor !== undefined) try { fs.closeSync(rootDescriptor); } catch { safe = false; }
    rootDescriptor = undefined;
    return safe;
  };
  return {
    async revisionSource() {
      if (state !== 'new') fail('m4_legacy_reconciliation_source_invalid'); state = 'building';
      try {
        rootDescriptor = fs.openSync(input.sortRoot,
          fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
        const pinnedRoot = fs.fstatSync(rootDescriptor);
        if (!pinnedRoot.isDirectory() || pinnedRoot.uid !== process.getuid() || (pinnedRoot.mode & 0o077) !== 0) {
          fail('m4_legacy_reconciliation_source_invalid');
        }
        const v2 = await deps.prepareM4V2UnifiedIndex({ authority: input.authority,
          ...structuredClone(input.v2IndexInput) });
        const preserved = await deps.prepareM4PreservedUnifiedIndex({ authority: input.authority,
          ...structuredClone(input.preservedIndexInput) });
        const unified = await deps.prepareM4UnifiedLogicalGroupSource({ authority: input.authority,
          indexes: { 'v2-archive': v2.index, ...preserved.indexes },
          materializers: { 'v2-archive': v2.materializer, ...preserved.materializers },
          resolveCanonicalLogicalId: input.resolveCanonicalLogicalId });
        let after = null; let chunk = []; let visited = 0; const chunks = [];
        const flush = () => {
          if (chunk.length === 0) return;
          chunk.sort((left, right) => left.eventId.localeCompare(right.eventId));
          const target = openAnonymousFile(rootDescriptor, ownedDescriptors); writeRows(target, chunk);
          chunks.push(target); chunk = [];
        };
        for (;;) {
          const before = after;
          const opened = await unified.open({ schema: 'amf.m4-preserved-group-replay-request/v1',
            authorityDigest: input.authority.authorityDigest, after, ...input.pageLimits });
          for await (const group of opened.groups) {
            const projected = await deps.projectM4V2LogicalGroup({ logical: group.logical,
              observations: group.observations, integrityFor: input.integrityFor });
            if (!Array.isArray(projected.events)) fail('m4_legacy_reconciliation_source_invalid');
            for (const event of projected.events) {
              visited += 1;
              if (visited > input.maxEvents) fail('m4_legacy_reconciliation_source_bound_exceeded');
              chunk.push(compact(event, 'm4_legacy_reconciliation_source_invalid'));
              if (chunk.length >= input.chunkMaxEvents) flush();
            }
            after = group.descriptor.groupDigest;
          }
          const done = await opened.completion();
          if (!plain(done) || typeof done.complete !== 'boolean') fail('m4_legacy_reconciliation_source_invalid');
          if (done.complete) break;
          if (after === before) fail('m4_legacy_reconciliation_source_invalid');
        }
        flush(); const snapshot = await mergePasses(rootDescriptor, chunks, ownedDescriptors);
        snapshotDescriptor = snapshot.descriptor; snapshotIdentity = snapshot.identity;
        const set = await attestEvents(snapshotDescriptor); assertDescriptorIdentity(snapshotDescriptor, snapshotIdentity);
        const binding = { schema: 'amf.m4-legacy-reconciliation-source/v1', archive: 'legacy-v2',
          authorityDigest: input.authority.authorityDigest,
          eventCount: set.eventCount, eventSetDigest: set.eventSetDigest, v2Attestation: v2.attestation,
          preservedAttestationDigest: preservedDigest(preserved) };
        const digest = `sha256:${crypto.createHash('sha256').update(canonicalJson(binding), 'utf8').digest('hex')}`;
        state = 'ready'; return { state: 'complete', checkpoint: { id: `m4legacy-${digest.slice(7)}`, digest } };
      } catch (error) {
        cleanup(); state = 'closed';
        if (error?.code?.startsWith?.('m4_')) throw error;
        fail('m4_legacy_reconciliation_source_invalid');
      }
    },
    get events() {
      return { async *[Symbol.asyncIterator]() {
        if (state !== 'ready' || read) fail('m4_legacy_reconciliation_source_invalid'); read = true;
        const source = openDescriptorLines(snapshotDescriptor);
        try { for await (const line of { [Symbol.asyncIterator]: () => source.iterator }) if (line) yield JSON.parse(line);
          assertDescriptorIdentity(snapshotDescriptor, snapshotIdentity); complete = true; }
        finally { source.close(); if (!complete) cleanup(); }
      } };
    },
    async close() {
      if (state === 'closed') return;
      if (state !== 'ready') fail('m4_legacy_reconciliation_source_invalid');
      const cleaned = cleanup(); state = 'closed';
      if (!cleaned) fail('m4_legacy_reconciliation_source_cleanup_failed');
    },
  };
}
