import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { M4PostCutoffIdentityStore } from '../src/migration/m4-post-cutoff-identity-store.mjs';
import { deriveM4V3ConversationIdFromLegacySessionId, deriveM4V3EventIdFromLegacyEventId, deriveM4V3SourceInstanceIdFromLegacySession } from '../src/migration/m4-v2-conversation-projector.mjs';

const digest = char => `sha256:${char.repeat(64)}`;
const binding = (suffix = 'a') => { const legacyEventId = `evt_${suffix.repeat(64)}`; const legacySessionId = `ses_${'b'.repeat(64)}`; const sourceTags = [`source:${'f'.repeat(64)}`]; return { legacyEventId, legacySessionId,
  eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId), conversationId: deriveM4V3ConversationIdFromLegacySessionId(legacySessionId), sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(legacySessionId, sourceTags), sourceTags, observedAt: '2026-07-22T00:00:00Z' }; };
function input(root) { return { rootPath: root, runId: 'm4-run-001', phase: 'paused-native', planDigest: digest('1'), registryAuthorityDigest: digest('2'), sourceTagAuthorityDigest: digest('3') }; }

test('post-cutoff store is content-free, restart-safe, idempotent, and namespace-bound', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-identity-'));
  try {
    const first = new M4PostCutoffIdentityStore(input(root)); const row = binding();
    assert.equal(first.load(row.legacyEventId), null); assert.deepEqual(first.commit(row), row); assert.deepEqual(first.commit(structuredClone(row)), row); first.close();
    const second = new M4PostCutoffIdentityStore(input(root)); assert.deepEqual(second.load(row.legacyEventId), row);
    assert.throws(() => second.commit({ ...row, observedAt: '2026-07-22T00:00:01Z' }), { code: 'm4_post_cutoff_identity_store_drift' }); second.close();
    const isolated = new M4PostCutoffIdentityStore({ ...input(root), planDigest: digest('4') }); assert.equal(isolated.load(row.legacyEventId), null); isolated.close();
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('post-cutoff store rejects symlink roots and unsafe state files', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-identity-')); const root = path.join(base, 'root');
  try {
    fs.symlinkSync('/tmp', root); assert.throws(() => new M4PostCutoffIdentityStore(input(root)), { code: 'm4_post_cutoff_identity_store_unsafe' });
    fs.unlinkSync(root); fs.mkdirSync(root, { mode: 0o700 }); const store = new M4PostCutoffIdentityStore(input(root)); store.close();
  } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('post-cutoff store isolates buckets and every authority namespace, recovers private temps, and rejects unsafe state entries', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-identity-'));
  try {
    const first = new M4PostCutoffIdentityStore(input(root)); const left = binding('a'); const right = binding('c'); first.commit(left); first.commit(right); first.close();
    const names = fs.readdirSync(root).filter(name => name.endsWith('.json')); assert.equal(names.length, 2);
    for (const changed of [{ registryAuthorityDigest: digest('4') }, { sourceTagAuthorityDigest: digest('5') }]) {
      const isolated = new M4PostCutoffIdentityStore({ ...input(root), ...changed }); assert.equal(isolated.load(left.legacyEventId), null); isolated.close();
    }
    const base = input(root); const samePrefix = `${base.registryAuthorityDigest.slice(0, -1)}${base.registryAuthorityDigest.endsWith('a') ? 'b' : 'a'}`;
    const collisionSafe = new M4PostCutoffIdentityStore({ ...base, registryAuthorityDigest: samePrefix }); assert.equal(collisionSafe.load(left.legacyEventId), null); collisionSafe.close();
    const temp = path.join(root, `.${names[0]}.${crypto.randomUUID()}.tmp`); fs.writeFileSync(temp, '{}', { mode: 0o600 });
    const recovered = new M4PostCutoffIdentityStore(input(root)); assert.equal(fs.existsSync(temp), false); recovered.close();
    fs.chmodSync(path.join(root, names[0]), 0o644); assert.throws(() => new M4PostCutoffIdentityStore(input(root)).load(left.legacyEventId), { code: 'm4_post_cutoff_identity_store_unsafe' });
    fs.chmodSync(path.join(root, names[0]), 0o600); fs.unlinkSync(path.join(root, names[0])); fs.symlinkSync('/tmp', path.join(root, names[0])); assert.throws(() => new M4PostCutoffIdentityStore(input(root)).load(left.legacyEventId), { code: 'm4_post_cutoff_identity_store_unsafe' });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
