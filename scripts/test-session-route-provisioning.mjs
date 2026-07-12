import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { ContextTokenVerifier, issueSessionRouteBinding } from '../src/context-token.mjs';
import { provisionSessionRoutes } from '../src/operator/session-route-provisioning.mjs';

const TAG_A = `hmac-sha256:routing-v1:${'a'.repeat(64)}`;
const TAG_B = `hmac-sha256:routing-v1:${'b'.repeat(64)}`;
function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}
function asRoot(operation) {
  const original = process.geteuid; process.geteuid = () => 0;
  try { return operation(); } finally { process.geteuid = original; }
}
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-session-routes-')); fs.chmodSync(root, 0o700);
  const inputPath = path.join(root, 'input.json'); const contextKeyRingPath = path.join(root, 'ring.json');
  const manifestPath = path.join(root, 'manifest.json');
  const ring = { currentKeyVersion: 'ctx-v1', keys: { 'ctx-v1': crypto.randomBytes(32).toString('base64') } };
  privateJson(contextKeyRingPath, ring);
  const binding = { actor: 'agent:vitae', canonicalScope: 'room:vitae:topic', conversationKind: 'group',
    contextTags: { conversation: [TAG_A], room: [TAG_A] } };
  privateJson(inputPath, { schema: 'amf.session-route-input/v1', bindings: [binding] });
  return { root, inputPath, contextKeyRingPath, manifestPath, ring, binding,
    serviceOwnerUid: fs.statSync(root).uid };
}

test('session route provisioner creates, verifies and atomically updates a private manifest', () => {
  const sample = fixture();
  try {
    const options = { inputPath: sample.inputPath, contextKeyRingPath: sample.contextKeyRingPath,
      manifestPath: sample.manifestPath, serviceOwnerUid: sample.serviceOwnerUid };
    const dry = provisionSessionRoutes({ ...options, dryRun: true });
    assert.deepEqual({ action: dry.action, bindingCount: dry.bindingCount, updatedBindingCount: dry.updatedBindingCount },
      { action: 'create', bindingCount: 1, updatedBindingCount: 1 });
    assert.equal(fs.existsSync(sample.manifestPath), false);
    const created = asRoot(() => provisionSessionRoutes(options)); assert.equal(created.action, 'create');
    assert.equal(fs.statSync(sample.manifestPath).mode & 0o777, 0o600);
    const first = JSON.parse(fs.readFileSync(sample.manifestPath, 'utf8'));
    const verifier = new ContextTokenVerifier({ keyRing: sample.ring, policyRevision: '' });
    assert.equal(verifier.verifySessionRouteBinding(first.bindings[0]).canonicalScope, sample.binding.canonicalScope);
    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v1', bindings: [
      { ...sample.binding, contextTags: { conversation: [TAG_B], room: [TAG_B] } }
    ] });
    const updated = asRoot(() => provisionSessionRoutes(options)); assert.equal(updated.action, 'update');
    assert.ok(updated.backupPath); assert.equal(fs.statSync(updated.backupPath).mode & 0o777, 0o600);
    const next = JSON.parse(fs.readFileSync(sample.manifestPath, 'utf8'));
    assert.deepEqual(verifier.verifySessionRouteBinding(next.bindings[0]).contextTags,
      { conversation: [TAG_B], room: [TAG_B] });
    assert.equal(JSON.stringify(updated).includes(TAG_B), false, 'operator output must not disclose route tags');
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('session route provisioner rejects wrong scope, literal tags and duplicate route identities', () => {
  const binding = { actor: 'agent:vitae', canonicalScope: 'room:vitae:topic', conversationKind: 'group',
    contextTags: { conversation: [TAG_A], room: [TAG_A] } };
  for (const bindings of [
    [{ ...binding, canonicalScope: '*' }],
    [{ ...binding, contextTags: { conversation: ['telegram:literal'], room: ['telegram:literal'] } }],
    [binding, binding]
  ]) {
    const sample = fixture();
    try {
      privateJson(sample.inputPath, { schema: 'amf.session-route-input/v1', bindings });
      assert.throws(() => provisionSessionRoutes({ inputPath: sample.inputPath,
        contextKeyRingPath: sample.contextKeyRingPath, manifestPath: sample.manifestPath,
        serviceOwnerUid: sample.serviceOwnerUid, dryRun: true }),
      /session_route_(?:input_invalid|binding_duplicate)/);
    } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
  }
});

test('multi-key rings require an explicit route key and sign with the consumer version, not current', () => {
  const sample = fixture();
  try {
    sample.ring.keys['ctx-vitae-v1'] = crypto.randomBytes(32).toString('base64');
    privateJson(sample.contextKeyRingPath, sample.ring);
    const options = { inputPath: sample.inputPath, contextKeyRingPath: sample.contextKeyRingPath,
      manifestPath: sample.manifestPath, serviceOwnerUid: sample.serviceOwnerUid };
    assert.throws(() => provisionSessionRoutes({ ...options, dryRun: true }),
      /session_route_key_version_required/);
    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v2', bindings: [
      { ...sample.binding, keyVersion: null }
    ] });
    assert.throws(() => provisionSessionRoutes({ ...options, dryRun: true }),
      /session_route_key_version_invalid/);
    assert.throws(() => issueSessionRouteBinding({ ...sample.binding, keyVersion: null }, sample.ring),
      /context_key_version_invalid/);

    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v2', bindings: [
      { ...sample.binding, keyVersion: 'ctx-vitae-v1' }
    ] });
    asRoot(() => provisionSessionRoutes(options));
    const manifest = JSON.parse(fs.readFileSync(sample.manifestPath, 'utf8'));
    assert.equal(manifest.bindings[0].keyVersion, 'ctx-vitae-v1');
    const verifier = new ContextTokenVerifier({ keyRing: sample.ring, policyRevision: '' });
    assert.equal(verifier.verifySessionRouteBinding(manifest.bindings[0]).keyVersion, 'ctx-vitae-v1');
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('legacy v1 input supports an explicit CLI key version and rejects conflicts or unknown versions', () => {
  const sample = fixture();
  try {
    sample.ring.keys['ctx-vitae-v1'] = crypto.randomBytes(32).toString('base64');
    privateJson(sample.contextKeyRingPath, sample.ring);
    const options = { inputPath: sample.inputPath, contextKeyRingPath: sample.contextKeyRingPath,
      manifestPath: sample.manifestPath, serviceOwnerUid: sample.serviceOwnerUid, dryRun: true };
    assert.equal(provisionSessionRoutes({ ...options, keyVersion: 'ctx-vitae-v1' }).ok, true);
    assert.throws(() => provisionSessionRoutes({ ...options, keyVersion: 'ctx-missing' }),
      /session_route_key_version_invalid/);
    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v2', bindings: [
      { ...sample.binding, keyVersion: 'ctx-vitae-v1' }
    ] });
    assert.throws(() => provisionSessionRoutes({ ...options, keyVersion: 'ctx-v1' }),
      /session_route_key_version_conflict/);

    const cli = path.resolve('scripts/amf-provision-session-routes.mjs');
    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v1', bindings: [sample.binding] });
    const result = spawnSync(process.execPath, [cli, '--input', sample.inputPath,
      '--context-key-ring', sample.contextKeyRingPath, '--manifest', sample.manifestPath,
      '--service-owner-uid', String(sample.serviceOwnerUid), '--key-version', 'ctx-vitae-v1', '--dry-run'],
    { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).ok, true);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('concurrent route updates cannot lose a binding and a lock-conflicted writer retries cleanly', () => {
  const sample = fixture(); const secondInputPath = path.join(sample.root, 'second-input.json');
  const secondBinding = { actor: 'agent:vitae', canonicalScope: 'room:vitae:second',
    conversationKind: 'group', contextTags: { conversation: [TAG_B], room: [TAG_B] } };
  privateJson(secondInputPath, { schema: 'amf.session-route-input/v1', bindings: [secondBinding] });
  const common = { contextKeyRingPath: sample.contextKeyRingPath, manifestPath: sample.manifestPath,
    serviceOwnerUid: sample.serviceOwnerUid };
  const originalOpen = fs.openSync; let nestedError; let intercepted = false;
  fs.openSync = function concurrentOpen(filePath, flags, ...args) {
    const fd = originalOpen.call(fs, filePath, flags, ...args);
    if (!intercepted && String(filePath).endsWith('.manifest.json.lock')
      && typeof flags === 'number' && (flags & fs.constants.O_EXCL)) {
      intercepted = true;
      try { asRoot(() => provisionSessionRoutes({ ...common, inputPath: secondInputPath })); }
      catch (error) { nestedError = error; }
    }
    return fd;
  };
  try {
    asRoot(() => provisionSessionRoutes({ ...common, inputPath: sample.inputPath }));
  } finally { fs.openSync = originalOpen; }
  try {
    assert.match(nestedError?.message || '', /session_route_lock_held/);
    asRoot(() => provisionSessionRoutes({ ...common, inputPath: secondInputPath }));
    const manifest = JSON.parse(fs.readFileSync(sample.manifestPath, 'utf8'));
    assert.deepEqual(manifest.bindings.map(item => item.canonicalScope).sort(),
      ['room:vitae:second', 'room:vitae:topic']);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('last-moment CAS rejects a same-inode same-size mutation without overwriting it', () => {
  const sample = fixture();
  const options = { inputPath: sample.inputPath, contextKeyRingPath: sample.contextKeyRingPath,
    manifestPath: sample.manifestPath, serviceOwnerUid: sample.serviceOwnerUid };
  try {
    asRoot(() => provisionSessionRoutes(options));
    privateJson(sample.inputPath, { schema: 'amf.session-route-input/v1', bindings: [
      { ...sample.binding, contextTags: { conversation: [TAG_B], room: [TAG_B] } }
    ] });
    const original = fs.readFileSync(sample.manifestPath);
    const external = Buffer.from(original); external[external.length - 1] = 0x20;
    const originalLstat = fs.lstatSync; let manifestStats = 0;
    fs.lstatSync = function mutatingLstat(filePath, ...args) {
      if (String(filePath).endsWith('/manifest.json') && ++manifestStats === 3) {
        fs.writeFileSync(sample.manifestPath, external, { mode: 0o600 });
      }
      return originalLstat.call(fs, filePath, ...args);
    };
    try {
      assert.throws(() => asRoot(() => provisionSessionRoutes(options)), /session_route_manifest_changed/);
    } finally { fs.lstatSync = originalLstat; }
    assert.deepEqual(fs.readFileSync(sample.manifestPath), external);
    assert.equal(fs.existsSync(path.join(sample.root, '.manifest.json.lock')), false);
    assert.equal(fs.readdirSync(sample.root).some(name => name.includes('.tmp.') || name.includes('.bak.')), false);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});

test('create publishes with atomic no-replace and preserves a racing target', () => {
  const sample = fixture();
  const options = { inputPath: sample.inputPath, contextKeyRingPath: sample.contextKeyRingPath,
    manifestPath: sample.manifestPath, serviceOwnerUid: sample.serviceOwnerUid };
  const external = Buffer.from('{"external":true}\n'); const originalLink = fs.linkSync; let injected = false;
  fs.linkSync = function racingLink(source, destination, ...args) {
    if (!injected && String(destination).endsWith('/manifest.json')) {
      injected = true; fs.writeFileSync(sample.manifestPath, external, { mode: 0o600 });
    }
    return originalLink.call(fs, source, destination, ...args);
  };
  try {
    assert.throws(() => asRoot(() => provisionSessionRoutes(options)), /session_route_manifest_changed/);
  } finally { fs.linkSync = originalLink; }
  try {
    assert.deepEqual(fs.readFileSync(sample.manifestPath), external);
    assert.equal(fs.existsSync(path.join(sample.root, '.manifest.json.lock')), false);
    assert.equal(fs.readdirSync(sample.root).some(name => name.includes('.tmp.')), false);
  } finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
});
