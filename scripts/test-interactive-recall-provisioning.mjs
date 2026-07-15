import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  INTERACTIVE_RECALL_HANDOFF_SCHEMA,
  INTERACTIVE_RECALL_PERMISSIONS,
  INTERACTIVE_RECALL_SCOPES,
  interactiveRecallProfile,
  provisionInteractiveRecall
} from '../src/operator/interactive-recall-provisioning.mjs';
import { loadInteractiveRecallHandoff } from '../src/operator/interactive-recall-mcp.mjs';

const FIXED_NOW = new Date('2026-07-15T09:00:00.000Z');

function key() { return crypto.randomBytes(32).toString('base64'); }
function bytes(filePath) { return fs.readFileSync(filePath); }
function json(filePath) { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}
function mode(filePath) { return fs.statSync(filePath).mode & 0o777; }

function nonRootOwner() {
  try {
    const row = fs.readFileSync('/etc/passwd', 'utf8').split('\n').map(line => line.split(':'))
      .find(fields => /^\d+$/.test(fields[2] || '') && Number(fields[2]) !== 0);
    return row ? { uid: Number(row[2]), gid: Number(row[3]) } : null;
  } catch { return null; }
}

function fixture(profile) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-interactive-recall-'));
  const authRegistryPath = path.join(root, 'auth-registry.json');
  const policyPath = path.join(root, 'policy.json');
  const contextKeyRingPath = path.join(root, 'context-key-ring.json');
  const backupRoot = path.join(root, 'backups'); const handoffParent = path.join(root, 'handoffs');
  fs.mkdirSync(backupRoot, { mode: 0o700 }); fs.mkdirSync(handoffParent, { mode: 0o700 });
  privateJson(authRegistryPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'),
    active: true, actor: 'existing-actor', mode: 'scoped', allowedScopes: ['domain:existing'],
    permissions: ['memory:search'] }] });
  privateJson(policyPath, { actors: { 'existing-actor': { mode: 'scoped', allowedScopes: ['domain:existing'] } },
    scopes: { 'domain:existing': { backendUserId: 'existing' } } });
  privateJson(contextKeyRingPath, { currentKeyVersion: 'ctx-existing-v1', keys: { 'ctx-existing-v1': key() } });
  return { root, options: { profile, authRegistryPath, policyPath, contextKeyRingPath,
    handoffPath: path.join(handoffParent, profile), backupRoot, backendUserId: 'openmemory',
    serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid, policyRevision: 'policy-v1',
    endpoint: 'https://amf.example.test/', clock: () => FIXED_NOW } };
}

function withEffectiveUid(uid, operation) {
  const original = process.geteuid; process.geteuid = () => uid;
  try { return operation(); } finally { process.geteuid = original; }
}

function instrumentWrites(operation) {
  const calls = []; const originals = new Map();
  const methods = ['chmodSync', 'chownSync', 'fchmodSync', 'fchownSync', 'fsyncSync', 'mkdirSync',
    'renameSync', 'rmSync', 'unlinkSync', 'writeFileSync'];
  for (const name of methods) {
    originals.set(name, fs[name]);
    fs[name] = function instrumented(...args) { calls.push(name); return originals.get(name).call(fs, ...args); };
  }
  const originalOpen = fs.openSync; originals.set('openSync', originalOpen);
  fs.openSync = function instrumentedOpen(filePath, flags, ...args) {
    const mask = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT
      | fs.constants.O_TRUNC | fs.constants.O_APPEND;
    if (typeof flags === 'string' ? flags !== 'r' && flags !== 'rs' : (flags & mask) !== 0) calls.push('openSync');
    return originalOpen.call(fs, filePath, flags, ...args);
  };
  try { return { result: operation(), calls }; }
  finally { for (const [name, original] of originals) fs[name] = original; }
}

test('Codex and Claude dry-runs are exact, read-only, and never generate secrets', () => {
  for (const profile of ['codex', 'claude']) {
    const { root, options } = fixture(profile);
    try {
      const originals = [options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes);
      const observed = instrumentWrites(() => provisionInteractiveRecall({ ...options, dryRun: true,
        randomBytes() { throw new Error('random_must_not_run'); } }));
      const expected = interactiveRecallProfile(profile);
      assert.deepEqual(observed.calls, []); assert.equal(observed.result.dryRun, true);
      assert.equal(observed.result.actor, expected.actor); assert.equal(observed.result.contextKeyVersion, expected.contextKeyVersion);
      assert.deepEqual(observed.result.permissions, INTERACTIVE_RECALL_PERMISSIONS);
      assert.deepEqual(observed.result.scopes, INTERACTIVE_RECALL_SCOPES);
      assert.equal(observed.result.backupPath, null); assert.equal(fs.existsSync(options.handoffPath), false);
      assert.deepEqual(fs.readdirSync(options.backupRoot), []);
      assert.deepEqual([options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes), originals);
      assert.equal(JSON.stringify(observed.result).includes('bearer'), false);
      assert.equal(JSON.stringify(observed.result).includes('context-key-ring'), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('the interactive provisioner writes only the strict profile and handoff metadata', () => {
  const { root, options } = fixture('codex');
  try {
    const expected = interactiveRecallProfile('codex');
    const result = withEffectiveUid(0, () => provisionInteractiveRecall(options));
    assert.equal(result.ok, true); assert.equal(result.schema, INTERACTIVE_RECALL_HANDOFF_SCHEMA);
    assert.equal(result.actor, 'agent:codex'); assert.equal(result.contextKeyVersion, 'ctx-codex-v1');
    assert.deepEqual(result.permissions, INTERACTIVE_RECALL_PERMISSIONS); assert.deepEqual(result.scopes, INTERACTIVE_RECALL_SCOPES);
    assert.equal(mode(options.handoffPath), 0o700);
    assert.deepEqual(fs.readdirSync(options.handoffPath).sort(), ['bearer.token', 'context-key-ring.json', 'manifest.json']);
    for (const name of fs.readdirSync(options.handoffPath)) assert.equal(mode(path.join(options.handoffPath, name)), 0o600);
    const registryRow = json(options.authRegistryPath).rows.find(row => row.actor === 'agent:codex');
    assert.deepEqual(Object.keys(registryRow).sort(), ['active', 'actor', 'allowedScopes', 'contextKeyVersions', 'mode', 'permissions', 'tokenSha256']);
    assert.equal(registryRow.active, true); assert.equal(registryRow.mode, 'read_only_scoped');
    assert.deepEqual(registryRow.allowedScopes, INTERACTIVE_RECALL_SCOPES);
    assert.deepEqual(registryRow.permissions, INTERACTIVE_RECALL_PERMISSIONS);
    assert.deepEqual(registryRow.contextKeyVersions, ['ctx-codex-v1']);
    assert.equal(Object.hasOwn(registryRow, 'token'), false);
    assert.deepEqual(json(options.policyPath).actors['agent:codex'], { mode: 'read_only_scoped',
      allowedScopes: INTERACTIVE_RECALL_SCOPES, contextKeyVersions: ['ctx-codex-v1'] });
    assert.deepEqual(json(path.join(options.handoffPath, 'manifest.json')), {
      schema: INTERACTIVE_RECALL_HANDOFF_SCHEMA, actor: expected.actor, runtime: expected.runtime,
      profile: expected.profile, contextKeyVersion: expected.contextKeyVersion,
      permissions: INTERACTIVE_RECALL_PERMISSIONS, scopes: INTERACTIVE_RECALL_SCOPES,
      scopeSetSha256: result.scopeSetSha256, purpose: 'conversation_recall',
      sessionDescriptor: expected.sessionDescriptor, policyRevision: 'policy-v1',
      endpoint: 'https://amf.example.test/', createdAt: FIXED_NOW.toISOString()
    });
    assert.equal(fs.readdirSync(options.handoffPath).some(name => /raw|session|proposal|decrypt/i.test(name)), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('profile, scope, capability, and endpoint widening are rejected before writes', () => {
  const { root, options } = fixture('codex');
  try {
    for (const override of [
      { profile: 'vitae' }, { scopes: ['shared:global', 'person:joseph'] }, { actor: 'agent:other' },
      { endpoint: 'http://127.0.0.1/' }, { endpoint: 'https://amf.example.test/v2/' }
    ]) {
      assert.throws(() => provisionInteractiveRecall({ ...options, ...override, dryRun: true }), /interactive_recall_/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('non-root live provisioning is blocked while dry-run remains read-only', () => {
  const { root, options } = fixture('claude');
  try {
    const nonRoot = options.serviceOwnerUid || 1000;
    assert.throws(() => withEffectiveUid(nonRoot, () => provisionInteractiveRecall(options)), /recall_consumer_root_required/);
    const observed = withEffectiveUid(nonRoot, () => instrumentWrites(() => provisionInteractiveRecall({ ...options, dryRun: true })));
    assert.equal(observed.result.ok, true); assert.deepEqual(observed.calls, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the separate CLI accepts only the strict interactive profile contract in dry-run mode', () => {
  const { root, options } = fixture('claude');
  try {
    const args = ['scripts/amf-provision-interactive-recall.mjs', '--dry-run', '--profile', options.profile,
      '--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--context-key-ring', options.contextKeyRingPath, '--handoff', options.handoffPath,
      '--backup-root', options.backupRoot, '--backend-user-id', options.backendUserId,
      '--service-owner-uid', String(options.serviceOwnerUid), '--policy-revision', options.policyRevision,
      '--endpoint', options.endpoint];
    const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(result.status, 0); assert.equal(result.stderr, '');
    const output = JSON.parse(result.stdout);
    assert.deepEqual(output.scopes, ['shared:global']);
    assert.deepEqual(output.permissions, INTERACTIVE_RECALL_PERMISSIONS);
    assert.equal(JSON.stringify(output).includes('bearer'), false);
    const widened = spawnSync(process.execPath, [...args, '--scope', 'person:joseph'], { encoding: 'utf8' });
    assert.equal(widened.status, 1); assert.match(widened.stderr, /cli_argument_unknown/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('actual root provisioning transfers the final handoff to the service owner', {
  skip: (process.geteuid?.() ?? -1) !== 0 || !nonRootOwner()
}, () => {
  const owner = nonRootOwner(); const { root, options } = fixture('codex');
  try {
    options.serviceOwnerUid = owner.uid;
    fs.chmodSync(root, 0o755);
    fs.chownSync(path.dirname(options.handoffPath), owner.uid, owner.gid);
    fs.chmodSync(path.dirname(options.handoffPath), 0o700);
    provisionInteractiveRecall(options);
    assert.equal(fs.statSync(options.handoffPath).uid, owner.uid);
    for (const name of fs.readdirSync(options.handoffPath)) {
      const stat = fs.statSync(path.join(options.handoffPath, name));
      assert.equal(stat.uid, owner.uid); assert.equal(stat.mode & 0o777, 0o600);
    }
    assert.equal(fs.statSync(options.handoffPath).mode & 0o777, 0o700);
    assert.equal(withEffectiveUid(owner.uid, () => loadInteractiveRecallHandoff(options.handoffPath)).actor, 'agent:codex');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
