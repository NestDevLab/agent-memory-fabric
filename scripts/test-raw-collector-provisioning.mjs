import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { provisionRawCollector, RAW_COLLECTOR_PERMISSIONS } from '../src/operator/raw-collector-provisioning.mjs';

const FIXED_NOW = new Date('2026-07-12T18:00:00.000Z');

function key() { return crypto.randomBytes(32).toString('base64'); }

function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-collector-provision-'));
  const authRegistryPath = path.join(root, 'auth-registry.json');
  const policyPath = path.join(root, 'policy.json');
  const ingestKeyRingPath = path.join(root, 'ingest-key-ring.json');
  const routingKeyRingPath = path.join(root, 'routing-key-ring.json');
  const backupRoot = path.join(root, 'backups'); const handoffParent = path.join(root, 'handoffs');
  fs.mkdirSync(backupRoot, { mode: 0o700 }); fs.mkdirSync(handoffParent, { mode: 0o700 });
  privateJson(authRegistryPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'),
    active: true, actor: 'existing-actor', mode: 'scoped', allowedScopes: ['agent:existing-actor'],
    permissions: RAW_COLLECTOR_PERMISSIONS }] });
  privateJson(policyPath, { actors: { 'existing-actor': { mode: 'scoped', allowedScopes: ['agent:existing-actor'] } },
    scopes: { 'agent:existing-actor': { backendUserId: 'existing-actor' } } });
  privateJson(ingestKeyRingPath, { keys: { 'existing-v1': key() }, digestKey: key(),
    logicalMessageKeys: { currentKeyVersion: 'logical-v1', keys: { 'logical-v1': key() } },
    authorizations: { 'existing-v1': { actors: ['existing-actor'], sourceInstances: ['existing-source'] } } });
  privateJson(routingKeyRingPath, { currentKeyVersion: 'routing-v1', keys: { 'routing-v1': key() } });
  const options = { authRegistryPath, policyPath, ingestKeyRingPath, routingKeyRingPath,
    actorId: 'ct110-hermes-vitae', sourceInstanceId: 'ct110-hermes-vitae', keyId: 'ct110-hermes-vitae-v1',
    handoffPath: path.join(handoffParent, 'ct110-hermes-vitae'), backupRoot,
    serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid, clock: () => FIXED_NOW };
  return { root, options };
}

function json(filePath) { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
function bytes(filePath) { return fs.readFileSync(filePath); }
function mode(filePath) { return fs.statSync(filePath).mode & 0o777; }
function decoded(value) { return Buffer.from(value, 'base64').toString('hex'); }

function withEffectiveUid(uid, operation) {
  const original = process.geteuid;
  process.geteuid = () => uid;
  try { return operation(); } finally { process.geteuid = original; }
}

function asRoot(operation) { return withEffectiveUid(0, operation); }

function instrumentWrites(operation) {
  const calls = []; const originals = new Map();
  const methods = ['chmodSync', 'chownSync', 'fchmodSync', 'fchownSync', 'fsyncSync', 'mkdirSync',
    'renameSync', 'rmSync', 'unlinkSync', 'writeFileSync'];
  for (const name of methods) {
    originals.set(name, fs[name]);
    fs[name] = function instrumentedWrite(...args) { calls.push(name); return originals.get(name).call(fs, ...args); };
  }
  const originalOpen = fs.openSync; originals.set('openSync', originalOpen);
  fs.openSync = function instrumentedOpen(filePath, flags, ...args) {
    const mask = fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT
      | fs.constants.O_TRUNC | fs.constants.O_APPEND;
    const writes = typeof flags === 'string' ? flags !== 'r' && flags !== 'rs' : (flags & mask) !== 0;
    if (writes) calls.push('openSync');
    return originalOpen.call(fs, filePath, flags, ...args);
  };
  try { return { result: operation(), calls }; }
  finally { for (const [name, original] of originals) fs[name] = original; }
}

test('provisioning atomically installs least-privilege actor, unique key and private handoff', () => {
  const { root, options } = fixture();
  try {
    const before = {
      auth: bytes(options.authRegistryPath), policy: bytes(options.policyPath),
      ingest: bytes(options.ingestKeyRingPath), routing: bytes(options.routingKeyRingPath)
    };
    const ownership = Object.fromEntries([options.authRegistryPath, options.policyPath, options.ingestKeyRingPath]
      .map(filePath => [filePath, { uid: fs.statSync(filePath).uid, gid: fs.statSync(filePath).gid }]));
    const result = asRoot(() => provisionRawCollector(options));
    assert.deepEqual(result.permissions, ['memory:status', 'raw:ingest']);
    assert.equal(result.scope, 'agent:ct110-hermes-vitae'); assert.equal(result.dryRun, false);
    assert.equal(mode(options.handoffPath), 0o700); assert.equal(mode(result.backupPath), 0o700);
    const expectedFiles = ['bearer.token', 'cursor.key', 'digest.key', 'ingest-master.key', 'lease.key',
      'logical-message-key-ring.json', 'manifest.json', 'routing-key-ring.json'];
    assert.deepEqual(fs.readdirSync(options.handoffPath).sort(), expectedFiles);
    for (const name of expectedFiles) assert.equal(mode(path.join(options.handoffPath, name)), 0o600);
    for (const name of fs.readdirSync(result.backupPath)) assert.equal(mode(path.join(result.backupPath, name)), 0o600);
    for (const [filePath, owner] of Object.entries(ownership)) {
      assert.equal(mode(filePath), 0o600); assert.equal(fs.statSync(filePath).uid, owner.uid); assert.equal(fs.statSync(filePath).gid, owner.gid);
    }

    const registry = json(options.authRegistryPath); const row = registry.rows.find(item => item.actor === options.actorId);
    const bearer = fs.readFileSync(path.join(options.handoffPath, 'bearer.token'), 'utf8').trim();
    assert.equal(row.tokenSha256, crypto.createHash('sha256').update(bearer).digest('hex'));
    assert.equal(Object.hasOwn(row, 'token'), false); assert.equal(row.active, true); assert.equal(row.mode, 'scoped');
    assert.deepEqual(row.allowedScopes, [`agent:${options.actorId}`]); assert.deepEqual(row.permissions, RAW_COLLECTOR_PERMISSIONS);

    const policy = json(options.policyPath);
    assert.deepEqual(policy.actors[options.actorId], { mode: 'scoped', allowedScopes: [`agent:${options.actorId}`] });
    assert.deepEqual(policy.scopes[`agent:${options.actorId}`], { backendUserId: options.actorId });
    const ring = json(options.ingestKeyRingPath);
    assert.deepEqual(ring.authorizations[options.keyId], { actors: [options.actorId], sourceInstances: [options.sourceInstanceId] });
    assert.equal(fs.readFileSync(path.join(options.handoffPath, 'ingest-master.key'), 'utf8').trim(), ring.keys[options.keyId]);
    assert.equal(fs.readFileSync(path.join(options.handoffPath, 'digest.key'), 'utf8').trim(), ring.digestKey);
    assert.deepEqual(json(path.join(options.handoffPath, 'logical-message-key-ring.json')), ring.logicalMessageKeys);
    assert.deepEqual(json(path.join(options.handoffPath, 'routing-key-ring.json')), json(options.routingKeyRingPath));
    const cryptoValues = [
      ...Object.values(ring.keys), ring.digestKey, ...Object.values(ring.logicalMessageKeys.keys),
      ...Object.values(json(options.routingKeyRingPath).keys),
      fs.readFileSync(path.join(options.handoffPath, 'cursor.key'), 'utf8').trim(),
      fs.readFileSync(path.join(options.handoffPath, 'lease.key'), 'utf8').trim()
    ].map(decoded);
    assert.equal(new Set(cryptoValues).size, cryptoValues.length);

    assert.deepEqual(bytes(path.join(result.backupPath, 'auth-registry.json')), before.auth);
    assert.deepEqual(bytes(path.join(result.backupPath, 'policy.json')), before.policy);
    assert.deepEqual(bytes(path.join(result.backupPath, 'ingest-key-ring.json')), before.ingest);
    assert.deepEqual(bytes(path.join(result.backupPath, 'routing-key-ring.json')), before.routing);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.collector-provision.lock`), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('dry-run validates the complete transaction with zero filesystem writes', () => {
  const { root, options } = fixture();
  try {
    const originals = [options.authRegistryPath, options.policyPath, options.ingestKeyRingPath].map(bytes);
    const observed = instrumentWrites(() => provisionRawCollector({ ...options, dryRun: true }));
    const result = observed.result;
    assert.equal(result.dryRun, true); assert.equal(result.backupPath, null);
    assert.deepEqual(observed.calls, []);
    assert.equal(fs.existsSync(options.handoffPath), false); assert.deepEqual(fs.readdirSync(options.backupRoot), []);
    assert.deepEqual([options.authRegistryPath, options.policyPath, options.ingestKeyRingPath].map(bytes), originals);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.collector-provision.lock`), false);

    fs.chmodSync(options.backupRoot, 0o755);
    assert.throws(() => provisionRawCollector({ ...options, dryRun: true }), /collector_backup_root_unsafe/);
    fs.chmodSync(options.backupRoot, 0o700); fs.chmodSync(path.dirname(options.handoffPath), 0o755);
    assert.throws(() => provisionRawCollector({ ...options, dryRun: true }), /collector_handoff_parent_unsafe/);
    fs.chmodSync(path.dirname(options.handoffPath), 0o700); fs.mkdirSync(options.handoffPath, { mode: 0o700 });
    assert.throws(() => provisionRawCollector({ ...options, dryRun: true }), /collector_handoff_exists/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('live provisioning requires root while non-root dry-run remains read-only', () => {
  const { root, options } = fixture();
  try {
    const nonRootUid = options.serviceOwnerUid || 1000;
    assert.throws(() => withEffectiveUid(nonRootUid, () => provisionRawCollector(options)), /collector_root_required/);
    const observed = withEffectiveUid(nonRootUid,
      () => instrumentWrites(() => provisionRawCollector({ ...options, dryRun: true })));
    assert.equal(observed.result.ok, true); assert.deepEqual(observed.calls, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('partial actor or source-instance authorization matches are provisioning conflicts', () => {
  for (const collision of ['actor', 'source']) {
    const { root, options } = fixture();
    try {
      const ring = json(options.ingestKeyRingPath);
      if (collision === 'actor') ring.authorizations['existing-v1'].actors.push(options.actorId);
      else ring.authorizations['existing-v1'].sourceInstances.push(options.sourceInstanceId);
      privateJson(options.ingestKeyRingPath, ring);
      assert.throws(() => provisionRawCollector({ ...options, dryRun: true }), /collector_provisioning_conflict/, collision);
      assert.equal(fs.existsSync(options.handoffPath), false);
      assert.equal(fs.existsSync(`${options.authRegistryPath}.collector-provision.lock`), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('provisioning is idempotent fail-closed and exposes no unsafe rotation path', () => {
  const { root, options } = fixture();
  try {
    asRoot(() => provisionRawCollector(options));
    assert.throws(() => asRoot(() => provisionRawCollector({ ...options,
      handoffPath: `${options.handoffPath}-again` })), /collector_already_provisioned/);
    assert.equal(json(options.authRegistryPath).rows.filter(row => row.actor === options.actorId).length, 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('handled transaction faults restore all server files and remove staged handoff', () => {
  for (const faultAt of ['after-ingest-key-ring-before-fsync', 'after-auth-registry', 'after-ingest-key-ring',
    'after-policy', 'after-handoff-before-fsync', 'after-handoff']) {
    const { root, options } = fixture();
    try {
      const originals = new Map([options.authRegistryPath, options.policyPath, options.ingestKeyRingPath]
        .map(filePath => [filePath, bytes(filePath)]));
      assert.throws(() => asRoot(() => provisionRawCollector({ ...options, faultAt })), new RegExp(`collector_test_fault_${faultAt}`));
      for (const [filePath, original] of originals) assert.deepEqual(bytes(filePath), original, faultAt);
      assert.equal(fs.existsSync(options.handoffPath), false); assert.equal(fs.existsSync(`${options.authRegistryPath}.collector-provision.lock`), false);
      assert.equal(fs.readdirSync(options.backupRoot).length, 1, 'recovery evidence must remain');
      if (faultAt === 'after-policy') {
        const retried = asRoot(() => provisionRawCollector(options));
        assert.equal(retried.ok, true); assert.equal(fs.existsSync(options.handoffPath), true);
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('a rollback failure preserves the lock and blocks retry against partial state', () => {
  const { root, options } = fixture();
  try {
    const originalPolicy = bytes(options.policyPath);
    assert.throws(() => asRoot(() => provisionRawCollector({ ...options,
      faultAt: ['after-policy', 'rollback-policy'] })), /collector_provisioning_rollback_failed/);
    assert.notDeepEqual(bytes(options.policyPath), originalPolicy, 'simulated failed restore leaves evidence of partial state');
    assert.equal(fs.existsSync(options.handoffPath), false);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.collector-provision.lock`), true);
    assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_provisioning_locked/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('unsafe permissions, duplicate crypto and held locks fail before handoff', () => {
  {
    const { root, options } = fixture();
    try {
      fs.chmodSync(options.authRegistryPath, 0o644);
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_auth_registry_file_unsafe/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      fs.linkSync(options.authRegistryPath, path.join(root, 'auth-registry-hardlink.json'));
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_auth_registry_file_unsafe/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      const original = `${options.authRegistryPath}.original`;
      fs.renameSync(options.authRegistryPath, original); fs.symlinkSync(original, options.authRegistryPath);
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_auth_registry_file_unsafe/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture(); const originalOpen = fs.openSync; let swapped = false;
    try {
      const validated = `${options.authRegistryPath}.validated`; const outside = path.join(root, 'outside-auth.json');
      privateJson(outside, json(options.authRegistryPath));
      fs.openSync = function swapBeforeOpen(filePath, flags, ...args) {
        if (!swapped && path.resolve(String(filePath)) === options.authRegistryPath) {
          fs.renameSync(options.authRegistryPath, validated); fs.symlinkSync(outside, options.authRegistryPath); swapped = true;
        }
        return originalOpen.call(fs, filePath, flags, ...args);
      };
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_auth_registry_file_unsafe/);
      assert.equal(swapped, true); assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.openSync = originalOpen; fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture(); const alias = `${root}-symlink`;
    try {
      fs.symlinkSync(root, alias);
      const throughAlias = Object.fromEntries(Object.entries(options).map(([name, value]) => [name,
        typeof value === 'string' && value.startsWith(root) ? `${alias}${value.slice(root.length)}` : value]));
      assert.throws(() => asRoot(() => provisionRawCollector(throughAlias)), /collector_lock_directory_unsafe/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(alias, { force: true }); fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      if ((process.geteuid?.() ?? 1) === 0) fs.chownSync(options.authRegistryPath, 65534, 65534);
      else options.serviceOwnerUid += 1;
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_(?:lock_directory|auth_registry_file)_unsafe/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      const ring = json(options.ingestKeyRingPath); ring.digestKey = ring.keys['existing-v1']; privateJson(options.ingestKeyRingPath, ring);
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_crypto_key_reuse_detected/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      fs.writeFileSync(`${options.authRegistryPath}.collector-provision.lock`, '{}', { mode: 0o600 });
      assert.throws(() => asRoot(() => provisionRawCollector(options)), /collector_provisioning_locked/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('operator CLI emits safe metadata only and never accepts secret argv', () => {
  const { root, options } = fixture();
  try {
    const cli = path.resolve('scripts/amf-provision-raw-collector.mjs');
    const args = ['--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--ingest-key-ring', options.ingestKeyRingPath, '--routing-key-ring', options.routingKeyRingPath,
      '--actor', options.actorId, '--source-instance', options.sourceInstanceId, '--key-id', options.keyId,
      '--handoff', options.handoffPath, '--backup-root', options.backupRoot,
      '--service-owner-uid', String(options.serviceOwnerUid), '--dry-run'];
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
    const output = JSON.parse(result.stdout); assert.equal(output.ok, true);
    assert.equal(/token|bearer|sha256|master\.key|digest\.key|cursor\.key|lease\.key/i.test(result.stdout), false);
    const rejected = spawnSync(process.execPath, [cli, '--token', 'must-not-be-echoed'], { encoding: 'utf8' });
    assert.equal(rejected.status, 1); assert.equal(rejected.stdout, '');
    assert.deepEqual(JSON.parse(rejected.stderr), { ok: false, error: 'cli_argument_unknown' });
    assert.equal(rejected.stderr.includes('must-not-be-echoed'), false);
    const rotate = spawnSync(process.execPath, [cli, '--rotate'], { encoding: 'utf8' });
    assert.equal(rotate.status, 1); assert.deepEqual(JSON.parse(rotate.stderr), { ok: false, error: 'cli_argument_unknown' });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
