import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';
import {
  provisionRecallConsumer,
  RECALL_CONSUMER_ACTOR,
  RECALL_CONSUMER_CONTEXT_KEY_VERSION,
  RECALL_CONSUMER_HANDOFF_SCHEMA,
  RECALL_CONSUMER_MAX_ADDITIONAL_SCOPES,
  RECALL_CONSUMER_PERMISSIONS,
  RECALL_CONSUMER_SESSION_OWNER_ACTORS,
  RECALL_CONSUMER_SCOPES
} from '../src/operator/recall-consumer-provisioning.mjs';

const FIXED_NOW = new Date('2026-07-12T20:00:00.000Z');

function key() { return crypto.randomBytes(32).toString('base64'); }
function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 }); fs.chmodSync(filePath, 0o600);
}
function json(filePath) { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
function bytes(filePath) { return fs.readFileSync(filePath); }
function mode(filePath) { return fs.statSync(filePath).mode & 0o777; }

function fixture({ withExistingScope = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-recall-consumer-'));
  const authRegistryPath = path.join(root, 'auth-registry.json');
  const policyPath = path.join(root, 'policy.json');
  const contextKeyRingPath = path.join(root, 'context-key-ring.json');
  const backupRoot = path.join(root, 'backups'); const handoffParent = path.join(root, 'handoffs');
  fs.mkdirSync(backupRoot, { mode: 0o700 }); fs.mkdirSync(handoffParent, { mode: 0o700 });
  privateJson(authRegistryPath, { rows: [{ tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'),
    active: true, actor: 'existing-actor', mode: 'scoped', allowedScopes: ['domain:existing'],
    permissions: ['memory:search'] }, { tokenSha256: crypto.createHash('sha256').update('collector').digest('hex'),
    active: true, actor: RECALL_CONSUMER_SESSION_OWNER_ACTORS[0], mode: 'scoped',
    allowedScopes: [`agent:${RECALL_CONSUMER_SESSION_OWNER_ACTORS[0]}`], permissions: ['memory:status', 'raw:ingest'] }] });
  const scopes = { 'domain:existing': { backendUserId: 'existing' } };
  if (withExistingScope) scopes['person:joseph'] = { backendUserId: 'existing-person' };
  privateJson(policyPath, { actors: { 'existing-actor': { mode: 'scoped', allowedScopes: ['domain:existing'] },
    [RECALL_CONSUMER_SESSION_OWNER_ACTORS[0]]: { mode: 'scoped',
      allowedScopes: [`agent:${RECALL_CONSUMER_SESSION_OWNER_ACTORS[0]}`] } }, scopes });
  privateJson(contextKeyRingPath, { currentKeyVersion: 'ctx-existing-v1', keys: { 'ctx-existing-v1': key() } });
  const options = { authRegistryPath, policyPath, contextKeyRingPath,
    handoffPath: path.join(handoffParent, 'vitae-recall'), backupRoot, backendUserId: 'openmemory',
    serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid, clock: () => FIXED_NOW };
  return { root, options };
}

function withEffectiveUid(uid, operation) {
  const original = process.geteuid; process.geteuid = () => uid;
  try { return operation(); } finally { process.geteuid = original; }
}
function asRoot(operation) { return withEffectiveUid(0, operation); }

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
    const writes = typeof flags === 'string' ? flags !== 'r' && flags !== 'rs' : (flags & mask) !== 0;
    if (writes) calls.push('openSync');
    return originalOpen.call(fs, filePath, flags, ...args);
  };
  try { return { result: operation(), calls }; }
  finally { for (const [name, original] of originals) fs[name] = original; }
}

test('provisions only the fixed Vitae recall principal and preserves server context keys', () => {
  const { root, options } = fixture();
  try {
    const original = { auth: bytes(options.authRegistryPath), policy: bytes(options.policyPath),
      context: bytes(options.contextKeyRingPath) };
    const oldRing = json(options.contextKeyRingPath);
    const result = asRoot(() => provisionRecallConsumer(options));
    assert.deepEqual(result, { ok: true, schema: RECALL_CONSUMER_HANDOFF_SCHEMA, action: 'provision', dryRun: false,
      actor: RECALL_CONSUMER_ACTOR, contextKeyVersion: RECALL_CONSUMER_CONTEXT_KEY_VERSION,
      permissions: RECALL_CONSUMER_PERMISSIONS, scopes: RECALL_CONSUMER_SCOPES,
      scopeSetSha256: result.scopeSetSha256,
      sessionOwnerActors: RECALL_CONSUMER_SESSION_OWNER_ACTORS,
      handoffPath: options.handoffPath, backupPath: result.backupPath });
    assert.equal(mode(options.handoffPath), 0o700); assert.equal(mode(result.backupPath), 0o700);
    assert.deepEqual(fs.readdirSync(options.handoffPath).sort(), ['bearer.token', 'context-key-ring.json', 'manifest.json']);
    for (const name of fs.readdirSync(options.handoffPath)) assert.equal(mode(path.join(options.handoffPath, name)), 0o600);
    for (const name of fs.readdirSync(result.backupPath)) assert.equal(mode(path.join(result.backupPath, name)), 0o600);

    const bearer = fs.readFileSync(path.join(options.handoffPath, 'bearer.token'), 'utf8').trim();
    const row = json(options.authRegistryPath).rows.find(item => item.actor === RECALL_CONSUMER_ACTOR);
    assert.equal(row.tokenSha256, crypto.createHash('sha256').update(bearer).digest('hex'));
    assert.equal(Object.hasOwn(row, 'token'), false); assert.equal(row.mode, 'read_only_scoped');
    assert.deepEqual(row.allowedScopes, RECALL_CONSUMER_SCOPES); assert.deepEqual(row.permissions, RECALL_CONSUMER_PERMISSIONS);
    assert.deepEqual(row.sessionOwnerActors, RECALL_CONSUMER_SESSION_OWNER_ACTORS);
    assert.deepEqual(row.contextKeyVersions, [RECALL_CONSUMER_CONTEXT_KEY_VERSION]);
    assert.deepEqual(json(options.policyPath).actors[RECALL_CONSUMER_ACTOR],
      { mode: 'read_only_scoped', allowedScopes: RECALL_CONSUMER_SCOPES,
        sessionOwnerActors: RECALL_CONSUMER_SESSION_OWNER_ACTORS,
        contextKeyVersions: [RECALL_CONSUMER_CONTEXT_KEY_VERSION] });
    assert.equal(json(options.policyPath).scopes['person:joseph'].backendUserId, 'existing-person');
    for (const scope of RECALL_CONSUMER_SCOPES.filter(value => value !== 'person:joseph')) {
      assert.equal(json(options.policyPath).scopes[scope].backendUserId, options.backendUserId);
    }

    const serverRing = json(options.contextKeyRingPath); const handoffRing = json(path.join(options.handoffPath, 'context-key-ring.json'));
    assert.equal(serverRing.currentKeyVersion, oldRing.currentKeyVersion);
    assert.equal(serverRing.keys['ctx-existing-v1'], oldRing.keys['ctx-existing-v1']);
    assert.deepEqual(handoffRing, { currentKeyVersion: RECALL_CONSUMER_CONTEXT_KEY_VERSION,
      keys: { [RECALL_CONSUMER_CONTEXT_KEY_VERSION]: serverRing.keys[RECALL_CONSUMER_CONTEXT_KEY_VERSION] } });
    assert.notEqual(Buffer.from(bearer, 'base64url').toString('hex'),
      Buffer.from(serverRing.keys[RECALL_CONSUMER_CONTEXT_KEY_VERSION], 'base64').toString('hex'));
    assert.deepEqual(json(path.join(options.handoffPath, 'manifest.json')), {
      schema: RECALL_CONSUMER_HANDOFF_SCHEMA, actor: RECALL_CONSUMER_ACTOR,
      contextKeyVersion: RECALL_CONSUMER_CONTEXT_KEY_VERSION, permissions: RECALL_CONSUMER_PERMISSIONS,
      scopes: RECALL_CONSUMER_SCOPES, scopeSetSha256: result.scopeSetSha256,
      sessionOwnerActors: RECALL_CONSUMER_SESSION_OWNER_ACTORS,
      purpose: 'conversation_recall', createdAt: FIXED_NOW.toISOString()
    });
    const request = { operation: 'memory_search', input: { query: 'appointment',
      scopes: ['room:vitae:joseph-dm'], purpose: 'conversation_recall' } };
    const token = issueContextToken({ actor: RECALL_CONSUMER_ACTOR, runtime: 'principia', profile: 'vitae',
      conversationKind: 'dm', contextTags: { room: [`hmac-sha256:routing-v1:${'a'.repeat(64)}`] },
      purpose: 'conversation_recall', policyRevision: 'policy-test',
      issuedAt: new Date(FIXED_NOW.getTime() - 1_000).toISOString(),
      expiresAt: new Date(FIXED_NOW.getTime() + 60_000).toISOString(), nonce: 'vitaeconsumer0001',
      requestDigest: requestDigest(request) }, handoffRing);
    assert.equal(new ContextTokenVerifier({ keyRing: serverRing, policyRevision: 'policy-test',
      clock: () => FIXED_NOW.getTime() }).verify(token, { actor: RECALL_CONSUMER_ACTOR,
      purpose: 'conversation_recall', request }).keyVersion, RECALL_CONSUMER_CONTEXT_KEY_VERSION);
    assert.deepEqual(bytes(path.join(result.backupPath, 'auth-registry.json')), original.auth);
    assert.deepEqual(bytes(path.join(result.backupPath, 'policy.json')), original.policy);
    assert.deepEqual(bytes(path.join(result.backupPath, 'context-key-ring.json')), original.context);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.recall-consumer-provision.lock`), false);
    assert.equal(fs.readdirSync(options.handoffPath).some(name => /raw|ingest|cursor|lease/i.test(name)), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('dry-run validates the complete plan with zero writes and no random generation', () => {
  const { root, options } = fixture();
  try {
    const originals = [options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes);
    const observed = instrumentWrites(() => provisionRecallConsumer({ ...options, dryRun: true,
      randomBytes() { throw new Error('random_must_not_run'); } }));
    assert.equal(observed.result.dryRun, true); assert.equal(observed.result.backupPath, null);
    assert.deepEqual(observed.calls, []); assert.equal(fs.existsSync(options.handoffPath), false);
    assert.deepEqual(fs.readdirSync(options.backupRoot), []);
    assert.deepEqual([options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes), originals);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.recall-consumer-provision.lock`), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('live provisioning requires root but non-root dry-run stays read-only', () => {
  const { root, options } = fixture();
  try {
    const nonRoot = options.serviceOwnerUid || 1000;
    assert.throws(() => withEffectiveUid(nonRoot, () => provisionRecallConsumer(options)), /recall_consumer_root_required/);
    const observed = withEffectiveUid(nonRoot, () => instrumentWrites(() => provisionRecallConsumer({ ...options, dryRun: true })));
    assert.equal(observed.result.ok, true); assert.deepEqual(observed.calls, []);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('partial credential, policy or context-key state fails closed', () => {
  for (const collision of ['registry', 'policy', 'context']) {
    const { root, options } = fixture();
    try {
      if (collision === 'registry') {
        const registry = json(options.authRegistryPath); registry.rows.push({ tokenSha256: crypto.randomBytes(32).toString('hex'),
          active: true, actor: RECALL_CONSUMER_ACTOR, mode: 'read_only_scoped', allowedScopes: RECALL_CONSUMER_SCOPES,
          permissions: RECALL_CONSUMER_PERMISSIONS }); privateJson(options.authRegistryPath, registry);
      } else if (collision === 'policy') {
        const policy = json(options.policyPath); policy.actors[RECALL_CONSUMER_ACTOR] = { mode: 'read_only_scoped',
          allowedScopes: RECALL_CONSUMER_SCOPES }; privateJson(options.policyPath, policy);
      } else {
        const ring = json(options.contextKeyRingPath); ring.keys[RECALL_CONSUMER_CONTEXT_KEY_VERSION] = key();
        privateJson(options.contextKeyRingPath, ring);
      }
      assert.throws(() => provisionRecallConsumer({ ...options, dryRun: true }), /recall_consumer_provisioning_conflict/);
      assert.equal(fs.existsSync(options.handoffPath), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('transaction faults restore every server file and remove the staged handoff', () => {
  for (const point of ['after-context-key-ring-before-fsync', 'after-context-key-ring', 'after-policy',
    'after-auth-registry', 'after-handoff-before-fsync', 'after-handoff']) {
    const { root, options } = fixture();
    try {
      const originals = new Map([options.authRegistryPath, options.policyPath, options.contextKeyRingPath]
        .map(filePath => [filePath, bytes(filePath)]));
      assert.throws(() => asRoot(() => provisionRecallConsumer({ ...options, faultAt: point })),
        new RegExp(`recall_consumer_test_fault_${point}`));
      for (const [filePath, original] of originals) assert.deepEqual(bytes(filePath), original, point);
      assert.equal(fs.existsSync(options.handoffPath), false); assert.equal(fs.readdirSync(options.backupRoot).length, 1);
      assert.equal(fs.existsSync(`${options.authRegistryPath}.recall-consumer-provision.lock`), false);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('rollback failure preserves the lock and prevents a retry over partial state', () => {
  const { root, options } = fixture();
  try {
    assert.throws(() => asRoot(() => provisionRecallConsumer({ ...options,
      faultAt: ['after-policy', 'rollback-policy'] })), /recall_consumer_provisioning_rollback_failed/);
    assert.equal(fs.existsSync(`${options.authRegistryPath}.recall-consumer-provision.lock`), true);
    assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_provisioning_locked/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('unsafe files, duplicate context material and held locks fail before handoff', () => {
  {
    const { root, options } = fixture();
    try {
      fs.chmodSync(options.authRegistryPath, 0o644);
      assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_auth_registry_file_unsafe/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      fs.linkSync(options.contextKeyRingPath, path.join(root, 'context-hardlink.json'));
      assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_context_key_ring_file_unsafe/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      const ring = json(options.contextKeyRingPath); ring.keys['ctx-duplicate'] = ring.keys['ctx-existing-v1'];
      privateJson(options.contextKeyRingPath, ring);
      assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_context_key_reuse_detected/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  {
    const { root, options } = fixture();
    try {
      fs.writeFileSync(`${options.authRegistryPath}.recall-consumer-provision.lock`, '{}', { mode: 0o600 });
      assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_provisioning_locked/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('auth registry rejects non-primitive actor, mode, digest and delegated-owner values', () => {
  for (const mutation of [
    row => { row.actor = [RECALL_CONSUMER_ACTOR]; },
    row => { row.mode = ['allow_all']; },
    row => { row.tokenSha256 = [row.tokenSha256]; },
    row => { row.sessionOwnerActors = [[RECALL_CONSUMER_SESSION_OWNER_ACTORS[0]]]; }
  ]) {
    const { root, options } = fixture();
    try {
      const registry = json(options.authRegistryPath); mutation(registry.rows[0]);
      privateJson(options.authRegistryPath, registry);
      assert.throws(() => provisionRecallConsumer({ ...options, dryRun: true }),
        /recall_consumer_auth_registry_invalid/);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  const { root, options } = fixture();
  try {
    const registry = json(options.authRegistryPath);
    registry.rows[0].contextKeyVersions = ['ctx-existing-v1'];
    privateJson(options.authRegistryPath, registry);
    assert.throws(() => provisionRecallConsumer({ ...options, dryRun: true }),
      /recall_consumer_context_actor_binding_invalid/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('pinned parent descriptors reject a directory swap without writing the replacement tree', () => {
  const { root, options } = fixture(); const originalRename = fs.renameSync;
  const live = path.join(root, 'auth-live'); const decoy = path.join(root, 'auth-decoy');
  const displaced = path.join(root, 'auth-displaced');
  fs.mkdirSync(live, { mode: 0o700 }); fs.mkdirSync(decoy, { mode: 0o700 });
  const originalAuth = bytes(options.authRegistryPath);
  originalRename(options.authRegistryPath, path.join(live, 'auth-registry.json'));
  fs.writeFileSync(path.join(decoy, 'auth-registry.json'), originalAuth, { mode: 0o600 });
  options.authRegistryPath = path.join(live, 'auth-registry.json');
  let swapped = false;
  try {
    fs.renameSync = function swapBeforePinnedRename(from, to) {
      if (!swapped && String(from).startsWith('/proc/self/fd/') && String(to).endsWith('/auth-registry.json')) {
        swapped = true; originalRename(live, displaced); originalRename(decoy, live);
      }
      return originalRename(from, to);
    };
    assert.throws(() => asRoot(() => provisionRecallConsumer(options)), /recall_consumer_input_changed/);
    assert.equal(swapped, true);
    assert.deepEqual(bytes(path.join(live, 'auth-registry.json')), originalAuth, 'replacement tree is untouched');
    assert.deepEqual(bytes(path.join(displaced, 'auth-registry.json')), originalAuth, 'pinned original is rolled back');
    assert.equal(fs.existsSync(options.handoffPath), false);
  } finally {
    fs.renameSync = originalRename;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('repeat provisioning fails closed and cannot widen actor or permissions through the CLI', () => {
  const { root, options } = fixture();
  try {
    asRoot(() => provisionRecallConsumer(options));
    assert.throws(() => asRoot(() => provisionRecallConsumer({ ...options,
      handoffPath: `${options.handoffPath}-second` })), /recall_consumer_already_provisioned/);
    const cli = path.resolve('scripts/amf-provision-recall-consumer.mjs');
    const base = ['--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--context-key-ring', options.contextKeyRingPath, '--handoff', `${options.handoffPath}-third`,
      '--backup-root', options.backupRoot, '--backend-user-id', options.backendUserId,
      '--service-owner-uid', String(options.serviceOwnerUid), '--dry-run'];
    for (const extra of [['--actor', 'attacker'], ['--permission', '*'], ['--token', 'secret-value']]) {
      const attempted = spawnSync(process.execPath, [cli, ...base, ...extra], { encoding: 'utf8' });
      assert.equal(attempted.status, 1); assert.equal(attempted.stdout, '');
      assert.deepEqual(JSON.parse(attempted.stderr), { ok: false, error: 'cli_argument_unknown' });
      assert.equal(attempted.stderr.includes(extra[1]), false);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('additional person, relationship and room scopes are sorted, bounded and manifest-bound', () => {
  const { root, options } = fixture({ withExistingScope: false });
  const additionalScopes = ['room:vitae:synthetic-group-topic', 'person:synthetic-member',
    'relationship:vitae:synthetic-member'];
  try {
    const result = asRoot(() => provisionRecallConsumer({ ...options, additionalScopes }));
    const expected = [...RECALL_CONSUMER_SCOPES, ...additionalScopes.sort()];
    assert.deepEqual(result.scopes, expected); assert.match(result.scopeSetSha256, /^[a-f0-9]{64}$/);
    const row = json(options.authRegistryPath).rows.find(item => item.actor === RECALL_CONSUMER_ACTOR);
    assert.deepEqual(row.allowedScopes, expected);
    const manifest = json(path.join(options.handoffPath, 'manifest.json'));
    assert.deepEqual(manifest.scopes, expected); assert.equal(manifest.scopeSetSha256, result.scopeSetSha256);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }

  for (const invalid of [['room:vitae:duplicate', 'room:vitae:duplicate'], ['*'], ['domain:forbidden'],
    ['agent:forbidden'], ['shared:forbidden'], [RECALL_CONSUMER_SCOPES[1]],
    Array.from({ length: RECALL_CONSUMER_MAX_ADDITIONAL_SCOPES + 1 }, (_, index) => `person:extra-${index}`)]) {
    const sample = fixture();
    try { assert.throws(() => provisionRecallConsumer({ ...sample.options, additionalScopes: invalid, dryRun: true }),
      /recall_consumer_scope_invalid/); }
    finally { fs.rmSync(sample.root, { recursive: true, force: true }); }
  }
});

test('dry-run CLI emits safe metadata only', () => {
  const { root, options } = fixture({ withExistingScope: false });
  try {
    const cli = path.resolve('scripts/amf-provision-recall-consumer.mjs');
    const args = ['--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--context-key-ring', options.contextKeyRingPath, '--handoff', options.handoffPath,
      '--backup-root', options.backupRoot, '--backend-user-id', options.backendUserId,
      '--service-owner-uid', String(options.serviceOwnerUid), '--dry-run'];
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
    const output = JSON.parse(result.stdout);
    assert.equal(output.actor, RECALL_CONSUMER_ACTOR); assert.deepEqual(output.permissions, RECALL_CONSUMER_PERMISSIONS);
    assert.equal(/bearer|tokenSha256|[A-Za-z0-9+/]{43}=/i.test(result.stdout), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('context actor binding comparison is independent of key-version input order', () => {
  const { root, options } = fixture();
  try {
    const registry = json(options.authRegistryPath);
    registry.rows.find(row => row.actor === 'existing-actor').contextKeyVersions = ['ctx-b', 'ctx-a'];
    privateJson(options.authRegistryPath, registry);
    const policy = json(options.policyPath);
    policy.actors['existing-actor'].contextKeyVersions = ['ctx-a', 'ctx-b'];
    privateJson(options.policyPath, policy);
    const ring = json(options.contextKeyRingPath);
    ring.keys['ctx-a'] = key(); ring.keys['ctx-b'] = key();
    privateJson(options.contextKeyRingPath, ring);
    const result = asRoot(() => provisionRecallConsumer({ ...options, dryRun: true }));
    assert.equal(result.ok, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI accepts repeatable canonical scopes and rejects duplicate or wildcard scope argv', () => {
  const { root, options } = fixture({ withExistingScope: false });
  try {
    const cli = path.resolve('scripts/amf-provision-recall-consumer.mjs');
    const base = ['--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--context-key-ring', options.contextKeyRingPath, '--handoff', options.handoffPath,
      '--backup-root', options.backupRoot, '--backend-user-id', options.backendUserId,
      '--service-owner-uid', String(options.serviceOwnerUid), '--dry-run'];
    const valid = spawnSync(process.execPath, [cli, ...base, '--scope', 'room:vitae:synthetic-topic',
      '--scope', 'person:synthetic-member'], { encoding: 'utf8' });
    assert.equal(valid.status, 0, valid.stderr);
    assert.deepEqual(JSON.parse(valid.stdout).scopes.slice(-2), ['person:synthetic-member', 'room:vitae:synthetic-topic']);
    for (const extra of [['--scope', '*'], ['--scope', 'domain:forbidden'],
      ['--scope', 'room:vitae:duplicate', '--scope', 'room:vitae:duplicate']]) {
      const rejected = spawnSync(process.execPath, [cli, ...base, ...extra], { encoding: 'utf8' });
      assert.equal(rejected.status, 1); assert.deepEqual(JSON.parse(rejected.stderr),
        { ok: false, error: 'recall_consumer_scope_invalid' });
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
