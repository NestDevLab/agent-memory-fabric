import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { ContextTokenVerifier, issueContextToken, requestDigest } from '../src/context-token.mjs';
import {
  DOCUMENT_CLIENT_HANDOFF_SCHEMA,
  DOCUMENT_CLIENT_PERMISSIONS,
  provisionDocumentClient
} from '../src/operator/recall-consumer-provisioning.mjs';

const NOW = new Date('2026-07-13T18:00:00Z');
const ACTOR = 'client:obsidian:synthetic';
const VAULT = 'vault:synthetic';
const KEY_VERSION = 'ctx-obsidian-synthetic-v1';
const SCOPES = ['domain:obsidian', 'shared:knowledge'];
const POLICY_REVISION = 'policy-test';

function privateJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-document-client-'));
  const auth = path.join(root, 'auth'); const config = path.join(root, 'config');
  const backupRoot = path.join(root, 'backups'); const handoffs = path.join(root, 'handoffs');
  for (const directory of [auth, config, backupRoot, handoffs]) fs.mkdirSync(directory, { mode: 0o700 });
  const authRegistryPath = path.join(auth, 'auth-registry.json');
  const policyPath = path.join(config, 'policy.json');
  const contextKeyRingPath = path.join(config, 'context-key-ring.json');
  privateJson(authRegistryPath, { rows: [{
    tokenSha256: crypto.createHash('sha256').update('existing').digest('hex'),
    active: true, actor: 'existing-actor', mode: 'scoped', allowedScopes: ['domain:existing'],
    permissions: ['memory:search']
  }] });
  privateJson(policyPath, { actors: { 'existing-actor': { mode: 'scoped', allowedScopes: ['domain:existing'] } },
    scopes: { 'domain:existing': { backendUserId: 'existing' } } });
  privateJson(contextKeyRingPath, { currentKeyVersion: 'ctx-existing-v1',
    keys: { 'ctx-existing-v1': crypto.randomBytes(32).toString('base64') } });
  const options = { authRegistryPath, policyPath, contextKeyRingPath,
    handoffPath: path.join(handoffs, 'obsidian-synthetic'), backupRoot,
    backendUserId: 'obsidian-synthetic', serviceOwnerUid: process.geteuid?.() ?? fs.statSync(root).uid,
    actor: ACTOR, vaultId: VAULT, scopes: [...SCOPES], contextKeyVersion: KEY_VERSION,
    policyRevision: POLICY_REVISION, endpoint: 'https://memory.example.test/', clock: () => NOW };
  return { root, options };
}

function json(filePath) { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
function bytes(filePath) { return fs.readFileSync(filePath); }
function asRoot(operation) {
  const original = process.geteuid; process.geteuid = () => 0;
  try { return operation(); } finally { process.geteuid = original; }
}

test('provisions a vault-bound document client and request-bound signer handoff', () => {
  const { root, options } = fixture();
  try {
    const result = asRoot(() => provisionDocumentClient(options));
    assert.equal(result.schema, DOCUMENT_CLIENT_HANDOFF_SCHEMA);
    assert.deepEqual(result.allowedVaults, [VAULT]);
    assert.deepEqual(result.permissions, DOCUMENT_CLIENT_PERMISSIONS);
    assert.deepEqual(result.scopes, [...SCOPES].sort());
    const registry = json(options.authRegistryPath);
    const row = registry.rows.find(candidate => candidate.actor === ACTOR);
    assert.equal(row.mode, 'scoped'); assert.deepEqual(row.allowedVaults, [VAULT]);
    assert.deepEqual(row.contextKeyVersions, [KEY_VERSION]); assert.equal(Object.hasOwn(row, 'token'), false);
    assert.deepEqual(json(options.policyPath).actors[ACTOR], {
      mode: 'scoped', allowedScopes: [...SCOPES].sort(), contextKeyVersions: [KEY_VERSION]
    });
    const manifest = json(path.join(options.handoffPath, 'manifest.json'));
    assert.deepEqual(manifest.allowedVaults, [VAULT]); assert.equal(manifest.policyRevision, POLICY_REVISION);
    assert.equal(manifest.endpoint, options.endpoint); assert.equal(manifest.purpose, 'operator_review');
    const bearer = fs.readFileSync(path.join(options.handoffPath, 'bearer.token'), 'utf8').trim();
    assert.equal(row.tokenSha256, crypto.createHash('sha256').update(bearer).digest('hex'));

    const request = { operation: 'context_search', input: { query: 'SQLite decision', vaultId: VAULT,
      scopes: ['domain:obsidian'], purpose: 'operator_review' } };
    const handoffRing = json(path.join(options.handoffPath, 'context-key-ring.json'));
    const token = issueContextToken({ actor: ACTOR, runtime: 'obsidian', profile: 'synthetic',
      conversationKind: 'session',
      contextTags: { actor: [`hmac-sha256:routing-v1:${'a'.repeat(64)}`] },
      purpose: 'operator_review', policyRevision: POLICY_REVISION,
      issuedAt: new Date(NOW.getTime() - 1_000).toISOString(),
      expiresAt: new Date(NOW.getTime() + 60_000).toISOString(), nonce: 'obsidiancanary01',
      requestDigest: requestDigest(request) }, handoffRing);
    const verified = new ContextTokenVerifier({ keyRing: json(options.contextKeyRingPath),
      policyRevision: POLICY_REVISION, clock: () => NOW.getTime() }).verify(token,
      { actor: ACTOR, purpose: 'operator_review', request, contextKeyVersions: [KEY_VERSION] });
    assert.equal(verified.keyVersion, KEY_VERSION);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('document client dry-run is read-only and emits no credentials', () => {
  const { root, options } = fixture();
  try {
    const before = [options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes);
    const result = provisionDocumentClient({ ...options, dryRun: true,
      randomBytes() { throw new Error('random_must_not_run'); } });
    assert.equal(result.dryRun, true); assert.equal(result.backupPath, null);
    assert.equal(fs.existsSync(options.handoffPath), false);
    assert.deepEqual([options.authRegistryPath, options.policyPath, options.contextKeyRingPath].map(bytes), before);
    assert.equal(JSON.stringify(result).includes('tokenSha256'), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('document client validation rejects wildcard scopes and non-Obsidian actors', () => {
  for (const mutation of [
    options => { options.scopes = ['*']; },
    options => { options.actor = 'agent:unrelated'; },
    options => { options.vaultId = '*'; },
    options => { options.contextKeyVersion = 'ctx-unrelated-v1'; },
    options => { options.endpoint = 'https://user:pass@example.test/'; }
  ]) {
    const { root, options } = fixture();
    try { mutation(options); assert.throws(() => provisionDocumentClient({ ...options, dryRun: true }),
      /document_client_(?:option|scope)_invalid/); }
    finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('transaction fault restores all server inputs and removes staged handoff', () => {
  const { root, options } = fixture();
  try {
    const before = new Map([options.authRegistryPath, options.policyPath, options.contextKeyRingPath]
      .map(filePath => [filePath, bytes(filePath)]));
    assert.throws(() => asRoot(() => provisionDocumentClient({ ...options, faultAt: 'after-policy' })),
      /recall_consumer_test_fault_after-policy/);
    for (const [filePath, original] of before) assert.deepEqual(bytes(filePath), original);
    assert.equal(fs.existsSync(options.handoffPath), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI accepts only explicit bounded document-client inputs and prints safe metadata', () => {
  const { root, options } = fixture();
  try {
    const cli = path.resolve('scripts/amf-provision-document-client.mjs');
    const args = ['--auth-registry', options.authRegistryPath, '--policy', options.policyPath,
      '--context-key-ring', options.contextKeyRingPath, '--handoff', options.handoffPath,
      '--backup-root', options.backupRoot, '--backend-user-id', options.backendUserId,
      '--service-owner-uid', String(options.serviceOwnerUid), '--actor', ACTOR, '--vault', VAULT,
      '--key-version', KEY_VERSION, '--policy-revision', POLICY_REVISION, '--endpoint', options.endpoint,
      '--scope', SCOPES[0], '--scope', SCOPES[1], '--dry-run'];
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
    assert.equal(/bearer|tokenSha256|[A-Za-z0-9+/]{43}=/i.test(result.stdout), false);
    assert.deepEqual(JSON.parse(result.stdout).allowedVaults, [VAULT]);
    const rejected = spawnSync(process.execPath, [cli, ...args, '--permission', '*'], { encoding: 'utf8' });
    assert.equal(rejected.status, 1); assert.deepEqual(JSON.parse(rejected.stderr),
      { ok: false, error: 'cli_argument_unknown' });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
