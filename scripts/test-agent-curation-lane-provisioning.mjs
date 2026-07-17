import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  planAgentCurationLane,
  provisionAgentCurationLane
} from '../src/operator/agent-curation-lane-provisioning.mjs';

const OWNER = { serviceOwnerUid: process.getuid(), serviceOwnerGid: process.getgid() };

function digest() {
  return crypto.randomBytes(32).toString('hex');
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-lane-'));
  const curationRoot = path.join(root, 'curation');
  fs.mkdirSync(path.join(curationRoot, 'secrets'), { recursive: true, mode: 0o700 });
  const unitDir = path.join(root, 'units');
  fs.mkdirSync(unitDir, { recursive: true });
  const backupRoot = path.join(root, 'backups');

  const authRegistryPath = path.join(root, 'auth-registry.json');
  fs.writeFileSync(authRegistryPath, `${JSON.stringify({
    rows: [
      {
        active: true,
        actor: 'service:memory-curator',
        allowedScopes: ['room:vitae:nestdev-friends'],
        mode: 'scoped',
        permissions: ['memory:curate', 'memory:status', 'purpose:memory_curation'],
        tokenSha256: digest()
      },
      {
        active: true,
        actor: 'service:memory-applicator',
        allowedScopes: ['room:vitae:nestdev-friends'],
        mode: 'scoped',
        permissions: ['memory:apply-receipt', 'memory:status'],
        tokenSha256: digest()
      }
    ]
  }, null, 2)}\n`, { mode: 0o600 });

  const pamConfigPath = path.join(root, 'pam-workspace-config.json');
  fs.writeFileSync(pamConfigPath, `${JSON.stringify({
    amfCurator: {
      autoPromote: true,
      minimumConfidence: 0.98,
      autoScopes: ['shared', 'room'],
      autoVisibilities: ['shared'],
      requireReviewForLifecycleChange: true,
      requireReviewForSupersession: true,
      rejectOnWarnings: true,
      reviewers: [{ tokenSha256: digest(), actorId: 'service:memory-curator', capabilities: ['memory:curate'] }]
    }
  }, null, 2)}\n`, { mode: 0o600 });

  const workspaceRoot = path.join(root, 'workspace');
  const referenceWorkerEnvPath = path.join(root, 'worker.env');
  fs.writeFileSync(referenceWorkerEnvPath, [
    `PAM_WORKSPACE_CONFIG=${pamConfigPath}`,
    'PAM_CURATOR_STATE_DIR=/ignored/state',
    'PAM_CURATOR_LEDGER_KEY=shared-ledger-key',
    'PAM_CURATOR_REVIEWER_TOKEN=shared-reviewer-token',
    'PAM_APPLICATOR_TOKEN=shared-applicator-token',
    `PAM_APPLICATOR_STATE_KEY_FILE=${path.join(root, 'state.key')}`,
    'PAM_FABRIC_BASE_URL=http://127.0.0.1:8787',
    `PAM_FABRIC_CURATOR_TOKEN_FILE=${path.join(root, 'shared-curator.token')}`,
    `PAM_FABRIC_APPLICATOR_TOKEN_FILE=${path.join(root, 'shared-applicator.token')}`,
    `PAM_GIT_WRITER_REPO_ROOT=${workspaceRoot}`,
    ''
  ].join('\n'), { mode: 0o600 });

  return {
    root,
    options: {
      authRegistryPath,
      pamConfigPath,
      referenceWorkerEnvPath,
      curationRoot,
      unitDir,
      backupRoot,
      ...OWNER
    }
  };
}

test('plan validates inputs and reports intended artifacts', () => {
  const { options } = fixture();
  const plan = planAgentCurationLane(options);
  assert.equal(plan.curatorActor, 'service:memory-curator-agent-vitae');
  assert.equal(plan.scope, 'agent:vitae');
  assert.equal(plan.applicatorScopeAlreadyPresent, false);
  assert.match(plan.files.tickScriptFile, /amf-agent-vitae-curation-tick\.mjs$/);
  assert.match(plan.files.serviceUnit, /amf-curation-agent-vitae\.service$/);
});

test('dry run mutates nothing', () => {
  const { options } = fixture();
  const before = fs.readFileSync(options.authRegistryPath, 'utf8');
  const report = provisionAgentCurationLane({ ...options, dryRun: true });
  assert.equal(report.dryRun, true);
  assert.equal(fs.readFileSync(options.authRegistryPath, 'utf8'), before);
  assert.equal(fs.existsSync(report.files.workerEnvFile), false);
  assert.equal(fs.existsSync(report.files.serviceUnit), false);
});

test('apply provisions registry, policy, secrets, env, tick script and units', () => {
  const { options } = fixture();
  const report = provisionAgentCurationLane(options);
  assert.equal(report.ok, true);

  const registry = JSON.parse(fs.readFileSync(options.authRegistryPath, 'utf8'));
  const curator = registry.rows.find((row) => row.actor === 'service:memory-curator-agent-vitae');
  assert.ok(curator);
  assert.deepEqual(curator.allowedScopes, ['agent:vitae']);
  assert.equal(curator.mode, 'scoped');
  const applicator = registry.rows.find((row) => row.actor === 'service:memory-applicator');
  assert.ok(applicator.allowedScopes.includes('agent:vitae'));
  assert.ok(applicator.allowedScopes.includes('room:vitae:nestdev-friends'));

  const pam = JSON.parse(fs.readFileSync(options.pamConfigPath, 'utf8'));
  assert.ok(pam.amfCurator.autoScopes.includes('agent'));
  assert.ok(pam.amfCurator.autoScopes.includes('room'));
  assert.ok(pam.amfCurator.autoVisibilities.includes('private'));
  const reviewer = pam.amfCurator.reviewers.find((entry) => entry.actorId === 'service:memory-curator-agent-vitae');
  assert.ok(reviewer);

  const token = fs.readFileSync(report.files.fabricCuratorTokenFile, 'utf8').trim();
  assert.equal(crypto.createHash('sha256').update(token, 'utf8').digest('hex'), curator.tokenSha256);
  const reviewerToken = fs.readFileSync(report.files.pamReviewerTokenFile, 'utf8').trim();
  assert.equal(crypto.createHash('sha256').update(reviewerToken, 'utf8').digest('hex'), reviewer.tokenSha256);

  for (const file of [report.files.fabricCuratorTokenFile, report.files.pamReviewerTokenFile, report.files.pamLedgerKeyFile, report.files.workerEnvFile]) {
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
  assert.equal(fs.statSync(report.files.tickScriptFile).mode & 0o777, 0o750);
  assert.equal(fs.statSync(report.files.stateDir).mode & 0o777, 0o700);

  const env = fs.readFileSync(report.files.workerEnvFile, 'utf8');
  assert.match(env, /PAM_APPLICATOR_TOKEN=shared-applicator-token/);
  assert.match(env, new RegExp(`PAM_CURATOR_STATE_DIR=${report.files.stateDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.match(env, /PAM_CURATOR_REVIEWER_TOKEN=(?!shared-reviewer-token)\S+/);

  const tick = fs.readFileSync(report.files.tickScriptFile, 'utf8');
  assert.match(tick, /const EXPECTED_SCOPE = "agent:vitae"/);
  assert.match(tick, /autoScopes\?\.includes\("agent"\)/);
  assert.match(tick, /autoVisibilities\?\.includes\("private"\)/);

  const service = fs.readFileSync(report.files.serviceUnit, 'utf8');
  assert.match(service, /ProtectSystem=strict/);
  assert.match(service, new RegExp(`ReadWritePaths=.* ${report.files.stateDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  assert.ok(fs.readFileSync(report.files.timerUnit, 'utf8').includes('amf-curation-agent-vitae.service'));

  assert.ok(fs.existsSync(report.backups.authRegistry));
  assert.ok(fs.existsSync(report.backups.pamConfig));

  const registryStat = fs.statSync(options.authRegistryPath);
  assert.equal(registryStat.mode & 0o777, 0o600);
});

test('apply preserves the registry file inode', () => {
  const { options } = fixture();
  const before = fs.statSync(options.authRegistryPath).ino;
  provisionAgentCurationLane(options);
  assert.equal(fs.statSync(options.authRegistryPath).ino, before);
});

test('refuses re-provisioning an existing lane', () => {
  const { options } = fixture();
  provisionAgentCurationLane(options);
  assert.throws(() => provisionAgentCurationLane(options), /lane_curator_already_provisioned/);
});

test('refuses when a shared env entry is missing', () => {
  const { options } = fixture();
  fs.writeFileSync(options.referenceWorkerEnvPath, 'PAM_WORKSPACE_CONFIG=/x\n', { mode: 0o600 });
  assert.throws(() => provisionAgentCurationLane(options), /worker_env_shared_entry_missing/);
});

test('refuses invalid lane names and scopes', () => {
  const { options } = fixture();
  assert.throws(() => planAgentCurationLane({ ...options, laneName: 'Bad Name' }), /lane_name_invalid/);
  assert.throws(() => planAgentCurationLane({ ...options, scope: 'room:vitae:x' }), /lane_scope_invalid/);
});

test('refuses a missing secrets dir before any mutation', () => {
  const { options } = fixture();
  fs.rmSync(path.join(options.curationRoot, 'secrets'), { recursive: true });
  const before = fs.readFileSync(options.authRegistryPath, 'utf8');
  assert.throws(() => provisionAgentCurationLane(options), /secrets_dir_missing/);
  assert.equal(fs.readFileSync(options.authRegistryPath, 'utf8'), before);
});

test('refuses an explicit pam-config that disagrees with the worker env', () => {
  const { options } = fixture();
  assert.throws(
    () => planAgentCurationLane({ ...options, pamConfigPath: path.join(options.curationRoot, 'other.json') }),
    /pam_config_path_mismatch/
  );
});

test('refuses when the applicator actor is missing', () => {
  const { options } = fixture();
  const registry = JSON.parse(fs.readFileSync(options.authRegistryPath, 'utf8'));
  registry.rows = registry.rows.filter((row) => row.actor !== 'service:memory-applicator');
  fs.writeFileSync(options.authRegistryPath, `${JSON.stringify(registry)}\n`);
  assert.throws(() => planAgentCurationLane(options), /applicator_actor_missing/);
});

test('rolls back both live files when a late artifact write fails', () => {
  const { options } = fixture();
  const registryBefore = fs.readFileSync(options.authRegistryPath, 'utf8');
  const pamBefore = fs.readFileSync(options.pamConfigPath, 'utf8');
  fs.rmSync(options.unitDir, { recursive: true });
  fs.writeFileSync(options.unitDir, 'not a directory\n');
  assert.throws(() => provisionAgentCurationLane(options), /lane_provisioning_rolled_back/);
  assert.equal(fs.readFileSync(options.authRegistryPath, 'utf8'), registryBefore);
  assert.equal(fs.readFileSync(options.pamConfigPath, 'utf8'), pamBefore);
  const secretsDir = path.join(options.curationRoot, 'secrets');
  assert.deepEqual(fs.readdirSync(secretsDir), []);
  assert.equal(fs.existsSync(path.join(options.curationRoot, 'worker-agent-vitae.env')), false);
  assert.equal(fs.existsSync(path.join(options.curationRoot, 'state-agent-vitae')), false);
  fs.rmSync(options.unitDir);
  fs.mkdirSync(options.unitDir, { recursive: true });
  const rerun = provisionAgentCurationLane({ ...options, dryRun: true });
  assert.equal(rerun.ok, true);
});

test('apply preserves the pam config inode and generated tick script parses', () => {
  const { options } = fixture();
  const before = fs.statSync(options.pamConfigPath).ino;
  const report = provisionAgentCurationLane(options);
  assert.equal(fs.statSync(options.pamConfigPath).ino, before);
  execFileSync(process.execPath, ['--check', report.files.tickScriptFile]);
  const service = fs.readFileSync(report.files.serviceUnit, 'utf8');
  assert.match(service, /User=stt/);
  const custom = fixture();
  const customReport = provisionAgentCurationLane({ ...custom.options, serviceUserName: 'svc_user' });
  assert.match(fs.readFileSync(customReport.files.serviceUnit, 'utf8'), /User=svc_user/);
});

test('reports already-present applicator scope and policy values', () => {
  const { options } = fixture();
  const registry = JSON.parse(fs.readFileSync(options.authRegistryPath, 'utf8'));
  registry.rows.find((row) => row.actor === 'service:memory-applicator').allowedScopes.push('agent:vitae');
  fs.writeFileSync(options.authRegistryPath, `${JSON.stringify(registry)}\n`);
  const pam = JSON.parse(fs.readFileSync(options.pamConfigPath, 'utf8'));
  pam.amfCurator.autoScopes.push('agent');
  fs.writeFileSync(options.pamConfigPath, `${JSON.stringify(pam)}\n`);
  const report = provisionAgentCurationLane({ ...options, dryRun: true });
  assert.equal(report.applicatorScopeExtended, false);
  assert.equal(report.autoScopeExtended, false);
  assert.equal(report.autoVisibilityExtended, true);
});
