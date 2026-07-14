import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  adoptIntegration,
  buildPlan,
  canonicalJson,
  disableIntegration,
  enableIntegration,
  installIntegration,
  integrationStatus,
  lifecycleInternals,
  loadConfirmedPlan,
  serializePlan,
  uninstallIntegration,
} from '../src/integrations/lifecycle.mjs';

function digest(bytes) { return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`; }

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-integration-test-'));
  const roots = {
    etc: path.join(root, 'etc'),
    systemd: path.join(root, 'systemd'),
    libexec: path.join(root, 'libexec'),
    state: path.join(root, 'state'),
  };
  for (const target of Object.values(roots)) fs.mkdirSync(target, { recursive: true });
  const vault = path.join(root, 'vault-one');
  fs.mkdirSync(path.join(vault, '.amf'), { recursive: true });
  const clientRoot = path.join(root, 'skill');
  const sourceRoot = path.join(root, 'source');
  fs.mkdirSync(clientRoot);
  fs.mkdirSync(sourceRoot);
  const sourceFiles = [
    { path: '__init__.py', bytes: Buffer.from('VALUE = 1\n') },
    { path: '__main__.py', bytes: Buffer.from('print("ok")\n') },
  ];
  const files = sourceFiles.map(item => {
    fs.writeFileSync(path.join(sourceRoot, item.path), item.bytes);
    return { path: item.path, size: item.bytes.length, digest: digest(item.bytes) };
  });
  const sourceDigest = digest(Buffer.from(canonicalJson(files)));
  const metadata = {
    schema: 'obsidian-amf-client/v1', name: 'obsidian_amf', version: 'test-1',
    source: { digest: sourceDigest, files },
  };
  const clientRelease = { version: 'test-1', sourceDigest, files };
  const calls = [];
  let timerOutput = '';
  let timersEnabled = true;
  const forcedEnabled = new Set();
  let failVerb = null;
  let daemonFailure = false;
  const deps = {
    roots,
    uid: process.getuid(),
    clientRelease,
    resolveClientSource: () => ({ sourceRoot, metadata }),
    runClientStatus: () => ({ healthy: true, mode: 'shadow', vaultId: 'vault-one', outbox: { pending: 0, retrying: 0, quarantined: 0 } }),
    systemctl(args) {
      calls.push(args);
      if (args[0] === failVerb) { failVerb = null; return { status: 1, stdout: '', stderr: 'synthetic' }; }
      if (args[0] === 'list-units') return { status: 0, stdout: timerOutput, stderr: '' };
      if (args[0] === 'list-unit-files') return { status: 0, stdout: '', stderr: '' };
      if (args[0] === 'is-enabled') return { status: (timersEnabled && timerOutput.includes(args[1])) || forcedEnabled.has(args[1]) ? 0 : 1, stdout: (timersEnabled && timerOutput.includes(args[1])) || forcedEnabled.has(args[1]) ? 'enabled\n' : 'disabled\n', stderr: '' };
      if (args[0] === 'is-active') return { status: timerOutput.includes(args[1]) ? 0 : 3, stdout: timerOutput.includes(args[1]) ? 'active\n' : 'inactive\n', stderr: '' };
      if (args[0] === 'daemon-reload' && daemonFailure) { daemonFailure = false; return { status: 1, stdout: '', stderr: 'synthetic' }; }
      return { status: 0, stdout: '', stderr: '' };
    },
  };
  const options = {
    instance: 'host-vault', vault, vaultId: 'vault-one', actor: 'client:obsidian:test',
    amfUrl: 'http://127.0.0.1:8787', sourceInstance: 'host-vault', clientRoot,
    serviceUser: 'operator', serviceGroup: 'operator', intervalSec: 600, jitterSec: 60,
  };
  return {
    root, roots, vault, clientRoot, sourceRoot, metadata, clientRelease, calls, deps, options,
    setTimer(value, enabled = true) { timerOutput = value; timersEnabled = enabled; },
    enableUnloaded(timer) { forcedEnabled.add(timer); },
    failNext(verb) { failVerb = verb; },
    failDaemonOnce() { daemonFailure = true; },
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

function tokenPath(value, instance = 'host-vault') { return path.join(value.roots.etc, `obsidian-sync-${instance}.token`); }
function privateFile(target, content) { fs.writeFileSync(target, content, { mode: 0o600 }); fs.chmodSync(target, 0o600); }

test('catalog plan is deterministic, redacted and renders safe systemd units', t => {
  const value = fixture(); t.after(value.cleanup);
  const first = buildPlan('obsidian-second-brain', value.options, value.deps);
  const second = buildPlan('obsidian-second-brain', value.options, value.deps);
  assert.deepEqual(first, second);
  assert.equal(first.clientSource.metadata.source.digest, value.clientRelease.sourceDigest);
  assert.deepEqual(first.observations.mutations, []);
  assert.deepEqual(first.observations.systemd.timers, []);
  assert.equal(JSON.stringify(first).includes('bearer-secret'), false);
  assert.match(first.artifacts.service.path, /amf-obsidian-sync@host-vault\.service$/);
  assert.match(first.artifacts.timer.path, /amf-obsidian-sync@host-vault\.timer$/);
});

test('confirmed plan rejects a changed file and symlinked parent', t => {
  const value = fixture(); t.after(value.cleanup);
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  const planPath = path.join(value.root, 'plan.json');
  const bytes = serializePlan(plan);
  fs.writeFileSync(planPath, bytes, { mode: 0o600 });
  assert.equal(loadConfirmedPlan(planPath, digest(bytes).slice(7), value.deps).planDigest, plan.planDigest);
  fs.appendFileSync(planPath, ' ');
  assert.throws(() => loadConfirmedPlan(planPath, digest(bytes).slice(7), value.deps), /integration_confirmation_mismatch/);

  const real = path.join(value.root, 'plans');
  const link = path.join(value.root, 'plans-link');
  fs.mkdirSync(real);
  fs.symlinkSync(real, link);
  const unsafe = path.join(link, 'plan.json');
  fs.writeFileSync(path.join(real, 'plan.json'), bytes, { mode: 0o600 });
  assert.throws(() => loadConfirmedPlan(unsafe, digest(bytes).slice(7), value.deps), /integration_parent_unsafe/);
});

test('managed install is disabled, idempotent, byte-verified and queue-aware', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'bearer-secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  const installed = installIntegration(plan, value.deps);
  assert.equal(installed.changed, true);
  const locations = lifecycleInternals.pathsFor('host-vault', value.roots);
  assert.equal(fs.existsSync(locations.marker), false);
  assert.equal(fs.existsSync(locations.manifest), true);
  assert.equal(fs.existsSync(path.join(locations.moduleRoot, '__main__.py')), true);
  assert.match(fs.readFileSync(locations.timer, 'utf8'), /Unit=amf-obsidian-sync@host-vault\.service/);
  assert.equal(installIntegration(plan, value.deps).changed, false);

  let status = integrationStatus('obsidian-second-brain', 'host-vault', value.deps);
  assert.equal(status.client.verified, true);
  assert.equal(status.bridge.pending, 0);
  assert.equal(status.healthy, true);
  const degradedDeps = { ...value.deps, runClientStatus: () => ({ healthy: true, mode: 'shadow', vaultId: 'vault-one', outbox: { pending: 1, retrying: 0, quarantined: 0 } }) };
  status = integrationStatus('obsidian-second-brain', 'host-vault', degradedDeps);
  assert.equal(status.bridge.reportedHealthy, true);
  assert.equal(status.bridge.healthy, false);
  assert.equal(status.healthy, false);

  fs.appendFileSync(path.join(locations.moduleRoot, '__main__.py'), '# tampered\n');
  let statusRuns = 0;
  const guarded = { ...value.deps, runClientStatus: () => { statusRuns += 1; throw new Error('must_not_run'); } };
  status = integrationStatus('obsidian-second-brain', 'host-vault', guarded);
  assert.equal(status.client.verified, false);
  assert.equal(status.healthy, false);
  assert.equal(statusRuns, 0);
  fs.writeFileSync(locations.service, '[Service]\nType=notify\n');
  status = integrationStatus('obsidian-second-brain', 'host-vault', value.deps);
  assert.equal(status.artifactParity, false);
});

test('managed install rolls all files back and reloads restored systemd state', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'bearer-secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  value.failDaemonOnce();
  assert.throws(() => installIntegration(plan, value.deps), /integration_systemctl_failed/);
  const locations = lifecycleInternals.pathsFor('host-vault', value.roots);
  assert.equal(fs.existsSync(locations.manifest), false);
  assert.equal(fs.existsSync(locations.env), false);
  assert.equal(fs.existsSync(locations.service), false);
  assert.equal(value.calls.filter(args => args[0] === 'daemon-reload').length, 2);
});

test('install requires a private token and plan rejects unsafe systemd paths or URL queries', t => {
  const value = fixture(); t.after(value.cleanup);
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  assert.throws(() => installIntegration(plan, value.deps), /integration_token_missing/);
  const spaced = path.join(value.root, 'vault with space');
  fs.mkdirSync(path.join(spaced, '.amf'), { recursive: true });
  assert.throws(() => buildPlan('obsidian-second-brain', { ...value.options, vault: spaced }, value.deps), /integration_vault_path_unsupported/);
  assert.throws(() => buildPlan('obsidian-second-brain', { ...value.options, amfUrl: 'https://memory.invalid/?token=secret' }, value.deps), /integration_url_invalid/);
});

test('legacy adoption recognizes vault suffix, requires one enabled timer, and is metadata-only', t => {
  const value = fixture(); t.after(value.cleanup);
  const suffix = 'vault-one';
  const legacy = lifecycleInternals.pathsFor(suffix, value.roots);
  const wrapper = Buffer.from('#!/bin/sh\nexit 0\n');
  const service = Buffer.from('[Service]\nType=oneshot\n');
  const timer = Buffer.from('[Timer]\nPersistent=true\n');
  fs.writeFileSync(legacy.wrapper, wrapper, { mode: 0o755 });
  fs.writeFileSync(legacy.templateService, service, { mode: 0o644 });
  fs.writeFileSync(legacy.templateTimer, timer, { mode: 0o644 });
  privateFile(legacy.env, [
    `OBSIDIAN_VAULT_PATH=${JSON.stringify(value.vault)}`,
    'OBSIDIAN_AMF_VAULT_ID="vault-one"',
    'OBSIDIAN_AMF_MODE="shadow"',
    'OBSIDIAN_AMF_CLIENT_ROOT="/installed/skill"',
    '',
  ].join('\n'));
  privateFile(legacy.token, 'do-not-read-this-token\n');
  privateFile(legacy.marker, 'enabled\n');
  value.deps.legacyHashes = { wrapper: digest(wrapper), service: digest(service), timer: digest(timer) };
  value.setTimer('amf-obsidian-sync@vault-one.timer loaded active waiting synthetic\n');
  const before = [legacy.wrapper, legacy.templateService, legacy.templateTimer, legacy.env, legacy.token, legacy.marker]
    .map(target => [target, digest(fs.readFileSync(target)), fs.statSync(target).mtimeMs]);
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  assert.equal(plan.observations.legacyLayout.suffix, suffix);
  assert.deepEqual(plan.observations.systemd.enabledTimers, ['amf-obsidian-sync@vault-one.timer']);
  const result = adoptIntegration(plan, value.deps);
  assert.equal(result.installation.legacy.suffix, suffix);
  assert.equal(result.installation.legacy.timer, 'amf-obsidian-sync@vault-one.timer');
  for (const [target, hash, mtime] of before) {
    assert.equal(digest(fs.readFileSync(target)), hash);
    assert.equal(fs.statSync(target).mtimeMs, mtime);
  }
  assert.equal(adoptIntegration(plan, value.deps).changed, false);

  const changed = buildPlan('obsidian-second-brain', { ...value.options, actor: 'client:obsidian:changed' }, value.deps);
  assert.throws(() => adoptIntegration(changed, value.deps), /integration_already_installed_different_plan/);
});

test('legacy adoption refuses zero, duplicate, or disabled runtime timers', t => {
  const value = fixture(); t.after(value.cleanup);
  const suffix = 'vault-one';
  const legacy = lifecycleInternals.pathsFor(suffix, value.roots);
  const wrapper = Buffer.from('wrapper'); const service = Buffer.from('service'); const timer = Buffer.from('timer');
  fs.writeFileSync(legacy.wrapper, wrapper, { mode: 0o755 });
  fs.writeFileSync(legacy.templateService, service, { mode: 0o644 });
  fs.writeFileSync(legacy.templateTimer, timer, { mode: 0o644 });
  privateFile(legacy.env, `OBSIDIAN_VAULT_PATH=${JSON.stringify(value.vault)}\nOBSIDIAN_AMF_VAULT_ID="vault-one"\nOBSIDIAN_AMF_MODE="shadow"\n`);
  privateFile(legacy.token, 'secret\n');
  value.deps.legacyHashes = { wrapper: digest(wrapper), service: digest(service), timer: digest(timer) };
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  assert.throws(() => adoptIntegration(plan, value.deps), /integration_legacy_timer_gate/);
  privateFile(path.join(value.roots.etc, 'obsidian-sync-other.env'), `OBSIDIAN_VAULT_PATH=${JSON.stringify(value.vault)}\n`);
  value.setTimer('amf-obsidian-sync@vault-one.timer loaded active waiting x\namf-obsidian-sync@other.timer loaded active waiting x\n');
  assert.throws(() => adoptIntegration(plan, value.deps), /integration_legacy_timer_gate/);
  privateFile(path.join(value.roots.etc, 'obsidian-sync-other.env'), 'OBSIDIAN_VAULT_PATH="/srv/another-vault"\n');
  assert.equal(adoptIntegration(plan, value.deps).installation.legacy.suffix, 'vault-one');
  fs.unlinkSync(lifecycleInternals.pathsFor('host-vault', value.roots).manifest);
  value.setTimer('amf-obsidian-sync@vault-one.timer loaded inactive dead x\n', false);
  assert.throws(() => adoptIntegration(plan, value.deps), /integration_legacy_timer_gate/);
});

test('mutation revalidates every descriptor-derived path despite a valid plan self-hash', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  plan.artifacts.environment.path = path.join(value.root, '..', 'escape.env');
  const unsigned = structuredClone(plan); delete unsigned.planDigest;
  plan.planDigest = digest(Buffer.from(canonicalJson(unsigned)));
  assert.throws(() => installIntegration(plan, value.deps), /integration_plan_artifact_mismatch/);
  assert.equal(fs.existsSync(path.join(value.root, '..', 'escape.env')), false);
});

test('default client resolver never executes a launcher and verifies pinned bytes', t => {
  const value = fixture(); t.after(value.cleanup);
  const skill = path.join(value.root, 'default-skill');
  const module = path.join(skill, 'scripts', 'obsidian_amf');
  fs.mkdirSync(module, { recursive: true });
  for (const item of value.metadata.source.files) fs.copyFileSync(path.join(value.sourceRoot, item.path), path.join(module, item.path));
  const launcher = path.join(skill, 'scripts', 'obsidian-memory');
  fs.writeFileSync(launcher, '#!/bin/sh\ntouch "' + path.join(value.root, 'executed') + '"\nexit 99\n', { mode: 0o755 });
  const deps = { ...value.deps }; delete deps.resolveClientSource;
  const plan = buildPlan('obsidian-second-brain', { ...value.options, clientRoot: skill }, deps);
  assert.equal(plan.clientSource.metadata.source.digest, value.clientRelease.sourceDigest);
  assert.equal(fs.existsSync(path.join(value.root, 'executed')), false);
});

test('uninstall rollback restores manifest, units and client when daemon reload fails', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  installIntegration(plan, value.deps);
  const locations = lifecycleInternals.pathsFor('host-vault', value.roots);
  value.failDaemonOnce();
  assert.throws(() => uninstallIntegration(plan, value.deps), /integration_systemctl_failed/);
  assert.equal(fs.existsSync(locations.manifest), true);
  assert.equal(fs.existsSync(locations.service), true);
  assert.equal(fs.existsSync(path.join(locations.moduleRoot, '__main__.py')), true);
  assert.equal(fs.existsSync(locations.token), true);
});

test('uninstall is idempotent and preserves token after vault and source disappear', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  installIntegration(plan, value.deps);
  fs.rmSync(value.vault, { recursive: true });
  fs.rmSync(value.sourceRoot, { recursive: true });
  fs.rmSync(value.clientRoot, { recursive: true });
  const first = uninstallIntegration(plan, value.deps);
  assert.equal(first.changed, true);
  assert.equal(fs.existsSync(tokenPath(value)), true);
  const second = uninstallIntegration(plan, value.deps);
  assert.equal(second.changed, false);
  assert.equal(second.installed, false);
});

test('enabled but unloaded timer for the same vault blocks a second install', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'secret\n');
  privateFile(path.join(value.roots.etc, 'obsidian-sync-other-instance.env'), `OBSIDIAN_VAULT_PATH=${JSON.stringify(value.vault)}\n`);
  value.enableUnloaded('amf-obsidian-sync@other-instance.timer');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  assert.deepEqual(plan.observations.systemd.enabledTimers, ['amf-obsidian-sync@other-instance.timer']);
  assert.throws(() => installIntegration(plan, value.deps), /integration_vault_timer_exists/);
});

test('enable and disable failures restore activation marker and prior timer state', t => {
  const value = fixture(); t.after(value.cleanup);
  privateFile(tokenPath(value), 'secret\n');
  const plan = buildPlan('obsidian-second-brain', value.options, value.deps);
  installIntegration(plan, value.deps);
  const locations = lifecycleInternals.pathsFor('host-vault', value.roots);
  value.failNext('enable');
  assert.throws(() => enableIntegration(plan, value.deps), /integration_systemctl_failed/);
  assert.equal(fs.existsSync(locations.marker), false);

  privateFile(locations.marker, 'enabled\n');
  value.enableUnloaded('amf-obsidian-sync@host-vault.timer');
  fs.unlinkSync(locations.marker);
  fs.symlinkSync(tokenPath(value), locations.marker);
  assert.throws(() => disableIntegration(plan, value.deps), /integration_path_unsafe/);
  assert.equal(value.calls.some(args => args[0] === 'enable' && args.includes('amf-obsidian-sync@host-vault.timer')), true);
});

test('trusted release rejects self-consistent but unpinned client bytes', t => {
  const value = fixture(); t.after(value.cleanup);
  const changed = Buffer.from('changed\n');
  fs.writeFileSync(path.join(value.sourceRoot, '__main__.py'), changed);
  const files = value.metadata.source.files.map(item => item.path === '__main__.py'
    ? { path: item.path, size: changed.length, digest: digest(changed) } : item);
  value.metadata.source.files = files;
  value.metadata.source.digest = digest(Buffer.from(canonicalJson(files)));
  assert.throws(() => buildPlan('obsidian-second-brain', value.options, value.deps), /integration_client_release_mismatch/);
});
