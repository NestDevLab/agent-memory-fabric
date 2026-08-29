import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { describeIntegration, listIntegrations } from '../src/integrations/catalog.mjs';
import {
  buildHarnessRawCapturePlan,
  disableHarnessRawCapture,
  enableHarnessRawCapture,
  harnessRawCaptureStatus,
  installHarnessRawCapture,
  loadConfirmedHarnessRawCapturePlan,
  serializeHarnessRawCapturePlan,
  uninstallHarnessRawCapture,
} from '../src/integrations/harness-raw-capture.mjs';

function fixture(conflictPolicy = 'disable-managed') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-hook-integration-'));
  const roots = { etc: path.join(root, 'etc'), systemd: path.join(root, 'systemd'),
    libexec: path.join(root, 'libexec'), state: path.join(root, 'state') };
  for (const directory of Object.values(roots)) fs.mkdirSync(directory, { recursive: true });
  const adapterRoot = path.join(root, 'adapter'); const bin = path.join(adapterRoot, 'runtime/raw-adapters/bin');
  const sessions = path.join(root, 'sessions'); fs.mkdirSync(bin, { recursive: true }); fs.mkdirSync(sessions);
  fs.writeFileSync(path.join(bin, 'amf-runtime-raw.mjs'), '#!/usr/bin/env node\n', { mode: 0o755 });
  const runtimeConfig = path.join(root, 'runtime.json'); const environmentFile = path.join(root, 'runtime.env');
  const triggerPath = path.join(root, 'triggers');
  fs.writeFileSync(runtimeConfig, JSON.stringify({ schema: 'amf.runtime-raw-adapters/v1', captureMode: 'hook-push',
    hookCapture: { schema: 'amf.runtime-raw-hook-capture/v1', triggerPath, maxTriggersPerPass: 100 },
    sources: [{ runtime: 'codex', sourceId: 'ct107-codex', root: sessions }] }), { mode: 0o600 });
  fs.writeFileSync(environmentFile, 'AMF_RAW_CURSOR_KEY=placeholder\n', { mode: 0o600 });
  const enabled = new Set(['agent-memory-fabric-runtime-raw@ct107-codex.timer']);
  const active = new Set(['agent-memory-fabric-runtime-raw@ct107-codex.timer']); const calls = [];
  const systemctl = args => {
    calls.push(args); const [verb, maybeNow, maybeUnit] = args; const unit = maybeUnit || maybeNow;
    if (verb === 'is-enabled') return { status: enabled.has(unit) ? 0 : 1, stdout: '', stderr: '' };
    if (verb === 'is-active') return { status: active.has(unit) ? 0 : 1, stdout: '', stderr: '' };
    if (verb === 'disable') { enabled.delete(unit); active.delete(unit); return { status: 0, stdout: '', stderr: '' }; }
    if (verb === 'enable') { enabled.add(unit); active.add(unit); return { status: 0, stdout: '', stderr: '' }; }
    return { status: 0, stdout: '', stderr: '' };
  };
  const options = { instance: 'ct107-codex', runtime: 'codex', adapterRoot, runtimeConfig, environmentFile,
    triggerPath, captureMode: 'hook-push', conflictPolicy, maxTriggersPerPass: 100 };
  return { root, roots, options, deps: { roots, systemctl }, calls, enabled, active, runtimeConfig, environmentFile, triggerPath };
}

test('catalog publishes configurable harness RAW capture without private host values', () => {
  const descriptor = describeIntegration('harness-raw-capture');
  assert.equal(descriptor.category, 'runtime-capture');
  assert.deepEqual(descriptor.agentwheel.supportedRuntimes, ['codex', 'claude']);
  assert.equal(listIntegrations().some(item => item.id === 'harness-raw-capture'), true);
  assert.equal(JSON.stringify(descriptor).includes('ct107'), false);
});

test('harness RAW capture lifecycle is digest-gated, disabled on install, conflict-aware, and preservative', () => {
  const value = fixture(); const first = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  const second = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  assert.deepEqual(first, second); assert.equal(first.operationDefaults.installEnabled, false);
  const bytes = serializeHarnessRawCapturePlan(first); const planPath = path.join(value.root, 'plan.json');
  fs.writeFileSync(planPath, bytes, { mode: 0o600 });
  const confirmed = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.deepEqual(loadConfirmedHarnessRawCapturePlan(planPath, confirmed, value.deps), first);
  const tampered = structuredClone(first); tampered.config.runtime = 'claude';
  assert.throws(() => installHarnessRawCapture(tampered, value.deps), /integration_plan_digest_mismatch/);

  const installed = installHarnessRawCapture(first, value.deps); assert.equal(installed.changed, true);
  assert.equal(value.calls.some(call => call[0] === 'enable'), false, 'install never activates the path unit');
  assert.equal(harnessRawCaptureStatus('harness-raw-capture', 'ct107-codex', value.deps).health, 'degraded');
  const enabled = enableHarnessRawCapture(first, value.deps);
  assert.equal(enabled.disabledConflict, 'agent-memory-fabric-runtime-raw@ct107-codex.timer');
  assert.deepEqual(value.calls.filter(call => ['disable', 'enable'].includes(call[0])).slice(-2), [
    ['disable', '--now', 'agent-memory-fabric-runtime-raw@ct107-codex.timer'],
    ['enable', '--now', 'agent-memory-fabric-runtime-raw-hook-ct107-codex.path']
  ]);
  assert.equal(harnessRawCaptureStatus('harness-raw-capture', 'ct107-codex', value.deps).health, 'healthy');
  disableHarnessRawCapture(first, value.deps); const removed = uninstallHarnessRawCapture(first, value.deps);
  assert.equal(removed.changed, true);
  for (const preserved of [value.runtimeConfig, value.environmentFile]) assert.equal(fs.existsSync(preserved), true);
});

test('fail conflict policy refuses activation while the managed RAW timer is active', () => {
  const value = fixture('fail'); const plan = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  installHarnessRawCapture(plan, value.deps);
  assert.throws(() => enableHarnessRawCapture(plan, value.deps), /integration_capture_conflict/);
  assert.equal(value.enabled.has('agent-memory-fabric-runtime-raw@ct107-codex.timer'), true);
});

test('confirmed plans cannot redirect lifecycle artifacts', () => {
  const value = fixture(); const plan = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  const forged = structuredClone(plan); forged.artifacts.wrapper.path = path.join(value.root, 'redirected-wrapper');
  delete forged.planDigest;
  // Rebuild the digest with the lifecycle canonicalizer's recursively sorted JSON representation.
  const sort = input => Array.isArray(input) ? input.map(sort) : input && typeof input === 'object'
    ? Object.fromEntries(Object.keys(input).sort().map(key => [key, sort(input[key])])) : input;
  forged.planDigest = `sha256:${crypto.createHash('sha256').update(JSON.stringify(sort(forged))).digest('hex')}`;
  const bytes = Buffer.from(`${JSON.stringify(forged, null, 2)}\n`); const planPath = path.join(value.root, 'forged-plan.json');
  fs.writeFileSync(planPath, bytes, { mode: 0o600 }); const confirmed = crypto.createHash('sha256').update(bytes).digest('hex');
  assert.throws(() => loadConfirmedHarnessRawCapturePlan(planPath, confirmed, value.deps), /integration_plan_drift:artifacts/);
});

test('install rolls back artifacts when daemon reload fails', () => {
  const value = fixture(); const plan = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  let failReload = true; const original = value.deps.systemctl;
  const deps = { ...value.deps, systemctl: args => {
    if (args[0] === 'daemon-reload' && failReload) { failReload = false; return { status: 1, stdout: '', stderr: 'injected' }; }
    return original(args);
  } };
  assert.throws(() => installHarnessRawCapture(plan, deps), /integration_systemctl_failed:daemon-reload/);
  for (const target of [plan.artifacts.wrapper.path, plan.artifacts.pathUnit.path, plan.artifacts.manifest]) {
    assert.equal(fs.existsSync(target), false);
  }
});

test('enable restores the managed timer when path activation fails', () => {
  const value = fixture(); const plan = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  installHarnessRawCapture(plan, value.deps); const original = value.deps.systemctl; let failEnable = true;
  const deps = { ...value.deps, systemctl: args => {
    if (args[0] === 'enable' && args.at(-1).endsWith('.path') && failEnable) {
      failEnable = false; return { status: 1, stdout: '', stderr: 'injected' };
    }
    return original(args);
  } };
  assert.throws(() => enableHarnessRawCapture(plan, deps), /integration_systemctl_failed:enable --now/);
  assert.equal(value.enabled.has('agent-memory-fabric-runtime-raw@ct107-codex.timer'), true);
  assert.equal(value.active.has('agent-memory-fabric-runtime-raw@ct107-codex.timer'), true);
  assert.equal(value.enabled.has('agent-memory-fabric-runtime-raw-hook-ct107-codex.path'), false);
});

test('uninstall restores files and path state when daemon reload fails', () => {
  const value = fixture(); const plan = buildHarnessRawCapturePlan('harness-raw-capture', value.options, value.deps);
  installHarnessRawCapture(plan, value.deps); enableHarnessRawCapture(plan, value.deps);
  let failReload = true; const original = value.deps.systemctl;
  const deps = { ...value.deps, systemctl: args => {
    if (args[0] === 'daemon-reload' && failReload) { failReload = false; return { status: 1, stdout: '', stderr: 'injected' }; }
    return original(args);
  } };
  assert.throws(() => uninstallHarnessRawCapture(plan, deps), /integration_systemctl_failed:daemon-reload/);
  for (const target of [plan.artifacts.wrapper.path, plan.artifacts.pathUnit.path, plan.artifacts.manifest]) {
    assert.equal(fs.existsSync(target), true);
  }
  assert.equal(value.enabled.has('agent-memory-fabric-runtime-raw-hook-ct107-codex.path'), true);
  assert.equal(value.active.has('agent-memory-fabric-runtime-raw-hook-ct107-codex.path'), true);
});
