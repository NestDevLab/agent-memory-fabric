import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { describeIntegration } from './catalog.mjs';
import { canonicalJson, DEFAULT_ROOTS } from './lifecycle.mjs';

const ID = 'harness-raw-capture';
const PLAN_SCHEMA = 'amf.harness-raw-capture-plan/v1';
const INSTALL_SCHEMA = 'amf.harness-raw-capture-installation/v1';

function fail(code, detail = '') { throw new Error(detail ? `${code}:${detail}` : code); }
function digest(bytes) { return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`; }
function jsonBytes(value) { return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8'); }
function safeName(value, label) {
  if (typeof value !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value)) fail('integration_option_invalid', label);
  return value;
}
function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value
    || /[\0\r\n'\s]/.test(value)) fail('integration_path_invalid', label);
  return value;
}
function bounded(value, fallback, label) {
  const result = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(result) || result < 1 || result > 10_000) fail('integration_option_invalid', label);
  return result;
}
function regular(fsImpl, target, options = {}) {
  let stat; try { stat = fsImpl.lstatSync(target); } catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('integration_path_unsafe', target);
  if (options.mode !== undefined && (stat.mode & 0o777) !== options.mode) fail('integration_permissions_unsafe', target);
  if (options.executable && (stat.mode & 0o111) === 0) fail('integration_permissions_unsafe', target);
  return stat;
}
function directory(fsImpl, target) {
  const stat = fsImpl.lstatSync(target);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fsImpl.realpathSync(target) !== target) fail('integration_path_unsafe', target);
  return stat;
}
function readRegular(fsImpl, target, options = {}) {
  regular(fsImpl, target, options); return fsImpl.readFileSync(target);
}
function artifact(target, bytes, mode) { return { path: target, digest: digest(bytes), size: bytes.length, mode: mode.toString(8).padStart(4, '0') }; }

function dependencies(overrides = {}) {
  const roots = { ...DEFAULT_ROOTS, ...(overrides.roots || {}) };
  return { fs: overrides.fs || fs, roots, systemctl: overrides.systemctl || (args => {
    const result = spawnSync('/usr/bin/systemctl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '' };
  }) };
}

function locations(instance, roots) {
  const base = path.join(roots.state, ID, instance);
  return { base, manifest: path.join(base, 'installation.json'),
    wrapper: path.join(roots.libexec, `amf-runtime-raw-hook-${instance}`),
    pathUnit: path.join(roots.systemd, `agent-memory-fabric-runtime-raw-hook-${instance}.path`) };
}
function unitNames(instance) { return { path: `agent-memory-fabric-runtime-raw-hook-${instance}.path`,
  service: `agent-memory-fabric-runtime-raw@${instance}.service`, timer: `agent-memory-fabric-runtime-raw@${instance}.timer` }; }

function validateOptions(value, deps, { requirePaths = true } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('integration_options_invalid');
  const instanceId = safeName(value.instance, 'instance'); const runtime = value.runtime;
  if (!['codex', 'claude'].includes(runtime)) fail('integration_option_invalid', 'runtime');
  const captureMode = value.captureMode === undefined ? 'hook-push' : value.captureMode;
  if (captureMode !== 'hook-push') fail('integration_option_invalid', 'capture-mode');
  const conflictPolicy = value.conflictPolicy === undefined ? 'fail' : value.conflictPolicy;
  if (!['fail', 'disable-managed'].includes(conflictPolicy)) fail('integration_option_invalid', 'conflict-policy');
  const adapterRoot = absolute(value.adapterRoot, 'adapter-root');
  const nodeBinary = absolute(value.nodeBinary, 'node-binary');
  const runtimeConfig = absolute(value.runtimeConfig, 'runtime-config');
  const environmentFile = absolute(value.environmentFile, 'environment-file');
  const triggerPath = absolute(value.triggerPath, 'trigger-path');
  const maxTriggersPerPass = bounded(value.maxTriggersPerPass, 100, 'max-triggers-per-pass');
  const hookFile = path.join(adapterRoot, 'runtime/raw-adapters/bin/amf-runtime-raw.mjs');
  if (requirePaths) {
    directory(deps.fs, adapterRoot); regular(deps.fs, nodeBinary, { executable: true });
    regular(deps.fs, hookFile); regular(deps.fs, runtimeConfig, { mode: 0o600 });
    regular(deps.fs, environmentFile, { mode: 0o600 });
    let parsed; try { parsed = JSON.parse(readRegular(deps.fs, runtimeConfig)); } catch { fail('integration_runtime_config_invalid'); }
    if (parsed?.schema !== 'amf.runtime-raw-adapters/v1' || parsed.captureMode !== captureMode
      || parsed.hookCapture?.schema !== 'amf.runtime-raw-hook-capture/v1'
      || parsed.hookCapture?.triggerPath !== triggerPath || parsed.hookCapture?.maxTriggersPerPass !== maxTriggersPerPass
      || !Array.isArray(parsed.sources) || !parsed.sources.some(source => source.runtime === runtime && source.root)) {
      fail('integration_runtime_config_mismatch');
    }
  }
  return { instanceId, runtime, captureMode, conflictPolicy, adapterRoot, nodeBinary, runtimeConfig, environmentFile,
    triggerPath, maxTriggersPerPass, hookFile };
}

function render(config, names, targets) {
  const wrapper = Buffer.from(`#!/bin/sh\nset -eu\nset -a\n. '${config.environmentFile}'\nset +a\nexec '${config.nodeBinary}' '${config.hookFile}' --config '${config.runtimeConfig}' --mode hook --harness '${config.runtime}'\n`, 'utf8');
  const pathUnit = Buffer.from(`[Unit]\nDescription=Agent Memory Fabric event-driven RAW capture (${config.instanceId})\nAfter=local-fs.target\n\n[Path]\nPathExistsGlob=${config.triggerPath}/*.enc.json\nUnit=${names.service}\n\n[Install]\nWantedBy=multi-user.target\n`, 'utf8');
  return { wrapper, pathUnit, targets };
}

function planUnsigned(id, options, overrides = {}) {
  if (id !== ID) fail('integration_unknown');
  const deps = dependencies(overrides); const descriptor = describeIntegration(id); const config = validateOptions(options, deps);
  const targets = locations(config.instanceId, deps.roots); const names = unitNames(config.instanceId);
  const rendered = render(config, names, targets); const adapterBytes = readRegular(deps.fs, config.hookFile);
  return { schema: PLAN_SCHEMA, integrationId: id, descriptorVersion: descriptor.version, instanceId: config.instanceId,
    operationDefaults: { installEnabled: false, scheduler: 'systemd-path' }, config,
    adapter: { entrypoint: config.hookFile, digest: digest(adapterBytes), size: adapterBytes.length },
    conflicts: [{ capability: 'raw-conversation-capture', managedUnit: names.timer, policy: config.conflictPolicy }],
    preservation: [...descriptor.dataPreservation], artifacts: { wrapper: artifact(targets.wrapper, rendered.wrapper, 0o755),
      pathUnit: artifact(targets.pathUnit, rendered.pathUnit, 0o644), manifest: targets.manifest }, observations: { mutations: [] } };
}

export function buildHarnessRawCapturePlan(id, options, overrides = {}) {
  const plan = planUnsigned(id, options, overrides); return { ...plan, planDigest: digest(Buffer.from(canonicalJson(plan), 'utf8')) };
}
export function serializeHarnessRawCapturePlan(plan) { return jsonBytes(plan); }

function validatePlan(plan, overrides = {}, requirePaths = true) {
  if (plan?.schema !== PLAN_SCHEMA || plan.integrationId !== ID) fail('integration_plan_invalid');
  const unsigned = structuredClone(plan); delete unsigned.planDigest;
  if (plan.planDigest !== digest(Buffer.from(canonicalJson(unsigned), 'utf8'))) fail('integration_plan_digest_mismatch');
  const deps = dependencies(overrides); const descriptor = describeIntegration(ID);
  const config = validateOptions({ instance: plan.config?.instanceId, runtime: plan.config?.runtime,
    captureMode: plan.config?.captureMode, conflictPolicy: plan.config?.conflictPolicy,
    adapterRoot: plan.config?.adapterRoot, nodeBinary: plan.config?.nodeBinary, runtimeConfig: plan.config?.runtimeConfig,
    environmentFile: plan.config?.environmentFile, triggerPath: plan.config?.triggerPath,
    maxTriggersPerPass: plan.config?.maxTriggersPerPass }, deps, { requirePaths });
  const targets = locations(config.instanceId, deps.roots); const names = unitNames(config.instanceId);
  const rendered = render(config, names, targets);
  const expectedShape = { schema: PLAN_SCHEMA, integrationId: ID, descriptorVersion: descriptor.version,
    instanceId: config.instanceId, operationDefaults: { installEnabled: false, scheduler: 'systemd-path' }, config,
    conflicts: [{ capability: 'raw-conversation-capture', managedUnit: names.timer, policy: config.conflictPolicy }],
    preservation: [...descriptor.dataPreservation], artifacts: {
      wrapper: artifact(targets.wrapper, rendered.wrapper, 0o755),
      pathUnit: artifact(targets.pathUnit, rendered.pathUnit, 0o644), manifest: targets.manifest,
    }, observations: { mutations: [] } };
  for (const key of ['schema', 'integrationId', 'descriptorVersion', 'instanceId', 'operationDefaults', 'config',
    'conflicts', 'preservation', 'artifacts', 'observations']) {
    if (canonicalJson(unsigned[key]) !== canonicalJson(expectedShape[key])) fail('integration_plan_drift', key);
  }
  if (plan.adapter?.entrypoint !== config.hookFile || !/^sha256:[0-9a-f]{64}$/.test(plan.adapter?.digest || '')
    || !Number.isSafeInteger(plan.adapter?.size) || plan.adapter.size < 1) fail('integration_plan_drift', 'adapter');
  if (requirePaths) {
    const adapterBytes = readRegular(deps.fs, config.hookFile);
    if (plan.adapter.digest !== digest(adapterBytes) || plan.adapter.size !== adapterBytes.length) fail('integration_plan_drift', 'adapter');
  }
  return plan;
}

export function loadConfirmedHarnessRawCapturePlan(planPath, confirmed, overrides = {}) {
  absolute(planPath, 'plan'); if (!/^[0-9a-f]{64}$/.test(confirmed || '')) fail('integration_confirmation_invalid');
  const bytes = readRegular(dependencies(overrides).fs, planPath);
  if (digest(bytes).slice(7) !== confirmed) fail('integration_confirmation_mismatch');
  let plan; try { plan = JSON.parse(bytes); } catch { fail('integration_plan_invalid_json'); }
  return validatePlan(plan, overrides, false);
}

function mkdirp(fsImpl, target, mode = 0o755) { fsImpl.mkdirSync(target, { recursive: true, mode }); }
function writeAtomic(fsImpl, target, bytes, mode) {
  mkdirp(fsImpl, path.dirname(target)); const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  try { fsImpl.writeFileSync(temporary, bytes, { flag: 'wx', mode }); fsImpl.chmodSync(temporary, mode); fsImpl.renameSync(temporary, target); }
  finally { try { fsImpl.unlinkSync(temporary); } catch {} }
}
function systemctlOk(deps, args, allowed = [0]) {
  const result = deps.systemctl(args); if (!allowed.includes(result.status)) fail('integration_systemctl_failed', args.join(' ')); return result;
}
function readManifest(deps, target) {
  if (!deps.fs.existsSync(target)) return null;
  let value; try { value = JSON.parse(readRegular(deps.fs, target, { mode: 0o600 })); } catch { fail('integration_manifest_invalid'); }
  if (value.schema !== INSTALL_SCHEMA || value.integrationId !== ID) fail('integration_manifest_invalid'); return value;
}

function snapshotFile(fsImpl, target) {
  if (!fsImpl.existsSync(target)) return { target, exists: false };
  const stat = regular(fsImpl, target); return { target, exists: true, bytes: fsImpl.readFileSync(target), mode: stat.mode & 0o777 };
}
function restoreFiles(fsImpl, snapshots) {
  for (const snapshot of snapshots) {
    if (snapshot.exists) writeAtomic(fsImpl, snapshot.target, snapshot.bytes, snapshot.mode);
    else if (fsImpl.existsSync(snapshot.target)) { regular(fsImpl, snapshot.target); fsImpl.unlinkSync(snapshot.target); }
  }
}
function unitState(deps, unit) { return { enabled: deps.systemctl(['is-enabled', unit]).status === 0,
  active: deps.systemctl(['is-active', unit]).status === 0 }; }
function restoreUnitState(deps, unit, previous) {
  systemctlOk(deps, [previous.enabled ? 'enable' : 'disable', unit], [0, 1]);
  systemctlOk(deps, [previous.active ? 'start' : 'stop', unit], [0, 1]);
}
function rollbackFiles(deps, snapshots, error, unitRestore = []) {
  try {
    restoreFiles(deps.fs, snapshots); systemctlOk(deps, ['daemon-reload']);
    for (const item of unitRestore) restoreUnitState(deps, item.unit, item.state);
  } catch (rollbackError) { fail('integration_rollback_failed', rollbackError.message); }
  throw error;
}

export function installHarnessRawCapture(plan, overrides = {}) {
  validatePlan(plan, overrides); const deps = dependencies(overrides); const targets = locations(plan.instanceId, deps.roots);
  const existing = readManifest(deps, targets.manifest);
  if (existing) { if (existing.planDigest !== plan.planDigest) fail('integration_already_installed_different_plan'); return { changed: false, installation: existing }; }
  for (const target of [targets.wrapper, targets.pathUnit]) {
    if (deps.fs.existsSync(target)) fail('integration_unowned_artifact_exists', target);
  }
  const names = unitNames(plan.instanceId); const rendered = render(plan.config, names, targets);
  if (digest(readRegular(deps.fs, plan.adapter.entrypoint)) !== plan.adapter.digest) fail('integration_adapter_plan_drift');
  const installation = { schema: INSTALL_SCHEMA, integrationId: ID, instanceId: plan.instanceId,
    descriptorVersion: plan.descriptorVersion, planDigest: plan.planDigest, config: structuredClone(plan.config),
    artifacts: structuredClone(plan.artifacts), units: names, preserved: [...plan.preservation] };
  const snapshots = [targets.wrapper, targets.pathUnit, targets.manifest].map(target => snapshotFile(deps.fs, target));
  try {
    writeAtomic(deps.fs, targets.wrapper, rendered.wrapper, 0o755); writeAtomic(deps.fs, targets.pathUnit, rendered.pathUnit, 0o644);
    writeAtomic(deps.fs, targets.manifest, jsonBytes(installation), 0o600); systemctlOk(deps, ['daemon-reload']);
  } catch (error) { rollbackFiles(deps, snapshots, error); }
  return { changed: true, installation };
}
function context(plan, overrides) {
  validatePlan(plan, overrides, false); const deps = dependencies(overrides); const targets = locations(plan.instanceId, deps.roots);
  const manifest = readManifest(deps, targets.manifest); if (!manifest || manifest.planDigest !== plan.planDigest) fail('integration_plan_not_installed');
  return { deps, targets, manifest, names: unitNames(plan.instanceId) };
}
export function runHarnessRawCapture(plan, overrides = {}) {
  const { deps, names } = context(plan, overrides); systemctlOk(deps, ['start', names.service]); return { changed: false, started: names.service };
}
export function enableHarnessRawCapture(plan, overrides = {}) {
  const { deps, names } = context(plan, overrides); const timerBefore = unitState(deps, names.timer);
  const pathBefore = unitState(deps, names.path); const timerEnabled = timerBefore.enabled; const timerActive = timerBefore.active;
  if ((timerEnabled || timerActive) && plan.config.conflictPolicy === 'fail') fail('integration_capture_conflict', names.timer);
  try {
    if (timerEnabled || timerActive) systemctlOk(deps, ['disable', '--now', names.timer], [0, 1]);
    systemctlOk(deps, ['enable', '--now', names.path]);
  } catch (error) {
    try { restoreUnitState(deps, names.path, pathBefore); restoreUnitState(deps, names.timer, timerBefore); }
    catch (rollbackError) { fail('integration_rollback_failed', rollbackError.message); }
    throw error;
  }
  return { changed: true, enabled: true, path: names.path, disabledConflict: timerEnabled || timerActive ? names.timer : null };
}
export function disableHarnessRawCapture(plan, overrides = {}) {
  const { deps, names } = context(plan, overrides); systemctlOk(deps, ['disable', '--now', names.path], [0, 1]);
  return { changed: true, enabled: false, path: names.path };
}
export function uninstallHarnessRawCapture(plan, overrides = {}) {
  const deps = dependencies(overrides); validatePlan(plan, overrides, false); const targets = locations(plan.instanceId, deps.roots);
  const manifest = readManifest(deps, targets.manifest);
  if (!manifest) return { changed: false, installed: false, preserved: [...plan.preservation] };
  if (manifest.planDigest !== plan.planDigest) fail('integration_plan_not_installed'); const names = unitNames(plan.instanceId);
  const pathBefore = unitState(deps, names.path);
  const snapshots = [targets.wrapper, targets.pathUnit, targets.manifest].map(target => snapshotFile(deps.fs, target));
  try {
    systemctlOk(deps, ['disable', '--now', names.path], [0, 1]);
    for (const target of [targets.wrapper, targets.pathUnit, targets.manifest]) {
      if (deps.fs.existsSync(target)) { regular(deps.fs, target); deps.fs.unlinkSync(target); }
    }
    systemctlOk(deps, ['daemon-reload']);
  } catch (error) { rollbackFiles(deps, snapshots, error, [{ unit: names.path, state: pathBefore }]); }
  return { changed: true, preserved: [...plan.preservation] };
}

function state(deps, verb, unit) { const result = deps.systemctl([verb, unit]); return result.status === 0; }
export function harnessRawCaptureStatus(id, instance, overrides = {}) {
  if (id !== ID) fail('integration_unknown'); safeName(instance, 'instance'); const deps = dependencies(overrides);
  const targets = locations(instance, deps.roots); const manifest = readManifest(deps, targets.manifest);
  if (!manifest) return { integrationId: id, instanceId: instance, installed: false, optional: true, health: 'skipped' };
  const names = unitNames(instance); let artifactParity = false;
  try {
    const rendered = render(manifest.config, names, targets);
    artifactParity = digest(readRegular(deps.fs, targets.wrapper)) === manifest.artifacts.wrapper.digest
      && Buffer.compare(readRegular(deps.fs, targets.wrapper), rendered.wrapper) === 0
      && digest(readRegular(deps.fs, targets.pathUnit)) === manifest.artifacts.pathUnit.digest
      && Buffer.compare(readRegular(deps.fs, targets.pathUnit), rendered.pathUnit) === 0;
  } catch { artifactParity = false; }
  const pathEnabled = state(deps, 'is-enabled', names.path); const pathActive = state(deps, 'is-active', names.path);
  const pollTimerEnabled = state(deps, 'is-enabled', names.timer); const pollTimerActive = state(deps, 'is-active', names.timer);
  const healthy = artifactParity && pathEnabled && !pollTimerEnabled && !pollTimerActive;
  return { integrationId: id, instanceId: instance, installed: true, captureMode: manifest.config.captureMode,
    artifactParity, pathEnabled, pathActive, pollTimerEnabled, pollTimerActive, healthy, health: healthy ? 'healthy' : 'degraded' };
}
