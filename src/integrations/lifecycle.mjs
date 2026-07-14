import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { describeIntegration, INTEGRATION_ROOT } from './catalog.mjs';

const INTEGRATION_ID = 'obsidian-second-brain';
const PLAN_SCHEMA = 'amf.integration-plan/v1';
const INSTALL_SCHEMA = 'amf.integration-installation/v1';
const LEGACY_HASHES = Object.freeze({
  wrapper: 'sha256:db0be6129fe57b501087ae795a8cf7dd4878e8cd1c22dea945ec15656eaf1bd8',
  service: 'sha256:db59171f422c865986c46b8decd128ba4c9ad58baf1afad3f97359c3e02fff85',
  timer: 'sha256:98f40e4ea06d6e05571ac351721783eb3d2ee85b7eea5b6c478d00ab348e367d',
});

export const DEFAULT_ROOTS = Object.freeze({
  etc: '/etc/agent-memory-fabric',
  systemd: '/etc/systemd/system',
  libexec: '/usr/local/libexec',
  state: '/var/lib/agent-memory-fabric/integrations',
});

function fail(code, detail = '') {
  throw new Error(detail ? `${code}:${detail}` : code);
}

function sha256(bytes) {
  return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function assertString(value, name, pattern = null) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || /[\0\r\n]/.test(value)) fail('integration_option_invalid', name);
  if (pattern && !pattern.test(value)) fail('integration_option_invalid', name);
  return value;
}

function assertAbsolute(value, name) {
  assertString(value, name);
  if (!path.isAbsolute(value) || path.normalize(value) !== value) fail('integration_path_invalid', name);
  return value;
}

function assertUrl(value) {
  assertString(value, 'amf-url');
  let parsed;
  try { parsed = new URL(value); } catch { fail('integration_url_invalid'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash || parsed.search) fail('integration_url_invalid');
  return parsed.toString().replace(/\/$/, '');
}

function assertNumber(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('integration_option_invalid', name);
  return value;
}

function safeLstat(fsImpl, target, kind, options = {}) {
  const { mode, uid } = options;
  const links = Object.hasOwn(options, 'links') ? options.links : (kind === 'file' ? 1 : undefined);
  let stat;
  try { stat = fsImpl.lstatSync(target); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
  if (stat.isSymbolicLink() || (kind === 'file' && !stat.isFile()) || (kind === 'directory' && !stat.isDirectory())) fail('integration_path_unsafe', target);
  if (mode !== undefined && (stat.mode & 0o777) !== mode) fail('integration_permissions_unsafe', target);
  if (uid !== undefined && stat.uid !== uid) fail('integration_owner_unsafe', target);
  if (links !== undefined && stat.nlink !== links) fail('integration_link_count_unsafe', target);
  return stat;
}

function assertParentsNoSymlink(fsImpl, target) {
  if (!path.isAbsolute(target)) fail('integration_path_invalid', target);
  const parent = path.dirname(target);
  const parts = parent.split(path.sep).filter(Boolean);
  let cursor = path.parse(parent).root;
  for (const part of parts) {
    cursor = path.join(cursor, part);
    const stat = fsImpl.lstatSync(cursor);
    if (stat.isSymbolicLink() || !stat.isDirectory()) fail('integration_parent_unsafe', cursor);
  }
  if (fsImpl.realpathSync(parent) !== parent) fail('integration_parent_unsafe', parent);
}

function readRegular(fsImpl, target, options = {}) {
  if (!fs.constants.O_NOFOLLOW) fail('integration_nofollow_unavailable');
  assertParentsNoSymlink(fsImpl, target);
  safeLstat(fsImpl, target, 'file', options);
  const descriptor = fsImpl.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fsImpl.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== (options.links ?? 1)) fail('integration_path_unsafe', target);
    const bytes = fsImpl.readFileSync(descriptor);
    const after = fsImpl.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) fail('integration_source_changed', target);
    return bytes;
  } finally { fsImpl.closeSync(descriptor); }
}

function validateClientPayload(payload, fsImpl, expectedRelease) {
  if (!payload || typeof payload !== 'object') fail('integration_client_metadata_invalid');
  const root = assertAbsolute(payload.sourceRoot, 'client-source-root');
  if (!safeLstat(fsImpl, root, 'directory', { links: undefined })) fail('integration_client_source_missing');
  const metadata = payload.metadata;
  if (metadata?.schema !== 'obsidian-amf-client/v1' || metadata.name !== 'obsidian_amf') fail('integration_client_metadata_invalid');
  if (expectedRelease?.version && metadata.version !== expectedRelease.version) fail('integration_client_version_mismatch');
  if (!Array.isArray(metadata?.source?.files) || !/^sha256:[0-9a-f]{64}$/.test(metadata?.source?.digest || '')) fail('integration_client_metadata_invalid');
  const seen = new Set();
  const verifiedBytes = new Map();
  const files = metadata.source.files.map(item => {
    if (!item || typeof item.path !== 'string' || item.path.includes('/') || item.path.includes('\\') || item.path === '.' || item.path === '..' || seen.has(item.path)) fail('integration_client_manifest_invalid');
    seen.add(item.path);
    const bytes = readRegular(fsImpl, path.join(root, item.path));
    if (bytes.length !== item.size || sha256(bytes) !== item.digest) fail('integration_client_source_mismatch', item.path);
    verifiedBytes.set(item.path, bytes);
    return { path: item.path, size: item.size, digest: item.digest };
  });
  const manifestDigest = sha256(Buffer.from(canonicalJson(files), 'utf8'));
  // Python emits compact JSON with sorted object keys; canonicalJson has identical ordering.
  if (manifestDigest !== metadata.source.digest) fail('integration_client_manifest_mismatch');
  if (expectedRelease?.sourceDigest && metadata.source.digest !== expectedRelease.sourceDigest) fail('integration_client_release_mismatch');
  if (expectedRelease?.files && canonicalJson(files) !== canonicalJson(expectedRelease.files)) fail('integration_client_release_manifest_mismatch');
  return { sourceRoot: root, metadata: structuredClone(metadata), files, verifiedBytes };
}

function defaultResolveClientSource(clientRoot, expectedRelease) {
  const candidates = [
    path.join(clientRoot, 'scripts', 'obsidian_amf'),
    path.join(clientRoot, 'obsidian_amf'),
    clientRoot,
  ];
  const sourceRoot = candidates.find(candidate => {
    try { return safeLstat(fs, candidate, 'directory', { links: undefined }) !== null && fs.existsSync(path.join(candidate, '__main__.py')); }
    catch { return false; }
  });
  if (!sourceRoot || !expectedRelease) fail('integration_client_source_missing');
  return {
    sourceRoot,
    metadata: {
      schema: expectedRelease.schema || 'obsidian-amf-client/v1',
      name: expectedRelease.name || 'obsidian_amf',
      version: expectedRelease.version,
      source: { digest: expectedRelease.sourceDigest, files: structuredClone(expectedRelease.files) },
    },
  };
}

function defaultSystemctl(args) {
  const result = spawnSync('systemctl', args, { encoding: 'utf8', timeout: 60_000, maxBuffer: 1024 * 1024 });
  return { status: result.status ?? 1, stdout: result.stdout || '', stderr: result.stderr || '' };
}

function defaultRunClientStatus({ pythonPath, environment, tokenPath }) {
  const allowed = ['OBSIDIAN_VAULT_PATH', 'OBSIDIAN_AMF_VAULT_ID', 'OBSIDIAN_AMF_MODE', 'OBSIDIAN_AMF_URL',
    'OBSIDIAN_AMF_ACTOR', 'OBSIDIAN_AMF_SOURCE_INSTANCE'];
  const cleanEnvironment = { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', PYTHONPATH: pythonPath, OBSIDIAN_AMF_TOKEN_FILE: tokenPath };
  for (const key of allowed) if (environment[key] !== undefined) cleanEnvironment[key] = environment[key];
  const result = spawnSync('/usr/bin/python3', ['-m', 'obsidian_amf', 'status'], {
    encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024, env: cleanEnvironment,
  });
  if (result.status !== 0) fail('integration_client_status_failed', String(result.status));
  try { return JSON.parse(result.stdout); } catch { fail('integration_client_status_invalid_json'); }
}

export function createDependencies(overrides = {}) {
  return {
    fs,
    roots: DEFAULT_ROOTS,
    resolveClientSource: defaultResolveClientSource,
    systemctl: defaultSystemctl,
    runClientStatus: defaultRunClientStatus,
    uid: 0,
    ...overrides,
    roots: { ...DEFAULT_ROOTS, ...(overrides.roots || {}) },
  };
}

function pathsFor(instance, roots) {
  const base = path.join(roots.state, INTEGRATION_ID, instance);
  return {
    base,
    manifest: path.join(base, 'installation.json'),
    clientRoot: path.join(base, 'client'),
    moduleRoot: path.join(base, 'client', 'scripts', 'obsidian_amf'),
    env: path.join(roots.etc, `obsidian-sync-${instance}.env`),
    token: path.join(roots.etc, `obsidian-sync-${instance}.token`),
    marker: path.join(roots.etc, `obsidian-sync-${instance}.enabled`),
    wrapper: path.join(roots.libexec, 'amf-obsidian-sync'),
    service: path.join(roots.systemd, `amf-obsidian-sync@${instance}.service`),
    timer: path.join(roots.systemd, `amf-obsidian-sync@${instance}.timer`),
    templateService: path.join(roots.systemd, 'amf-obsidian-sync@.service'),
    templateTimer: path.join(roots.systemd, 'amf-obsidian-sync@.timer'),
  };
}

function quoteEnvironment(value) {
  assertString(value, 'environment-value');
  return JSON.stringify(value);
}

function renderEnvironment(config, installedClientRoot) {
  return `${[
    ['OBSIDIAN_VAULT_PATH', config.vault.path],
    ['OBSIDIAN_AMF_VAULT_ID', config.vault.id],
    ['OBSIDIAN_AMF_MODE', 'shadow'],
    ['OBSIDIAN_AMF_URL', config.amfUrl],
    ['OBSIDIAN_AMF_ACTOR', config.actor],
    ['OBSIDIAN_AMF_SOURCE_INSTANCE', config.sourceInstanceId],
    ['OBSIDIAN_AMF_CLIENT_ROOT', installedClientRoot],
  ].map(([key, value]) => `${key}=${quoteEnvironment(value)}`).join('\n')}\n`;
}

function readTemplate(name) {
  return fs.readFileSync(path.join(INTEGRATION_ROOT, 'integrations', INTEGRATION_ID, 'systemd', name), 'utf8');
}

function renderTemplate(name, values) {
  let content = readTemplate(name);
  for (const [key, value] of Object.entries(values)) content = content.replaceAll(`@@${key}@@`, String(value));
  if (/@@[A-Z_]+@@/.test(content)) fail('integration_template_unresolved', name);
  return content;
}

function renderArtifacts(config, locations) {
  const service = renderTemplate('amf-obsidian-sync.service.in', {
    INSTANCE: config.instanceId,
    SERVICE_USER: config.service.user,
    SERVICE_GROUP: config.service.group,
    ENV_PATH: locations.env,
    TOKEN_PATH: locations.token,
    MARKER_PATH: locations.marker,
    WRAPPER_PATH: locations.wrapper,
    VAULT_STATE_PATH: path.join(config.vault.path, '.amf'),
  });
  const timer = renderTemplate('amf-obsidian-sync.timer.in', {
    INSTANCE: config.instanceId,
    INTERVAL_SEC: config.service.intervalSec,
    JITTER_SEC: config.service.jitterSec,
    SERVICE_UNIT: `amf-obsidian-sync@${config.instanceId}.service`,
  });
  const wrapper = fs.readFileSync(path.join(INTEGRATION_ROOT, 'integrations', INTEGRATION_ID, 'amf-obsidian-sync'));
  return {
    wrapper,
    env: Buffer.from(renderEnvironment(config, locations.clientRoot)),
    service: Buffer.from(service),
    timer: Buffer.from(timer),
  };
}

function artifactRecord(target, bytes, mode) {
  return { path: target, mode: mode.toString(8).padStart(4, '0'), size: bytes.length, digest: sha256(bytes) };
}

function validatePlanOptions(options, deps, { requirePaths = true } = {}) {
  const instanceId = assertString(options.instance, 'instance', /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
  const vaultPath = assertAbsolute(options.vault, 'vault');
  if (!/^\/[A-Za-z0-9._/-]+$/.test(vaultPath)) fail('integration_vault_path_unsupported');
  if (requirePaths && !safeLstat(deps.fs, vaultPath, 'directory', { links: undefined })) fail('integration_path_missing', 'vault');
  if (requirePaths && !safeLstat(deps.fs, path.join(vaultPath, '.amf'), 'directory', { links: undefined })) fail('integration_path_missing', 'vault-state');
  const clientRoot = assertAbsolute(options.clientRoot, 'client-root');
  if (requirePaths && !safeLstat(deps.fs, clientRoot, 'directory', { links: undefined })) fail('integration_path_missing', 'client-root');
  const intervalSec = assertNumber(Number(options.intervalSec), 'interval-sec', 60, 86_400);
  const jitterSec = assertNumber(Number(options.jitterSec), 'jitter-sec', 0, intervalSec);
  return {
    instanceId,
    integrationId: INTEGRATION_ID,
    mode: 'shadow',
    vault: { path: vaultPath, id: assertString(options.vaultId, 'vault-id', /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/) },
    actor: assertString(options.actor, 'actor', /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/),
    amfUrl: assertUrl(options.amfUrl),
    sourceInstanceId: assertString(options.sourceInstance, 'source-instance', /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/),
    sourceClientRoot: clientRoot,
    service: {
      scheduler: 'systemd',
      user: assertString(options.serviceUser, 'service-user', /^[a-z_][a-z0-9_-]{0,31}$/i),
      group: assertString(options.serviceGroup, 'service-group', /^[a-z_][a-z0-9_-]{0,31}$/i),
      intervalSec,
      jitterSec,
    },
  };
}

function observeTimers(deps) {
  const loaded = deps.systemctl(['list-units', 'amf-obsidian-sync@*.timer', '--all', '--no-legend', '--no-pager']);
  const installed = deps.systemctl(['list-unit-files', 'amf-obsidian-sync@*.timer', '--no-legend', '--no-pager']);
  if (loaded.status !== 0 || installed.status !== 0) return { available: false, timers: [], enabledTimers: [] };
  const parse = text => text.split(/\r?\n/)
    .map(line => line.trim().split(/\s+/)[0])
    .filter(name => /^amf-obsidian-sync@[^@.][^/]*\.timer$/.test(name));
  let configured = [];
  try {
    configured = deps.fs.readdirSync(deps.roots.etc, { withFileTypes: true })
      .filter(entry => entry.isFile() && /^obsidian-sync-[a-z0-9][a-z0-9-]{0,62}\.env$/.test(entry.name))
      .map(entry => `amf-obsidian-sync@${entry.name.slice('obsidian-sync-'.length, -'.env'.length)}.timer`);
  } catch { return { available: false, timers: [], enabledTimers: [] }; }
  const timers = [...new Set([...parse(loaded.stdout), ...parse(installed.stdout), ...configured])].sort();
  const enabledTimers = timers.filter(name => deps.systemctl(['is-enabled', name]).status === 0);
  return { available: true, timers, enabledTimers };
}

function timersForVault(vaultPath, observed, deps) {
  const matches = [];
  for (const timer of observed.timers) {
    const suffix = timer.slice('amf-obsidian-sync@'.length, -'.timer'.length);
    const envPath = pathsFor(suffix, deps.roots).env;
    if (!deps.fs.existsSync(envPath)) fail('integration_timer_ownership_unknown', timer);
    const env = environmentValues(readRegular(deps.fs, envPath).toString('utf8'));
    if (env.OBSIDIAN_VAULT_PATH === vaultPath) matches.push(timer);
  }
  return matches;
}

export function buildPlan(id, options, overrides = {}) {
  if (id !== INTEGRATION_ID) fail('integration_unknown');
  const deps = createDependencies(overrides);
  const descriptor = describeIntegration(id);
  const config = validatePlanOptions(options, deps);
  const locations = pathsFor(config.instanceId, deps.roots);
  const release = deps.clientRelease || descriptor.clientRelease;
  const source = validateClientPayload(deps.resolveClientSource(config.sourceClientRoot, release), deps.fs, release);
  const rendered = renderArtifacts(config, locations);
  const plan = {
    schema: PLAN_SCHEMA,
    integrationId: id,
    descriptorVersion: descriptor.version,
    instanceId: config.instanceId,
    operationDefaults: { installEnabled: false, automatedMode: 'shadow', scheduler: 'systemd' },
    config,
    clientSource: { metadata: source.metadata },
    secretRefs: { amfToken: locations.token },
    preservation: [...descriptor.dataPreservation],
    artifacts: {
      wrapper: artifactRecord(locations.wrapper, rendered.wrapper, 0o755),
      environment: artifactRecord(locations.env, rendered.env, 0o600),
      service: artifactRecord(locations.service, rendered.service, 0o644),
      timer: artifactRecord(locations.timer, rendered.timer, 0o644),
      client: source.files.map(item => ({ ...item, target: path.join(locations.moduleRoot, item.path), mode: '0644' })),
      manifest: locations.manifest,
    },
  };
  const legacy = legacyCandidates(plan, deps);
  plan.observations = {
    legacyLayout: legacy ? {
      recognized: true,
      suffix: legacy.suffix,
      unit: `amf-obsidian-sync@${legacy.suffix}.service`,
      timer: `amf-obsidian-sync@${legacy.suffix}.timer`,
      artifactParity: true,
    } : { recognized: false },
    systemd: observeTimers(deps),
    mutations: [],
  };
  plan.planDigest = sha256(Buffer.from(canonicalJson(plan), 'utf8'));
  return plan;
}

export function serializePlan(plan) { return jsonBytes(plan); }

function validatePlan(plan, deps = createDependencies(), { requirePaths = true } = {}) {
  if (plan?.schema !== PLAN_SCHEMA || plan.integrationId !== INTEGRATION_ID) fail('integration_plan_invalid');
  const digest = plan.planDigest;
  const unsigned = structuredClone(plan);
  delete unsigned.planDigest;
  if (digest !== sha256(Buffer.from(canonicalJson(unsigned), 'utf8'))) fail('integration_plan_digest_mismatch');
  const descriptor = describeIntegration(INTEGRATION_ID);
  if (plan.descriptorVersion !== descriptor.version) fail('integration_descriptor_version_mismatch');
  const config = validatePlanOptions({
    instance: plan.config?.instanceId,
    vault: plan.config?.vault?.path,
    vaultId: plan.config?.vault?.id,
    actor: plan.config?.actor,
    amfUrl: plan.config?.amfUrl,
    sourceInstance: plan.config?.sourceInstanceId,
    clientRoot: plan.config?.sourceClientRoot,
    serviceUser: plan.config?.service?.user,
    serviceGroup: plan.config?.service?.group,
    intervalSec: plan.config?.service?.intervalSec,
    jitterSec: plan.config?.service?.jitterSec,
  }, deps, { requirePaths });
  if (canonicalJson(plan.config) !== canonicalJson(config)) fail('integration_plan_config_mismatch');
  const release = deps.clientRelease || descriptor.clientRelease;
  if (plan.clientSource?.metadata?.version !== release.version
    || plan.clientSource?.metadata?.source?.digest !== release.sourceDigest
    || canonicalJson(plan.clientSource?.metadata?.source?.files) !== canonicalJson(release.files)) fail('integration_plan_client_release_mismatch');
  if (canonicalJson(plan.preservation) !== canonicalJson(descriptor.dataPreservation)) fail('integration_plan_preservation_mismatch');
  if (canonicalJson(plan.operationDefaults) !== canonicalJson({ installEnabled: false, automatedMode: 'shadow', scheduler: 'systemd' })) fail('integration_plan_defaults_mismatch');
  const locations = pathsFor(plan.instanceId, deps.roots);
  if (plan.instanceId !== config.instanceId || plan.secretRefs?.amfToken !== locations.token || plan.artifacts?.manifest !== locations.manifest) fail('integration_plan_path_mismatch');
  const rendered = renderArtifacts(config, locations);
  const expected = {
    wrapper: artifactRecord(locations.wrapper, rendered.wrapper, 0o755),
    environment: artifactRecord(locations.env, rendered.env, 0o600),
    service: artifactRecord(locations.service, rendered.service, 0o644),
    timer: artifactRecord(locations.timer, rendered.timer, 0o644),
  };
  for (const key of Object.keys(expected)) if (canonicalJson(plan.artifacts?.[key]) !== canonicalJson(expected[key])) fail('integration_plan_artifact_mismatch', key);
  const clients = release.files.map(item => ({ ...item, target: path.join(locations.moduleRoot, item.path), mode: '0644' }));
  if (canonicalJson(plan.artifacts?.client) !== canonicalJson(clients)) fail('integration_plan_artifact_mismatch', 'client');
  return plan;
}

export function loadConfirmedPlan(planPath, confirmed, overrides = {}) {
  const deps = createDependencies(overrides);
  assertAbsolute(planPath, 'plan');
  if (!/^[0-9a-f]{64}$/.test(confirmed || '')) fail('integration_confirmation_invalid');
  const bytes = readRegular(deps.fs, planPath, { links: 1 });
  if (sha256(bytes).slice(7) !== confirmed) fail('integration_confirmation_mismatch');
  let parsed;
  try { parsed = JSON.parse(bytes); } catch { fail('integration_plan_invalid_json'); }
  return validatePlan(parsed, deps, { requirePaths: false });
}

class FileTransaction {
  constructor(fsImpl) { this.fs = fsImpl; this.changes = []; this.closed = false; }
  mkdir(target, mode = 0o755) {
    if (this.fs.existsSync(target)) { safeLstat(this.fs, target, 'directory', { links: undefined }); return; }
    this.fs.mkdirSync(target, { recursive: false, mode });
    this.changes.push({ kind: 'created-dir', target });
  }
  mkdirp(target, mode = 0o755) {
    const missing = [];
    let cursor = target;
    while (!this.fs.existsSync(cursor)) { missing.push(cursor); cursor = path.dirname(cursor); }
    safeLstat(this.fs, cursor, 'directory', { links: undefined });
    for (const item of missing.reverse()) this.mkdir(item, mode);
  }
  write(target, bytes, mode) {
    this.mkdirp(path.dirname(target));
    const existing = this.fs.existsSync(target) ? readRegular(this.fs, target, { links: 1 }) : null;
    const existingMode = existing ? (this.fs.lstatSync(target).mode & 0o777) : null;
    if (existing && Buffer.compare(existing, bytes) === 0 && existingMode === mode) return false;
    const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
    this.fs.writeFileSync(temporary, bytes, { mode, flag: 'wx' });
    this.fs.chmodSync(temporary, mode);
    this.fs.renameSync(temporary, target);
    this.changes.push({ kind: 'write', target, existing, existingMode });
    return true;
  }
  remove(target) {
    if (!this.fs.existsSync(target)) return false;
    const bytes = readRegular(this.fs, target, { links: 1 });
    const mode = this.fs.lstatSync(target).mode & 0o777;
    this.fs.unlinkSync(target);
    this.changes.push({ kind: 'remove', target, existing: bytes, existingMode: mode });
    return true;
  }
  commit() { this.closed = true; this.changes = []; }
  rollback() {
    if (this.closed) return;
    const failures = [];
    for (const change of [...this.changes].reverse()) {
      try {
        if (change.kind === 'created-dir') this.fs.rmdirSync(change.target);
        else if (change.existing === null) this.fs.rmSync(change.target, { force: true });
        else this.fs.writeFileSync(change.target, change.existing, { mode: change.existingMode });
      } catch (error) { failures.push(`${change.target}:${error.code || error.message}`); }
    }
    this.closed = true;
    if (failures.length) fail('integration_rollback_failed', failures.join(','));
  }
}

function rollbackPrivileged(tx, { deps, reload = false, timer = null, previous = null } = {}) {
  const failures = [];
  try { tx.rollback(); } catch (error) { failures.push(error.message); }
  if (reload) {
    try {
      const result = deps.systemctl(['daemon-reload']);
      if (result.status !== 0) failures.push('daemon-reload');
    } catch (error) { failures.push(`daemon-reload:${error.message}`); }
  }
  if (timer && previous) {
    try { restoreTimerState(deps, timer, previous); } catch (error) { failures.push(error.message); }
  }
  if (failures.length) fail('integration_rollback_failed', failures.join(','));
}

function verifyPlanSource(plan, deps) {
  const descriptor = describeIntegration(INTEGRATION_ID);
  const release = deps.clientRelease || descriptor.clientRelease;
  const source = validateClientPayload(deps.resolveClientSource(plan.config.sourceClientRoot, release), deps.fs, release);
  if (source.metadata.source.digest !== plan.clientSource.metadata.source.digest || source.metadata.version !== plan.clientSource.metadata.version) fail('integration_client_plan_drift');
  return source;
}

function verifyArtifact(record, bytes) {
  if (record.digest !== sha256(bytes) || record.size !== bytes.length) fail('integration_artifact_plan_drift', record.path);
}

function systemctlOk(deps, args, allowed = [0]) {
  const result = deps.systemctl(args);
  if (!allowed.includes(result.status)) fail('integration_systemctl_failed', `${args.join(' ')}:${result.stderr.trim()}`);
  return result;
}

function environmentValues(text) {
  const values = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    const key = line.slice(0, index);
    const raw = line.slice(index + 1);
    try { values[key] = JSON.parse(raw); } catch { values[key] = raw; }
  }
  return values;
}

function legacyCandidates(plan, deps) {
  const candidates = new Map();
  const configured = pathsFor(plan.instanceId, deps.roots);
  candidates.set(plan.instanceId, configured);
  const vaultSuffix = path.basename(plan.config.vault.path);
  if (vaultSuffix !== plan.instanceId && /^[a-z0-9][a-z0-9-]{0,62}$/.test(vaultSuffix)) candidates.set(vaultSuffix, pathsFor(vaultSuffix, deps.roots));
  const matches = [];
  for (const [suffix, locations] of candidates) {
    const files = [locations.env, locations.token, locations.wrapper, locations.templateService, locations.templateTimer];
    if (!files.every(item => deps.fs.existsSync(item))) continue;
    const env = environmentValues(readRegular(deps.fs, locations.env).toString('utf8'));
    if (env.OBSIDIAN_VAULT_PATH !== plan.config.vault.path || env.OBSIDIAN_AMF_VAULT_ID !== plan.config.vault.id || env.OBSIDIAN_AMF_MODE !== 'shadow') continue;
    const hashes = {
      wrapper: sha256(readRegular(deps.fs, locations.wrapper)),
      service: sha256(readRegular(deps.fs, locations.templateService)),
      timer: sha256(readRegular(deps.fs, locations.templateTimer)),
    };
    const expectedLegacyHashes = deps.legacyHashes || LEGACY_HASHES;
    if (Object.entries(expectedLegacyHashes).some(([key, digest]) => hashes[key] !== digest)) fail('integration_legacy_parity_mismatch', suffix);
    safeLstat(deps.fs, locations.token, 'file', { mode: 0o600, uid: deps.uid, links: 1 });
    safeLstat(deps.fs, locations.env, 'file', { mode: 0o600, uid: deps.uid, links: 1 });
    matches.push({ suffix, locations, env, hashes });
  }
  if (matches.length > 1) fail('integration_legacy_ambiguous');
  return matches[0] || null;
}

function installationManifest(plan, layout, extra = {}) {
  return {
    schema: INSTALL_SCHEMA,
    integrationId: plan.integrationId,
    instanceId: plan.instanceId,
    descriptorVersion: plan.descriptorVersion,
    planDigest: plan.planDigest,
    mode: 'shadow',
    layout,
    config: structuredClone(plan.config),
    artifacts: structuredClone(plan.artifacts),
    client: {
      version: plan.clientSource.metadata.version,
      sourceDigest: plan.clientSource.metadata.source.digest,
      files: structuredClone(plan.clientSource.metadata.source.files),
      sourceClientRoot: plan.config.sourceClientRoot,
    },
    preserved: [...plan.preservation],
    ...extra,
  };
}

function writeManifest(tx, target, manifest) { tx.write(target, jsonBytes(manifest), 0o600); }

function readManifest(deps, target) {
  if (!deps.fs.existsSync(target)) return null;
  const parsed = JSON.parse(readRegular(deps.fs, target, { mode: 0o600, uid: deps.uid, links: 1 }));
  if (parsed.schema !== INSTALL_SCHEMA || parsed.integrationId !== INTEGRATION_ID) fail('integration_manifest_invalid');
  return parsed;
}

export function adoptIntegration(plan, overrides = {}) {
  const deps = createDependencies(overrides);
  validatePlan(plan, deps);
  const locations = pathsFor(plan.instanceId, deps.roots);
  const existing = readManifest(deps, locations.manifest);
  if (existing) {
    if (existing.planDigest !== plan.planDigest) fail('integration_already_installed_different_plan');
    return { changed: false, installation: existing };
  }
  verifyPlanSource(plan, deps);
  const legacy = legacyCandidates(plan, deps);
  if (!legacy) fail('integration_legacy_not_found');
  const observed = observeTimers(deps);
  const expectedTimer = `amf-obsidian-sync@${legacy.suffix}.timer`;
  const vaultTimers = observed.available ? timersForVault(plan.config.vault.path, observed, deps) : [];
  const enabledVaultTimers = vaultTimers.filter(timer => observed.enabledTimers.includes(timer));
  if (!observed.available || vaultTimers.length !== 1 || vaultTimers[0] !== expectedTimer
    || enabledVaultTimers.length !== 1 || enabledVaultTimers[0] !== expectedTimer) fail('integration_legacy_timer_gate');
  const manifest = installationManifest(plan, 'legacy-pr36', {
    adopted: true,
    legacy: {
      suffix: legacy.suffix,
      unit: `amf-obsidian-sync@${legacy.suffix}.service`,
      timer: `amf-obsidian-sync@${legacy.suffix}.timer`,
      artifacts: legacy.hashes,
    },
  });
  const tx = new FileTransaction(deps.fs);
  try { tx.mkdirp(path.dirname(locations.manifest), 0o700); writeManifest(tx, locations.manifest, manifest); tx.commit(); }
  catch (error) { tx.rollback(); throw error; }
  return { changed: true, installation: manifest };
}

export function installIntegration(plan, overrides = {}) {
  const deps = createDependencies(overrides);
  validatePlan(plan, deps);
  const locations = pathsFor(plan.instanceId, deps.roots);
  const existing = readManifest(deps, locations.manifest);
  if (existing) {
    if (existing.planDigest !== plan.planDigest) fail('integration_already_installed_different_plan');
    return { changed: false, installation: existing };
  }
  if (legacyCandidates(plan, deps)) fail('integration_legacy_requires_adopt');
  const observedTimers = observeTimers(deps);
  if (!observedTimers.available) fail('integration_timer_inventory_unavailable');
  if (timersForVault(plan.config.vault.path, observedTimers, deps).length) fail('integration_vault_timer_exists');
  const source = verifyPlanSource(plan, deps);
  if (!safeLstat(deps.fs, locations.token, 'file', { mode: 0o600, uid: deps.uid, links: 1 })) fail('integration_token_missing');
  const rendered = renderArtifacts(plan.config, locations);
  verifyArtifact(plan.artifacts.wrapper, rendered.wrapper);
  verifyArtifact(plan.artifacts.environment, rendered.env);
  verifyArtifact(plan.artifacts.service, rendered.service);
  verifyArtifact(plan.artifacts.timer, rendered.timer);
  const manifest = installationManifest(plan, 'managed-v1', {
    adopted: false,
    units: { service: path.basename(locations.service), timer: path.basename(locations.timer) },
    ownedArtifacts: [locations.env, locations.service, locations.timer, locations.clientRoot, locations.manifest],
  });
  const tx = new FileTransaction(deps.fs);
  try {
    tx.write(locations.wrapper, rendered.wrapper, 0o755);
    tx.write(locations.env, rendered.env, 0o600);
    for (const item of source.files) tx.write(path.join(locations.moduleRoot, item.path), source.verifiedBytes.get(item.path), 0o644);
    tx.write(locations.service, rendered.service, 0o644);
    tx.write(locations.timer, rendered.timer, 0o644);
    writeManifest(tx, locations.manifest, manifest);
    systemctlOk(deps, ['daemon-reload']);
    tx.commit();
  } catch (error) {
    rollbackPrivileged(tx, { deps, reload: true });
    throw error;
  }
  return { changed: true, installation: manifest };
}

function mutationContext(plan, overrides) {
  const deps = createDependencies(overrides);
  validatePlan(plan, deps);
  const locations = pathsFor(plan.instanceId, deps.roots);
  const manifest = readManifest(deps, locations.manifest);
  if (!manifest) fail('integration_not_installed');
  if (manifest.planDigest !== plan.planDigest) fail('integration_plan_not_installed');
  return { deps, locations, manifest };
}

function runtimeNames(manifest, instance) {
  if (manifest.layout === 'legacy-pr36') return { service: manifest.legacy.unit, timer: manifest.legacy.timer };
  return { service: `amf-obsidian-sync@${instance}.service`, timer: `amf-obsidian-sync@${instance}.timer` };
}

function runtimeLocations(manifest, instance, roots) {
  return pathsFor(manifest.layout === 'legacy-pr36' ? manifest.legacy.suffix : instance, roots);
}

export function runIntegration(plan, overrides = {}) {
  const { deps, locations, manifest } = mutationContext(plan, overrides);
  const names = runtimeNames(manifest, plan.instanceId);
  const runtime = runtimeLocations(manifest, plan.instanceId, deps.roots);
  const hadMarker = deps.fs.existsSync(runtime.marker);
  const tx = new FileTransaction(deps.fs);
  try {
    if (!hadMarker) tx.write(runtime.marker, Buffer.from('manual-canary\n'), 0o600);
    systemctlOk(deps, ['start', names.service]);
    if (!hadMarker) tx.remove(runtime.marker);
    tx.commit();
  } catch (error) { tx.rollback(); throw error; }
  return { changed: false, started: names.service };
}

export function enableIntegration(plan, overrides = {}) {
  const { deps, locations, manifest } = mutationContext(plan, overrides);
  const names = runtimeNames(manifest, plan.instanceId);
  const runtime = runtimeLocations(manifest, plan.instanceId, deps.roots);
  const wasEnabled = deps.systemctl(['is-enabled', names.timer]).status === 0;
  const wasActive = deps.systemctl(['is-active', names.timer]).status === 0;
  const tx = new FileTransaction(deps.fs);
  try {
    const changed = deps.fs.existsSync(runtime.marker) ? false : tx.write(runtime.marker, Buffer.from('enabled-by-amf\n'), 0o600);
    systemctlOk(deps, ['enable', '--now', names.timer]);
    tx.commit();
    return { changed, enabled: true, timer: names.timer };
  } catch (error) {
    rollbackPrivileged(tx, { deps, timer: names.timer, previous: { enabled: wasEnabled, active: wasActive } });
    throw error;
  }
}

function restoreTimerState(deps, timer, previous) {
  const results = [];
  if (previous.enabled) results.push(deps.systemctl(previous.active ? ['enable', '--now', timer] : ['enable', timer]));
  else {
    results.push(deps.systemctl(['disable', '--now', timer]));
    if (previous.active) results.push(deps.systemctl(['start', timer]));
  }
  if (results.some(result => result.status !== 0)) fail('integration_timer_rollback_failed', timer);
}

export function disableIntegration(plan, overrides = {}) {
  const { deps, locations, manifest } = mutationContext(plan, overrides);
  const names = runtimeNames(manifest, plan.instanceId);
  const runtime = runtimeLocations(manifest, plan.instanceId, deps.roots);
  const previous = {
    enabled: deps.systemctl(['is-enabled', names.timer]).status === 0,
    active: deps.systemctl(['is-active', names.timer]).status === 0,
  };
  systemctlOk(deps, ['disable', '--now', names.timer], [0, 1]);
  const tx = new FileTransaction(deps.fs);
  try { const changed = tx.remove(runtime.marker); tx.commit(); return { changed, enabled: false, timer: names.timer }; }
  catch (error) { rollbackPrivileged(tx, { deps, timer: names.timer, previous }); throw error; }
}

function removeTreeSafe(fsImpl, target) {
  if (!fsImpl.existsSync(target)) return;
  safeLstat(fsImpl, target, 'directory', { links: undefined });
  fsImpl.rmSync(target, { recursive: true, force: false });
}

export function uninstallIntegration(plan, overrides = {}) {
  const deps = createDependencies(overrides);
  validatePlan(plan, deps, { requirePaths: false });
  const locations = pathsFor(plan.instanceId, deps.roots);
  const manifest = readManifest(deps, locations.manifest);
  if (!manifest) return { changed: false, installed: false, preserved: ['vault', '.amf', 'outbox', 'token', 'actor'] };
  if (manifest.planDigest !== plan.planDigest) fail('integration_plan_not_installed');
  if (manifest.layout === 'legacy-pr36') {
    const tx = new FileTransaction(deps.fs);
    try { tx.remove(locations.manifest); tx.commit(); } catch (error) { tx.rollback(); throw error; }
    return { changed: true, preservedLegacy: true };
  }
  const names = runtimeNames(manifest, plan.instanceId);
  const previous = {
    enabled: deps.systemctl(['is-enabled', names.timer]).status === 0,
    active: deps.systemctl(['is-active', names.timer]).status === 0,
  };
  systemctlOk(deps, ['disable', '--now', names.timer], [0, 1]);
  const tx = new FileTransaction(deps.fs);
  const quarantine = `${locations.clientRoot}.uninstall-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
  let clientMoved = false;
  try {
    for (const target of [locations.marker, locations.env, locations.service, locations.timer, locations.manifest]) tx.remove(target);
    if (deps.fs.existsSync(locations.clientRoot)) {
      safeLstat(deps.fs, locations.clientRoot, 'directory', { links: undefined });
      deps.fs.renameSync(locations.clientRoot, quarantine);
      clientMoved = true;
    }
    systemctlOk(deps, ['daemon-reload']);
    tx.commit();
  } catch (error) {
    if (clientMoved && deps.fs.existsSync(quarantine) && !deps.fs.existsSync(locations.clientRoot)) deps.fs.renameSync(quarantine, locations.clientRoot);
    rollbackPrivileged(tx, { deps, reload: true, timer: names.timer, previous });
    throw error;
  }
  if (clientMoved) removeTreeSafe(deps.fs, quarantine);
  // The protected token, vault, .amf state, actor and source client remain untouched.
  return { changed: true, preserved: ['vault', '.amf', 'outbox', 'token', 'actor'] };
}

function systemdState(deps, verb, unit) {
  const result = deps.systemctl([verb, unit]);
  return { ok: result.status === 0, value: result.stdout.trim() || (result.status === 0 ? 'yes' : 'no') };
}

function clientStatus(planLike, deps, manifest) {
  const clientRoot = manifest.layout === 'managed-v1'
    ? pathsFor(manifest.instanceId, deps.roots).moduleRoot
    : manifest.client.sourceClientRoot;
  if (!clientRoot) return { public: { verified: false, reason: 'source_unavailable' }, source: null };
  try {
    const descriptor = describeIntegration(INTEGRATION_ID);
    let payload;
    if (manifest.layout === 'managed-v1') payload = { sourceRoot: clientRoot, metadata: { version: manifest.client.version, schema: 'obsidian-amf-client/v1', name: 'obsidian_amf', source: { digest: manifest.client.sourceDigest, files: manifest.client.files } } };
    else payload = deps.resolveClientSource(clientRoot, deps.clientRelease || descriptor.clientRelease);
    const verified = validateClientPayload(payload, deps.fs, deps.clientRelease || descriptor.clientRelease);
    const publicStatus = { verified: verified.metadata.source.digest === manifest.client.sourceDigest, version: verified.metadata.version, sourceDigest: verified.metadata.source.digest };
    return { public: publicStatus, source: publicStatus.verified ? verified : null };
  } catch (error) { return { public: { verified: false, reason: error.message }, source: null }; }
}

function managedArtifactParity(deps, manifest, locations) {
  try {
    const rendered = renderArtifacts(manifest.config, locations);
    const entries = [
      ['wrapper', locations.wrapper, rendered.wrapper],
      ['environment', locations.env, rendered.env],
      ['service', locations.service, rendered.service],
      ['timer', locations.timer, rendered.timer],
    ];
    for (const [key, target, expectedBytes] of entries) {
      const record = manifest.artifacts?.[key];
      const actual = readRegular(deps.fs, target, { links: 1 });
      if (!record || record.path !== target || record.digest !== sha256(expectedBytes)
        || Buffer.compare(actual, expectedBytes) !== 0 || (deps.fs.lstatSync(target).mode & 0o777).toString(8).padStart(4, '0') !== record.mode) return false;
    }
    return true;
  } catch { return false; }
}

function readBridgeHealth(deps, manifest, locations, verifiedSource) {
  const envPath = manifest.layout === 'legacy-pr36'
    ? pathsFor(manifest.legacy.suffix, deps.roots).env
    : locations.env;
  try {
    const env = environmentValues(readRegular(deps.fs, envPath).toString('utf8'));
    const vault = env.OBSIDIAN_VAULT_PATH;
    if (!vault) return null;
    const tokenPath = manifest.layout === 'legacy-pr36'
      ? pathsFor(manifest.legacy.suffix, deps.roots).token
      : locations.token;
    safeLstat(deps.fs, tokenPath, 'file', { mode: 0o600, uid: deps.uid, links: 1 });
    const snapshotParent = path.join(deps.roots.state, INTEGRATION_ID, '.status');
    deps.fs.mkdirSync(snapshotParent, { recursive: true, mode: 0o700 });
    assertParentsNoSymlink(deps.fs, path.join(snapshotParent, 'candidate'));
    safeLstat(deps.fs, snapshotParent, 'directory', { links: undefined });
    const snapshot = deps.fs.mkdtempSync(path.join(snapshotParent, 'client-'));
    let status;
    try {
      const moduleRoot = path.join(snapshot, 'scripts', 'obsidian_amf');
      deps.fs.mkdirSync(moduleRoot, { recursive: true, mode: 0o700 });
      for (const item of verifiedSource.files) deps.fs.writeFileSync(path.join(moduleRoot, item.path), verifiedSource.verifiedBytes.get(item.path), { mode: 0o600, flag: 'wx' });
      status = deps.runClientStatus({ pythonPath: path.join(snapshot, 'scripts'), environment: env, tokenPath });
    }
    finally { deps.fs.rmSync(snapshot, { recursive: true, force: true }); }
    const pending = Number(status.outbox?.pending);
    const retrying = Number(status.outbox?.retrying);
    const quarantined = Number(status.outbox?.quarantined);
    if (![pending, retrying, quarantined].every(Number.isSafeInteger)) fail('integration_client_status_queue_invalid');
    return {
      reportedHealthy: status.healthy === true,
      mode: status.mode,
      vaultId: status.vaultId,
      pending,
      retrying,
      quarantined,
      healthy: status.healthy === true && status.mode === 'shadow' && pending === 0 && retrying === 0 && quarantined === 0,
    };
  } catch (error) { return { healthy: false, reason: error.message }; }
  return null;
}

export function integrationStatus(id, instance, overrides = {}) {
  if (id !== INTEGRATION_ID) fail('integration_unknown');
  assertString(instance, 'instance', /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
  const deps = createDependencies(overrides);
  const locations = pathsFor(instance, deps.roots);
  const manifest = readManifest(deps, locations.manifest);
  if (!manifest) return { integrationId: id, instanceId: instance, installed: false, optional: true, health: 'skipped' };
  const names = runtimeNames(manifest, instance);
  const active = systemdState(deps, 'is-active', names.timer);
  const enabled = systemdState(deps, 'is-enabled', names.timer);
  let parity = true;
  if (manifest.layout === 'legacy-pr36') {
    const legacy = pathsFor(manifest.legacy.suffix, deps.roots);
    try {
      const expectedLegacyHashes = deps.legacyHashes || LEGACY_HASHES;
      parity = sha256(readRegular(deps.fs, legacy.wrapper)) === expectedLegacyHashes.wrapper
        && sha256(readRegular(deps.fs, legacy.templateService)) === expectedLegacyHashes.service
        && sha256(readRegular(deps.fs, legacy.templateTimer)) === expectedLegacyHashes.timer;
    } catch { parity = false; }
  } else parity = managedArtifactParity(deps, manifest, locations);
  const checkedClient = clientStatus(null, deps, manifest);
  const client = checkedClient.public;
  const bridge = client.verified ? readBridgeHealth(deps, manifest, locations, checkedClient.source) : { healthy: false, reason: 'client_unverified' };
  const healthy = parity && client.verified && (!enabled.ok || active.ok) && bridge?.healthy === true;
  return {
    integrationId: id,
    instanceId: instance,
    installed: true,
    adopted: manifest.adopted === true,
    layout: manifest.layout,
    mode: manifest.mode,
    units: names,
    enabled: enabled.ok,
    active: active.ok,
    artifactParity: parity,
    client,
    bridge,
    healthy,
    health: healthy ? 'healthy' : 'degraded',
  };
}

export const lifecycleInternals = Object.freeze({
  LEGACY_HASHES,
  PLAN_SCHEMA,
  INSTALL_SCHEMA,
  pathsFor,
  validateClientPayload,
  renderArtifacts,
});
