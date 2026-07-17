import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const AGENT_CURATION_LANE_SCHEMA = 'amf.agent-curation-lane/v1';
export const LANE_CURATOR_PERMISSIONS = Object.freeze([
  'memory:curate',
  'memory:status',
  'purpose:memory_curation'
]);
export const LANE_APPLICATOR_ACTOR = 'service:memory-applicator';
export const LANE_AUTO_SCOPE_TYPE = 'agent';
export const LANE_AUTO_VISIBILITY = 'private';

const SAFE_LANE_NAME = /^[a-z][a-z0-9-]{2,48}$/;
const SAFE_SCOPE = /^agent:[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const HEX_DIGEST = /^[a-f0-9]{64}$/;
const AUTH_MODES = new Set(['allow_all', 'scoped', 'read_only_scoped', 'deny']);

function fail(code, cause = null) {
  const error = new Error(code);
  if (cause) error.cause = cause;
  return error;
}

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function mintToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function readJson(filePath, code) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (cause) {
    throw fail(code, cause);
  }
  try {
    return JSON.parse(raw);
  } catch (cause) {
    throw fail(`${code}_invalid_json`, cause);
  }
}

function validateRegistry(registry) {
  if (!object(registry) || !Array.isArray(registry.rows)) throw fail('auth_registry_shape_invalid');
  for (const row of registry.rows) {
    if (!object(row) || typeof row.actor !== 'string' || !row.actor.trim()) throw fail('auth_registry_row_invalid');
    if (!AUTH_MODES.has(row.mode)) throw fail('auth_registry_mode_invalid');
    if (!Array.isArray(row.permissions) || !Array.isArray(row.allowedScopes)) throw fail('auth_registry_row_invalid');
    if (!HEX_DIGEST.test(String(row.tokenSha256 ?? ''))) throw fail('auth_registry_digest_invalid');
  }
}

function validatePamConfig(config) {
  if (!object(config) || !object(config.amfCurator)) throw fail('pam_config_shape_invalid');
  const curator = config.amfCurator;
  if (!Array.isArray(curator.autoScopes) || !Array.isArray(curator.autoVisibilities)) throw fail('pam_config_policy_invalid');
  if (!Array.isArray(curator.reviewers)) throw fail('pam_config_reviewers_invalid');
  for (const reviewer of curator.reviewers) {
    if (!object(reviewer) || !HEX_DIGEST.test(String(reviewer.tokenSha256 ?? ''))) throw fail('pam_config_reviewer_invalid');
    if (typeof reviewer.actorId !== 'string' || !reviewer.actorId.trim()) throw fail('pam_config_reviewer_invalid');
  }
}

function parseEnvFile(filePath) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (cause) {
    throw fail('worker_env_unreadable', cause);
  }
  const entries = new Map();
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator < 1) throw fail('worker_env_line_invalid');
    entries.set(trimmed.slice(0, separator), trimmed.slice(separator + 1));
  }
  return entries;
}

function backupFile(sourcePath, backupRoot, stamp, ownership) {
  const name = `${path.basename(sourcePath)}.bak-${stamp}`;
  const target = path.join(backupRoot, name);
  fs.copyFileSync(sourcePath, target);
  fs.chmodSync(target, 0o600);
  if (ownership) fs.chownSync(target, ownership.uid, ownership.gid);
  return target;
}

function writePrivateFile(filePath, content, mode, ownership) {
  fs.writeFileSync(filePath, content, { mode });
  fs.chmodSync(filePath, mode);
  if (ownership) fs.chownSync(filePath, ownership.uid, ownership.gid);
}

const REQUIRED_SHARED_ENV = Object.freeze([
  'PAM_WORKSPACE_CONFIG',
  'PAM_APPLICATOR_TOKEN',
  'PAM_APPLICATOR_STATE_KEY_FILE',
  'PAM_FABRIC_BASE_URL',
  'PAM_FABRIC_APPLICATOR_TOKEN_FILE',
  'PAM_GIT_WRITER_REPO_ROOT'
]);

export function planAgentCurationLane(options = {}) {
  const {
    laneName = 'agent-vitae',
    scope = 'agent:vitae',
    authRegistryPath,
    pamConfigPath,
    referenceWorkerEnvPath,
    curationRoot,
    unitDir = '/etc/systemd/system',
    serviceOwnerUid,
    serviceOwnerGid,
    nodeBin = '/usr/bin/node',
    workspaceRoot = '/srv/brain-shared',
    timerIntervalSec = 120
  } = options;

  if (!SAFE_LANE_NAME.test(String(laneName ?? ''))) throw fail('lane_name_invalid');
  if (!SAFE_SCOPE.test(String(scope ?? ''))) throw fail('lane_scope_invalid');
  for (const [label, value] of [
    ['auth_registry_path', authRegistryPath],
    ['pam_config_path', pamConfigPath],
    ['reference_worker_env_path', referenceWorkerEnvPath],
    ['curation_root', curationRoot]
  ]) {
    if (typeof value !== 'string' || !value.trim() || !path.isAbsolute(value)) throw fail(`${label}_invalid`);
  }
  const uid = Number(serviceOwnerUid);
  const gid = Number(serviceOwnerGid);
  if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) throw fail('service_owner_invalid');
  const interval = Number(timerIntervalSec);
  if (!Number.isSafeInteger(interval) || interval < 30 || interval > 86_400) throw fail('timer_interval_invalid');

  const registry = readJson(authRegistryPath, 'auth_registry_unreadable');
  validateRegistry(registry);
  const pamConfig = readJson(pamConfigPath, 'pam_config_unreadable');
  validatePamConfig(pamConfig);
  const referenceEnv = parseEnvFile(referenceWorkerEnvPath);
  for (const key of REQUIRED_SHARED_ENV) {
    if (!referenceEnv.get(key)) throw fail('worker_env_shared_entry_missing');
  }

  const curatorActor = `service:memory-curator-${laneName}`;
  const applicatorRow = registry.rows.find((row) => row.actor === LANE_APPLICATOR_ACTOR);
  if (!applicatorRow) throw fail('applicator_actor_missing');
  const existingCurator = registry.rows.find((row) => row.actor === curatorActor);
  if (existingCurator) throw fail('lane_curator_already_provisioned');

  const secretsDir = path.join(curationRoot, 'secrets');
  const stateDir = path.join(curationRoot, `state-${laneName}`);
  const plan = {
    schema: AGENT_CURATION_LANE_SCHEMA,
    laneName,
    scope,
    curatorActor,
    applicatorActor: LANE_APPLICATOR_ACTOR,
    applicatorScopeAlreadyPresent: applicatorRow.allowedScopes.includes(scope),
    autoScopeAlreadyPresent: pamConfig.amfCurator.autoScopes.includes(LANE_AUTO_SCOPE_TYPE),
    autoVisibilityAlreadyPresent: pamConfig.amfCurator.autoVisibilities.includes(LANE_AUTO_VISIBILITY),
    files: {
      fabricCuratorTokenFile: path.join(secretsDir, `fabric-curator-${laneName}.token`),
      pamReviewerTokenFile: path.join(secretsDir, `pam-reviewer-${laneName}.token`),
      pamLedgerKeyFile: path.join(secretsDir, `pam-ledger-${laneName}.key`),
      workerEnvFile: path.join(curationRoot, `worker-${laneName}.env`),
      tickScriptFile: path.join(curationRoot, `amf-${laneName}-curation-tick.mjs`),
      stateDir,
      serviceUnit: path.join(unitDir, `amf-curation-${laneName}.service`),
      timerUnit: path.join(unitDir, `amf-curation-${laneName}.timer`)
    },
    ownership: { uid, gid },
    nodeBin,
    workspaceRoot,
    timerIntervalSec: interval,
    registry,
    pamConfig,
    referenceEnv,
    authRegistryPath,
    pamConfigPath
  };
  for (const filePath of [
    plan.files.fabricCuratorTokenFile,
    plan.files.pamReviewerTokenFile,
    plan.files.pamLedgerKeyFile,
    plan.files.workerEnvFile,
    plan.files.tickScriptFile
  ]) {
    if (fs.existsSync(filePath)) throw fail('lane_artifact_already_exists');
  }
  return plan;
}

function tickScriptContent(plan) {
  return `#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import {
  dispatchFabricApplyReceipt,
  drainFabricProposals,
  replayFabricDecisionOutbox
} from "/opt/portable-agent-memory/tools/lib/amf-fabric-transport.mjs";
import {
  applyDecisionReceipt,
  deliverAppliedMemoryToGit
} from "/opt/portable-agent-memory/tools/lib/memory-receipt-applicator.mjs";
import { loadWorkspaceConfig } from "/opt/portable-agent-memory/tools/lib/workspace.mjs";

const EXPECTED_SCOPE = ${JSON.stringify(plan.scope)};
const WORKSPACE = ${JSON.stringify(plan.workspaceRoot)};
const STATE_DIR = ${JSON.stringify(plan.files.stateDir)};
const LAST_TICK = path.join(STATE_DIR, "last-tick.json");
const DECISION_DIR = path.join(WORKSPACE, "memory/amf/curator/decision-receipts");
const LIMIT = 10;
const MAX_PAGES = 1;
const MAX_RECOVERY_DECISIONS = 10;

function fail(message) {
  throw new Error(message);
}

function git(...args) {
  return execFileSync("git", args, { cwd: WORKSPACE, encoding: "utf8", maxBuffer: 1024 * 1024 }).trim();
}

function assertPolicy(config) {
  const curator = config.amfCurator || {};
  const writer = config.amfApplicator?.gitWriter || {};
  if (curator.autoPromote !== true || curator.minimumConfidence !== 0.98) fail("lane curator policy mismatch");
  if (!curator.autoScopes?.includes(${JSON.stringify(LANE_AUTO_SCOPE_TYPE)})) fail("agent auto-promotion scope is unavailable");
  if (!curator.autoVisibilities?.includes(${JSON.stringify(LANE_AUTO_VISIBILITY)})) fail("private auto-promotion visibility is unavailable");
  if (curator.requireReviewForLifecycleChange !== true || curator.requireReviewForSupersession !== true || curator.rejectOnWarnings !== true) fail("review safety gates are not enabled");
  if (writer.enabled !== true || writer.allowedBranches?.length !== 1 || writer.allowedBranches[0] !== "main") fail("Git writer branch policy mismatch");
  if (writer.push?.enabled !== true || writer.push.remote !== "origin" || writer.push.allowedRemotes?.length !== 1 || writer.push.allowedRemotes[0] !== "origin") fail("Git push policy mismatch");
  if (git("symbolic-ref", "--quiet", "--short", "HEAD") !== "main") fail("PAM workspace is not on main");
  const dirty = git("status", "--porcelain=v1");
  if (dirty && approvedDecisionsForScope().length === 0) fail("PAM workspace contains changes without a recoverable lane decision");
  const divergence = git("rev-list", "--left-right", "--count", "HEAD...origin/main");
  if (divergence !== "0\\t0") fail("PAM workspace is not aligned with origin/main");
}

function approvedDecisionsForScope() {
  if (!fs.existsSync(DECISION_DIR)) return [];
  const selected = [];
  for (const name of fs.readdirSync(DECISION_DIR).sort()) {
    if (!/^decision-[0-9a-f]{40}\\.json$/.test(name)) continue;
    const value = JSON.parse(fs.readFileSync(path.join(DECISION_DIR, name), "utf8"));
    if (value.outcome === "approved_pending_apply" && value.fabricProposalScope === EXPECTED_SCOPE
        && /^decision-[0-9a-f]{40}$/.test(String(value.decisionId || ""))
        && gitDeliveryStatus(value.decisionId) !== "pushed") selected.push(value.decisionId);
    if (selected.length >= MAX_RECOVERY_DECISIONS) break;
  }
  return selected;
}

function gitDeliveryStatus(decisionId) {
  const absolute = path.join(WORKSPACE, "memory/amf/applicator/git-delivery", decisionId + ".json");
  if (!fs.existsSync(absolute)) return null;
  try {
    const value = JSON.parse(fs.readFileSync(absolute, "utf8"));
    return value.phase || value.status || null;
  }
  catch { return null; }
}

function writeSummary(summary) {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const temporary = LAST_TICK + "." + process.pid + ".tmp";
  fs.writeFileSync(temporary, JSON.stringify(summary, null, 2) + "\\n", { mode: 0o600 });
  fs.renameSync(temporary, LAST_TICK);
  fs.chmodSync(LAST_TICK, 0o600);
}

async function convergeDecision(config, decisionId) {
  const idempotencyKey = "amf-" + ${JSON.stringify(plan.laneName)} + "-apply:" + decisionId;
  const applied = applyDecisionReceipt(WORKSPACE, config, { decisionId, idempotencyKey });
  if (!applied.ok) fail("PAM apply failed for an authenticated decision: " + (applied.error || applied.status));
  const dispatched = await dispatchFabricApplyReceipt(WORKSPACE, config, { decisionId });
  if (!dispatched.ok) fail("Fabric apply receipt dispatch failed: " + (dispatched.error || dispatched.status));
  const delivered = deliverAppliedMemoryToGit(WORKSPACE, config, { decisionId, push: true });
  if (!delivered.ok) fail("Git delivery failed: " + (delivered.error || delivered.status));
  return { gitStatus: delivered.status, duplicateGit: delivered.duplicate === true };
}

async function tick(config) {
  const startedAt = new Date().toISOString();
  const replay = await replayFabricDecisionOutbox(WORKSPACE, config, { limit: LIMIT, maxPages: MAX_PAGES });
  if (!replay.ok) fail("decision outbox replay failed");

  const before = new Set(approvedDecisionsForScope());
  const drain = await drainFabricProposals(WORKSPACE, config, { limit: LIMIT, maxPages: MAX_PAGES, dispatch: true });
  if (!drain.ok) fail("bounded proposal drain failed");

  const approved = new Set([...before, ...approvedDecisionsForScope()]);
  for (const item of drain.results) {
    if (item.status === "approved_pending_apply" && /^decision-[0-9a-f]{40}$/.test(String(item.decisionId || ""))) approved.add(item.decisionId);
  }
  const ordered = [...approved].slice(0, MAX_RECOVERY_DECISIONS);
  let applied = 0;
  let gitPushed = 0;
  let duplicateGit = 0;
  for (const decisionId of ordered) {
    const result = await convergeDecision(config, decisionId);
    applied += 1;
    if (result.gitStatus === "pushed") gitPushed += 1;
    if (result.duplicateGit) duplicateGit += 1;
  }

  const statuses = {};
  for (const item of drain.results) statuses[item.status] = (statuses[item.status] || 0) + 1;
  const summary = {
    ok: true,
    mode: "production",
    lane: ${JSON.stringify(plan.laneName)},
    startedAt,
    finishedAt: new Date().toISOString(),
    expectedScope: EXPECTED_SCOPE,
    bounds: { limit: LIMIT, maxPages: MAX_PAGES },
    replay: { processed: replay.processed, scanned: replay.scanned || 0 },
    drain: { processed: drain.processed, pages: drain.pages, hasNext: Boolean(drain.nextCursor), statuses },
    convergence: { approvedDecisions: ordered.length, applied, gitPushed, duplicateGit },
    reviewRequired: statuses.review_required || 0
  };
  writeSummary(summary);
  return summary;
}

async function main() {
  if (process.argv.length > 2) fail("unknown argument");
  const config = loadWorkspaceConfig(WORKSPACE);
  assertPolicy(config);
  const result = await tick(config);
  process.stdout.write(JSON.stringify(result) + "\\n");
}

main().catch(error => {
  process.stderr.write("amf-${plan.laneName}-curation: " + error.message + "\\n");
  process.exitCode = 1;
});
`;
}

function workerEnvContent(plan, secrets) {
  const shared = plan.referenceEnv;
  const lines = [
    `PAM_WORKSPACE_CONFIG=${shared.get('PAM_WORKSPACE_CONFIG')}`,
    `PAM_CURATOR_STATE_DIR=${plan.files.stateDir}`,
    `PAM_CURATOR_LEDGER_KEY=${secrets.pamLedgerKey}`,
    `PAM_CURATOR_REVIEWER_TOKEN=${secrets.pamReviewerToken}`,
    `PAM_APPLICATOR_TOKEN=${shared.get('PAM_APPLICATOR_TOKEN')}`,
    `PAM_APPLICATOR_STATE_KEY_FILE=${shared.get('PAM_APPLICATOR_STATE_KEY_FILE')}`,
    `PAM_FABRIC_BASE_URL=${shared.get('PAM_FABRIC_BASE_URL')}`,
    `PAM_FABRIC_CURATOR_TOKEN_FILE=${plan.files.fabricCuratorTokenFile}`,
    `PAM_FABRIC_APPLICATOR_TOKEN_FILE=${shared.get('PAM_FABRIC_APPLICATOR_TOKEN_FILE')}`,
    `PAM_GIT_WRITER_REPO_ROOT=${shared.get('PAM_GIT_WRITER_REPO_ROOT')}`
  ];
  return `${lines.join('\n')}\n`;
}

function serviceUnitContent(plan) {
  return `[Unit]
Description=Agent Memory Fabric bounded ${plan.laneName} curation lane
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=stt
Group=stt
EnvironmentFile=${plan.files.workerEnvFile}
WorkingDirectory=/opt/portable-agent-memory
ExecStart=/usr/bin/flock -n ${plan.files.stateDir}/tick.lock ${plan.nodeBin} ${plan.files.tickScriptFile}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${plan.workspaceRoot} ${plan.files.stateDir}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
`;
}

function timerUnitContent(plan) {
  return `[Unit]
Description=Run bounded Agent Memory Fabric ${plan.laneName} curation

[Timer]
OnActiveSec=15s
OnBootSec=2min
OnUnitActiveSec=${plan.timerIntervalSec}s
RandomizedDelaySec=15s
AccuracySec=5s
Persistent=true
Unit=amf-curation-${plan.laneName}.service

[Install]
WantedBy=timers.target
`;
}

export function provisionAgentCurationLane(options = {}) {
  const { dryRun = false, backupRoot } = options;
  const plan = planAgentCurationLane(options);
  if (typeof backupRoot !== 'string' || !path.isAbsolute(backupRoot)) throw fail('backup_root_invalid');

  const report = {
    ok: true,
    schema: AGENT_CURATION_LANE_SCHEMA,
    dryRun,
    laneName: plan.laneName,
    scope: plan.scope,
    curatorActor: plan.curatorActor,
    applicatorScopeExtended: !plan.applicatorScopeAlreadyPresent,
    autoScopeExtended: !plan.autoScopeAlreadyPresent,
    autoVisibilityExtended: !plan.autoVisibilityAlreadyPresent,
    files: { ...plan.files },
    nextSteps: [
      'systemctl daemon-reload',
      `systemctl start amf-curation-${plan.laneName}.service`,
      `systemctl enable --now amf-curation-${plan.laneName}.timer`
    ]
  };
  if (dryRun) return report;

  fs.mkdirSync(backupRoot, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, '').slice(0, 15);
  report.backups = {
    authRegistry: backupFile(plan.authRegistryPath, backupRoot, stamp, plan.ownership),
    pamConfig: backupFile(plan.pamConfigPath, backupRoot, stamp, plan.ownership)
  };

  const secrets = {
    fabricCuratorToken: mintToken(),
    pamReviewerToken: mintToken(),
    pamLedgerKey: mintToken()
  };

  const curatorRow = {
    active: true,
    actor: plan.curatorActor,
    allowedScopes: [plan.scope],
    mode: 'scoped',
    permissions: [...LANE_CURATOR_PERMISSIONS],
    tokenSha256: sha256Hex(secrets.fabricCuratorToken)
  };
  plan.registry.rows.push(curatorRow);
  const applicatorRow = plan.registry.rows.find((row) => row.actor === LANE_APPLICATOR_ACTOR);
  if (!applicatorRow.allowedScopes.includes(plan.scope)) applicatorRow.allowedScopes.push(plan.scope);

  const curatorPolicy = plan.pamConfig.amfCurator;
  if (!curatorPolicy.autoScopes.includes(LANE_AUTO_SCOPE_TYPE)) curatorPolicy.autoScopes.push(LANE_AUTO_SCOPE_TYPE);
  if (!curatorPolicy.autoVisibilities.includes(LANE_AUTO_VISIBILITY)) curatorPolicy.autoVisibilities.push(LANE_AUTO_VISIBILITY);
  curatorPolicy.reviewers.push({
    tokenSha256: sha256Hex(secrets.pamReviewerToken),
    actorId: plan.curatorActor,
    capabilities: ['memory:curate']
  });

  // Bind-mounted files must keep their inode: write in place, never rename over.
  const registryHandle = fs.openSync(plan.authRegistryPath, 'r+');
  try {
    const payload = `${JSON.stringify(plan.registry, null, 2)}\n`;
    fs.ftruncateSync(registryHandle, 0);
    fs.writeSync(registryHandle, payload, 0, 'utf8');
  } finally {
    fs.closeSync(registryHandle);
  }
  const pamHandle = fs.openSync(plan.pamConfigPath, 'r+');
  try {
    const payload = `${JSON.stringify(plan.pamConfig, null, 2)}\n`;
    fs.ftruncateSync(pamHandle, 0);
    fs.writeSync(pamHandle, payload, 0, 'utf8');
  } finally {
    fs.closeSync(pamHandle);
  }

  writePrivateFile(plan.files.fabricCuratorTokenFile, `${secrets.fabricCuratorToken}\n`, 0o600, plan.ownership);
  writePrivateFile(plan.files.pamReviewerTokenFile, `${secrets.pamReviewerToken}\n`, 0o600, plan.ownership);
  writePrivateFile(plan.files.pamLedgerKeyFile, `${secrets.pamLedgerKey}\n`, 0o600, plan.ownership);
  writePrivateFile(plan.files.workerEnvFile, workerEnvContent(plan, secrets), 0o600, plan.ownership);
  writePrivateFile(plan.files.tickScriptFile, tickScriptContent(plan), 0o750, plan.ownership);
  fs.mkdirSync(plan.files.stateDir, { recursive: true, mode: 0o700 });
  fs.chownSync(plan.files.stateDir, plan.ownership.uid, plan.ownership.gid);
  fs.writeFileSync(plan.files.serviceUnit, serviceUnitContent(plan), { mode: 0o644 });
  fs.writeFileSync(plan.files.timerUnit, timerUnitContent(plan), { mode: 0o644 });

  return report;
}
