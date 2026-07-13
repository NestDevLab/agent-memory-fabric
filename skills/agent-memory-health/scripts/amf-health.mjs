#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPORT_SCHEMA = "amf.health-report/v1";
const CONFIG_SCHEMA = "amf.health/v1";
const RANK = { healthy: 0, skipped: 0, degraded: 1, critical: 2 };

export function aggregateStatus(checks) {
  return checks.reduce((worst, check) => RANK[check.status] > RANK[worst] ? check.status : worst, "healthy");
}

export function parseEnvText(text) {
  const values = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const index = line.indexOf("=");
    if (index < 1) continue;
    const key = line.slice(0, index).trim();
    let value = line.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  return values;
}

export function evaluateFabricPayload(payload, { requireSemanticBackend = false, maxQueuedProposals = null } = {}) {
  const store = payload?.data?.fabricStore;
  const canonical = payload?.data?.canonicalStore;
  const backend = payload?.data?.backend;
  if (payload?.ok !== true || !store) return check("fabric", "critical", "Fabric status payload is invalid");
  if (store.healthy !== true || store.closed === true) return check("fabric", "critical", "Fabric store is unhealthy or closed");
  if (store.rawProjectionV2Ready !== true || store.rawProjectionV2ReadinessReason !== null || store.legacyV1WritesEnabled !== false) {
    return check("fabric", "critical", "RAW projection v2 readiness contract failed");
  }
  if (canonical?.configured !== true) return check("fabric", "degraded", "Canonical memory store is not configured");
  if (requireSemanticBackend && backend?.configured !== true) return check("fabric", "degraded", "Semantic backend is required but disabled");
  if (Number.isFinite(maxQueuedProposals) && Number(store.queuedProposals ?? 0) > maxQueuedProposals) {
    return check("fabric", "degraded", `Queued proposals exceed threshold (${store.queuedProposals}/${maxQueuedProposals})`);
  }
  return check("fabric", "healthy", `Fabric ${payload.data?.version ?? "unknown"}: ${store.backend ?? "store"}, schema ${store.schemaVersion ?? "unknown"}`,
    { rawObjects: finite(store.rawObjects), queuedProposals: finite(store.queuedProposals), backend: backend?.kind ?? "unknown" });
}

export function evaluateCollectorSnapshot(snapshot, { maxPending = 0, maxAgeMs = 15 * 60_000 } = {}) {
  const id = `collector:${snapshot.id}`;
  if (snapshot.timerActive !== true) return check(id, "critical", "Collector timer is not active", publicCollectorEvidence(snapshot));
  if (snapshot.result && snapshot.result !== "success") return check(id, "critical", `Collector result is ${snapshot.result}`, publicCollectorEvidence(snapshot));
  if (Number(snapshot.execMainStatus ?? 0) !== 0) return check(id, "critical", `Collector exit status is ${snapshot.execMainStatus}`, publicCollectorEvidence(snapshot));
  if (Number(snapshot.dead ?? 0) > 0) return check(id, "degraded", `Collector has ${snapshot.dead} dead event(s)`, publicCollectorEvidence(snapshot));
  if (Number(snapshot.pending ?? 0) > maxPending) return check(id, "degraded", `Collector has ${snapshot.pending} pending event(s)`, publicCollectorEvidence(snapshot));
  if (snapshot.lastTriggerMs && Date.now() - snapshot.lastTriggerMs > maxAgeMs) {
    return check(id, "degraded", "Collector has not triggered recently", publicCollectorEvidence(snapshot));
  }
  return check(id, "healthy", "Collector timer and outbox are healthy", publicCollectorEvidence(snapshot));
}

export function formatHuman(report) {
  const marks = { healthy: "OK", degraded: "WARN", critical: "FAIL", skipped: "SKIP" };
  return [
    `Agent Memory Fabric: ${report.overall.toUpperCase()}`,
    ...report.checks.map(item => `[${marks[item.status]}] ${item.id}: ${item.summary}`)
  ].join("\n");
}

export async function runHealth(options = {}) {
  const config = loadConfig(options.config);
  const settings = { ...config, ...defined(options) };
  const checks = [];
  const endpoint = settings.endpoint || process.env.AMF_BASE_URL || process.env.AGENT_MEMORY_FABRIC_URL || discoverEndpoint(settings.configRoot);
  const tokenEnv = settings.tokenEnv || "AMF_RAW_INGEST_TOKEN";
  const fileEnv = settings.envFile ? parseEnvText(readFileSync(settings.envFile, "utf8")) : {};
  const token = process.env[tokenEnv] || fileEnv[tokenEnv] || process.env.AMF_STATUS_TOKEN || fileEnv.AMF_STATUS_TOKEN;

  if (settings.offline) {
    checks.push(check("fabric", "skipped", "Fabric HTTP status skipped by --offline"));
  } else if (!endpoint) {
    checks.push(check("fabric", "degraded", "Fabric endpoint was not discovered"));
  } else if (!token) {
    checks.push(check("fabric", "degraded", `Status token is unavailable (${tokenEnv})`));
  } else {
    checks.push(await fetchFabricStatus(endpoint, token, settings));
  }

  const collectors = Array.isArray(settings.collectors) ? settings.collectors : discoverCollectors(settings.configRoot);
  if (!collectors.length) checks.push(check("collectors", "skipped", "No local RAW collectors discovered"));
  for (const collector of collectors) {
    const snapshot = collectorSnapshot(collector, settings.stateRoot);
    checks.push(evaluateCollectorSnapshot(snapshot, {
      maxPending: finiteOr(collector.maxPending, finiteOr(settings.maxPending, 0)),
      maxAgeMs: finiteOr(collector.maxAgeMs, finiteOr(settings.maxAgeMs, 15 * 60_000))
    }));
  }

  checks.push(codexMemoryCheck(settings.home));
  if (settings.deep) checks.push(...deepRuntimeChecks(settings));

  const overall = aggregateStatus(checks);
  return { schema: REPORT_SCHEMA, generatedAt: new Date().toISOString(), overall, exitCode: RANK[overall], checks };
}

function check(id, status, summary, evidence = undefined) {
  return { id, status, summary, ...(evidence ? { evidence } : {}) };
}

function defined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function finite(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function finiteOr(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

function loadConfig(configPath) {
  if (!configPath) return {};
  const parsed = JSON.parse(readFileSync(configPath, "utf8"));
  if (parsed.schema !== CONFIG_SCHEMA) throw new Error(`health_config_schema_invalid:${parsed.schema ?? "missing"}`);
  return parsed;
}

function discoverEndpoint(configRoot = "/etc/agent-memory-fabric") {
  for (const file of [...enabledConfigFiles(configRoot), ...configFiles(configRoot)]) {
    try {
      const endpoint = JSON.parse(readFileSync(file, "utf8")).endpoint;
      if (endpoint) return endpoint;
    } catch {
      // Continue across unreadable or invalid deployment files.
    }
  }
  return "";
}

function discoverCollectors(configRoot = "/etc/agent-memory-fabric") {
  return enabledConfigFiles(configRoot).map(file => ({ id: path.basename(file).replace(/^runtime-raw-/, "").replace(/\.json$/, "") }));
}

function enabledConfigFiles(root) {
  return configFiles(root).filter(file => existsSync(file.replace(/\.json$/, ".enabled")));
}

function configFiles(root) {
  try {
    return readdirSync(root)
      .filter(name => /^runtime-raw-.+\.json$/.test(name))
      .sort()
      .map(name => path.join(root, name));
  } catch {
    return [];
  }
}

async function fetchFabricStatus(endpoint, token, settings) {
  try {
    const url = new URL("/v2/status", endpoint);
    const response = await fetch(url, {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(finiteOr(settings.timeoutMs, 10_000))
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) return check("fabric", response.status >= 500 ? "critical" : "degraded", `Fabric status returned HTTP ${response.status}`);
    return evaluateFabricPayload(body, settings);
  } catch (error) {
    return check("fabric", "critical", `Fabric status failed: ${oneLine(error?.message ?? error)}`);
  }
}

function collectorSnapshot(collector, stateRoot = "/var/lib/agent-memory-fabric/runtime-raw") {
  const id = String(collector.id);
  const timer = systemctlShow(`agent-memory-fabric-runtime-raw@${id}.timer`);
  const service = systemctlShow(`agent-memory-fabric-runtime-raw@${id}.service`);
  const outbox = collector.outbox || path.join(stateRoot, id, "outbox");
  return {
    id,
    timerActive: timer.ActiveState === "active",
    timerState: timer.SubState || "unknown",
    lastTriggerMs: dateMs(timer.LastTriggerUSec),
    serviceState: service.ActiveState || "unknown",
    result: service.Result || "",
    execMainStatus: finiteOr(service.ExecMainStatus, 0),
    pending: countFiles(path.join(outbox, "pending")),
    dead: countFiles(path.join(outbox, "dead"))
  };
}

function systemctlShow(unit) {
  const result = run("systemctl", ["show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "LastTriggerUSec", "-p", "Result", "-p", "ExecMainStatus"]);
  if (result.error || result.status !== 0) return {};
  return Object.fromEntries(result.stdout.split(/\r?\n/).filter(Boolean).map(line => {
    const index = line.indexOf("=");
    return [line.slice(0, index), line.slice(index + 1)];
  }));
}

function countFiles(directory) {
  try {
    return readdirSync(directory, { withFileTypes: true }).filter(entry => entry.isFile()).length;
  } catch {
    return 0;
  }
}

function dateMs(value) {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : null;
}

function publicCollectorEvidence(snapshot) {
  return {
    timerState: snapshot.timerState,
    serviceState: snapshot.serviceState,
    result: snapshot.result || "unknown",
    execMainStatus: snapshot.execMainStatus,
    pending: snapshot.pending,
    dead: snapshot.dead,
    lastTriggerAt: snapshot.lastTriggerMs ? new Date(snapshot.lastTriggerMs).toISOString() : null
  };
}

function codexMemoryCheck(home = process.env.AMF_HEALTH_HOME || process.env.HOME || os.homedir()) {
  const result = typeof process.getuid === "function" && process.getuid() === 0 && process.env.SUDO_USER
    ? run("runuser", ["-u", process.env.SUDO_USER, "--", "codex", "features", "list"])
    : run("codex", ["features", "list"]);
  if (result.error?.code === "ENOENT") return check("codex:native-memory", "skipped", "Codex CLI is not installed locally");
  const enabled = /^memories\s+\S+\s+true\s*$/m.test(result.stdout);
  if (!enabled) return check("codex:native-memory", "degraded", "Codex native memories feature is disabled or unavailable");
  const summary = path.join(home, ".codex", "memories", "memory_summary.md");
  if (!existsSync(summary)) return check("codex:native-memory", "degraded", "Codex memories are enabled but no summary exists");
  return check("codex:native-memory", "healthy", "Codex native memories are enabled and materialized", { summaryUpdatedAt: statSync(summary).mtime.toISOString() });
}

function deepRuntimeChecks(settings) {
  const checks = [];
  const runtimes = Array.isArray(settings.runtimes) ? settings.runtimes : [{ id: "openclaw", kind: "openclaw" }, { id: "hermes", kind: "hermes" }];
  for (const runtime of runtimes) {
    if (runtime.kind === "openclaw") checks.push(openClawCheck(runtime));
    if (runtime.kind === "hermes") checks.push(hermesCheck(runtime));
  }
  return checks;
}

function openClawCheck(runtime) {
  const args = ["memory", "status", ...(runtime.agent ? ["--agent", runtime.agent] : [])];
  const result = run("openclaw", args, 4 * 1024 * 1024);
  if (result.error?.code === "ENOENT") return check(`runtime:${runtime.id}`, "skipped", "OpenClaw CLI is not installed locally");
  const output = `${result.stdout}\n${result.stderr}`;
  if (/Memory search disabled|Vector search: paused/i.test(output) || /Indexed:\s*0\//i.test(output)) {
    return check(`runtime:${runtime.id}`, "degraded", "OpenClaw memory search or index is unavailable");
  }
  return check(`runtime:${runtime.id}`, result.status === 0 ? "healthy" : "critical", result.status === 0 ? "OpenClaw memory status passed" : "OpenClaw memory status failed");
}

function hermesCheck(runtime) {
  const args = [...(runtime.profile ? ["--profile", runtime.profile] : []), "memory", "status"];
  const result = run("hermes", args);
  if (result.error?.code === "ENOENT") return check(`runtime:${runtime.id}`, "skipped", "Hermes CLI is not installed locally");
  const output = `${result.stdout}\n${result.stderr}`;
  if (/Status:\s+available/i.test(output) || /Built-in:\s+always active/i.test(output)) return check(`runtime:${runtime.id}`, "healthy", "Hermes memory provider is available");
  return check(`runtime:${runtime.id}`, result.status === 0 ? "degraded" : "critical", "Hermes memory provider is unavailable or unverified");
}

function run(command, args, maxBuffer = 1024 * 1024) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer, timeout: 15_000 });
  return { status: result.status, stdout: result.stdout || "", stderr: result.stderr || "", error: result.error };
}

function oneLine(value) {
  return String(value).replace(/\s+/g, " ").trim().slice(0, 180);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--json") options.json = true;
    else if (arg === "--deep") options.deep = true;
    else if (arg === "--offline") options.offline = true;
    else if (["--config", "--endpoint", "--deployment-env", "--token-env", "--timeout-ms"].includes(arg)) {
      const value = argv[++index];
      if (!value) throw new Error(`missing_value:${arg}`);
      const key = { "--config": "config", "--endpoint": "endpoint", "--deployment-env": "envFile", "--token-env": "tokenEnv", "--timeout-ms": "timeoutMs" }[arg];
      options[key] = arg === "--timeout-ms" ? Number(value) : value;
    } else if (arg === "--help" || arg === "-h") options.help = true;
    else throw new Error(`unknown_argument:${arg}`);
  }
  return options;
}

function usage() {
  return `Usage: amf-health.mjs [--json] [--deep] [--offline] [--config FILE] [--endpoint URL] [--deployment-env FILE] [--token-env NAME] [--timeout-ms N]\n\nExit codes: 0 healthy, 1 degraded, 2 critical.`;
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
      console.log(usage());
      return;
    }
    const report = await runHealth(options);
    console.log(options.json ? JSON.stringify(report, null, 2) : formatHuman(report));
    process.exitCode = report.exitCode;
  } catch (error) {
    const report = { schema: REPORT_SCHEMA, generatedAt: new Date().toISOString(), overall: "critical", exitCode: 2, checks: [check("probe", "critical", oneLine(error?.message ?? error))] };
    console.log(process.argv.includes("--json") ? JSON.stringify(report, null, 2) : formatHuman(report));
    process.exitCode = 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
