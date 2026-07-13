import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  aggregateStatus,
  evaluateClaudeSnapshot,
  evaluateCodexSnapshot,
  evaluateCollectorSnapshot,
  evaluateFabricPayload,
  evaluateHermesSnapshot,
  evaluateOpenClawSnapshot,
  evaluateRuntimeCoverage,
  formatHuman,
  parseEnvText,
  parseHarnessMap
} from "../skills/agent-memory-health/scripts/amf-health.mjs";

const healthyFabric = {
  ok: true,
  data: {
    version: "0.5.7",
    backend: { kind: "disabled", configured: false },
    canonicalStore: { kind: "pam-stdio", configured: true },
    documentStore: { kind: "sqlite", configured: true },
    fabricStore: {
      healthy: true,
      closed: false,
      backend: "postgres",
      schemaVersion: 7,
      rawProjectionV2Ready: true,
      rawProjectionV2ReadinessReason: null,
      legacyV1WritesEnabled: false,
      rawObjects: 42,
      queuedProposals: 2
    }
  }
};

test("Fabric accepts healthy file-first operation and can require the semantic backend", () => {
  assert.equal(evaluateFabricPayload(healthyFabric).status, "healthy");
  assert.equal(evaluateFabricPayload(healthyFabric, { requireDocumentStore: true }).status, "healthy");
  assert.equal(evaluateFabricPayload(healthyFabric, { requireSemanticBackend: true }).status, "degraded");
});

test("Fabric document corpus requirement fails closed when unconfigured", () => {
  const withoutDocuments = structuredClone(healthyFabric);
  withoutDocuments.data.documentStore = { kind: "unconfigured", configured: false };
  const result = evaluateFabricPayload(withoutDocuments, { requireDocumentStore: true });
  assert.equal(result.status, "degraded");
  assert.match(result.summary, /Document corpus/);
});

test("Fabric fails closed on RAW readiness or store health", () => {
  const notReady = structuredClone(healthyFabric);
  notReady.data.fabricStore.rawProjectionV2Ready = false;
  assert.equal(evaluateFabricPayload(notReady).status, "critical");
  const closed = structuredClone(healthyFabric);
  closed.data.fabricStore.closed = true;
  assert.equal(evaluateFabricPayload(closed).status, "critical");
});

test("proposal thresholds degrade without exposing payloads", () => {
  const result = evaluateFabricPayload(healthyFabric, { maxQueuedProposals: 1 });
  assert.equal(result.status, "degraded");
  assert.match(result.summary, /2\/1/);
});

test("collector distinguishes normal one-shot inactivity, dead letters, and timer failure", () => {
  const base = { id: "runtime", timerActive: true, timerState: "waiting", serviceState: "inactive", result: "success", execMainStatus: 0, pending: 0, dead: 0, lastTriggerMs: Date.now() };
  assert.equal(evaluateCollectorSnapshot(base).status, "healthy");
  assert.equal(evaluateCollectorSnapshot({ ...base, dead: 1 }).status, "degraded");
  assert.equal(evaluateCollectorSnapshot({ ...base, timerActive: false }).status, "critical");
});

test("pending and stale collectors degrade", () => {
  const base = { id: "runtime", timerActive: true, result: "success", execMainStatus: 0, pending: 2, dead: 0, lastTriggerMs: Date.now() };
  assert.equal(evaluateCollectorSnapshot(base).status, "degraded");
  assert.equal(evaluateCollectorSnapshot({ ...base, pending: 0, lastTriggerMs: Date.now() - 60_000 }, { maxAgeMs: 1000 }).status, "degraded");
});

test("environment parser handles comments and quotes without logging values", () => {
  assert.deepEqual(parseEnvText("# x\nTOKEN='secret'\nPLAIN=value\n"), { TOKEN: "secret", PLAIN: "value" });
});

test("overall status and human output preserve severity", () => {
  const checks = [{ id: "a", status: "healthy", summary: "ok" }, { id: "b", status: "degraded", summary: "lag" }];
  assert.equal(aggregateStatus(checks), "degraded");
  assert.match(formatHuman({ overall: "degraded", checks }), /\[WARN\] b: lag/);
});

test("fleet coverage always requires Codex, Claude, OpenClaw, and Hermes", () => {
  const all = ["codex", "claude", "openclaw", "hermes"].map(kind => ({ kind }));
  assert.equal(evaluateRuntimeCoverage(all).status, "healthy");
  const missingHermes = evaluateRuntimeCoverage(all.filter(target => target.kind !== "hermes"));
  assert.equal(missingHermes.status, "critical");
  assert.match(missingHermes.summary, /hermes/);
});

test("canonical harness map produces the four fleet targets and excludes Vitae", () => {
  const topology = parseHarnessMap(`hosts:
  ct107:
    access:
      ssh: administrator@10.0.0.107
  ct110:
    access:
      ssh_from_ct107: administrator@10.0.0.110
  ct111:
    access:
      ssh_alias: elsewhere
canonical:
`, "/srv/agent");
  assert.deepEqual(topology.targets.map(target => target.kind), ["codex", "claude", "openclaw", "hermes"]);
  assert.equal(topology.targets.some(target => /vitae/i.test(target.id)), false);
  assert.equal(topology.collectors.length, 4);
  assert.equal(topology.targets[3].host, "10.0.0.110");
});

test("Codex and Claude require materialized native memory", () => {
  const ok = { status: 0, stdout: "memories stable true\n", stderr: "" };
  assert.equal(evaluateCodexSnapshot({ checkId: "codex", command: ok, materialized: true }).status, "healthy");
  assert.equal(evaluateCodexSnapshot({ checkId: "codex", command: ok, materialized: false }).status, "degraded");
  assert.equal(evaluateClaudeSnapshot({ checkId: "claude", command: { status: 0, stdout: "2.1.207", stderr: "" }, materialized: true }).status, "healthy");
  assert.equal(evaluateClaudeSnapshot({ checkId: "claude", command: { status: 0, stdout: "2.1.207", stderr: "" }, materialized: false }).status, "degraded");
});

test("OpenClaw detects paused or empty indexes while Hermes detects its provider", () => {
  const openclaw = evaluateOpenClawSnapshot({ checkId: "openclaw", command: { status: 0, stdout: "Indexed: 0/20\nVector search: paused", stderr: "" } });
  assert.equal(openclaw.status, "degraded");
  const hermes = evaluateHermesSnapshot({ checkId: "hermes", command: { status: 0, stdout: "Built-in: always active\nStatus: available", stderr: "" } });
  assert.equal(hermes.status, "healthy");
});

test("unreachable remote runtime is critical", () => {
  const result = evaluateHermesSnapshot({ checkId: "hermes", command: { status: 255, stdout: "", stderr: "timeout" } });
  assert.equal(result.status, "critical");
});

test("CLI accepts deployment env files without colliding with Node options", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const script = path.join(here, "../skills/agent-memory-health/scripts/amf-health.mjs");
  const result = spawnSync(process.execPath, [script, "--deployment-env", "/dev/null", "--offline", "--json"], { encoding: "utf8" });
  assert.ok([0, 1, 2].includes(result.status), result.stderr);
  assert.equal(JSON.parse(result.stdout).schema, "amf.health-report/v1");
});
