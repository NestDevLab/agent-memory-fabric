import assert from "node:assert/strict";
import test from "node:test";

import {
  aggregateStatus,
  evaluateCollectorSnapshot,
  evaluateFabricPayload,
  formatHuman,
  parseEnvText
} from "../skills/agent-memory-health/scripts/amf-health.mjs";

const healthyFabric = {
  ok: true,
  data: {
    version: "0.5.7",
    backend: { kind: "disabled", configured: false },
    canonicalStore: { kind: "pam-stdio", configured: true },
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
  assert.equal(evaluateFabricPayload(healthyFabric, { requireSemanticBackend: true }).status, "degraded");
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
