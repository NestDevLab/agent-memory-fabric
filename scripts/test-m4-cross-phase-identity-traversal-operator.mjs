import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  digest,
  fixture,
  sign,
} from "./helpers/m4-traversal-completion-fixtures.mjs";
import {
  planM4CrossPhaseIdentityTraversalOperator,
  runM4CrossPhaseIdentityTraversalOperator,
} from "../src/operator/m4-cross-phase-identity-traversal-operator.mjs";
import { createM4CrossPhaseIdentityTraversalGroupCheckpoint } from "../src/migration/m4-cross-phase-identity-traversal-store.mjs";
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from "../src/migration/m4-v2-conversation-projector.mjs";
import { runM4CrossPhaseIdentityTraversal } from "../src/migration/m4-cross-phase-identity-traversal-runner.mjs";

function write(file, value, mode = 0o600) {
  fs.writeFileSync(file, JSON.stringify(value));
  fs.chmodSync(file, mode);
}
function setup() {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "amf-m4-cross-phase-operator-"),
  );
  const value = fixture({
    coverage: {
      schema: "amf.m4-cross-phase-identity-streaming-coverage/v1",
      state: "open",
      expectedBlockCount: 1,
      blockCount: 1,
      sessionCount: 1,
      eventCount: 1,
    },
    registrySecret: Buffer.alloc(32, 4),
  });
  const files = Object.fromEntries(
    [
      "config",
      "fabric",
      "delivery",
      "archive",
      "archiveKey",
      "baseline",
      "catalogKey",
      "traversalKey",
      "registryKey",
    ].map((name) => [name, path.join(root, `${name}.json`)]),
  );
  const artifactRoot = path.join(root, "artifacts");
  fs.mkdirSync(artifactRoot, { mode: 0o700 });
  fs.chmodSync(artifactRoot, 0o700);
  write(files.fabric, {
    schema: "amf.m4-v2-backfill-fabric/v1",
    rootPath: root,
    env: {
      AMF_RAW_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      AMF_RAW_ENCRYPTION_KEY_ID: "raw-key",
      AMF_DATA_PATH: path.join(root, "fabric-data"),
      AMF_CATALOG_KIND: "sqlite",
      AMF_CATALOG_PATH: path.join(root, "catalog.sqlite"),
      AMF_RAW_V2_CUTOVER: "true",
      AMF_INGEST_KEY_RING_JSON: JSON.stringify({
        keys: { ingest: Buffer.alloc(32, 8).toString("base64") },
        digestKey: Buffer.alloc(32, 9).toString("base64"),
        logicalMessageKeys: {
          currentKeyVersion: "logical-key",
          keys: { "logical-key": Buffer.alloc(32, 10).toString("base64") },
        },
        authorizations: {
          ingest: {
            actors: ["synthetic-actor"],
            sourceInstances: ["synthetic-source"],
          },
        },
      }),
    },
  });
  write(files.delivery, {
    schema: "amf.m4-v2-delivery-key-ring/v1",
    currentKeyId: "delivery-key",
    keys: { "delivery-key": Buffer.alloc(32, 11).toString("base64") },
    cursorKey: Buffer.alloc(32, 12).toString("base64"),
    retentionDays: 30,
  });
  write(files.archive, value.input.archiveCompletion);
  write(files.archiveKey, value.input.archiveCompletionKeyDocument);
  write(files.baseline, value.input.catalogBaseline);
  write(files.catalogKey, value.input.catalogKeyDocument);
  write(files.traversalKey, value.input.completionKeyDocument);
  write(files.registryKey, value.input.registryKeyDocument);
  const config = {
    schema: "amf.m4-cross-phase-identity-traversal-operator/v1",
    artifactRoot,
    manifestId: "traversal-operator-fixture",
    revision: 1,
    fabricConfigPath: files.fabric,
    deliveryKeyRingPath: files.delivery,
    leasePath: path.join(root, "lease.json"),
    traversalStateRoot: path.join(root, "traversal-state"),
    spoolRoot: path.join(root, "spool"),
    archiveCompletionPath: files.archive,
    archiveCompletionKeyPath: files.archiveKey,
    catalogBaselinePath: files.baseline,
    catalogAttestationKeyPath: files.catalogKey,
    traversalCompletionKeyPath: files.traversalKey,
    registryKeyPath: files.registryKey,
  };
  write(files.config, config);
  return { root, files, config, value };
}
function cleanup(item) {
  fs.rmSync(item.root, { recursive: true, force: true });
}
function acceptedRow() {
  const hash = (value) =>
    crypto.createHash("sha256").update(value).digest("hex");
  const legacySessionId = `ses_${hash("accepted-session")}`,
    legacyEventId = `evt_${hash("accepted-event")}`,
    conversationId =
      deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
    opaque = `hmac-sha256:test:${hash("opaque")}`,
    tag = `test:${hash("tag")}`;
  const identityBlock = {
    schema: "amf.m4-cross-phase-projector-identity-block/v1",
    session: {
      legacySessionId,
      conversationId,
      conversationKind: "dm",
      sessionContextTags: { conversation: [opaque], room: [opaque] },
    },
    events: [
      {
        legacyEventId,
        legacySessionId,
        eventId: deriveM4V3EventIdFromLegacyEventId(legacyEventId),
        conversationId,
        sourceInstanceId: deriveM4V3SourceInstanceIdFromLegacySession(
          legacySessionId,
          [tag],
        ),
        sourceTags: [tag],
        conversationKind: "dm",
        authorizationContextTags: {
          sender: [opaque],
          conversation: [opaque],
          room: [opaque],
        },
        role: "user",
        direction: "inbound",
        state: "active",
        revision: 1,
        replacesLegacyEventId: null,
        tombstonesLegacyEventId: null,
        conflictsWithLegacyEventIds: [],
      },
    ],
  };
  const logicalMessageId = `lmsg_${hash("accepted-logical")}`,
    identityBlockDigest = digest(identityBlock);
  return {
    sequence: 1,
    checkpoint: createM4CrossPhaseIdentityTraversalGroupCheckpoint({
      sequence: 1,
      logicalMessageId,
      outcome: "accepted",
      identityBlockDigest,
    }),
    logicalMessageId,
    outcome: "accepted",
    reason: null,
    identityBlock,
    identityBlockDigest,
  };
}

test("plans a redacted deterministic cross-phase identity traversal without creating runtime resources", async () => {
  const item = setup();
  try {
    const first = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    const second = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    assert.deepEqual(first, second);
    assert.deepEqual(Object.keys(first).sort(), [
      "confirmationDigest",
      "operation",
      "phase",
      "runId",
      "schema",
    ]);
    assert.match(first.runId, /^m4-[a-f0-9]{64}$/);
    assert.match(first.confirmationDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(JSON.stringify(first).includes(item.root), false);
    assert.equal(fs.existsSync(item.config.traversalStateRoot), false);
    assert.equal(fs.existsSync(item.config.spoolRoot), false);
    assert.equal(fs.existsSync(item.config.leasePath), false);
  } finally {
    cleanup(item);
  }
});

test("rejects hostile, non-exact and non-normalized configuration before planning", async () => {
  const hostile = {};
  Object.defineProperty(hostile, "configPath", {
    enumerable: true,
    get() {
      throw new Error("private");
    },
  });
  await assert.rejects(
    () => planM4CrossPhaseIdentityTraversalOperator(hostile),
    { code: "m4_cross_phase_identity_traversal_operator_input_invalid" },
  );
  const item = setup();
  try {
    const config = JSON.parse(fs.readFileSync(item.files.config));
    write(item.files.config, { ...config, extra: true });
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_config_invalid" },
    );
    write(item.files.config, config);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: `${item.root}/./config.json`,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_input_invalid" },
    );
    fs.chmodSync(item.files.config, 0o644);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_config_invalid" },
    );
  } finally {
    cleanup(item);
  }
});

test("rejects broad and symlinked private inputs and invalid fabric/delivery documents", async () => {
  const item = setup();
  try {
    fs.chmodSync(item.files.delivery, 0o640);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    fs.chmodSync(item.files.delivery, 0o600);
    const real = `${item.files.delivery}.real`;
    fs.renameSync(item.files.delivery, real);
    fs.symlinkSync(real, item.files.delivery);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    fs.unlinkSync(item.files.delivery);
    fs.renameSync(real, item.files.delivery);
    write(item.files.delivery, { schema: "bad" });
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
  } finally {
    cleanup(item);
  }
});

test("binds archive completion and signed nonempty baseline and rejects invalid keys", async () => {
  const item = setup();
  try {
    const archive = JSON.parse(fs.readFileSync(item.files.archive));
    archive.integrity.signature = "a".repeat(43);
    write(item.files.archive, archive);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    write(item.files.archive, item.value.input.archiveCompletion);
    const baseline = JSON.parse(fs.readFileSync(item.files.baseline));
    baseline.traversal.groupCount = 0;
    write(item.files.baseline, baseline);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    const changed = structuredClone(item.value.input.catalogBaseline);
    changed.traversal.pageLimit = 49;
    const body = { schema: changed.schema, traversal: changed.traversal };
    changed.integrity.payloadDigest = digest(body);
    changed.integrity.signature = sign(
      "amf.m4-v2-catalog-revision-attestation/v2/integrity",
      body,
      item.value.input.catalogKeyDocument,
    );
    write(item.files.baseline, changed);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    write(item.files.baseline, item.value.input.catalogBaseline);
    const registry = JSON.parse(fs.readFileSync(item.files.registryKey));
    registry.key = Buffer.alloc(31, 4).toString("base64");
    write(item.files.registryKey, registry);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
  } finally {
    cleanup(item);
  }
});

test("changes confirmation on a referenced indirect ingest-ring file and rejects key reuse", async () => {
  const item = setup();
  try {
    const ring = path.join(item.root, "ingest-ring.json");
    const fabric = JSON.parse(fs.readFileSync(item.files.fabric));
    const ingest = JSON.parse(fabric.env.AMF_INGEST_KEY_RING_JSON);
    write(ring, ingest);
    delete fabric.env.AMF_INGEST_KEY_RING_JSON;
    fabric.env.AMF_INGEST_KEY_RING_PATH = ring;
    write(item.files.fabric, fabric);
    const first = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    ingest.keys.ingest = Buffer.alloc(32, 19).toString("base64");
    write(ring, ingest);
    const second = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    assert.notEqual(first.confirmationDigest, second.confirmationDigest);
    const registry = JSON.parse(fs.readFileSync(item.files.registryKey));
    registry.keyId = item.value.input.catalogKeyDocument.keyId;
    write(item.files.registryKey, registry);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      {
        code: "m4_cross_phase_identity_traversal_operator_key_separation_invalid",
      },
    );
    registry.keyId = "registry-different-key";
    registry.key = item.value.input.catalogKeyDocument.key;
    write(item.files.registryKey, registry);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      {
        code: "m4_cross_phase_identity_traversal_operator_key_separation_invalid",
      },
    );
  } finally {
    cleanup(item);
  }
});

test("keeps V2 IDs distinct from migration signing IDs and accepts 64-byte signing material", async () => {
  const item = setup();
  try {
    const delivery = JSON.parse(fs.readFileSync(item.files.delivery));
    delivery.currentKeyId = "Delivery.Key_1";
    delivery.keys = { "Delivery.Key_1": delivery.keys["delivery-key"] };
    write(item.files.delivery, delivery);
    const traversal = JSON.parse(fs.readFileSync(item.files.traversalKey));
    traversal.key = Buffer.alloc(64, 31).toString("base64");
    write(item.files.traversalKey, traversal);
    await assert.doesNotReject(() =>
      planM4CrossPhaseIdentityTraversalOperator({
        configPath: item.files.config,
      }),
    );
    delivery.currentKeyId = "bad/id";
    delivery.keys = { "bad/id": Buffer.alloc(32, 12).toString("base64") };
    write(item.files.delivery, delivery);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    write(item.files.delivery, {
      schema: "amf.m4-v2-delivery-key-ring/v1",
      currentKeyId: "delivery-key",
      keys: { "delivery-key": `${Buffer.alloc(32, 12).toString("base64")}=` },
      cursorKey: Buffer.alloc(32, 12).toString("base64"),
      retentionDays: 30,
    });
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
  } finally {
    cleanup(item);
  }
});

test("enforces V2 fabric raw ring and catalog transport bounds", async () => {
  const item = setup();
  try {
    const fabric = JSON.parse(fs.readFileSync(item.files.fabric));
    fabric.env.AMF_RAW_ENCRYPTION_KEY_ID = "bad/id";
    write(item.files.fabric, fabric);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    fabric.env.AMF_RAW_ENCRYPTION_KEY_ID = "RAW.Key_1";
    fabric.env.AMF_CATALOG_POOL_MAX = "101";
    write(item.files.fabric, fabric);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    delete fabric.env.AMF_CATALOG_POOL_MAX;
    fabric.env.AMF_CATALOG_SSL_MODE = "require";
    write(item.files.fabric, fabric);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
    delete fabric.env.AMF_CATALOG_SSL_MODE;
    delete fabric.env.AMF_RAW_ENCRYPTION_KEY;
    delete fabric.env.AMF_RAW_ENCRYPTION_KEY_ID;
    fabric.env.AMF_RAW_KEY_RING_JSON = JSON.stringify({
      currentKeyId: "Raw.Key_1",
      keys: { "Raw.Key_1": Buffer.alloc(31, 1).toString("base64") },
    });
    write(item.files.fabric, fabric);
    await assert.rejects(
      () =>
        planM4CrossPhaseIdentityTraversalOperator({
          configPath: item.files.config,
        }),
      { code: "m4_cross_phase_identity_traversal_operator_reference_invalid" },
    );
  } finally {
    cleanup(item);
  }
});

test("rejects confirmation or private-reference drift before every runtime dependency", async () => {
  const item = setup();
  try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    let calls = 0;
    const dependencies = {
      createFabricStoreFromEnv() {
        calls += 1;
      },
      BackfillLease() {
        calls += 1;
      },
      M4CrossPhaseIdentityTraversalStore() {
        calls += 1;
      },
      createM4CrossPhaseIdentityTraversalSource() {
        calls += 1;
      },
      createM4CrossPhaseIdentityStreamingWriter() {
        calls += 1;
      },
      createM4CrossPhaseIdentityPageStore() {
        calls += 1;
      },
      preflightM4CrossPhaseIdentityStreamingCapacity() {
        calls += 1;
      },
      runM4CrossPhaseIdentityTraversal() {
        calls += 1;
      },
      attestM4V2CatalogRevision() {
        calls += 1;
      },
      verifyM4CrossPhaseIdentityAuthority() {
        calls += 1;
      },
      verifyM4CrossPhaseIdentityTraversalCompletion() {
        calls += 1;
      },
      writePrivateArtifactIdempotent() {
        calls += 1;
      },
      filesystemStats() {
        calls += 1;
      },
    };
    await assert.rejects(
      () =>
        runM4CrossPhaseIdentityTraversalOperator(
          {
            configPath: item.files.config,
            confirmedPlanDigest: `sha256:${"f".repeat(64)}`,
          },
          { dependencies },
        ),
      {
        code: "m4_cross_phase_identity_traversal_operator_confirmation_invalid",
      },
    );
    assert.equal(calls, 0);
    const delivery = JSON.parse(fs.readFileSync(item.files.delivery));
    delivery.keys["delivery-key"] = Buffer.alloc(32, 66).toString("base64");
    write(item.files.delivery, delivery);
    await assert.rejects(
      () =>
        runM4CrossPhaseIdentityTraversalOperator(
          {
            configPath: item.files.config,
            confirmedPlanDigest: plan.confirmationDigest,
          },
          { dependencies },
        ),
      {
        code: "m4_cross_phase_identity_traversal_operator_confirmation_invalid",
      },
    );
    assert.equal(calls, 0);
  } finally {
    cleanup(item);
  }
});

test("all-excluded run uses the real runner, publishes a zero authority, and never creates spool or pages", async () => {
  const item = setup();
  try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    let fabricClosed = 0,
      statfs = 0,
      pageStores = 0;
    const checkpoint = createM4CrossPhaseIdentityTraversalGroupCheckpoint({
      sequence: 1,
      logicalMessageId: `lmsg_${"a".repeat(64)}`,
      outcome: "excluded",
      identityBlockDigest: null,
    });
    const dependencies = {
      createFabricStoreFromEnv() {
        return {
          catalog: {},
          rawStore: {},
          async audit() {},
          async close() {
            fabricClosed += 1;
          },
        };
      },
      createM4CrossPhaseIdentityTraversalSource(input) {
        return {
          binding: {
            runId: input.runId,
            planDigest: input.planDigest,
            catalogBaselineDigest: digest(input.catalogBaseline),
            groupCount: 1,
          },
          open() {
            return (async function* () {
              yield {
                sequence: 1,
                checkpoint,
                logicalMessageId: `lmsg_${"a".repeat(64)}`,
                outcome: "excluded",
                reason: "preferred_ineligible",
                identityBlock: null,
                identityBlockDigest: null,
              };
            })();
          },
        };
      },
      attestM4V2CatalogRevision() {
        return item.value.input.catalogBaseline;
      },
      filesystemStats() {
        statfs += 1;
        return { bavail: 1n, bsize: 1n };
      },
      createM4CrossPhaseIdentityPageStore() {
        pageStores += 1;
        throw new Error("must not create");
      },
    };
    const result = await runM4CrossPhaseIdentityTraversalOperator(
      {
        configPath: item.files.config,
        confirmedPlanDigest: plan.confirmationDigest,
      },
      { dependencies },
    );
    assert.deepEqual(Object.keys(result).sort(), [
      "operation",
      "phase",
      "publication",
      "runId",
      "schema",
    ]);
    assert.equal(result.publication.state, "published");
    assert.match(result.publication.artifactDigest, /^sha256:/);
    assert.equal(statfs, 0);
    assert.equal(pageStores, 0);
    assert.equal(fs.existsSync(item.config.spoolRoot), false);
    assert.equal(fabricClosed, 0);
    const target = path.join(
      item.config.artifactRoot,
      "m4",
      "cross-phase-identity",
      "traversal-operator-fixture-r1.json",
    );
    assert.equal(fs.existsSync(target), true);
  } finally {
    cleanup(item);
  }
});

test("accepted run lazily preflights once, persists pages, and publishes a redacted root", async () => {
  const item = setup();
  try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    let statfs = 0,
      closed = 0;
    const row = acceptedRow();
    const dependencies = {
      createFabricStoreFromEnv() {
        return {
          catalog: {},
          rawStore: {},
          async audit() {},
          async close() {
            closed += 1;
          },
        };
      },
      createM4CrossPhaseIdentityTraversalSource(input) {
        return {
          binding: {
            runId: input.runId,
            planDigest: input.planDigest,
            catalogBaselineDigest: digest(input.catalogBaseline),
            groupCount: 1,
          },
          open() {
            return (async function* () {
              yield row;
            })();
          },
        };
      },
      attestM4V2CatalogRevision() {
        return item.value.input.catalogBaseline;
      },
      filesystemStats() {
        statfs += 1;
        return { bavail: 6n * 1024n * 1024n * 1024n, bsize: 1n };
      },
    };
    const result = await runM4CrossPhaseIdentityTraversalOperator(
      {
        configPath: item.files.config,
        confirmedPlanDigest: plan.confirmationDigest,
      },
      { dependencies },
    );
    assert.equal(result.publication.state, "published");
    assert.equal(statfs, 1);
    assert.equal(closed, 0);
    assert.equal(fs.existsSync(item.config.spoolRoot), true);
    const pages = path.join(
      item.config.artifactRoot,
      "m4",
      "cross-phase-identity-pages",
      "traversal-operator-fixture-r1",
    );
    assert.equal(
      fs.readdirSync(pages).some((name) => name.endsWith(".json")),
      true,
    );
    const root = JSON.parse(
      fs.readFileSync(
        path.join(
          item.config.artifactRoot,
          "m4",
          "cross-phase-identity",
          "traversal-operator-fixture-r1.json",
        ),
      ),
    );
    assert.equal(JSON.stringify(root).includes(item.root), false);
  } finally {
    cleanup(item);
  }
});

test("a held lease constructs neither Fabric nor traversal state", async () => {
  const item = setup();
  try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config });
    let fabricCalls = 0, storeCalls = 0, sourceCalls = 0;
    const dependencies = {
      createFabricStoreFromEnv() { fabricCalls += 1; throw new Error("private"); },
      M4CrossPhaseIdentityTraversalStore: class { constructor() { storeCalls += 1; } },
      BackfillLease: class { acquire() { throw new Error("held"); } heartbeat() {} release() {} },
      createM4CrossPhaseIdentityTraversalSource(input) { sourceCalls += 1; return { binding: { runId: input.runId, planDigest: input.planDigest, catalogBaselineDigest: digest(input.catalogBaseline), groupCount: 1 }, open() { throw new Error("unreachable"); } }; },
    };
    await assert.rejects(() => runM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: "m4_cross_phase_identity_traversal_runner_lease_failed" });
    assert.deepEqual([fabricCalls, storeCalls, sourceCalls], [0, 0, 1]);
    assert.equal(fs.existsSync(item.config.traversalStateRoot), false);
  } finally { cleanup(item); }
});

test("rejects hostile or extra runtime options before private work", async () => {
  const hostile = {};
  Object.defineProperty(hostile, "dependencies", { enumerable: true, get() { throw new Error("private"); } });
  await assert.rejects(() => runM4CrossPhaseIdentityTraversalOperator({ configPath: "/private/config.json", confirmedPlanDigest: `sha256:${"a".repeat(64)}` }, hostile), { code: "m4_cross_phase_identity_traversal_operator_options_invalid" });
  await assert.rejects(() => runM4CrossPhaseIdentityTraversalOperator({ configPath: "/private/config.json", confirmedPlanDigest: `sha256:${"a".repeat(64)}` }, { extra: true }), { code: "m4_cross_phase_identity_traversal_operator_options_invalid" });
});

test("source callbacks open Fabric once and use audit, opaque tags, baseline page limit, and tracked key", async () => {
  const item = setup(); try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config }); let source, opens = 0, audited = null, delivery, limit = null;
    const dependencies = {
      createFabricStoreFromEnv() { opens += 1; return { catalog: { listM4V2LogicalGroups() {} }, rawStore: { opaqueTags(kind, id) { return [`${kind}:${id}`]; } }, async audit(value) { audited = value; }, async close() {} }; },
      createM4CrossPhaseIdentityTraversalSource(value) { source = value; return { binding: { runId: value.runId, planDigest: value.planDigest, catalogBaselineDigest: digest(value.catalogBaseline), groupCount: 1 }, open() { return (async function* () {})(); } }; },
      attestM4V2CatalogRevision({ catalog, pageLimit }) { catalog.listM4V2LogicalGroups(); limit = pageLimit; return item.value.input.catalogBaseline; },
      runM4CrossPhaseIdentityTraversal: async input => { assert.equal(typeof input.traversalStore.commitExcludedBatch, "function"); assert.deepEqual(await source.verifyCatalogBinding({ actorId: "actor", sourceInstanceId: "source", ownerTag: "raw-owner:actor", sourceTag: "raw-source:source" }), { owner: true, source: true }); await source.auditDecrypt({ eventId: "event", contentId: "content" }); delivery = await source.integrityFor(); await input.catalogAttestor(); const error = new Error(); error.code = "m4_cross_phase_identity_traversal_operator_source_test"; throw error; },
    };
    await assert.rejects(() => runM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: "m4_cross_phase_identity_traversal_operator_source_test" });
    assert.equal(opens, 1); assert.equal(limit, item.value.input.catalogBaseline.traversal.pageLimit); assert.deepEqual(audited.details, { transport: "m4-cross-phase-identity-traversal" }); assert.equal(delivery.key.every(byte => byte === 0), true);
    assert.equal(source.ingestKeys.keys instanceof Map, false);
    assert.equal(typeof source.ingestKeys.keys.ingest, "string");
  } finally { cleanup(item); }
});

test("cleanup continues through page, state, and Fabric failures while preserving the primary error", async () => {
  const item = setup(); try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config }); const events = [];
    const dependencies = {
      createFabricStoreFromEnv() { return { catalog: { listM4V2LogicalGroups() {} }, rawStore: { opaqueTags() { return []; } }, async audit() {}, async close() { events.push("fabric"); throw new Error(); } }; },
      M4CrossPhaseIdentityTraversalStore: class { load() {} close() { events.push("store"); throw new Error(); } },
      createM4CrossPhaseIdentityTraversalSource(value) { return { binding: { runId: value.runId, planDigest: value.planDigest, catalogBaselineDigest: digest(value.catalogBaseline), groupCount: 1 }, open() { return (async function* () {})(); } }; },
      createM4CrossPhaseIdentityPageStore() { return { writePage() {}, close() { events.push("page"); throw new Error(); } }; },
      createM4CrossPhaseIdentityStreamingWriter() { return { accept() {}, seal() {}, close() {} }; }, preflightM4CrossPhaseIdentityStreamingCapacity() {},
      attestM4V2CatalogRevision({ catalog }) { catalog.listM4V2LogicalGroups(); return item.value.input.catalogBaseline; },
      runM4CrossPhaseIdentityTraversal: async value => { await value.catalogAttestor(); value.traversalStore.load(); await value.createWriter({ expectedBlockCount: 1, firstBlock: {} }); const error = new Error(); error.code = "m4_cross_phase_identity_primary"; throw error; },
    };
    await assert.rejects(() => runM4CrossPhaseIdentityTraversalOperator({ configPath: item.files.config, confirmedPlanDigest: plan.confirmationDigest }, { dependencies }), { code: "m4_cross_phase_identity_primary" }); assert.deepEqual(events, ["page", "store", "fabric"]);
  } finally { cleanup(item); }
});

test("CLI emits one compact redacted plan line and normalizes malformed and confirmation failures", async () => {
  const item = setup();
  const cli = path.join(process.cwd(), "scripts", "amf-m4-cross-phase-identity-traversal.mjs");
  const invoke = args => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
  try {
    const plan = invoke(["plan", "--config", item.files.config]);
    assert.equal(plan.status, 0); assert.equal(plan.stderr, ""); assert.equal(plan.stdout.split("\n").filter(Boolean).length, 1);
    const output = JSON.parse(plan.stdout); assert.deepEqual(Object.keys(output).sort(), ["confirmationDigest", "ok", "operation", "phase", "runId", "schema"]); assert.equal(JSON.stringify(output).includes(item.root), false); assert.equal(JSON.stringify(output).includes("delivery-key"), false); assert.equal(JSON.stringify(output).includes("sqlite"), false);
    for (const args of [["plan"], ["plan", "--config", item.files.config, "--config", item.files.config], ["plan", "--unknown", item.files.config], ["plan", "--config", "relative.json"]]) { const result = invoke(args); assert.equal(result.status, 78); assert.deepEqual(JSON.parse(result.stderr), { ok: false, error: "m4_cross_phase_identity_traversal_operator_argument_invalid" }); assert.equal(result.stdout, ""); }
    const wrong = invoke(["run", "--config", item.files.config, "--confirmed-plan-digest", `sha256:${"f".repeat(64)}`]); assert.equal(wrong.status, 78); const error = JSON.parse(wrong.stderr); assert.deepEqual(error, { ok: false, error: "m4_cross_phase_identity_traversal_operator_confirmation_invalid" }); assert.equal(JSON.stringify(error).includes(item.root), false);
  } finally { cleanup(item); }
});

test("rejects registry coverage drift before publishing the root artifact", async () => {
  const item = setup();
  try {
    const plan = await planM4CrossPhaseIdentityTraversalOperator({
      configPath: item.files.config,
    });
    const logicalMessageId = `lmsg_${"b".repeat(64)}`;
    const checkpoint = createM4CrossPhaseIdentityTraversalGroupCheckpoint({
      sequence: 1,
      logicalMessageId,
      outcome: "excluded",
      identityBlockDigest: null,
    });
    const dependencies = {
      createM4CrossPhaseIdentityTraversalSource(input) {
        return {
          binding: {
            runId: input.runId,
            planDigest: input.planDigest,
            catalogBaselineDigest: digest(input.catalogBaseline),
            groupCount: 1,
          },
          open() {
            return (async function* () {
              yield {
                sequence: 1,
                checkpoint,
                logicalMessageId,
                outcome: "excluded",
                reason: "preferred_ineligible",
                identityBlock: null,
                identityBlockDigest: null,
              };
            })();
          },
        };
      },
      attestM4V2CatalogRevision() {
        return item.value.input.catalogBaseline;
      },
      async runM4CrossPhaseIdentityTraversal(input) {
        return runM4CrossPhaseIdentityTraversal({
          ...input,
          publish(value) {
            return input.publish({
              ...value,
              registry: {
                ...value.registry,
                coverage: {
                  ...value.registry.coverage,
                  acceptedBlockCount:
                    value.registry.coverage.acceptedBlockCount + 1,
                },
              },
            });
          },
        });
      },
    };
    await assert.rejects(
      () =>
        runM4CrossPhaseIdentityTraversalOperator(
          {
            configPath: item.files.config,
            confirmedPlanDigest: plan.confirmationDigest,
          },
          { dependencies },
        ),
      {
        code: "m4_cross_phase_identity_traversal_runner_publish_failed",
      },
    );
    assert.equal(
      fs.existsSync(
        path.join(
          item.config.artifactRoot,
          "m4",
          "cross-phase-identity",
          "traversal-operator-fixture-r1.json",
        ),
      ),
      false,
    );
  } finally {
    cleanup(item);
  }
});
