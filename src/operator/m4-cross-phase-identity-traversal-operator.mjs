import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "../ingest/transcripts/canonical.mjs";
import { normalizeIngestKeyRing } from "../ingest/raw-event-contract.mjs";
import {
  deriveM4V2ArchiveRegistryBinding,
  verifyM4V2ArchiveBackfillCompletion,
} from "../migration/m4-v2-backfill-completion.mjs";
import { verifyM4V2CatalogRevisionAttestation } from "../migration/m4-v2-catalog-revision-attestation.mjs";
import { BackfillLease } from "../ingest/transcripts/backfill.mjs";
import { createFabricStoreFromEnv } from "../fabric-store.mjs";
import { M4CrossPhaseIdentityTraversalStore } from "../migration/m4-cross-phase-identity-traversal-store.mjs";
import { createM4CrossPhaseIdentityTraversalSource } from "../migration/m4-cross-phase-identity-traversal-source.mjs";
import {
  createM4CrossPhaseIdentityStreamingWriter,
  preflightM4CrossPhaseIdentityStreamingCapacity,
} from "../migration/m4-cross-phase-identity-streaming-writer.mjs";
import { runM4CrossPhaseIdentityTraversal } from "../migration/m4-cross-phase-identity-traversal-runner.mjs";
import { verifyM4CrossPhaseIdentityAuthority } from "../migration/m4-cross-phase-identity-registry.mjs";
import { verifyM4CrossPhaseIdentityTraversalCompletion } from "../migration/m4-cross-phase-identity-traversal-completion.mjs";
import { attestM4V2CatalogRevision } from "../migration/m4-v2-catalog-revision-attestation.mjs";
import { createM4CrossPhaseIdentityPageStore } from "./m4-cross-phase-identity-page-store.mjs";
import {
  canonicalDigest,
  validateArtifactRoot,
  readPrivateJsonWithDigest,
  writePrivateArtifactIdempotent,
} from "./private-artifacts.mjs";

const ID = /^[a-z][a-z0-9-]{2,79}$/;
const V2_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const KEY32_B64 = /^[A-Za-z0-9+/]{43}=$/;
const SIGNING_B64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const CONFIG_KEYS = [
  "schema",
  "artifactRoot",
  "manifestId",
  "revision",
  "fabricConfigPath",
  "deliveryKeyRingPath",
  "leasePath",
  "traversalStateRoot",
  "spoolRoot",
  "archiveCompletionPath",
  "archiveCompletionKeyPath",
  "catalogBaselinePath",
  "catalogAttestationKeyPath",
  "traversalCompletionKeyPath",
  "registryKeyPath",
];
const ENV_KEYS = new Set([
  "AMF_DATA_PATH",
  "AMF_CATALOG_KIND",
  "AMF_CATALOG_PATH",
  "AMF_CATALOG_DATABASE_URL",
  "AMF_CATALOG_POOL_MAX",
  "AMF_CATALOG_SSL_MODE",
  "AMF_CATALOG_CONNECT_TIMEOUT_MS",
  "AMF_CATALOG_QUERY_TIMEOUT_MS",
  "AMF_CATALOG_STATEMENT_TIMEOUT_MS",
  "AMF_RAW_ENCRYPTION_KEY",
  "AMF_RAW_ENCRYPTION_KEY_ID",
  "AMF_RAW_KEY_RING_PATH",
  "AMF_RAW_KEY_RING_JSON",
  "AMF_INGEST_KEY_RING_PATH",
  "AMF_INGEST_KEY_RING_JSON",
  "AMF_RAW_V2_CUTOVER",
]);
function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
function exact(value, keys) {
  return (
    plain(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}
function digest(value) {
  return `sha256:${crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}
function absolute(value, code) {
  if (
    typeof value !== "string" ||
    !path.isAbsolute(value) ||
    path.normalize(value) !== value
  )
    fail(code);
  return value;
}
function noSymlinks(target, code) {
  const safe = absolute(target, code),
    parsed = path.parse(target);
  let current = parsed.root;
  try {
    for (const item of safe
      .slice(parsed.root.length)
      .split(path.sep)
      .filter(Boolean)) {
      current = path.join(current, item);
      try {
        if (fs.lstatSync(current).isSymbolicLink()) fail(code);
      } catch (error) {
        if (error?.code === "ENOENT") return safe;
        throw error;
      }
    }
    return safe;
  } catch (error) {
    if (error?.code === code) throw error;
    fail(code);
  }
}
function clone(value, code) {
  try {
    return structuredClone(value);
  } catch {
    fail(code);
  }
}
function key(value, code, exactLength = null) {
  const safe = clone(value, code);
  if (
    !exact(safe, ["schema", "keyId", "key"]) ||
    safe.schema !== "amf.migration-signing-key/v1" ||
    !ID.test(safe.keyId) ||
    typeof safe.key !== "string" ||
    !SIGNING_B64.test(safe.key)
  )
    fail(code);
  const material = Buffer.from(safe.key, "base64");
  if (
    material.length < (exactLength ?? 32) ||
    material.length > 64 ||
    (exactLength !== null && material.length !== exactLength) ||
    material.toString("base64") !== safe.key
  ) {
    material.fill(0);
    fail(code);
  }
  return { keyId: safe.keyId, key: material };
}
function independent(keys, code) {
  try {
    for (let a = 0; a < keys.length; a += 1)
      for (let b = a + 1; b < keys.length; b += 1) {
        const left = Buffer.alloc(64),
          right = Buffer.alloc(64);
        try {
          keys[a].key.copy(left);
          keys[b].key.copy(right);
          if (
            keys[a].keyId === keys[b].keyId ||
            crypto.timingSafeEqual(left, right)
          )
            fail(code);
        } finally {
          left.fill(0);
          right.fill(0);
        }
      }
  } finally {
    for (const item of keys) item.key.fill(0);
  }
}
function configShape(value) {
  const safe = clone(
    value,
    "m4_cross_phase_identity_traversal_operator_config_invalid",
  );
  if (
    !exact(safe, CONFIG_KEYS) ||
    safe.schema !== "amf.m4-cross-phase-identity-traversal-operator/v1" ||
    !ID.test(safe.manifestId) ||
    !Number.isSafeInteger(safe.revision) ||
    safe.revision < 1
  )
    fail("m4_cross_phase_identity_traversal_operator_config_invalid");
  for (const name of CONFIG_KEYS.filter(
    (name) =>
      name.endsWith("Path") ||
      ["artifactRoot", "leasePath", "traversalStateRoot", "spoolRoot"].includes(
        name,
      ),
  ))
    absolute(
      safe[name],
      "m4_cross_phase_identity_traversal_operator_config_invalid",
    );
  validateArtifactRoot(
    safe.artifactRoot,
    "m4_cross_phase_identity_traversal_operator_config_invalid",
  );
  return safe;
}
function fabricShape(value) {
  const safe = clone(
    value,
    "m4_cross_phase_identity_traversal_operator_reference_invalid",
  );
  if (
    !exact(safe, ["schema", "rootPath", "env"]) ||
    safe.schema !== "amf.m4-v2-backfill-fabric/v1" ||
    !plain(safe.env)
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  absolute(
    safe.rootPath,
    "m4_cross_phase_identity_traversal_operator_reference_invalid",
  );
  if (
    Object.entries(safe.env).some(
      ([name, item]) => !ENV_KEYS.has(name) || typeof item !== "string",
    )
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  const env = safe.env;
  for (const name of [
    "AMF_DATA_PATH",
    "AMF_CATALOG_PATH",
    "AMF_RAW_KEY_RING_PATH",
    "AMF_INGEST_KEY_RING_PATH",
  ])
    if (env[name] !== undefined)
      absolute(
        env[name],
        "m4_cross_phase_identity_traversal_operator_reference_invalid",
      );
  if (
    !env.AMF_DATA_PATH ||
    !["sqlite", "postgres"].includes(env.AMF_CATALOG_KIND) ||
    !["true", "false"].includes(env.AMF_RAW_V2_CUTOVER)
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  const rawRing =
    env.AMF_RAW_KEY_RING_PATH !== undefined ||
    env.AMF_RAW_KEY_RING_JSON !== undefined;
  if (
    rawRing === (env.AMF_RAW_ENCRYPTION_KEY !== undefined) ||
    (rawRing && env.AMF_RAW_ENCRYPTION_KEY_ID !== undefined)
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  if (
    env.AMF_RAW_ENCRYPTION_KEY !== undefined &&
    (!KEY32_B64.test(env.AMF_RAW_ENCRYPTION_KEY) ||
      !V2_ID.test(env.AMF_RAW_ENCRYPTION_KEY_ID || ""))
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  if (
    env.AMF_CATALOG_KIND === "sqlite" &&
    (!env.AMF_CATALOG_PATH || env.AMF_CATALOG_DATABASE_URL !== undefined)
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  if (
    env.AMF_CATALOG_KIND === "postgres" &&
    (env.AMF_CATALOG_PATH !== undefined ||
      !/^postgres(?:ql)?:\/\/[^\s\x00-\x1f]{1,4096}$/.test(
        env.AMF_CATALOG_DATABASE_URL || "",
      ))
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  for (const name of [
    "AMF_CATALOG_POOL_MAX",
    "AMF_CATALOG_CONNECT_TIMEOUT_MS",
    "AMF_CATALOG_QUERY_TIMEOUT_MS",
    "AMF_CATALOG_STATEMENT_TIMEOUT_MS",
  ])
    if (env[name] !== undefined) {
      const number = Number(env[name]),
        minimum = name === "AMF_CATALOG_POOL_MAX" ? 1 : 100,
        maximum = name === "AMF_CATALOG_POOL_MAX" ? 100 : 120000;
      if (!Number.isInteger(number) || number < minimum || number > maximum)
        fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
    }
  if (
    env.AMF_CATALOG_SSL_MODE !== undefined &&
    !["disable", "require", "verify-full"].includes(env.AMF_CATALOG_SSL_MODE)
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  if (
    env.AMF_CATALOG_KIND === "sqlite" &&
    ["AMF_CATALOG_POOL_MAX", "AMF_CATALOG_SSL_MODE"].some(
      (name) => env[name] !== undefined,
    )
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  return safe;
}
function deliveryShape(value) {
  const safe = clone(
    value,
    "m4_cross_phase_identity_traversal_operator_reference_invalid",
  );
  if (
    !exact(safe, [
      "schema",
      "currentKeyId",
      "keys",
      "cursorKey",
      "retentionDays",
    ]) ||
    safe.schema !== "amf.m4-v2-delivery-key-ring/v1" ||
    !V2_ID.test(safe.currentKeyId || "") ||
    !plain(safe.keys) ||
    !KEY32_B64.test(safe.cursorKey) ||
    !Number.isSafeInteger(safe.retentionDays) ||
    safe.retentionDays < 1 ||
    safe.retentionDays > 3650 ||
    Object.keys(safe.keys).length < 1 ||
    Object.keys(safe.keys).length > 32 ||
    !Object.hasOwn(safe.keys, safe.currentKeyId) ||
    Object.entries(safe.keys).some(
      ([id, value]) => !V2_ID.test(id) || !KEY32_B64.test(value),
    )
  )
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  return safe;
}
function normalizeFabric(fabric, references) {
  const env = { ...fabric.env };
  for (const [pathName, jsonName] of [
    ["AMF_RAW_KEY_RING_PATH", "AMF_RAW_KEY_RING_JSON"],
    ["AMF_INGEST_KEY_RING_PATH", "AMF_INGEST_KEY_RING_JSON"],
  ]) {
    if (env[pathName] !== undefined && env[jsonName] !== undefined)
      fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
    if (env[pathName] !== undefined) {
      const loaded = read(env[pathName]);
      references.push([pathName, loaded.digest]);
      env[jsonName] = canonicalJson(loaded.value);
      delete env[pathName];
    }
  }
  if (!env.AMF_INGEST_KEY_RING_JSON)
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  try {
    const ingestKeys = JSON.parse(env.AMF_INGEST_KEY_RING_JSON);
    normalizeIngestKeyRing(ingestKeys);
    if (env.AMF_RAW_KEY_RING_JSON !== undefined) {
      const raw = JSON.parse(env.AMF_RAW_KEY_RING_JSON);
      if (
        !exact(raw, ["currentKeyId", "keys"]) ||
        !V2_ID.test(raw.currentKeyId || "") ||
        !plain(raw.keys) ||
        Object.keys(raw.keys).length < 1 ||
        Object.keys(raw.keys).length > 32 ||
        !Object.hasOwn(raw.keys, raw.currentKeyId) ||
        Object.entries(raw.keys).some(
          ([id, value]) => !V2_ID.test(id) || !KEY32_B64.test(value),
        )
      )
        throw new Error();
    }
    return {
      rootPath: fabric.rootPath,
      env,
      ingestKeys: structuredClone(ingestKeys),
    };
  } catch {
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  }
}
function read(file) {
  return readPrivateJsonWithDigest(
    file,
    "m4_cross_phase_identity_traversal_operator_reference_invalid",
    { maxBytes: 1024 * 1024 },
  );
}
function preparedInput(input = {}) {
  let request;
  try {
    request = clone(
      input,
      "m4_cross_phase_identity_traversal_operator_input_invalid",
    );
  } catch {
    fail("m4_cross_phase_identity_traversal_operator_input_invalid");
  }
  if (!exact(request, ["configPath"]))
    fail("m4_cross_phase_identity_traversal_operator_input_invalid");
  absolute(
    request.configPath,
    "m4_cross_phase_identity_traversal_operator_input_invalid",
  );
  const configLoaded = readPrivateJsonWithDigest(
    request.configPath,
    "m4_cross_phase_identity_traversal_operator_config_invalid",
    { maxBytes: 1024 * 1024 },
  );
  const config = configShape(configLoaded.value);
  const references = [["config", configLoaded.digest]];
  const fabricLoaded = read(config.fabricConfigPath);
  references.push(["fabric", fabricLoaded.digest]);
  const fabric = normalizeFabric(fabricShape(fabricLoaded.value), references);
  const deliveryLoaded = read(config.deliveryKeyRingPath);
  const delivery = deliveryShape(deliveryLoaded.value);
  references.push(["delivery", deliveryLoaded.digest]);
  const archive = read(config.archiveCompletionPath),
    archiveKey = read(config.archiveCompletionKeyPath),
    baseline = read(config.catalogBaselinePath),
    catalogKey = read(config.catalogAttestationKeyPath),
    traversalKey = read(config.traversalCompletionKeyPath),
    registryKey = read(config.registryKeyPath);
  for (const [role, item] of [
    ["archive-completion", archive],
    ["archive-key", archiveKey],
    ["catalog-baseline", baseline],
    ["catalog-key", catalogKey],
    ["traversal-key", traversalKey],
    ["registry-key", registryKey],
  ])
    references.push([role, item.digest]);
  let archiveSigning, catalogSigning, traversalSigning, registrySigning;
  try {
    archiveSigning = key(
      archiveKey.value,
      "m4_cross_phase_identity_traversal_operator_reference_invalid",
    );
    catalogSigning = key(
      catalogKey.value,
      "m4_cross_phase_identity_traversal_operator_reference_invalid",
    );
    traversalSigning = key(
      traversalKey.value,
      "m4_cross_phase_identity_traversal_operator_reference_invalid",
    );
    registrySigning = key(
      registryKey.value,
      "m4_cross_phase_identity_traversal_operator_reference_invalid",
      32,
    );
    independent(
      [archiveSigning, catalogSigning, traversalSigning, registrySigning],
      "m4_cross_phase_identity_traversal_operator_key_separation_invalid",
    );
    archiveSigning = catalogSigning = traversalSigning = registrySigning = null;
    const safeArchive = verifyM4V2ArchiveBackfillCompletion(
      archive.value,
      archiveKey.value,
    );
    const safeBaseline = verifyM4V2CatalogRevisionAttestation(
      baseline.value,
      catalogKey.value,
    );
    if (
      safeBaseline.traversal.groupCount < 1 ||
      safeBaseline.traversal.coveredThrough === null
    )
      fail("m4_cross_phase_identity_traversal_operator_baseline_invalid");
    deriveM4V2ArchiveRegistryBinding(
      safeArchive,
      archiveKey.value,
      safeBaseline,
      catalogKey.value,
    );
    references.sort(
      (a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]),
    );
    const runId = `m4-${crypto
      .createHash("sha256")
      .update(
        canonicalJson([
          "amf.m4-cross-phase-identity-traversal-operator/run-id/v1",
          config.manifestId,
          config.revision,
          digest(safeArchive),
          digest(safeBaseline),
        ]),
        "utf8",
      )
      .digest("hex")}`;
    const selection = {
      artifactRoot: config.artifactRoot,
      fabricRoot: fabric.rootPath,
      dataPath: fabric.env.AMF_DATA_PATH,
      catalogTarget:
        fabric.env.AMF_CATALOG_KIND === "sqlite"
          ? fabric.env.AMF_CATALOG_PATH
          : fabric.env.AMF_CATALOG_DATABASE_URL,
      leasePath: config.leasePath,
      traversalStateRoot: config.traversalStateRoot,
      spoolRoot: config.spoolRoot,
    };
    const confirmationDigest = digest({
      schema: "amf.m4-cross-phase-identity-traversal-operator-plan-binding/v1",
      configDigest: configLoaded.digest,
      referenceDigests: references,
      runId,
      manifestId: config.manifestId,
      revision: config.revision,
      resourceSelectionDigest: digest(selection),
    });
    return {
      config,
      fabric,
      delivery,
      archive: safeArchive,
      archiveKey: archiveKey.value,
      baseline: safeBaseline,
      catalogKey: catalogKey.value,
      traversalKey: traversalKey.value,
      registryKey: registryKey.value,
      runId,
      confirmationDigest,
    };
  } catch (error) {
    archiveSigning?.key.fill(0);
    catalogSigning?.key.fill(0);
    traversalSigning?.key.fill(0);
    registrySigning?.key.fill(0);
    if (
      error?.code?.startsWith?.("m4_cross_phase_identity_traversal_operator_")
    )
      throw error;
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  }
}

export async function planM4CrossPhaseIdentityTraversalOperator(input = {}) {
  const prepared = preparedInput(input);
  return Object.freeze({
    schema: "amf.m4-cross-phase-identity-traversal-operator-plan/v1",
    operation: "plan",
    runId: prepared.runId,
    phase: "cross-phase-identity",
    confirmationDigest: prepared.confirmationDigest,
  });
}

function runtimeInput(value) {
  const safe = clone(
    value,
    "m4_cross_phase_identity_traversal_operator_run_input_invalid",
  );
  if (
    !exact(safe, ["configPath", "confirmedPlanDigest"]) ||
    typeof safe.confirmedPlanDigest !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(safe.confirmedPlanDigest)
  )
    fail("m4_cross_phase_identity_traversal_operator_run_input_invalid");
  absolute(
    safe.configPath,
    "m4_cross_phase_identity_traversal_operator_run_input_invalid",
  );
  return safe;
}
function runtimeDependencies(value = {}) {
  const defaults = {
    createFabricStoreFromEnv,
    BackfillLease,
    M4CrossPhaseIdentityTraversalStore,
    createM4CrossPhaseIdentityTraversalSource,
    createM4CrossPhaseIdentityStreamingWriter,
    createM4CrossPhaseIdentityPageStore,
    preflightM4CrossPhaseIdentityStreamingCapacity,
    runM4CrossPhaseIdentityTraversal,
    attestM4V2CatalogRevision,
    verifyM4CrossPhaseIdentityAuthority,
    verifyM4CrossPhaseIdentityTraversalCompletion,
    writePrivateArtifactIdempotent,
    filesystemStats: fs.statfsSync,
  };
  try {
    if (!plain(value) || Object.keys(value).some((name) => !["dependencies", "clock", "nonceFactory"].includes(name)) || (value.clock !== undefined && typeof value.clock !== "function") || (value.nonceFactory !== undefined && typeof value.nonceFactory !== "function")) fail("m4_cross_phase_identity_traversal_operator_options_invalid");
    const supplied = value.dependencies ?? {};
    if (
      !plain(supplied) ||
      Object.keys(supplied).some((name) => !Object.hasOwn(defaults, name))
    )
      fail("m4_cross_phase_identity_traversal_operator_options_invalid");
    const merged = { ...defaults, ...supplied };
    if (Object.values(merged).some((item) => typeof item !== "function"))
      fail("m4_cross_phase_identity_traversal_operator_options_invalid");
    return merged;
  } catch (error) {
    if (
      error?.code ===
      "m4_cross_phase_identity_traversal_operator_options_invalid"
    )
      throw error;
    fail("m4_cross_phase_identity_traversal_operator_options_invalid");
  }
}
function revalidate(prepared) {
  for (const item of [
    prepared.config.leasePath,
    prepared.config.traversalStateRoot,
    prepared.config.spoolRoot,
    prepared.fabric.rootPath,
    prepared.fabric.env.AMF_DATA_PATH,
    ...(prepared.fabric.env.AMF_CATALOG_KIND === "sqlite"
      ? [prepared.fabric.env.AMF_CATALOG_PATH]
      : []),
  ])
    noSymlinks(
      item,
      "m4_cross_phase_identity_traversal_operator_resource_unsafe",
    );
}
function availableBytes(root, statfs) {
  let current = root;
  while (true) {
    noSymlinks(
      current,
      "m4_cross_phase_identity_traversal_operator_resource_unsafe",
    );
    try {
      const stat = fs.lstatSync(current);
      if (!stat.isDirectory())
        fail("m4_cross_phase_identity_traversal_operator_resource_unsafe");
      const result = statfs(current);
      const available = BigInt(result.bavail) * BigInt(result.bsize);
      return Number(
        available > BigInt(Number.MAX_SAFE_INTEGER)
          ? BigInt(Number.MAX_SAFE_INTEGER)
          : available,
      );
    } catch (error) {
      if (error?.code === "ENOENT") {
        const parent = path.dirname(current);
        if (parent === current)
          fail("m4_cross_phase_identity_traversal_operator_resource_unsafe");
        current = parent;
        continue;
      }
      if (
        error?.code?.startsWith?.("m4_cross_phase_identity_traversal_operator_")
      )
        throw error;
      fail("m4_cross_phase_identity_traversal_operator_resource_unsafe");
    }
  }
}
function databasePath(prepared) {
  return path.join(
    prepared.config.spoolRoot,
    `${crypto
      .createHash("sha256")
      .update(
        canonicalJson([
          "amf.m4-cross-phase-identity-traversal-operator/spool/v1",
          prepared.runId,
          prepared.confirmationDigest,
          digest(prepared.baseline),
        ]),
        "utf8",
      )
      .digest("hex")}.sqlite`,
  );
}
function utcNow(clock) {
  const value = clock();
  if (!(value instanceof Date) || Number.isNaN(value.getTime()))
    fail("m4_cross_phase_identity_traversal_operator_clock_invalid");
  return value.toISOString();
}
export async function runM4CrossPhaseIdentityTraversalOperator(
  input = {},
  options = {},
) {
  const request = runtimeInput(input);
  const dependencies = runtimeDependencies(options);
  let prepared;
  try {
    prepared = preparedInput({ configPath: request.configPath });
  } catch (error) {
    if (
      error?.code?.startsWith?.("m4_cross_phase_identity_traversal_operator_")
    )
      throw error;
    fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
  }
  if (prepared.confirmationDigest !== request.confirmedPlanDigest)
    fail("m4_cross_phase_identity_traversal_operator_confirmation_invalid");
  revalidate(prepared);
  let fabric = null,
    store = null,
    pageStore = null;
  let registrySecret = null;
  const deliveryBuffers = [];
  let primary = null;
  try {
    registrySecret = Buffer.from(prepared.registryKey.key, "base64");
    if (registrySecret.length !== 32)
      fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
    const ensureFabric = () => {
      if (fabric === null) {
        fabric = dependencies.createFabricStoreFromEnv({ rootPath: prepared.fabric.rootPath, env: prepared.fabric.env });
        if (!fabric?.catalog || !fabric?.rawStore || typeof fabric.audit !== "function" || typeof fabric.close !== "function") fail("m4_cross_phase_identity_traversal_operator_dependency_invalid");
      }
      return fabric;
    };
    const ensureStore = () => {
      if (store === null) store = new dependencies.M4CrossPhaseIdentityTraversalStore({ rootPath: prepared.config.traversalStateRoot, runId: prepared.runId, planDigest: prepared.confirmationDigest, catalogBaselineDigest: digest(prepared.baseline) });
      return store;
    };
    const catalog = { listM4V2LogicalGroups: (...args) => ensureFabric().catalog.listM4V2LogicalGroups(...args) };
    const rawStore = {
      getClientCiphertext: (...args) => ensureFabric().rawStore.getClientCiphertext(...args),
      opaqueTags: (...args) => ensureFabric().rawStore.opaqueTags(...args),
    };
    const traversalStore = {
      load: (...args) => ensureStore().load(...args),
      commit: (...args) => ensureStore().commit(...args),
      commitExcludedBatch: (...args) => ensureStore().commitExcludedBatch(...args),
      complete: (...args) => ensureStore().complete(...args),
    };
    const lease = new dependencies.BackfillLease({
      leasePath: prepared.config.leasePath,
    });
    const currentDelivery = Buffer.from(
      prepared.delivery.keys[prepared.delivery.currentKeyId],
      "base64",
    );
    deliveryBuffers.push(currentDelivery);
    if (currentDelivery.length !== 32)
      fail("m4_cross_phase_identity_traversal_operator_reference_invalid");
    const clock = options.clock ?? (() => new Date());
    const nonceFactory =
      options.nonceFactory ??
      (() => crypto.randomBytes(18).toString("base64url"));
    const source = dependencies.createM4CrossPhaseIdentityTraversalSource({
      catalog,
      rawStore,
      ingestKeys: prepared.fabric.ingestKeys,
      verifyCatalogBinding: async (value) => ({
        owner: rawStore
          .opaqueTags("raw-owner", value.actorId)
          .includes(value.ownerTag),
        source: rawStore
          .opaqueTags("raw-source", value.sourceInstanceId)
          .includes(value.sourceTag),
      }),
      auditDecrypt: async (value) => {
        await ensureFabric().audit({
          actor: "m4-cross-phase-identity-traversal",
          action: "raw_redacted_decrypt_intent",
          outcome: "authorized",
          targetId: value.eventId,
          details: { transport: "m4-cross-phase-identity-traversal" },
        });
        return {
          recorded: true,
          eventId: value.eventId,
          contentId: value.contentId,
        };
      },
      integrityFor: async () => ({
        keyId: prepared.delivery.currentKeyId,
        key: currentDelivery,
        sentAt: utcNow(clock),
        nonce: nonceFactory(),
      }),
      catalogBaseline: prepared.baseline,
      catalogKeyDocument: prepared.catalogKey,
      runId: prepared.runId,
      planDigest: prepared.confirmationDigest,
      pageLimit: prepared.baseline.traversal.pageLimit,
    });
    const catalogAttestor = async () =>
      dependencies.attestM4V2CatalogRevision({
        catalog,
        keyDocument: prepared.catalogKey,
        pageLimit: prepared.baseline.traversal.pageLimit,
      });
    const spool = databasePath(prepared);
    const createWriter = async ({ expectedBlockCount, firstBlock }) => {
      if (pageStore !== null) fail("m4_cross_phase_identity_traversal_operator_writer_reused");
      const capacity = {
        availableBytes: availableBytes(prepared.config.spoolRoot, dependencies.filesystemStats),
        sampleBlocks: [firstBlock], expectedBlockCount,
      };
      dependencies.preflightM4CrossPhaseIdentityStreamingCapacity(capacity);
      pageStore = dependencies.createM4CrossPhaseIdentityPageStore({ artifactRoot: prepared.config.artifactRoot, manifestId: prepared.config.manifestId, revision: prepared.config.revision });
      const writer = dependencies.createM4CrossPhaseIdentityStreamingWriter({
        databasePath: spool,
        registrySecret,
        registryKeyId: prepared.registryKey.keyId,
        capacityPreflight: capacity,
        pageSink: { writePage: (page) => pageStore.writePage(page) },
      });
      return { writer, databasePath: spool };
    };
    const publish = async (value) => {
      const safe = clone(value, "m4_cross_phase_identity_traversal_operator_publication_invalid");
      if (!exact(safe, ["traversalCompletion", "registry", "coverage"]) || !exact(safe.registry, ["authority", "coverage"]) || !exact(safe.registry.coverage, ["acceptedBlockCount", "sessionCount", "eventCount", "pageCount"]) || !exact(safe.coverage, ["schema", "state", "expectedBlockCount", "blockCount", "sessionCount", "eventCount"])) fail("m4_cross_phase_identity_traversal_operator_publication_invalid");
      const completion =
        dependencies.verifyM4CrossPhaseIdentityTraversalCompletion(
          safe.traversalCompletion,
          prepared.traversalKey,
        );
      if (
        completion.manifestId !== prepared.config.manifestId ||
        completion.revision !== prepared.config.revision ||
        completion.catalogBaselineDigest !== digest(prepared.baseline) ||
        canonicalJson(completion.archiveBinding) !==
          canonicalJson(
            deriveM4V2ArchiveRegistryBinding(
              prepared.archive,
              prepared.archiveKey,
              prepared.baseline,
              prepared.catalogKey,
            ),
          )
      )
        fail("m4_cross_phase_identity_traversal_operator_publication_invalid");
      const authority = dependencies.verifyM4CrossPhaseIdentityAuthority(
        safe.registry.authority,
        registrySecret,
      );
      const registryCoverage = safe.registry.coverage;
      if (registryCoverage.sessionCount !== authority.coverage.sessionCount || registryCoverage.eventCount !== authority.coverage.eventCount || registryCoverage.pageCount !== authority.pages.length || registryCoverage.acceptedBlockCount !== completion.traversalRecord.acceptedGroupCount || registryCoverage.acceptedBlockCount !== safe.coverage.blockCount || canonicalJson(safe.coverage) !== canonicalJson(completion.coverage)) fail("m4_cross_phase_identity_traversal_operator_publication_invalid");
      if (safe.coverage.blockCount === 0) {
        if (
          pageStore !== null ||
          authority.pages.length !== 0 ||
          authority.coverage.sessionCount !== 0 ||
          authority.coverage.eventCount !== 0
        )
          fail(
            "m4_cross_phase_identity_traversal_operator_publication_invalid",
          );
      } else {
        if (pageStore === null)
          fail(
            "m4_cross_phase_identity_traversal_operator_publication_invalid",
          );
        for (const descriptor of authority.pages)
          pageStore.verifyPage({ pageKey: descriptor.pageKey, digest: descriptor.digest });
      }
      const publication = {
        schema: "amf.m4-cross-phase-identity-publication/v1",
        state: "published",
        manifestId: prepared.config.manifestId,
        revision: prepared.config.revision,
        traversalCompletion: completion,
        registry: { authority, coverage: registryCoverage },
      };
      dependencies.writePrivateArtifactIdempotent(
        prepared.config.artifactRoot,
        "cross-phase-identity",
        prepared.config.manifestId,
        prepared.config.revision,
        publication,
      );
      return {
        state: "published",
        artifactDigest: canonicalDigest(publication),
      };
    };
    const output = await dependencies.runM4CrossPhaseIdentityTraversal({
      source,
      traversalStore,
      lease,
      runId: prepared.runId,
      planDigest: prepared.confirmationDigest,
      catalogBaseline: prepared.baseline,
      catalogKeyDocument: prepared.catalogKey,
      archiveCompletion: prepared.archive,
      archiveCompletionKeyDocument: prepared.archiveKey,
      completionKeyDocument: prepared.traversalKey,
      registryKeyDocument: prepared.registryKey,
      manifestId: prepared.config.manifestId,
      revision: prepared.config.revision,
      registrySecret,
      registryKeyId: prepared.registryKey.keyId,
      createWriter,
      catalogAttestor,
      publish,
    });
    return Object.freeze({
      schema: "amf.m4-cross-phase-identity-traversal-operator-result/v1",
      operation: "run",
      runId: prepared.runId,
      phase: "cross-phase-identity",
      publication: output.publication,
    });
  } catch (error) {
    primary = error;
    if (error?.code?.startsWith?.("m4_cross_phase_identity_")) throw error;
    fail("m4_cross_phase_identity_traversal_operator_runtime_failed");
  } finally {
    registrySecret?.fill(0);
    for (const item of deliveryBuffers) item.fill(0);
    let cleanupFailed = false;
    try { pageStore?.close(); } catch { cleanupFailed = true; }
    try { store?.close(); } catch { cleanupFailed = true; }
    try { await fabric?.close?.(); } catch { cleanupFailed = true; }
    if (primary === null && cleanupFailed) fail("m4_cross_phase_identity_traversal_operator_cleanup_failed");
  }
}
