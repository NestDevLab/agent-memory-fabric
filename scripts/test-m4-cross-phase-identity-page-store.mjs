import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createM4CrossPhaseIdentityPage } from "../src/migration/m4-cross-phase-identity-registry.mjs";
import { deriveM4V3ConversationIdFromLegacySessionId } from "../src/migration/m4-v2-conversation-projector.mjs";
import { createM4CrossPhaseIdentityPageStore } from "../src/operator/m4-cross-phase-identity-page-store.mjs";
import { writePrivateArtifactIdempotent } from "../src/operator/private-artifacts.mjs";
const hash = (v) => crypto.createHash("sha256").update(v).digest("hex");
const root = () => fs.mkdtempSync(path.join(os.tmpdir(), "amf-page-store-"));
function page() {
  const legacySessionId = `ses_${hash("session")}`;
  return createM4CrossPhaseIdentityPage({
    bucket: legacySessionId.slice(4, 6),
    entryKind: "session",
    shard: 0,
    entries: [
      {
        legacySessionId,
        conversationId:
          deriveM4V3ConversationIdFromLegacySessionId(legacySessionId),
        conversationKind: "dm",
        sessionContextTags: {
          conversation: [`hmac-sha256:test:${hash("c")}`],
          room: [`hmac-sha256:test:${hash("r")}`],
        },
      },
    ],
  });
}
test("writes immutable pages, retries identical bytes, and closes pinned namespace", async () => {
  const artifactRoot = root();
  try {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    const value = page();
    assert.deepEqual(await store.writePage(value), {
      pageKey: value.pageKey,
      digest: value.digest,
    });
    assert.deepEqual(await store.writePage(value), {
      pageKey: value.pageKey,
      digest: value.digest,
    });
    assert.deepEqual(store.describe(), {
      schema: "amf.m4-cross-phase-identity-page-store/v1",
      manifestId: "page-fixture",
      revision: 1,
    });
    store.close();
    store.close();
    await assert.rejects(() => store.writePage(value), {
      code: "m4_cross_phase_identity_page_store_closed",
    });
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});
test("rejects conflict and idempotently writes a private root artifact", async () => {
  const artifactRoot = root();
  try {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    const value = page();
    await store.writePage(value);
    const altered = { ...value, digest: `sha256:${"f".repeat(64)}` };
    await assert.rejects(() => store.writePage(altered), {
      code: "m4_cross_phase_identity_page_store_page_invalid",
    });
    const target = writePrivateArtifactIdempotent(
      artifactRoot,
      "cross-phase-identity",
      "page-fixture",
      1,
      { state: "published" },
    );
    assert.equal(
      writePrivateArtifactIdempotent(
        artifactRoot,
        "cross-phase-identity",
        "page-fixture",
        1,
        { state: "published" },
      ),
      target,
    );
    assert.throws(
      () =>
        writePrivateArtifactIdempotent(
          artifactRoot,
          "cross-phase-identity",
          "page-fixture",
          1,
          { state: "other" },
        ),
      { code: "private_artifact_conflict" },
    );
    store.close();
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test("rejects a different valid page with the same page key", async () => {
  const artifactRoot = root();
  try {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    const first = page();
    await store.writePage(first);
    let second;
    for (let index = 0; index < 2000; index += 1) {
      const id = `ses_${hash(`other:${index}`)}`;
      if (id.slice(4, 6) !== first.bucket) continue;
      second = createM4CrossPhaseIdentityPage({
        bucket: first.bucket,
        entryKind: "session",
        shard: 0,
        entries: [
          {
            legacySessionId: id,
            conversationId: deriveM4V3ConversationIdFromLegacySessionId(id),
            conversationKind: "dm",
            sessionContextTags: {
              conversation: [`hmac-sha256:test:${hash("c2")}`],
              room: [`hmac-sha256:test:${hash("r2")}`],
            },
          },
        ],
      });
      break;
    }
    assert.ok(second);
    await assert.rejects(() => store.writePage(second), {
      code: "m4_cross_phase_identity_page_store_conflict",
    });
    store.close();
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test("rejects unsafe roots, aliases, manifests, revisions, and namespace modes", () => {
  const artifactRoot = root();
  try {
    fs.chmodSync(artifactRoot, 0o755);
    assert.throws(
      () =>
        createM4CrossPhaseIdentityPageStore({
          artifactRoot,
          manifestId: "page-fixture",
          revision: 1,
        }),
      { code: "m4_cross_phase_identity_page_store_input_invalid" },
    );
    fs.chmodSync(artifactRoot, 0o700);
    assert.throws(
      () =>
        createM4CrossPhaseIdentityPageStore({
          artifactRoot: `${artifactRoot}/..`,
          manifestId: "page-fixture",
          revision: 1,
        }),
      { code: "m4_cross_phase_identity_page_store_input_invalid" },
    );
    assert.throws(
      () =>
        createM4CrossPhaseIdentityPageStore({
          artifactRoot,
          manifestId: "BAD",
          revision: 1,
        }),
      { code: "m4_cross_phase_identity_page_store_input_invalid" },
    );
    assert.throws(
      () =>
        createM4CrossPhaseIdentityPageStore({
          artifactRoot,
          manifestId: "page-fixture",
          revision: 0,
        }),
      { code: "m4_cross_phase_identity_page_store_input_invalid" },
    );
    fs.mkdirSync(path.join(artifactRoot, "m4"), { mode: 0o755 });
    fs.chmodSync(path.join(artifactRoot, "m4"), 0o755);
    assert.throws(
      () =>
        createM4CrossPhaseIdentityPageStore({
          artifactRoot,
          manifestId: "page-fixture",
          revision: 1,
        }),
      { code: "m4_cross_phase_identity_page_store_unsafe" },
    );
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test("rejects namespace and target symlink substitution without redirecting a pinned store", async () => {
  const artifactRoot = root();
  const outside = root();
  try {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    const namespace = path.join(
      artifactRoot,
      "m4",
      "cross-phase-identity-pages",
      "page-fixture-r1",
    );
    const moved = `${namespace}-moved`;
    fs.renameSync(namespace, moved);
    fs.symlinkSync(outside, namespace);
    const value = page();
    await store.writePage(value);
    assert.equal(fs.readdirSync(outside).length, 0);
    const target = fs.readdirSync(moved).find((name) => name.endsWith(".json"));
    fs.unlinkSync(path.join(moved, target));
    fs.symlinkSync(path.join(outside, "leaf"), path.join(moved, target));
    await assert.rejects(() => store.writePage(value), {
      code: "m4_cross_phase_identity_page_store_existing_invalid",
    });
    store.close();
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("creates exact private modes and rejects corrupt or permissive existing leaves", async () => {
  const artifactRoot = root();
  try {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    const value = page();
    await store.writePage(value);
    const namespace = path.join(
      artifactRoot,
      "m4",
      "cross-phase-identity-pages",
      "page-fixture-r1",
    );
    const leaf = fs
      .readdirSync(namespace)
      .find((name) => name.endsWith(".json"));
    assert.equal(fs.statSync(namespace).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(namespace, leaf)).mode & 0o777, 0o600);
    fs.chmodSync(path.join(namespace, leaf), 0o640);
    await assert.rejects(() => store.writePage(value), {
      code: "m4_cross_phase_identity_page_store_existing_invalid",
    });
    store.close();
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test("root artifact normalizes hostile values and rejects symlink targets", () => {
  const artifactRoot = root();
  try {
    assert.throws(
      () =>
        writePrivateArtifactIdempotent(
          artifactRoot,
          "cross-phase-identity",
          "page-fixture",
          1,
          {
            get state() {
              throw new Error("private");
            },
          },
        ),
      { code: "private_artifact_value_invalid" },
    );
    assert.throws(
      () =>
        writePrivateArtifactIdempotent(
          artifactRoot,
          "cross-phase-identity",
          "page-fixture",
          1,
          { state: 1n },
        ),
      { code: "private_artifact_value_invalid" },
    );
    const stage = path.join(artifactRoot, "m4", "cross-phase-identity");
    fs.mkdirSync(path.join(artifactRoot, "m4"), { mode: 0o700 });
    fs.mkdirSync(stage, { mode: 0o700 });
    fs.symlinkSync("/tmp", path.join(stage, "page-fixture-r1.json"));
    assert.throws(
      () =>
        writePrivateArtifactIdempotent(
          artifactRoot,
          "cross-phase-identity",
          "page-fixture",
          1,
          { state: "published" },
        ),
      { code: "private_artifact_existing_invalid" },
    );
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test("reopens and verifies exactly the durable descriptor without exposing page content", async () => {
  const artifactRoot = root();
  try {
    const value = page();
    let store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    await store.writePage(value);
    assert.deepEqual(
      store.verifyPage({ pageKey: value.pageKey, digest: value.digest }),
      { pageKey: value.pageKey, digest: value.digest },
    );
    assert.throws(
      () =>
        store.verifyPage({
          pageKey: value.pageKey,
          digest: `sha256:${"a".repeat(64)}`,
        }),
      { code: "m4_cross_phase_identity_page_store_existing_invalid" },
    );
    store.close();
    store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: "page-fixture",
      revision: 1,
    });
    assert.deepEqual(
      store.verifyPage({ pageKey: value.pageKey, digest: value.digest }),
      { pageKey: value.pageKey, digest: value.digest },
    );
    assert.throws(
      () => store.verifyPage({ pageKey: "missing", digest: value.digest }),
      { code: "m4_cross_phase_identity_page_store_existing_invalid" },
    );
    store.close();
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});
