import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { SqliteConversationArchive } from '../src/conversation-archive-v1.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import { canonicalJson } from '../src/ingest/transcripts/canonical.mjs';
import { aggregatePauseCheckpointInputs, createPauseManifest } from '../src/migration-pause.mjs';
import { createM4RollbackManifest, verifyM4BackfillGate } from '../src/migration/m4-backfill-gate.mjs';
import {
  createM4NativePausedShardCatalog,
  deriveM4NativePausedPhaseRunId,
  planM4NativePausedPhase,
  runM4NativePausedPhase,
  verifyM4NativePausedPhaseCompletion,
  verifyM4NativePausedShardCatalog,
} from '../src/migration/m4-native-paused-phase-orchestrator.mjs';
import { M4NativePausedPhaseStore } from '../src/migration/m4-native-paused-phase-store.mjs';
import { M4ProgressStore } from '../src/migration/m4-progress-store.mjs';

const EVENT_KEY = Buffer.alloc(32, 7);
const DERIVATION_KEY = Buffer.alloc(32, 3);
const CATALOG_KEY = keyDocument('native-catalog-key', 12);
const RECEIPT_KEY = keyDocument('native-receipt-key', 14);
const COMPLETION_KEY = keyDocument('native-phase-completion-key', 13);

function digest(value) {
  return `sha256:${crypto.createHash('sha256').update(String(value)).digest('hex')}`;
}

function canonicalDigest(value) {
  return `sha256:${crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

function signatureFor(keyValue, domain, valueDigest) {
  return crypto.createHmac('sha256', Buffer.from(keyValue.key, 'base64'))
    .update(canonicalJson([domain, valueDigest, keyValue.keyId]), 'utf8').digest('base64url');
}

function checkpoint(id, value = id) {
  return { id, digest: digest(value) };
}

function keyDocument(keyId, byte) {
  return { schema: 'amf.migration-signing-key/v1', keyId,
    key: Buffer.alloc(32, byte).toString('base64') };
}

function gateFixture() {
  const pauseKey = keyDocument('native-pause-key', 10);
  const rollbackKey = keyDocument('native-rollback-key', 11);
  const collector = `pause-collector-${'1'.repeat(64)}`;
  const pauseInput = {
    schema: 'amf.migration-pause-checkpoints/v1',
    manifestId: 'pause-manifest-native',
    revision: 1,
    keyId: pauseKey.keyId,
    pause: {
      state: 'paused',
      collectorCursor: checkpoint('collector-cursor-native'),
      pendingOutbox: checkpoint('pending-outbox-native'),
      acknowledgements: checkpoint('acknowledgements-native'),
      deadLetters: checkpoint('dead-letters-native'),
      sourceCheckpoint: checkpoint('source-checkpoint-native'),
      nativeTranscriptAuthority: checkpoint('native-authority-native'),
      evidence: checkpoint(collector),
    },
  };
  const roster = {
    schema: 'amf.migration-pause-collector-roster/v1',
    manifestId: pauseInput.manifestId,
    revision: pauseInput.revision,
    keyId: pauseKey.keyId,
    collectors: [collector],
  };
  const pauseManifest = createPauseManifest(aggregatePauseCheckpointInputs([pauseInput], roster), pauseKey);
  const rollbackManifest = createM4RollbackManifest({
    schema: 'amf.migration-manifest/v1',
    manifestId: 'rollback-manifest-native',
    phase: 'rollback',
    revision: 1,
    rollback: {
      pauseEvidence: {
        manifestId: pauseManifest.manifestId,
        digest: pauseManifest.integrity.payloadDigest,
        signature: pauseManifest.integrity.signature,
      },
      sourceCheckpoint: pauseManifest.pause.sourceCheckpoint,
      targetCheckpoint: checkpoint('target-checkpoint-native'),
      compatibilityRouteRevision: 'compatibility-route-native',
      recoveryCopy: checkpoint('recovery-copy-native'),
      restoreTest: 'passed',
    },
  }, rollbackKey);
  return { pauseManifest, pauseKeyDocument: pauseKey, rollbackManifest,
    rollbackKeyDocument: rollbackKey };
}

function gateTemplate(gateFiles) {
  return {
    pauseManifest: gateFiles.pauseManifest,
    pauseKeyDocument: gateFiles.pauseKeyDocument,
    rollbackManifest: gateFiles.rollbackManifest,
    rollbackKeyDocument: gateFiles.rollbackKeyDocument,
  };
}

function sourceBinding(runtime = 'codex', sourceId = 'source-one') {
  return `hmac-sha256:source-v1:${crypto.createHmac('sha256', DERIVATION_KEY)
    .update(canonicalJson(['amf.m4-native-paused/tag/source-v1/v1', runtime, sourceId]), 'utf8')
    .digest('hex')}`;
}

function authorityFor(gateFiles, startExclusive, endInclusive, options = {}) {
  const temporaryGate = verifyM4BackfillGate({
    runId: 'temporary-native-run',
    phase: 'paused-native',
    ...gateFiles,
  });
  return {
    schema: 'amf.m4-native-paused-interval-authority/v1',
    pauseEvidence: temporaryGate.pauseEvidence,
    source: gateFiles.pauseManifest.pause.nativeTranscriptAuthority,
    sourceBinding: options.sourceBinding ?? sourceBinding(),
    interval: {
      startExclusive,
      endInclusive,
      chain: checkpoint(options.chainId ?? `native-chain-${endInclusive}`),
    },
    initialCheckpoint: temporaryGate.sourceCheckpoint,
  };
}

function legacyCompletion(value = 'one') {
  return {
    schema: 'amf.m4-legacy-group-replay-completion/v1',
    state: 'complete',
    authorityDigest: digest(`legacy-authority-${value}`),
    checkpoint: checkpoint(`legacy-checkpoint-${value}`),
    evidence: {
      manifestId: `legacy-manifest-${value}`,
      digest: digest(`legacy-evidence-${value}`),
      signature: Buffer.alloc(32, value.charCodeAt(0)).toString('base64url'),
    },
  };
}

function catalogFor(authorities, maxEvents = 1) {
  const first = authorities[0];
  return createM4NativePausedShardCatalog({
    pauseEvidence: first.pauseEvidence,
    source: first.source,
    initialCheckpoint: first.initialCheckpoint,
    shards: authorities.map((item, ordinal) => ({ ordinal, authority: item, maxEvents })),
    keyDocument: CATALOG_KEY,
  });
}

function serialInput(gateFiles, catalog, completion, overrides = {}) {
  return {
    gateInput: gateTemplate(gateFiles),
    catalog,
    catalogKey: CATALOG_KEY,
    legacyCompletion: completion,
    maxCallsPerInvocationPerShard: overrides.maxCallsPerInvocationPerShard ?? 4,
    maxCallsPerInvocationTotal: overrides.maxCallsPerInvocationTotal ?? 8,
    receiptKeyId: RECEIPT_KEY.keyId,
    completionManifestId: 'native-phase-completion',
    completionKeyId: COMPLETION_KEY.keyId,
  };
}

function nativeReader(authorityValue) {
  const records = Array.from({
    length: authorityValue.interval.endInclusive - authorityValue.interval.startExclusive,
  }, (_, index) => {
    const position = authorityValue.interval.startExclusive + index + 1;
    const timestamp = `2026-07-22T00:00:${String(position).padStart(2, '0')}Z`;
    const messageId = `message-${position}`;
    return {
      native: {
        runtime: 'codex',
        sourceId: 'source-one',
        conversationId: 'session-one',
        threadId: null,
        messageId,
        position,
        sourceOccurredAt: timestamp,
      },
      sessionHint: 'session-one',
      value: {
        type: 'response_item',
        session_id: 'session-one',
        id: messageId,
        timestamp,
        payload: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: `synthetic message ${position}` }],
        },
      },
    };
  });
  return {
    async open(input) {
      assert.deepEqual(input, {
        schema: authorityValue.schema,
        source: authorityValue.source,
        interval: authorityValue.interval,
      });
      return {
        schema: 'amf.m4-native-paused-reader/v1',
        source: authorityValue.source,
        interval: authorityValue.interval,
        runtime: 'codex',
        sourceId: 'source-one',
        records: (async function* iterate() { yield* records; }()),
        completion: async () => ({
          schema: 'amf.m4-native-paused-completion/v1',
          source: authorityValue.source,
          endInclusive: authorityValue.interval.endInclusive,
          chain: authorityValue.interval.chain,
        }),
      };
    },
  };
}

function pauseVerifier(authorityValue) {
  return async () => ({
    pauseEvidence: authorityValue.pauseEvidence,
    nativeTranscriptAuthority: authorityValue.source,
    sourceCheckpoint: authorityValue.initialCheckpoint,
  });
}

function batchFactories(root, calls, ordinal) {
  return {
    lease: async () => {
      calls.push(`lease-${ordinal}`);
      return { async acquire() {}, async heartbeat() {}, async release() {} };
    },
    outbox: async () => {
      calls.push(`outbox-${ordinal}`);
      return new ConversationEventPlaintextOutbox({
        rootPath: path.join(root, 'outbox'),
        resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
        clock: () => Date.parse('2026-07-22T00:01:00Z'),
        nonceFactory: () => `deliverynonce${String(ordinal).padStart(6, '0')}`,
      });
    },
    archive: async () => {
      calls.push(`archive-${ordinal}`);
      return {
        archive: new SqliteConversationArchive({
          filename: path.join(root, 'archive.sqlite'),
          resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
          resolveExpiresAt: () => '2027-07-22T00:00:00Z',
          cursorKey: Buffer.alloc(32, 4),
        }),
        resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      };
    },
    checkpointStore: async input => {
      calls.push(`checkpoint-${ordinal}`);
      return new M4ProgressStore({
        rootPath: path.join(root, 'progress'),
        runId: input.runId,
        phase: input.phase,
        planDigest: input.planDigest,
      });
    },
  };
}

function shardRuntime(gateFiles, authorityValue, completion, root, calls, ordinal, overrides = {}) {
  return {
    gateInput: {
      runId: overrides.runId,
      phase: 'paused-native',
      ...gateFiles,
    },
    reader: nativeReader(authorityValue),
    derivationKey: DERIVATION_KEY,
    derivationKeyId: 'native-test-k1',
    verifyPauseEvidence: overrides.verifyPauseEvidence ?? pauseVerifier(authorityValue),
    verifyLegacyCompletion: async () => completion,
    integrityFor: async () => ({
      keyId: 'event-k1',
      key: EVENT_KEY,
      sentAt: '2026-07-22T00:00:30Z',
      nonce: `eventnonce${String(ordinal).padStart(7, '0')}`,
    }),
    factories: batchFactories(root, calls, ordinal),
  };
}

function phaseFactories({ gateFiles, catalog, completion, root, calls, storeFactory, completionClose,
  shardOverrides, leaseState = { held: false } } = {}) {
  return {
    receiptKey: async () => {
      calls.push('receipt-key');
      return { value: RECEIPT_KEY, close: null };
    },
    phaseLease: async () => ({
      value: {
        async acquire() {
          calls.push('phase-lease-acquire');
          if (leaseState.held) throw new Error('held');
          leaseState.held = true;
        },
        async heartbeat() {
          calls.push('phase-lease-heartbeat');
          if (!leaseState.held) throw new Error('not held');
        },
        async release() {
          calls.push('phase-lease-release');
          if (!leaseState.held) throw new Error('not held');
          leaseState.held = false;
        },
      },
      close: null,
    }),
    phaseStore: async context => {
      calls.push('phase-store');
      if (storeFactory) return storeFactory(context);
      const store = new M4NativePausedPhaseStore({ rootPath: path.join(root, 'phase'), ...context });
      return { value: store, close: async () => store.close() };
    },
    shard: async context => {
      calls.push(`shard-${context.ordinal}`);
      const authorityValue = catalog.shards[context.ordinal].authority;
      return {
        value: shardRuntime(gateFiles, authorityValue, completion, root, calls, context.ordinal, {
          runId: context.runId,
          ...shardOverrides?.(context, authorityValue),
        }),
        close: async () => calls.push(`shard-close-${context.ordinal}`),
      };
    },
    completionKey: async () => {
      calls.push('completion-key');
      return { value: COMPLETION_KEY, close: completionClose ?? null };
    },
  };
}

async function setup(options = {}) {
  const gateFiles = gateFixture();
  const authorities = options.authorities ?? [
    authorityFor(gateFiles, 0, 2, { chainId: 'native-chain-first' }),
    authorityFor(gateFiles, 2, 3, { chainId: 'native-chain-second' }),
  ];
  const catalog = catalogFor(authorities, options.maxEvents ?? 1);
  const completion = legacyCompletion();
  const serial = serialInput(gateFiles, catalog, completion, options);
  const plan = await planM4NativePausedPhase(serial);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-native-phase-run-'));
  const calls = [];
  const runtime = {
    ...serial,
    confirmedPlanDigest: plan.confirmationDigest,
    verifyCurrentCatalog: async () => catalog,
    verifyLegacyCompletion: async () => completion,
    factories: phaseFactories({ gateFiles, catalog, completion, root, calls }),
  };
  return { gateFiles, authorities, catalog, completion, serial, plan, root, calls, runtime };
}

function cleanup(value) {
  fs.rmSync(value.root, { recursive: true, force: true });
}

test('plans internally and completes two real shards in strict durable order', async () => {
  const value = await setup();
  try {
    assert.match(value.plan.runId, /^m4-phase-[a-f0-9]{64}$/);
    assert.equal(value.plan.runId.length <= 79, true);
    assert.equal(value.plan.childPlans.length, 2);
    assert.equal(deriveM4NativePausedPhaseRunId({
      gateEvidenceDigest: value.plan.gateEvidenceDigest,
      catalogDigest: value.plan.catalogDigest,
      legacyCompletionDigest: value.plan.legacyCompletionDigest,
      childPlans: value.plan.childPlans,
      maxCallsPerInvocationPerShard: value.plan.maxCallsPerInvocationPerShard,
      maxCallsPerInvocationTotal: value.plan.maxCallsPerInvocationTotal,
      receiptKeyId: value.plan.receiptKeyId,
      completionManifestId: value.plan.completionManifestId,
      completionKeyId: value.plan.completionKeyId,
    }), value.plan.runId);
    const result = await runM4NativePausedPhase(value.runtime);
    assert.equal(result.complete, true);
    assert.deepEqual(result.receipts.map(item => item.ordinal), [0, 1]);
    assert.deepEqual(verifyM4NativePausedPhaseCompletion(result.completion, COMPLETION_KEY),
      result.completion);
    assert.deepEqual(value.calls.filter(item => item.startsWith('shard-') && !item.includes('close')),
      ['shard-0', 'shard-0', 'shard-1']);
    assert.ok(value.calls.indexOf('shard-close-0') < value.calls.indexOf('shard-1'));
    assert.ok(value.calls.indexOf('completion-key') > value.calls.lastIndexOf('shard-close-1'));
    assert.equal(value.calls.at(-1), 'phase-lease-release');
    assert.equal(fs.readdirSync(path.join(value.root, 'progress')).length, 2);
    const archive = new SqliteConversationArchive({
      filename: path.join(value.root, 'archive.sqlite'),
      resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      resolveExpiresAt: () => '2027-07-22T00:00:00Z',
      cursorKey: Buffer.alloc(32, 4),
    });
    assert.equal(archive.db.prepare('SELECT COUNT(*) AS count FROM conversation_archive_events_v1')
      .get().count, 3);
    archive.close();
    assert.doesNotMatch(JSON.stringify(result), /synthetic message|payload text|private/);
  } finally {
    cleanup(value);
  }
});

test('wrong confirmation reads no runtime getter and current catalog mismatch opens no resource', async () => {
  const value = await setup();
  try {
    const wrong = { ...value.serial, confirmedPlanDigest: digest('wrong') };
    let reads = 0;
    for (const name of ['verifyCurrentCatalog', 'verifyLegacyCompletion', 'factories']) {
      Object.defineProperty(wrong, name, {
        enumerable: true,
        get() { reads += 1; throw new Error('private getter detail'); },
      });
    }
    await assert.rejects(() => runM4NativePausedPhase(wrong), {
      code: 'm4_native_phase_confirmation_invalid',
    });
    assert.equal(reads, 0);

    const altered = createM4NativePausedShardCatalog({
      pauseEvidence: value.catalog.pauseEvidence,
      source: value.catalog.source,
      initialCheckpoint: value.catalog.initialCheckpoint,
      shards: value.catalog.shards.map(item => ({ ...item, maxEvents: 2 })),
      keyDocument: CATALOG_KEY,
    });
    let resources = 0;
    const mismatch = {
      ...value.runtime,
      verifyCurrentCatalog: async () => altered,
      factories: Object.fromEntries(['receiptKey', 'phaseLease', 'phaseStore', 'shard', 'completionKey']
        .map(name => [name, async () => { resources += 1; throw new Error(name); }])),
    };
    await assert.rejects(() => runM4NativePausedPhase(mismatch), {
      code: 'm4_native_phase_catalog_mismatch',
    });
    assert.equal(resources, 0);
  } finally {
    cleanup(value);
  }
});

test('catalog authentication rejects subset, reorder, duplicate, gaps, overlap, reentry, and tamper', async () => {
  const gateFiles = gateFixture();
  const first = authorityFor(gateFiles, 0, 1);
  const second = authorityFor(gateFiles, 1, 2);
  const catalog = catalogFor([first, second]);
  assert.equal(verifyM4NativePausedShardCatalog(catalog, CATALOG_KEY).shards.length, 2);
  const subset = structuredClone(catalog);
  subset.shards.pop();
  await assert.rejects(async () => verifyM4NativePausedShardCatalog(subset, CATALOG_KEY), {
    code: 'm4_native_phase_catalog_digest_mismatch',
  });
  const reordered = structuredClone(catalog);
  reordered.shards.reverse();
  await assert.rejects(async () => verifyM4NativePausedShardCatalog(reordered, CATALOG_KEY), {
    code: 'm4_native_phase_catalog_invalid',
  });
  assert.throws(() => catalogFor([first, first]), { code: 'm4_native_phase_catalog_invalid' });
  assert.throws(() => catalogFor([first, authorityFor(gateFiles, 2, 3)]), {
    code: 'm4_native_phase_catalog_invalid',
  });
  assert.throws(() => catalogFor([
    authorityFor(gateFiles, 0, 2), authorityFor(gateFiles, 1, 3),
  ]), { code: 'm4_native_phase_catalog_invalid' });
  const otherBinding = sourceBinding('codex', 'source-two');
  assert.throws(() => catalogFor([
    first,
    authorityFor(gateFiles, 0, 1, { sourceBinding: otherBinding }),
    second,
  ]), { code: 'm4_native_phase_catalog_invalid' });
  const changedSource = { ...second, source: checkpoint('other-source') };
  assert.throws(() => catalogFor([first, changedSource]), {
    code: 'm4_native_phase_catalog_invalid',
  });
  const tampered = structuredClone(catalog);
  tampered.shards[1].authority.interval.chain = checkpoint('other-chain');
  await assert.rejects(async () => verifyM4NativePausedShardCatalog(tampered, CATALOG_KEY), {
    code: 'm4_native_phase_catalog_digest_mismatch',
  });

  const alternateKey = keyDocument('alternate-catalog-key', 12);
  const resigned = createM4NativePausedShardCatalog({
    pauseEvidence: catalog.pauseEvidence,
    source: catalog.source,
    initialCheckpoint: catalog.initialCheckpoint,
    shards: catalog.shards,
    keyDocument: alternateKey,
  });
  const completion = legacyCompletion();
  const firstPlan = await planM4NativePausedPhase(serialInput(gateFiles, catalog, completion));
  const alternatePlan = await planM4NativePausedPhase({
    ...serialInput(gateFiles, resigned, completion),
    catalogKey: alternateKey,
  });
  assert.notEqual(firstPlan.catalogDigest, alternatePlan.catalogDigest);
  assert.notEqual(firstPlan.confirmationDigest, alternatePlan.confirmationDigest);

  await assert.rejects(() => planM4NativePausedPhase({
    ...serialInput(gateFiles, catalog, completion),
    receiptKeyId: CATALOG_KEY.keyId,
  }), { code: 'm4_native_phase_key_separation_invalid' });
});

test('receipt key rejects catalog-equivalent secret bytes under a different key ID', async () => {
  const value = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    let laterFactories = 0;
    const factories = phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
      completion: value.completion, root: value.root, calls: value.calls });
    factories.receiptKey = async () => ({
      value: keyDocument(RECEIPT_KEY.keyId, 12),
      close: null,
    });
    for (const name of ['phaseLease', 'phaseStore', 'shard', 'completionKey']) {
      const original = factories[name];
      factories[name] = async context => { laterFactories += 1; return original(context); };
    }
    await assert.rejects(() => runM4NativePausedPhase({ ...value.runtime, factories }), {
      code: 'm4_native_phase_key_separation_invalid',
    });
    assert.equal(laterFactories, 0);
  } finally {
    cleanup(value);
  }
});

test('receipt key rejects zero-padded HMAC equivalence under a different key ID', async () => {
  const value = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    let laterFactories = 0;
    const factories = phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
      completion: value.completion, root: value.root, calls: value.calls });
    const catalogBytes = Buffer.from(CATALOG_KEY.key, 'base64');
    const equivalentBytes = Buffer.concat([catalogBytes, Buffer.from([0])]);
    const equivalentKey = equivalentBytes.toString('base64');
    factories.receiptKey = async () => ({
      value: { schema: CATALOG_KEY.schema, keyId: RECEIPT_KEY.keyId,
        key: equivalentKey },
      close: null,
    });
    catalogBytes.fill(0);
    equivalentBytes.fill(0);
    for (const name of ['phaseLease', 'phaseStore', 'shard', 'completionKey']) {
      const original = factories[name];
      factories[name] = async context => { laterFactories += 1; return original(context); };
    }
    await assert.rejects(() => runM4NativePausedPhase({ ...value.runtime, factories }), {
      code: 'm4_native_phase_key_separation_invalid',
    });
    assert.equal(laterFactories, 0);
  } finally {
    cleanup(value);
  }
});

test('one phase lease excludes a concurrent writer before either phase store is opened', async () => {
  const value = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  let held = false;
  let acquiredResolve;
  const acquired = new Promise(resolve => { acquiredResolve = resolve; });
  let proceedResolve;
  const proceed = new Promise(resolve => { proceedResolve = resolve; });
  function leaseFactory(block) {
    return async () => ({
      value: {
        async acquire() {
          if (held) throw new Error('held');
          held = true;
          acquiredResolve();
          if (block) await proceed;
        },
        async heartbeat() { if (!held) throw new Error('not held'); },
        async release() { if (!held) throw new Error('not held'); held = false; },
      },
      close: null,
    });
  }
  try {
    const firstCalls = [];
    const firstFactories = phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
      completion: value.completion, root: value.root, calls: firstCalls });
    firstFactories.phaseLease = leaseFactory(true);
    const first = runM4NativePausedPhase({ ...value.runtime, factories: firstFactories });
    await acquired;

    const secondCalls = [];
    const secondFactories = phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
      completion: value.completion, root: value.root, calls: secondCalls });
    secondFactories.phaseLease = leaseFactory(false);
    await assert.rejects(() => runM4NativePausedPhase({ ...value.runtime, factories: secondFactories }), {
      code: 'm4_native_phase_lease_acquire_failed',
    });
    assert.equal(secondCalls.includes('phase-store'), false);
    proceedResolve();
    assert.equal((await first).complete, true);
  } finally {
    proceedResolve?.();
    cleanup(value);
  }
});

test('per-invocation bounds block later shards and the completion key, then resume safely', async () => {
  const value = await setup({ maxCallsPerInvocationPerShard: 1, maxCallsPerInvocationTotal: 1 });
  try {
    await assert.rejects(() => runM4NativePausedPhase(value.runtime), {
      code: 'm4_native_phase_bound_exhausted',
    });
    assert.deepEqual(value.calls.filter(item => item.startsWith('shard-') && !item.includes('close')),
      ['shard-0']);
    assert.equal(value.calls.includes('shard-1'), false);
    assert.equal(value.calls.includes('completion-key'), false);

    const resumedSerial = serialInput(value.gateFiles, value.catalog, value.completion, {
      maxCallsPerInvocationPerShard: 4,
      maxCallsPerInvocationTotal: 8,
    });
    const resumedPlan = await planM4NativePausedPhase(resumedSerial);
    const resumedCalls = [];
    const resumed = await runM4NativePausedPhase({
      ...resumedSerial,
      confirmedPlanDigest: resumedPlan.confirmationDigest,
      verifyCurrentCatalog: async () => value.catalog,
      verifyLegacyCompletion: async () => value.completion,
      factories: phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
        completion: value.completion, root: value.root, calls: resumedCalls }),
    });
    assert.equal(resumed.complete, true);
    assert.deepEqual(resumedCalls.filter(item => item.startsWith('shard-') && !item.includes('close')),
      ['shard-0', 'shard-1']);
  } finally {
    cleanup(value);
  }
});

test('crash before receipt commit reruns the idempotent child without duplicate archive rows', async () => {
  const value = await setup({
    authorities: [authorityFor(gateFixture(), 0, 1)],
  });
  try {
    let first = true;
    value.runtime.factories = phaseFactories({
      gateFiles: value.gateFiles,
      catalog: value.catalog,
      completion: value.completion,
      root: value.root,
      calls: value.calls,
      storeFactory: context => {
        const real = new M4NativePausedPhaseStore({ rootPath: path.join(value.root, 'phase'), ...context });
        return {
          value: {
            load: () => real.load(),
            commit(receiptValue) {
              if (first) { first = false; throw Object.assign(new Error('crash'), { code: 'm4_test_crash_before' }); }
              return real.commit(receiptValue);
            },
          },
          close: async () => real.close(),
        };
      },
    });
    await assert.rejects(() => runM4NativePausedPhase(value.runtime), {
      code: 'm4_native_phase_store_commit_failed',
    });
    const secondCalls = [];
    const completed = await runM4NativePausedPhase({
      ...value.runtime,
      factories: phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
        completion: value.completion, root: value.root, calls: secondCalls }),
    });
    assert.equal(completed.complete, true);
    const archive = new SqliteConversationArchive({
      filename: path.join(value.root, 'archive.sqlite'),
      resolveIntegrityKey: keyId => keyId === 'event-k1' ? EVENT_KEY : null,
      resolveExpiresAt: () => '2027-07-22T00:00:00Z',
      cursorKey: Buffer.alloc(32, 4),
    });
    assert.equal(archive.db.prepare('SELECT COUNT(*) AS count FROM conversation_archive_events_v1')
      .get().count, 1);
    archive.close();
  } finally {
    cleanup(value);
  }
});

test('crash after receipt commit skips the terminal child on restart', async () => {
  const value = await setup();
  try {
    let crashed = false;
    value.runtime.factories = phaseFactories({
      gateFiles: value.gateFiles,
      catalog: value.catalog,
      completion: value.completion,
      root: value.root,
      calls: value.calls,
      storeFactory: context => {
        const real = new M4NativePausedPhaseStore({ rootPath: path.join(value.root, 'phase'), ...context });
        return {
          value: {
            load: () => real.load(),
            commit(receiptValue) {
              const committed = real.commit(receiptValue);
              if (!crashed) {
                crashed = true;
                throw Object.assign(new Error('crash'), { code: 'm4_test_crash_after' });
              }
              return committed;
            },
          },
          close: async () => real.close(),
        };
      },
    });
    await assert.rejects(() => runM4NativePausedPhase(value.runtime), {
      code: 'm4_native_phase_store_commit_failed',
    });
    const secondCalls = [];
    const completed = await runM4NativePausedPhase({
      ...value.runtime,
      factories: phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
        completion: value.completion, root: value.root, calls: secondCalls }),
    });
    assert.equal(completed.complete, true);
    assert.deepEqual(secondCalls.filter(item => item.startsWith('shard-') && !item.includes('close')),
      ['shard-1']);
  } finally {
    cleanup(value);
  }
});

test('tampered receipts and changed final catalog fail before child or completion key access', async () => {
  const value = await setup();
  try {
    const first = await runM4NativePausedPhase(value.runtime);
    assert.equal(first.complete, true);
    const phaseFile = fs.readdirSync(path.join(value.root, 'phase'))
      .find(name => name.endsWith('.json'));
    const phasePath = path.join(value.root, 'phase', phaseFile);
    const state = JSON.parse(fs.readFileSync(phasePath, 'utf8'));
    state.receipts[0].resultDigest = digest('substituted-result');
    const { integrity, ...payload } = state.receipts[0];
    integrity.keyId = CATALOG_KEY.keyId;
    integrity.payloadDigest = canonicalDigest(payload);
    integrity.signature = signatureFor(CATALOG_KEY,
      'amf.m4-native-paused-phase-receipt/v1/integrity', integrity.payloadDigest);
    fs.writeFileSync(phasePath, JSON.stringify(state), { mode: 0o600 });
    const tamperCalls = [];
    await assert.rejects(() => runM4NativePausedPhase({
      ...value.runtime,
      factories: phaseFactories({ gateFiles: value.gateFiles, catalog: value.catalog,
        completion: value.completion, root: value.root, calls: tamperCalls }),
    }), { code: 'm4_native_phase_receipt_key_mismatch' });
    assert.equal(tamperCalls.some(item => item.startsWith('shard-')), false);
    assert.equal(tamperCalls.includes('completion-key'), false);
  } finally {
    cleanup(value);
  }

  const recheck = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    const altered = createM4NativePausedShardCatalog({
      pauseEvidence: recheck.catalog.pauseEvidence,
      source: recheck.catalog.source,
      initialCheckpoint: recheck.catalog.initialCheckpoint,
      shards: recheck.catalog.shards.map(item => ({ ...item, maxEvents: 2 })),
      keyDocument: CATALOG_KEY,
    });
    let catalogReads = 0;
    recheck.runtime.verifyCurrentCatalog = async () => {
      catalogReads += 1;
      return catalogReads === 1 ? recheck.catalog : altered;
    };
    await assert.rejects(() => runM4NativePausedPhase(recheck.runtime), {
      code: 'm4_native_phase_catalog_mismatch',
    });
    assert.equal(recheck.calls.includes('completion-key'), false);
  } finally {
    cleanup(recheck);
  }
});

test('completion verification rejects checkpoint, payload, signature, and key substitution', async () => {
  const value = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    const result = await runM4NativePausedPhase(value.runtime);
    const checkpointTamper = structuredClone(result.completion);
    checkpointTamper.checkpoint = checkpoint('other-checkpoint');
    assert.throws(() => verifyM4NativePausedPhaseCompletion(checkpointTamper, COMPLETION_KEY), {
      code: 'm4_native_phase_completion_invalid',
    });
    const payloadTamper = structuredClone(result.completion);
    payloadTamper.catalogDigest = digest('other-catalog');
    assert.throws(() => verifyM4NativePausedPhaseCompletion(payloadTamper, COMPLETION_KEY), {
      code: 'm4_native_phase_completion_invalid',
    });
    const signatureTamper = structuredClone(result.completion);
    signatureTamper.evidence.signature = 'a'.repeat(43);
    assert.throws(() => verifyM4NativePausedPhaseCompletion(signatureTamper, COMPLETION_KEY), {
      code: 'm4_native_phase_completion_signature_mismatch',
    });
    assert.throws(() => verifyM4NativePausedPhaseCompletion(result.completion,
      keyDocument('other-completion-key', 13)), {
      code: 'm4_native_phase_completion_key_mismatch',
    });
  } finally {
    cleanup(value);
  }
});

test('child primary failure survives cleanup failure and successful cleanup failure is stable', async () => {
  const value = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    value.runtime.factories = phaseFactories({
      gateFiles: value.gateFiles,
      catalog: value.catalog,
      completion: value.completion,
      root: value.root,
      calls: value.calls,
      shardOverrides: () => ({
        verifyPauseEvidence: async () => ({
          pauseEvidence: value.catalog.pauseEvidence,
          nativeTranscriptAuthority: checkpoint('wrong-native-authority'),
          sourceCheckpoint: value.catalog.initialCheckpoint,
        }),
      }),
    });
    const originalShard = value.runtime.factories.shard;
    value.runtime.factories.shard = async context => {
      const resource = await originalShard(context);
      return { ...resource, close: async () => { throw new Error('private cleanup detail'); } };
    };
    await assert.rejects(() => runM4NativePausedPhase(value.runtime), {
      code: 'm4_native_batch_pause_mismatch',
    });
  } finally {
    cleanup(value);
  }

  const cleanupFailure = await setup({ authorities: [authorityFor(gateFixture(), 0, 1)] });
  try {
    cleanupFailure.runtime.factories = phaseFactories({
      gateFiles: cleanupFailure.gateFiles,
      catalog: cleanupFailure.catalog,
      completion: cleanupFailure.completion,
      root: cleanupFailure.root,
      calls: cleanupFailure.calls,
      completionClose: async () => { throw new Error('private cleanup detail'); },
    });
    await assert.rejects(() => runM4NativePausedPhase(cleanupFailure.runtime), {
      code: 'm4_native_phase_cleanup_failed',
    });
  } finally {
    cleanup(cleanupFailure);
  }
});
