import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createConversationEvent } from '../src/conversation-event-v3.mjs';
import { ConversationEventPlaintextOutbox } from '../src/ingest/conversation-event-v3-outbox.mjs';
import {
  createM4PreservedReplayCoordinator,
  M4_PRESERVED_REPLAY_MAX_CIPHERTEXT_BYTES,
  M4_PRESERVED_REPLAY_MAX_VISITED_RECORDS,
} from '../src/migration/m4-preserved-replay-coordinator.mjs';
import { deriveM4V3EventIdFromLegacyEventId } from '../src/migration/m4-v2-conversation-projector.mjs';

const EVENT_KEY = Buffer.alloc(32, 9);
const DERIVATION_KEY = Buffer.alloc(32, 3);
const digest = character => `sha256:${character.repeat(64)}`;
const checkpoint = (id, character) => ({ id, digest: digest(character) });
const pauseEvidence = {
  manifestId: 'pause-manifest-001',
  digest: digest('a'),
  signature: 'a'.repeat(43),
};
const pendingOutbox = checkpoint('pending-outbox-001', 'b');
const acknowledgements = checkpoint('acknowledgements-001', 'c');
const deadLetters = checkpoint('dead-letters-001', 'd');
const outboxChain = checkpoint('outbox-chain-001', 'e');
const deadletterChain = checkpoint('deadletter-chain-001', 'f');
const outboxInitial = checkpoint('outbox-initial-001', '1');
const deadletterInitial = checkpoint('deadletter-initial-001', '2');

const authority = {
  schema: 'amf.m4-preserved-replay-authority/v2',
  pauseEvidence,
  acknowledgements,
  sources: {
    outbox: {
      pauseCheckpoint: pendingOutbox,
      interval: { startExclusive: 0, endInclusive: 20_050, chain: outboxChain },
      initialCheckpoint: outboxInitial,
    },
    deadletter: {
      pauseCheckpoint: deadLetters,
      interval: { startExclusive: 0, endInclusive: 20_050, chain: deadletterChain },
      initialCheckpoint: deadletterInitial,
    },
  },
};

function legacyEventId(index = 1) {
  return `evt_${index.toString(16).padStart(64, '0')}`;
}

function conversationEvent(legacyId, text = 'synthetic visible text', options = {}) {
  return createConversationEvent({
    eventId: options.eventId ?? deriveM4V3EventIdFromLegacyEventId(legacyId),
    conversationId: 'ccon_abcdefgh',
    sourceInstanceId: 'src_abcdefgh',
    role: 'user',
    visibleText: text,
    sourceOccurredAt: '2026-07-22T00:00:00Z',
    occurredAt: '2026-07-22T00:00:00Z',
    ordering: { sourceSequence: options.sourceSequence ?? 1 },
    direction: 'inbound',
    conversationKind: 'session',
    authorizationContextTags: {
      conversation: [`hmac-sha256:synthetic:${'a'.repeat(64)}`],
    },
    state: 'active',
    revision: 1,
  }, {
    keyId: 'event-key',
    key: EVENT_KEY,
    sentAt: '2026-07-22T00:00:00Z',
    nonce: 'syntheticnonce0001',
  });
}

function replayFixture({
  sourceKind = 'outbox',
  position = 1,
  legacyId = legacyEventId(position),
  text = `synthetic text ${position}`,
  ciphertextLabel = `${sourceKind}-${position}-${text}`,
  event = null,
} = {}) {
  const ciphertext = Buffer.from(ciphertextLabel, 'utf8');
  const envelopeDigest = `sha256:${crypto.createHash('sha256').update(ciphertext).digest('hex')}`;
  return {
    record: { sourceKind, position, legacyEventId: legacyId, envelopeDigest, ciphertext },
    decoded: event ?? conversationEvent(legacyId, text, { sourceSequence: position }),
  };
}

function completionFor(kind, authorityValue = authority) {
  const selected = authorityValue.sources[kind];
  return {
    schema: 'amf.m4-preserved-replay-completion/v2',
    sourceKind: kind,
    pauseCheckpoint: selected.pauseCheckpoint,
    endInclusive: selected.interval.endInclusive,
    chain: selected.interval.chain,
  };
}

class FixtureReader {
  constructor(recordsByKind, options = {}) {
    this.recordsByKind = recordsByKind;
    this.options = options;
    this.openCalls = 0;
    this.completionCalls = 0;
    this.openInputs = [];
  }

  async open(input) {
    this.openCalls += 1;
    this.openInputs.push(structuredClone(input));
    const authorityValue = this.options.authority ?? authority;
    const selected = authorityValue.sources[input.sourceKind];
    const values = this.recordsByKind[input.sourceKind] ?? [];
    const startIndex = input.afterSequence === 0 ? 0 : input.afterSequence - 1;
    const records = this.options.records ?? (async function* enumerate(values) {
      for (const value of values) yield value;
    })(values.slice(startIndex));
    return {
      schema: 'amf.m4-preserved-replay-reader/v2',
      sourceKind: this.options.attestedKind ?? input.sourceKind,
      pauseCheckpoint: selected.pauseCheckpoint,
      interval: selected.interval,
      records,
      completion: async () => {
        this.completionCalls += 1;
        return this.options.completion ?? completionFor(input.sourceKind, authorityValue);
      },
    };
  }
}

class FixtureDecoder {
  constructor(decodedByDigest, override = null) {
    this.decodedByDigest = decodedByDigest;
    this.override = override;
    this.calls = 0;
  }

  async normalize(input) {
    this.calls += 1;
    if (this.override) return this.override(input);
    return {
      schema: 'amf.m4-preserved-replay-decoded/v2',
      legacyEventId: input.legacyEventId,
      envelopeDigest: input.envelopeDigest,
      event: this.decodedByDigest.get(input.envelopeDigest),
    };
  }

  resolveIntegrityKey(keyId) {
    return keyId === 'event-key' ? EVENT_KEY : null;
  }
}

class FixtureNativeSink {
  constructor() {
    this.calls = 0;
    this.received = new Map();
  }

  async deliver(event, input) {
    this.calls += 1;
    assert.equal(input.idempotencyKey, event.eventId);
    assert.equal(input.payloadDigest, event.integrity.payloadDigest);
    const prior = this.received.get(event.eventId);
    if (prior !== undefined && prior !== input.payloadDigest) throw new Error('synthetic conflict');
    this.received.set(event.eventId, input.payloadDigest);
    return {
      acknowledged: true,
      eventId: event.eventId,
      payloadDigest: input.payloadDigest,
      status: prior === undefined ? 'stored' : 'duplicate',
    };
  }
}

class MemoryOutbox {
  constructor() {
    this.accepted = new Map();
    this.pending = new Map();
    this.enqueueCalls = 0;
    this.deliverCalls = 0;
  }

  async enqueue(event) {
    this.enqueueCalls += 1;
    const accepted = this.accepted.get(event.eventId);
    if (accepted !== undefined) {
      return {
        eventId: event.eventId,
        payloadDigest: event.integrity.payloadDigest,
        state: accepted === event.integrity.payloadDigest ? 'acknowledged' : 'conflict',
        duplicate: accepted === event.integrity.payloadDigest,
      };
    }
    this.pending.set(event.eventId, event);
    return {
      eventId: event.eventId,
      payloadDigest: event.integrity.payloadDigest,
      state: 'pending',
      duplicate: false,
    };
  }

  async deliver(eventId, sink) {
    this.deliverCalls += 1;
    const event = this.pending.get(eventId);
    const result = await sink.deliver(event, {
      idempotencyKey: event.eventId,
      payloadDigest: event.integrity.payloadDigest,
    });
    this.accepted.set(event.eventId, event.integrity.payloadDigest);
    this.pending.delete(eventId);
    return {
      eventId,
      payloadDigest: event.integrity.payloadDigest,
      state: 'acknowledged',
      duplicate: result.status === 'duplicate',
    };
  }
}

function decodedMap(fixtures) {
  return new Map(fixtures.map(item => [item.record.envelopeDigest, item.decoded]));
}

function coordinator({
  fixtures = [],
  recordsByKind = null,
  reader = null,
  decoder = null,
  outbox = new MemoryOutbox(),
  nativeSink = new FixtureNativeSink(),
  authorize = async () => true,
  verifyPauseEvidence = async () => ({ pauseEvidence, pendingOutbox, acknowledgements, deadLetters }),
  authorityValue = authority,
} = {}) {
  const grouped = recordsByKind ?? {
    outbox: fixtures.filter(item => item.record.sourceKind === 'outbox').map(item => item.record),
    deadletter: fixtures.filter(item => item.record.sourceKind === 'deadletter').map(item => item.record),
  };
  return {
    value: createM4PreservedReplayCoordinator({
      authority: authorityValue,
      derivationKey: DERIVATION_KEY,
      verifyPauseEvidence,
      reader: reader ?? new FixtureReader(grouped, { authority: authorityValue }),
      authorize,
      decoder: decoder ?? new FixtureDecoder(decodedMap(fixtures)),
      outbox,
      nativeSink,
    }),
    outbox,
    nativeSink,
  };
}

async function rows(value, {
  sourceKind = 'outbox',
  after = authority.sources[sourceKind].initialCheckpoint,
  afterSequence = 0,
  maxEvents = 10,
} = {}) {
  const result = [];
  for await (const row of value.open({ sourceKind, after, afterSequence, maxEvents })) result.push(row);
  return result;
}

async function rejects(call, code) {
  await assert.rejects(call, error => error?.code === code && error.message === code);
}

function realOutbox(root) {
  return new ConversationEventPlaintextOutbox({
    rootPath: root,
    resolveIntegrityKey: keyId => keyId === 'event-key' ? EVENT_KEY : null,
    clock: () => Date.parse('2026-07-22T00:01:00Z'),
    nonceFactory: () => 'deliverynonce0001',
  });
}

test('delivers through the real durable v3 outbox and deduplicates the same event from deadletter', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-preserved-replay-'));
  try {
    const legacyId = legacyEventId(1);
    const first = replayFixture({ legacyId, ciphertextLabel: 'shared-envelope' });
    const second = {
      ...first,
      record: { ...first.record, sourceKind: 'deadletter' },
    };
    const sink = new FixtureNativeSink();
    const initial = coordinator({ fixtures: [first], outbox: realOutbox(root), nativeSink: sink });
    const accepted = await rows(initial.value);
    assert.equal(accepted[0].outcome, 'accepted');
    assert.equal(accepted[0].duplicate, false);
    assert.equal(sink.calls, 1);
    assert.doesNotMatch(JSON.stringify(accepted), /shared-envelope|synthetic visible text/);

    const restarted = coordinator({ fixtures: [second], outbox: realOutbox(root), nativeSink: sink });
    const duplicate = await rows(restarted.value, { sourceKind: 'deadletter' });
    assert.equal(duplicate[0].outcome, 'duplicate');
    assert.equal(duplicate[0].eventId, accepted[0].eventId);
    assert.equal(sink.calls, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('persists a changed payload as a visible conflict across coordinator and outbox restarts', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-m4-preserved-conflict-'));
  try {
    const legacyId = legacyEventId(2);
    const original = replayFixture({ legacyId, text: 'first value', ciphertextLabel: 'first-envelope' });
    const changed = replayFixture({ legacyId, position: 2, text: 'second value', ciphertextLabel: 'second-envelope' });
    const sink = new FixtureNativeSink();
    await rows(coordinator({ fixtures: [original], outbox: realOutbox(root), nativeSink: sink }).value);
    const changedOutbox = realOutbox(root);
    const conflict = await rows(coordinator({ fixtures: [changed], outbox: changedOutbox, nativeSink: sink }).value);
    assert.equal(conflict[0].outcome, 'conflict');
    assert.equal(conflict[0].duplicate, false);
    assert.deepEqual(conflict[0].conflict, {
      schema: 'amf.m4-preserved-replay-conflict/v2',
      eventId: changed.decoded.eventId,
      receivedPayloadDigest: changed.decoded.integrity.payloadDigest,
    });
    assert.equal(sink.calls, 1);
    assert.equal(changedOutbox.readConflict(changed.decoded.eventId, changed.decoded.integrity.payloadDigest)?.visibleText, 'second value');
    const repeated = await rows(coordinator({ fixtures: [changed], outbox: realOutbox(root), nativeSink: sink }).value);
    assert.equal(repeated[0].outcome, 'conflict');
    assert.equal(repeated[0].duplicate, true);
    assert.equal(sink.calls, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('rejects invalid or unauthorized records before decoder, outbox, or native delivery', async () => {
  const fixture = replayFixture();
  const invalid = { ...fixture.record, envelopeDigest: digest('9') };
  const decoder = new FixtureDecoder(decodedMap([fixture]));
  const outbox = new MemoryOutbox();
  const sink = new FixtureNativeSink();
  const invalidValue = coordinator({
    fixtures: [fixture],
    recordsByKind: { outbox: [invalid], deadletter: [] },
    decoder,
    outbox,
    nativeSink: sink,
    authorize: async () => { throw new Error('must not run'); },
  }).value;
  await rejects(() => rows(invalidValue), 'm4_preserved_replay_envelope_mismatch');
  assert.deepEqual([decoder.calls, outbox.enqueueCalls, sink.calls], [0, 0, 0]);

  let authorizationCalls = 0;
  const deniedDecoder = new FixtureDecoder(decodedMap([fixture]));
  const denied = coordinator({
    fixtures: [fixture],
    decoder: deniedDecoder,
    outbox,
    nativeSink: sink,
    authorize: async () => { authorizationCalls += 1; return false; },
  }).value;
  await rejects(() => rows(denied), 'm4_preserved_replay_authorization_failed');
  assert.equal(authorizationCalls, 1);
  assert.deepEqual([deniedDecoder.calls, outbox.enqueueCalls, sink.calls], [0, 0, 0]);

  const empty = { ...fixture.record, ciphertext: Buffer.alloc(0), envelopeDigest: `sha256:${crypto.createHash('sha256').digest('hex')}` };
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], recordsByKind: { outbox: [empty], deadletter: [] } }).value),
    'm4_preserved_replay_record_invalid',
  );
  assert.equal(M4_PRESERVED_REPLAY_MAX_CIPHERTEXT_BYTES, 16 * 1024 * 1024);
});

test('binds decoder output to the authenticated envelope and deterministic v2-to-v3 identity', async () => {
  const fixture = replayFixture();
  const wrongBinding = new FixtureDecoder(decodedMap([fixture]), input => ({
    schema: 'amf.m4-preserved-replay-decoded/v2',
    legacyEventId: input.legacyEventId,
    envelopeDigest: digest('8'),
    event: fixture.decoded,
  }));
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], decoder: wrongBinding }).value),
    'm4_preserved_replay_decoder_binding_invalid',
  );

  const wrongIdentityEvent = conversationEvent(legacyEventId(99));
  const wrongIdentity = new FixtureDecoder(decodedMap([fixture]), input => ({
    schema: 'amf.m4-preserved-replay-decoded/v2',
    legacyEventId: input.legacyEventId,
    envelopeDigest: input.envelopeDigest,
    event: wrongIdentityEvent,
  }));
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], decoder: wrongIdentity }).value),
    'm4_preserved_replay_event_identity_invalid',
  );

  const hostile = new FixtureDecoder(decodedMap([fixture]), () => {
    const error = new Error('private payload');
    error.code = 'm4_preserved_replay_private_payload';
    throw error;
  });
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], decoder: hostile }).value),
    'm4_preserved_replay_decode_failed',
  );
});

test('binds both queue kinds to verified pause evidence before opening a reader', async () => {
  const fixture = replayFixture();
  const reader = new FixtureReader({ outbox: [fixture.record], deadletter: [] });
  const mismatched = coordinator({
    fixtures: [fixture],
    reader,
    verifyPauseEvidence: async () => ({
      pauseEvidence,
      pendingOutbox: checkpoint('pending-outbox-001', '9'),
      acknowledgements,
      deadLetters,
    }),
  }).value;
  await rejects(() => rows(mismatched), 'm4_preserved_replay_pause_mismatch');
  assert.equal(reader.openCalls, 0);

  const wrongKindReader = new FixtureReader({ outbox: [fixture.record], deadletter: [] }, { attestedKind: 'deadletter' });
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], reader: wrongKindReader }).value),
    'm4_preserved_replay_reader_attestation_mismatch',
  );
});

test('resumes from an exact row checkpoint without re-enqueuing earlier records', async () => {
  const fixtures = [1, 2, 3].map(position => replayFixture({ position }));
  const baseline = await rows(coordinator({ fixtures }).value);
  const resumeOutbox = new MemoryOutbox();
  const resumeReader = new FixtureReader({ outbox: fixtures.map(item => item.record), deadletter: [] });
  const resumed = await rows(coordinator({ fixtures, reader: resumeReader, outbox: resumeOutbox }).value, {
    after: baseline[0].checkpoint,
    afterSequence: 1,
  });
  assert.deepEqual(resumed.map(item => item.sequence), [2, 3]);
  assert.equal(resumeOutbox.enqueueCalls, 2);
  assert.equal(resumeReader.openInputs[0].afterSequence, 1);

  const finalReader = new FixtureReader({ outbox: fixtures.map(item => item.record), deadletter: [] });
  const finalOutbox = new MemoryOutbox();
  const final = await rows(coordinator({ fixtures, reader: finalReader, outbox: finalOutbox }).value, {
    after: baseline[1].checkpoint,
    afterSequence: 2,
  });
  assert.deepEqual(final.map(item => item.sequence), [3]);
  assert.equal(finalOutbox.enqueueCalls, 1);
  assert.equal(finalReader.openInputs[0].afterSequence, 2);

  const reader = new FixtureReader({ outbox: fixtures.map(item => item.record), deadletter: [] });
  const unknownOutbox = new MemoryOutbox();
  await rejects(() => rows(coordinator({ fixtures, reader, outbox: unknownOutbox }).value, {
    after: { id: `m4pr-${'f'.repeat(64)}`, digest: digest('8') },
    afterSequence: 1,
  }), 'm4_preserved_replay_checkpoint_drift');
  assert.equal(unknownOutbox.enqueueCalls, 0);
  assert.equal(reader.completionCalls, 0);
});

test('accepts an empty attested interval and rejects an out-of-range resume before opening the reader', async () => {
  const emptyAuthority = structuredClone(authority);
  for (const kind of ['outbox', 'deadletter']) {
    emptyAuthority.sources[kind].interval = {
      startExclusive: 0,
      endInclusive: 0,
      chain: checkpoint(`${kind}-empty-chain`, kind === 'outbox' ? '4' : '5'),
    };
    emptyAuthority.sources[kind].initialCheckpoint = checkpoint(`${kind}-empty-initial`, kind === 'outbox' ? '6' : '7');
  }
  const reader = new FixtureReader({ outbox: [], deadletter: [] }, { authority: emptyAuthority });
  const empty = coordinator({ fixtures: [], reader, authorityValue: emptyAuthority }).value;
  assert.deepEqual(await rows(empty, { after: emptyAuthority.sources.outbox.initialCheckpoint }), []);
  assert.equal(reader.openCalls, 1);
  assert.equal(reader.completionCalls, 1);

  const deniedReader = new FixtureReader({ outbox: [], deadletter: [] }, { authority: emptyAuthority });
  await rejects(() => rows(coordinator({ fixtures: [], reader: deniedReader, authorityValue: emptyAuthority }).value, {
    after: { id: `m4pr-${'f'.repeat(64)}`, digest: digest('8') },
    afterSequence: 1,
  }), 'm4_preserved_replay_checkpoint_drift');
  assert.equal(deniedReader.openCalls, 0);
});

test('keeps maxEvents as a hard durable bound while probing natural completion', async () => {
  const fixtures = [1, 2, 3].map(position => replayFixture({ position }));
  const boundedReader = new FixtureReader({ outbox: fixtures.map(item => item.record), deadletter: [] });
  const boundedOutbox = new MemoryOutbox();
  const bounded = await rows(coordinator({ fixtures, reader: boundedReader, outbox: boundedOutbox }).value, { maxEvents: 1 });
  assert.equal(bounded.length, 1);
  assert.equal(boundedOutbox.enqueueCalls, 1);
  assert.equal(boundedOutbox.deliverCalls, 1);
  assert.equal(boundedReader.completionCalls, 0);

  const exactBoundReader = new FixtureReader({ outbox: [fixtures[0].record], deadletter: [] });
  const exactBoundOutbox = new MemoryOutbox();
  const exactBound = await rows(coordinator({ fixtures: [fixtures[0]], reader: exactBoundReader, outbox: exactBoundOutbox }).value, {
    maxEvents: 1,
  });
  assert.equal(exactBound.length, 1);
  assert.equal(exactBoundOutbox.enqueueCalls, 1);
  assert.equal(exactBoundOutbox.deliverCalls, 1);
  assert.equal(exactBoundReader.completionCalls, 1);

  const invalidCompletion = new FixtureReader(
    { outbox: [fixtures[0].record], deadletter: [] },
    { completion: { ...completionFor('outbox'), endInclusive: 20_049 } },
  );
  await rejects(
    () => rows(coordinator({ fixtures: [fixtures[0]], reader: invalidCompletion }).value, { maxEvents: 1 }),
    'm4_preserved_replay_completion_mismatch',
  );
});

test('fails after the exact visited-record bound without touching the durable outbox', async () => {
  const fixture = replayFixture();
  const records = (async function* enumerate() {
    for (let position = 1; position <= M4_PRESERVED_REPLAY_MAX_VISITED_RECORDS + 1; position += 1) {
      yield { ...fixture.record, position };
    }
  })();
  const reader = new FixtureReader({ outbox: [], deadletter: [] }, { records });
  const outbox = new MemoryOutbox();
  await rejects(() => rows(coordinator({ fixtures: [fixture], reader, outbox }).value, {
    after: { id: `m4pr-${'f'.repeat(64)}`, digest: digest('8') },
    afterSequence: 1,
  }), 'm4_preserved_replay_scan_limit');
  assert.equal(outbox.enqueueCalls, 0);
  assert.equal(reader.completionCalls, 0);
});

test('reads iterator methods once and normalizes hostile reader errors without losing the primary error', async () => {
  const fixture = replayFixture();
  let nextReads = 0;
  let returnReads = 0;
  let step = 0;
  const iterator = {};
  Object.defineProperty(iterator, 'next', {
    get() {
      nextReads += 1;
      return async () => step++ === 0 ? { value: fixture.record, done: false } : { value: undefined, done: true };
    },
  });
  Object.defineProperty(iterator, 'return', {
    get() {
      returnReads += 1;
      return async () => ({ value: undefined, done: true });
    },
  });
  const records = { [Symbol.asyncIterator]: () => iterator };
  const reader = new FixtureReader({ outbox: [], deadletter: [] }, { records });
  await rows(coordinator({ fixtures: [fixture], reader }).value);
  assert.deepEqual([nextReads, returnReads], [1, 1]);

  const hostileRecords = {};
  Object.defineProperty(hostileRecords, Symbol.asyncIterator, {
    get() { throw new Error('private reader detail'); },
  });
  const hostileReader = new FixtureReader({ outbox: [], deadletter: [] }, { records: hostileRecords });
  await rejects(
    () => rows(coordinator({ fixtures: [fixture], reader: hostileReader }).value),
    'm4_preserved_replay_reader_invalid',
  );

  const closeOnly = {
    [Symbol.asyncIterator]() {
      return {
        async next() { return { value: undefined, done: true }; },
        async return() { throw new Error('private close detail'); },
      };
    },
  };
  await rejects(
    () => rows(coordinator({ fixtures: [], reader: new FixtureReader({ outbox: [], deadletter: [] }, { records: closeOnly }) }).value),
    'm4_preserved_replay_reader_close_failed',
  );

  const readAndClose = {
    [Symbol.asyncIterator]() {
      return {
        async next() { throw new Error('private read detail'); },
        async return() { throw new Error('private close detail'); },
      };
    },
  };
  await rejects(
    () => rows(coordinator({ fixtures: [], reader: new FixtureReader({ outbox: [], deadletter: [] }, { records: readAndClose }) }).value),
    'm4_preserved_replay_reader_read_failed',
  );
});
