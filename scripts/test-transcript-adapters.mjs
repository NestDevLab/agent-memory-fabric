import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { EncryptedOutbox, FakeRawEventSink } from '../src/ingest/outbox.mjs';
import { main as ingestCli } from './amf-transcript-ingest.mjs';
import { parseClaudeRecord } from '../src/ingest/transcripts/claude.mjs';
import { parseCodexRecord } from '../src/ingest/transcripts/codex.mjs';
import { CursorStore, sourceCursorKey } from '../src/ingest/transcripts/cursor-store.mjs';
import { stableEventId, stableSessionId } from '../src/ingest/transcripts/identity.mjs';
import { TranscriptIngestor } from '../src/ingest/transcripts/ingestor.mjs';
import { BackfillLease, discoverTranscriptFiles, runTranscriptBackfill } from '../src/ingest/transcripts/backfill.mjs';
import { decodeJsonLine, readCompleteJsonl, tailBootstrapOffset } from '../src/ingest/transcripts/jsonl-tail.mjs';

const fixtures = path.join(import.meta.dirname, 'fixtures', 'transcripts');
const KEY = crypto.createHash('sha256').update('synthetic-test-key').digest('hex');
const KEY2 = crypto.createHash('sha256').update('synthetic-test-key-rotated').digest('hex');
const CHECKPOINT_KEY = crypto.createHash('sha256').update('synthetic-checkpoint-key').digest('hex');
const OUTBOX_OPTIONS = { encryptionKey: KEY, digestKey: KEY, sourceInstanceId: 'synthetic-host', actorId: 'synthetic-actor' };

function tempTree() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-ingest-'));
  return {
    root,
    outbox: new EncryptedOutbox({ rootPath: path.join(root, 'spool'), ...OUTBOX_OPTIONS, keyId: 'test-v1' }),
    cursors: new CursorStore({ rootPath: path.join(root, 'cursors'), encryptionKey: KEY, keyId: 'test-v1' }),
    cleanup: () => fs.rmSync(root, { recursive: true, force: true })
  };
}

test('JSONL reader emits complete LF/CRLF records only and preserves byte offsets', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-jsonl-'));
  const file = path.join(root, 'input.jsonl');
  try {
    const first = JSON.stringify({ text: 'caffè ☕' });
    const second = JSON.stringify({ ok: true });
    fs.writeFileSync(file, Buffer.from(`${first}\r\n${second.slice(0, -1)}`, 'utf8'));
    const batch = readCompleteJsonl(file);
    assert.equal(batch.entries.length, 1);
    assert.equal(batch.entries[0].lineEnding, 'crlf');
    assert.deepEqual(batch.entries[0].value, { text: 'caffè ☕' });
    assert.equal(batch.offset, Buffer.byteLength(`${first}\r\n`));
    assert.equal(batch.partialBytes, Buffer.byteLength(second) - 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('JSONL decoder accepts a BOM only on the first line and rejects malformed UTF-8/JSON', () => {
  assert.deepEqual(decodeJsonLine(Buffer.from('\ufeff{"ok":true}'), { firstLine: true }), { ok: true });
  assert.throws(() => decodeJsonLine(Buffer.from([0xc3, 0x28])), TypeError);
  assert.throws(() => decodeJsonLine(Buffer.from('{bad json}')), /transcript_json_invalid/);
});

test('identities are path-independent and bind native event id plus subtype', () => {
  const base = { runtime: 'claude', nativeSessionId: 'session-1', nativeEventId: 'event-1', rawBytes: Buffer.from('ignored') };
  assert.equal(stableSessionId({ runtime: 'claude', nativeSessionId: 'session-1' }), stableSessionId({ runtime: 'claude', nativeSessionId: 'session-1' }));
  assert.equal(stableEventId({ ...base, subtype: 'user' }), stableEventId({ ...base, subtype: 'user' }));
  assert.notEqual(stableEventId({ ...base, subtype: 'user' }), stableEventId({ ...base, subtype: 'assistant' }));
  assert.notEqual(stableEventId({ ...base, subtype: 'user' }), stableEventId({ ...base, nativeEventId: 'event-2', subtype: 'user' }));
});

test('fallback identities use literal bytes but not source paths', () => {
  const input = { runtime: 'codex', nativeSessionId: 'session', nativeEventId: null, subtype: 'message', rawBytes: Buffer.from('{"same":true}') };
  assert.equal(stableEventId(input), stableEventId({ ...input }));
  assert.notEqual(stableEventId(input), stableEventId({ ...input, rawBytes: Buffer.from('{"same":false}') }));
});

test('Codex parser preserves literal RAW while exposing only safe projection fields', () => {
  const rawBytes = Buffer.from(fs.readFileSync(path.join(fixtures, 'codex-synthetic.jsonl'), 'utf8').split('\n')[0]);
  const value = JSON.parse(rawBytes.toString('utf8'));
  const item = parseCodexRecord({ value, rawBytes, lineEnding: 'lf', sessionHint: null });
  assert.equal(item.event.occurredAt, '2026-07-11T10:00:00.000Z');
  assert.equal(Buffer.from(item.event.raw.line, 'base64').equals(rawBytes), true);
  const projection = JSON.stringify(item.projection);
  for (const forbidden of ['codex-session-synthetic', '/synthetic/not-real']) assert.equal(projection.includes(forbidden), false);
});

test('Codex event_msg maps user and agent messages to the correct safe roles', () => {
  for (const [type, expected] of [['user_message', 'user'], ['agent_message', 'assistant']]) {
    const value = { type: 'event_msg', payload: { type, message: 'synthetic private text' } };
    const item = parseCodexRecord({ value, rawBytes: Buffer.from(JSON.stringify(value)), lineEnding: 'lf', sessionHint: 'session' });
    assert.equal(item.projection.role, expected);
  }
});

test('cursor state is encrypted and authenticated at rest and key configuration fails closed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cursor-'));
  const key = sourceCursorKey('codex', 'opaque-source');
  try {
    assert.throws(() => new CursorStore({ rootPath: root }), /cursor_encryption_key_required/);
    const store = new CursorStore({ rootPath: root, encryptionKey: KEY, keyId: 'cursor-v1' });
    const cursor = { version: 1, offset: 42, sessionHint: 'SYNTHETIC_NATIVE_SESSION', privatePath: '/synthetic/private/path' };
    store.write(key, cursor);
    const file = store.file(key);
    const disk = fs.readFileSync(file, 'utf8');
    assert.equal(disk.includes('SYNTHETIC_NATIVE_SESSION'), false);
    assert.equal(disk.includes('/synthetic/private/path'), false);
    assert.deepEqual(store.read(key), cursor);
    const rotated = new CursorStore({ rootPath: root, keyRing: { currentKeyId: 'cursor-v2', keys: { 'cursor-v1': KEY, 'cursor-v2': KEY2 } } });
    assert.deepEqual(rotated.read(key), cursor, 'rotated cursor ring must read the old envelope');
    rotated.write(key, { ...cursor, offset: 43 });
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).keyId, 'cursor-v2');
    store.write(key, cursor);
    const wrong = new CursorStore({ rootPath: root, encryptionKey: 'f'.repeat(64), keyId: 'cursor-v1' });
    assert.throws(() => wrong.read(key), /cursor_authentication_failed/);
    const envelope = JSON.parse(disk);
    envelope.cursorKey = '0'.repeat(64);
    fs.writeFileSync(file, JSON.stringify(envelope));
    assert.throws(() => store.read(key), /cursor_key_mismatch/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('Claude parser does not invent missing or invalid event timestamps', () => {
  const base = { type: 'assistant', uuid: 'evt', sessionId: 'ses', message: { role: 'assistant', content: 'secret' } };
  const missing = parseClaudeRecord({ value: base, rawBytes: Buffer.from(JSON.stringify(base)), lineEnding: 'lf' });
  const invalidValue = { ...base, timestamp: 'yesterday-ish' };
  const invalid = parseClaudeRecord({ value: invalidValue, rawBytes: Buffer.from(JSON.stringify(invalidValue)), lineEnding: 'lf' });
  assert.equal(missing.event.occurredAt, null);
  assert.equal(invalid.event.occurredAt, null);
  assert.equal(JSON.stringify(missing.projection).includes('secret'), false);
});

test('untrusted type and timestamp strings cannot enter the safe projection', () => {
  const secret = 'synthetic-private-type';
  const value = { type: secret, uuid: 'evt-safe', sessionId: 'ses-safe', timestamp: 'July 11 2026', message: { role: 'user', content: 'private' } };
  const item = parseClaudeRecord({ value, rawBytes: Buffer.from(JSON.stringify(value)), lineEnding: 'lf' });
  assert.equal(item.projection.subtype, 'unknown');
  assert.equal(item.projection.occurredAt, null);
  assert.equal(JSON.stringify(item.projection).includes(secret), false);
});

test('outbox rejects extra projection fields instead of forwarding them to a catalog sink', () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"type":"user","uuid":"projection-event","sessionId":"projection-session"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
    item.projection = { ...item.projection, text: 'synthetic leak' };
    assert.throws(() => tree.outbox.enqueue(item), /outbox_projection_fields_invalid/);
  } finally { tree.cleanup(); }
});

test('outbox fails closed without a canonical 32-byte key and safe key id', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-outbox-key-'));
  try {
    assert.throws(() => new EncryptedOutbox({ rootPath: root }), /outbox_encryption_key_required/);
    assert.throws(() => new EncryptedOutbox({ rootPath: root, encryptionKey: 'short', digestKey: KEY, sourceInstanceId: 'host', actorId: 'actor' }), /outbox_encryption_key_invalid/);
    assert.throws(() => new EncryptedOutbox({ rootPath: root, ...OUTBOX_OPTIONS, keyId: 'bad:key' }), /outbox_key_id_invalid/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('outbox spool contains ciphertext only, authenticates AAD and detects conflicts', () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"private":"SYNTHETIC_SPOOL_SECRET"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf', sessionHint: 'session' });
    tree.outbox.enqueue(item);
    const file = tree.outbox.pendingFile(item.event.eventId);
    const disk = fs.readFileSync(file, 'utf8');
    assert.equal(disk.includes('SYNTHETIC_SPOOL_SECRET'), false);
    assert.equal(disk.includes(raw.toString('base64')), false);
    assert.deepEqual(tree.outbox.read(item.event.eventId), item);
    assert.equal(tree.outbox.enqueue(item).duplicate, true);
    const different = structuredClone(item);
    different.event.raw.line = Buffer.from('{"different":true}').toString('base64');
    assert.throws(() => tree.outbox.enqueue(different), /outbox_event_id_conflict/);
    const envelope = JSON.parse(disk);
    envelope.eventId = `evt_${'0'.repeat(64)}`;
    fs.writeFileSync(file, JSON.stringify(envelope));
    assert.throws(() => tree.outbox.read(item.event.eventId), /outbox_authentication_failed/);
  } finally { tree.cleanup(); }
});

test('outbox rotation replays old pending ciphertext and keeps checkpoints stable', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-outbox-rotation-'));
  const raw = Buffer.from('{"type":"user","uuid":"rotation-pending","sessionId":"rotation-session","message":{"role":"user","content":"synthetic"}}');
  const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
  try {
    const old = new EncryptedOutbox({ rootPath: root, ...OUTBOX_OPTIONS, checkpointKey: CHECKPOINT_KEY, keyId: 'old' });
    old.enqueue(item);
    assert.equal(old.readEnvelope(item.event.eventId).keyId, 'old');
    assert.throws(() => new EncryptedOutbox({ rootPath: root, keyRing: { currentKeyId: 'new', keys: { old: KEY, new: KEY2 } }, digestKey: KEY, sourceInstanceId: 'synthetic-host', actorId: 'synthetic-actor' }), /outbox_checkpoint_key_required/);
    const rotated = new EncryptedOutbox({
      rootPath: root, keyRing: { currentKeyId: 'new', keys: { old: KEY, new: KEY2 } },
      digestKey: KEY, checkpointKey: CHECKPOINT_KEY, sourceInstanceId: 'synthetic-host', actorId: 'synthetic-actor'
    });
    assert.deepEqual(rotated.read(item.event.eventId), item);
    assert.equal(rotated.checkpoint(Buffer.from('same')), old.checkpoint(Buffer.from('same')));
    assert.equal(rotated.chainCheckpoint(rotated.chainSeed(), Buffer.from('line\n')), old.chainCheckpoint(old.chainSeed(), Buffer.from('line\n')));
    const sink = new FakeRawEventSink();
    assert.equal((await rotated.replay(sink)).length, 1);
    assert.equal(rotated.pendingIds().length, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('invalid sink ACK never removes pending ciphertext', async () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"type":"user","uuid":"ack-event","sessionId":"ack-session"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
    tree.outbox.enqueue(item);
    await assert.rejects(tree.outbox.deliver(item.event.eventId, { deliver: async () => ({ acknowledged: true, eventId: 'wrong' }) }), /raw_event_ack_invalid/);
    assert.equal(tree.outbox.pendingIds().includes(item.event.eventId), true);
  } finally { tree.cleanup(); }
});

test('ingestor enqueues before delivery and advances cursor only after a verified ACK', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'claude.jsonl');
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), file);
  const logicalSource = 'claude:synthetic-active';
  try {
    const failedSink = new FakeRawEventSink({ fail: new Error('synthetic_outage') });
    const failed = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink: failedSink });
    await assert.rejects(failed.ingestFile({ runtime: 'claude', filePath: file, logicalSource }), /synthetic_outage/);
    assert.equal(tree.cursors.read(sourceCursorKey('claude', logicalSource)).offset, 0);
    assert.equal(tree.outbox.pendingIds().length, 1);

    const sink = new FakeRawEventSink();
    const recovered = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
    const result = await recovered.ingestFile({ runtime: 'claude', filePath: file, logicalSource });
    assert.equal(result.results.length, 2);
    assert.equal(result.offset, fs.statSync(file).size);
    assert.equal(sink.deliveries.length, 2);
    assert.equal(tree.outbox.pendingIds().length, 0);
  } finally { tree.cleanup(); }
});

test('partial final line remains unread until completed and does not advance the cursor', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'partial.jsonl');
  const full = '{"type":"user","uuid":"partial-event","sessionId":"partial-session","message":{"role":"user","content":"synthetic"}}';
  fs.writeFileSync(file, full.slice(0, -1));
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    const first = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'partial' });
    assert.equal(first.results.length, 0);
    assert.equal(first.offset, 0);
    fs.appendFileSync(file, '}\n');
    const second = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'partial' });
    assert.equal(second.results.length, 1);
    assert.equal(second.offset, fs.statSync(file).size);
  } finally { tree.cleanup(); }
});

test('tail bootstrap never advances beyond its captured size when a complete line arrives concurrently', () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'concurrent-append.jsonl');
  try {
    fs.writeFileSync(file, '{"first":true}\n');
    const capturedSize = fs.statSync(file).size;
    fs.appendFileSync(file, '{"arrived":"after-snapshot"}\n');
    assert.equal(tailBootstrapOffset(file, { size: capturedSize }), capturedSize);
    assert.equal(tailBootstrapOffset(file), fs.statSync(file).size);
  } finally { tree.cleanup(); }
});

test('tail bootstrap namespaces realtime from backfill, preserves Codex session identity and a partial line across rotation', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'codex-active.jsonl');
  const lines = fs.readFileSync(path.join(fixtures, 'codex-synthetic.jsonl'), 'utf8').trimEnd().split('\n');
  const completePrefix = `${lines[0]}\n${lines[1]}\n`;
  const partial = lines[2].slice(0, -1);
  fs.writeFileSync(file, `${completePrefix}${partial}`);
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    assert.equal(tailBootstrapOffset(file), Buffer.byteLength(completePrefix));
    const seeded = await ingestor.ingestFile({
      runtime: 'codex', filePath: file, logicalSource: 'codex:host:active', cursorNamespace: 'realtime', bootstrapTail: true, requireExistingCursor: true
    });
    assert.equal(seeded.bootstrapped, true);
    assert.equal(seeded.results.length, 0);
    assert.equal(seeded.partialBytes, Buffer.byteLength(partial));
    const realtimeKey = sourceCursorKey('codex', 'codex:host:active', 'realtime');
    const cursorDisk = fs.readFileSync(tree.cursors.file(realtimeKey), 'utf8');
    assert.equal(cursorDisk.includes('codex-session-synthetic'), false);
    await assert.rejects(ingestor.ingestFile({
      runtime: 'codex', filePath: file, logicalSource: 'codex:host:active', cursorNamespace: 'realtime', requireExistingCursor: true, fullAudit: true
    }), /transcript_full_audit_requires_backfill_cursor/);

    fs.appendFileSync(file, '}\n');
    const appended = await ingestor.ingestFile({
      runtime: 'codex', filePath: file, logicalSource: 'codex:host:active', cursorNamespace: 'realtime', requireExistingCursor: true
    });
    assert.equal(appended.results.length, 1, 'the partial line present during bootstrap is not skipped');

    fs.renameSync(file, `${file}.old`);
    fs.copyFileSync(path.join(fixtures, 'codex-synthetic.jsonl'), file);
    const rotated = await ingestor.ingestFile({
      runtime: 'codex', filePath: file, logicalSource: 'codex:host:active', cursorNamespace: 'realtime', requireExistingCursor: true
    });
    assert.equal(rotated.rotated, true);
    assert.equal(rotated.generation, 1);
    assert.equal(rotated.results.length, 3);

    const historical = await ingestor.ingestFile({ runtime: 'codex', filePath: file, logicalSource: 'codex:host:active', cursorNamespace: 'backfill' });
    assert.equal(historical.results.length, 3);
    assert.notEqual(realtimeKey, sourceCursorKey('codex', 'codex:host:active', 'backfill'));
  } finally { tree.cleanup(); }
});

test('active/archive copies deduplicate by path-independent event ids', async () => {
  const tree = tempTree();
  const active = path.join(tree.root, 'active.jsonl');
  const archive = path.join(tree.root, 'archive.jsonl');
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), active);
  fs.copyFileSync(active, archive);
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    const first = await ingestor.ingestFile({ runtime: 'claude', filePath: active, logicalSource: 'active' });
    const second = await ingestor.ingestFile({ runtime: 'claude', filePath: archive, logicalSource: 'archive' });
    assert.deepEqual(second.results.map(item => item.eventId), first.results.map(item => item.eventId));
    assert.equal(sink.deliveries.length, 2);
  } finally { tree.cleanup(); }
});

test('truncate/rotation starts a new cursor generation without redelivering duplicates', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'rotating.jsonl');
  const source = fs.readFileSync(path.join(fixtures, 'claude-synthetic.jsonl'));
  fs.writeFileSync(file, source);
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'rotating' });
    fs.renameSync(file, `${file}.old`);
    fs.writeFileSync(file, source);
    const rotated = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'rotating' });
    assert.equal(rotated.rotated, true);
    assert.equal(rotated.generation, 1);
    assert.equal(sink.deliveries.length, 2);
  } finally { tree.cleanup(); }
});

test('truncate and regrow on the same inode is detected by an opaque boundary checkpoint', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'same-inode.jsonl');
  const original = fs.readFileSync(path.join(fixtures, 'claude-synthetic.jsonl'));
  fs.writeFileSync(file, original);
  const originalInode = fs.statSync(file).ino;
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'same-inode' });
    const lines = original.toString('utf8').trimEnd().split('\n');
    const replacement = `${lines[0].replace('claude-event-user', 'XXXXXX-event-user')}\n${lines[1]}\n`;
    assert.equal(Buffer.byteLength(replacement), original.length);
    fs.truncateSync(file, 0);
    fs.writeFileSync(file, replacement);
    assert.equal(fs.statSync(file).ino, originalInode);
    const result = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'same-inode' });
    assert.equal(result.rotated, true);
    assert.equal(result.generation, 1);
    assert.equal(sink.deliveries.length, 3, 'changed first event is delivered, unchanged final event remains deduplicated');
  } finally { tree.cleanup(); }
});

test('same-size middle replacement is detected when inode, first window and final line are unchanged', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'middle-rewrite.jsonl');
  const line = value => JSON.stringify(value);
  const first = line({ type: 'user', uuid: 'first-event', sessionId: 'chain-session', message: { role: 'user', content: `synthetic-${'x'.repeat(5000)}` } });
  const middleA = line({ type: 'assistant', uuid: 'middle-event-a', sessionId: 'chain-session', message: { role: 'assistant', content: 'synthetic-middle' } });
  const middleB = middleA.replace('middle-event-a', 'middle-event-b');
  const final = line({ type: 'assistant', uuid: 'final-event', sessionId: 'chain-session', message: { role: 'assistant', content: 'synthetic-final' } });
  const original = `${first}\n${middleA}\n${final}\n`;
  const replacement = `${first}\n${middleB}\n${final}\n`;
  assert.equal(Buffer.byteLength(original), Buffer.byteLength(replacement));
  fs.writeFileSync(file, original);
  const inode = fs.statSync(file).ino;
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'middle-rewrite' });
    fs.writeFileSync(file, replacement);
    assert.equal(fs.statSync(file).ino, inode);
    const result = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'middle-rewrite' });
    assert.equal(result.rotated, true);
    assert.equal(result.generation, 1);
    assert.equal(sink.deliveries.length, 4, 'only the changed middle event is newly delivered');
  } finally { tree.cleanup(); }
});

test('durable replay retries pending events and ACK markers survive restart', async () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"type":"user","uuid":"replay-event","sessionId":"replay-session"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
    tree.outbox.enqueue(item);
    const restarted = new EncryptedOutbox({ rootPath: path.join(tree.root, 'spool'), ...OUTBOX_OPTIONS, keyId: 'test-v1' });
    const sink = new FakeRawEventSink();
    const replayed = await restarted.replay(sink);
    assert.equal(replayed.length, 1);
    assert.equal(restarted.isAcknowledged(item.event.eventId), true);
    assert.equal(restarted.pendingIds().length, 0);
    assert.equal(restarted.enqueue(item).state, 'acknowledged');
    const different = structuredClone(item);
    different.event.raw.line = Buffer.from('{"changed":true}').toString('base64');
    assert.throws(() => restarted.enqueue(different), /outbox_event_id_conflict/);
    fs.writeFileSync(restarted.pendingFile(item.event.eventId), JSON.stringify(restarted.encrypt(different)));
    await assert.rejects(restarted.deliver(item.event.eventId, sink), /outbox_event_id_conflict/);
    const ackDisk = fs.readFileSync(restarted.ackFile(item.event.eventId), 'utf8');
    assert.match(ackDisk, /"payloadDigest":"hmac-sha256:v1:[a-f0-9]{64}"/);
    assert.equal(ackDisk.includes('replay-session'), false);
  } finally { tree.cleanup(); }
});

test('CLI requires an injectable sink and returns redacted ingestion results', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cli-'));
  try {
    const result = await ingestCli([
      '--runtime', 'claude',
      '--file', path.join(fixtures, 'claude-synthetic.jsonl'),
      '--spool', path.join(root, 'spool'),
      '--cursors', path.join(root, 'cursors'),
      '--test-mode',
      '--sink-module', path.join(fixtures, 'fake-sink.mjs')
    ], { AMF_OUTBOX_ENCRYPTION_KEY: KEY, AMF_OUTBOX_KEY_ID: 'cli-test' });
    assert.equal(result.results.length, 2);
    const serialized = JSON.stringify(result);
    for (const secret of ['SYNTHETIC_PRIVATE_CLAUDE_TEXT', 'SYNTHETIC_PRIVATE_CLAUDE_REPLY', 'claude-session-synthetic']) {
      assert.equal(serialized.includes(secret), false);
    }
    await assert.rejects(ingestCli([
      '--runtime', 'claude', '--file', path.join(fixtures, 'claude-synthetic.jsonl'),
      '--spool', path.join(root, 'other-spool'), '--cursors', path.join(root, 'other-cursors'),
      '--sink-module', path.join(fixtures, 'fake-sink.mjs')
    ], { AMF_OUTBOX_ENCRYPTION_KEY: KEY }), /sink_module_test_mode_only/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI is fixtures-only by default and rejects symlinks or unallowlisted live sources', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cli-policy-'));
  const live = path.join(root, 'live.jsonl');
  const link = path.join(root, 'linked.jsonl');
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), live);
  fs.symlinkSync(path.join(fixtures, 'claude-synthetic.jsonl'), link);
  const base = ['--runtime', 'claude', '--spool', path.join(root, 'spool'), '--cursors', path.join(root, 'cursors')];
  const env = { AMF_OUTBOX_ENCRYPTION_KEY: KEY };
  try {
    await assert.rejects(ingestCli([...base, '--file', live], env, { sink: new FakeRawEventSink() }), /live_source_opt_in_required/);
    await assert.rejects(ingestCli([...base, '--file', link], env, { sink: new FakeRawEventSink() }), /transcript_source_symlink_forbidden/);
    await assert.rejects(ingestCli([...base, '--file', live, '--allow-live-source', '--source-instance', 'host-a'], env, { sink: new FakeRawEventSink() }), /transcript_allowed_roots_invalid/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI live opt-in requires allowlists, an isolated realtime cursor and explicit tail bootstrap', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cli-live-'));
  const file = path.join(root, 'synthetic-live.jsonl');
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), file);
  const args = [
    '--runtime', 'claude', '--file', file, '--allow-live-source', '--source-instance', 'synthetic-host',
    '--spool', path.join(root, 'spool'), '--cursors', path.join(root, 'cursors')
  ];
  const env = {
    AMF_OUTBOX_ENCRYPTION_KEY: KEY,
    AMF_INGEST_DIGEST_KEY: KEY,
    AMF_INGEST_ACTOR_ID: 'synthetic-actor',
    AMF_TRANSCRIPT_ALLOWED_ROOTS: JSON.stringify([root]),
    AMF_TRANSCRIPT_SOURCE_INSTANCES: JSON.stringify(['synthetic-host'])
  };
  try {
    await assert.rejects(ingestCli(args, env, { sink: new FakeRawEventSink() }), /realtime_cursor_namespace_required/);
    const realtimeArgs = [...args, '--cursor-namespace', 'realtime'];
    await assert.rejects(ingestCli(realtimeArgs, env, { sink: new FakeRawEventSink() }), /realtime_cursor_uninitialized/);
    const seeded = await ingestCli([...realtimeArgs, '--bootstrap-tail'], env, { sink: new FakeRawEventSink() });
    assert.equal(seeded.bootstrapped, true);
    assert.equal(seeded.results.length, 0);
    fs.appendFileSync(file, '{"type":"user","uuid":"after-bootstrap","sessionId":"claude-session-synthetic","message":{"role":"user","content":"synthetic"}}\n');
    const result = await ingestCli(realtimeArgs, env, { sink: new FakeRawEventSink() });
    assert.equal(result.results.length, 1);
    const wrongInstance = realtimeArgs.map(value => value === 'synthetic-host' ? 'other-host' : value);
    await assert.rejects(ingestCli(wrongInstance, env, { sink: new FakeRawEventSink() }), /source_instance_not_allowlisted/);
    await assert.rejects(ingestCli([...realtimeArgs, '--test-mode', '--sink-module', path.join(fixtures, 'fake-sink.mjs')], env), /sink_module_test_mode_only/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI replay rejects an arbitrary spool before loading a test sink or reading encryption state', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-replay-exploit-'));
  const allowed = path.join(root, 'allowed');
  const arbitrary = path.join(root, 'arbitrary');
  const marker = path.join(root, 'sink-loaded');
  const maliciousSink = path.join(root, 'malicious-sink.mjs');
  const escapedLink = path.join(allowed, 'escape');
  fs.mkdirSync(allowed);
  fs.mkdirSync(arbitrary);
  fs.symlinkSync(arbitrary, escapedLink);
  fs.writeFileSync(maliciousSink, `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'loaded'); export default () => ({ deliver: async () => ({ acknowledged: true }) });\n`);
  try {
    await assert.rejects(ingestCli([
      '--replay', '--test-mode', '--spool', arbitrary, '--cursors', path.join(root, 'cursors'),
      '--sink-module', maliciousSink
    ], {
      AMF_TRANSCRIPT_TEST_SPOOL_ROOTS: JSON.stringify([allowed])
    }), /replay_spool_not_allowlisted/);
    assert.equal(fs.existsSync(marker), false, 'untrusted sink module must not be imported before the spool gate');
    await assert.rejects(ingestCli([
      '--replay', '--test-mode', '--spool', escapedLink, '--cursors', path.join(root, 'cursors'),
      '--sink-module', maliciousSink
    ], {
      AMF_TRANSCRIPT_TEST_SPOOL_ROOTS: JSON.stringify([allowed])
    }), /replay_spool_symlink_forbidden/);
    assert.equal(fs.existsSync(marker), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('CLI permits replay from an explicitly allowlisted fixture spool', async () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"type":"user","uuid":"cli-replay","sessionId":"cli-replay-session"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
    tree.outbox.enqueue(item);
    const result = await ingestCli([
      '--replay', '--test-mode', '--spool', path.join(tree.root, 'spool'), '--cursors', path.join(tree.root, 'cursors'),
      '--source-instance-id', 'synthetic-host',
      '--sink-module', path.join(fixtures, 'fake-sink.mjs')
    ], {
      AMF_OUTBOX_ENCRYPTION_KEY: KEY,
      AMF_INGEST_DIGEST_KEY: KEY,
      AMF_INGEST_ACTOR_ID: 'synthetic-actor',
      AMF_OUTBOX_KEY_ID: 'test-v1',
      AMF_TRANSCRIPT_TEST_SPOOL_ROOTS: JSON.stringify([tree.root])
    });
    assert.equal(result.replayed.length, 1);
    assert.equal(tree.outbox.isAcknowledged(item.event.eventId), true);
  } finally { tree.cleanup(); }
});

test('CLI live replay binds sourceInstanceId to an approved spool root and injected sink', async () => {
  const tree = tempTree();
  try {
    const raw = Buffer.from('{"type":"user","uuid":"live-replay","sessionId":"live-replay-session"}');
    const item = parseClaudeRecord({ value: JSON.parse(raw), rawBytes: raw, lineEnding: 'lf' });
    tree.outbox.enqueue(item);
    const args = [
      '--replay', '--allow-live-source', '--source-instance-id', 'synthetic-host',
      '--spool', path.join(tree.root, 'spool'), '--cursors', path.join(tree.root, 'cursors')
    ];
    const env = {
      AMF_OUTBOX_ENCRYPTION_KEY: KEY,
      AMF_INGEST_DIGEST_KEY: KEY,
      AMF_INGEST_ACTOR_ID: 'synthetic-actor',
      AMF_OUTBOX_KEY_ID: 'test-v1',
      AMF_TRANSCRIPT_SOURCE_INSTANCES: JSON.stringify(['synthetic-host']),
      AMF_TRANSCRIPT_LIVE_REPLAY_ROOTS: JSON.stringify({ 'synthetic-host': [tree.root] })
    };
    const result = await ingestCli(args, env, { sink: new FakeRawEventSink() });
    assert.equal(result.replayed.length, 1);
    await assert.rejects(ingestCli([
      ...args, '--sink-module', path.join(fixtures, 'fake-sink.mjs')
    ], env), /replay_sink_module_forbidden/);
  } finally { tree.cleanup(); }
});

test('backfill discovers deterministically, leases exclusively and deduplicates active/archive overlap', async () => {
  const tree = tempTree();
  const sourceRoot = path.join(tree.root, 'sources');
  const leasePath = path.join(tree.root, 'leases', 'backfill.lease');
  fs.mkdirSync(path.join(sourceRoot, 'archive'), { recursive: true });
  fs.mkdirSync(path.join(sourceRoot, 'active'), { recursive: true });
  const fixture = fs.readFileSync(path.join(fixtures, 'claude-synthetic.jsonl'));
  fs.writeFileSync(path.join(sourceRoot, 'archive', 'session.jsonl'), fixture);
  fs.writeFileSync(path.join(sourceRoot, 'active', 'session.jsonl'), fixture);
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    assert.deepEqual(discoverTranscriptFiles(sourceRoot).map(file => path.relative(sourceRoot, file)), ['active/session.jsonl', 'archive/session.jsonl']);
    const held = new BackfillLease({ leasePath }); held.acquire();
    await assert.rejects(runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor, leasePath }), /backfill_lease_held/);
    held.release();
    const first = await runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor, leasePath });
    assert.equal(first.files.length, 2);
    assert.equal(sink.deliveries.length, 2, 'overlapping copies must not redeliver');
    const second = await runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor, leasePath });
    assert.equal(second.totalEvents, 0, 'persistent cursors make reruns incremental');
    assert.equal(fs.existsSync(leasePath), false);
  } finally { tree.cleanup(); }
});

test('backfill drains every bounded chunk through EOF and persists the complete checkpoint', async () => {
  const tree = tempTree();
  const sourceRoot = path.join(tree.root, 'twenty');
  const leasePath = path.join(tree.root, 'leases', 'twenty.lease');
  fs.mkdirSync(sourceRoot);
  const lines = Array.from({ length: 20 }, (_, index) => JSON.stringify({
    type: 'user', uuid: `bounded-${index}`, sessionId: 'bounded-session', timestamp: `2026-07-12T00:${String(index).padStart(2, '0')}:00Z`,
    message: { role: 'user', content: `synthetic-${index}` }
  }));
  const file = path.join(sourceRoot, 'history.jsonl');
  fs.writeFileSync(file, `${lines.join('\n')}\n`);
  const maxBytes = Buffer.byteLength(`${lines[0]}\n`) + 4;
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink, maxBytes });
  try {
    const result = await runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor, leasePath });
    assert.equal(result.totalEvents, 20);
    assert.equal(result.files[0].result.results.length, 20);
    assert.ok(result.files[0].result.chunks.length > 1);
    const cursor = tree.cursors.read(sourceCursorKey('claude', 'claude:synthetic-host:history.jsonl'));
    assert.equal(cursor.offset, fs.statSync(file).size);
    let expected = tree.outbox.chainSeed();
    for (const line of lines) expected = tree.outbox.chainCheckpoint(expected, Buffer.from(`${line}\n`));
    assert.equal(cursor.consumedCheckpoint, expected);
    assert.equal((await runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor, leasePath })).totalEvents, 0);
  } finally { tree.cleanup(); }
});

test('backfill outage releases lease and retry resumes from encrypted outbox/cursor state', async () => {
  const tree = tempTree();
  const sourceRoot = path.join(tree.root, 'sources');
  const leasePath = path.join(tree.root, 'leases', 'backfill.lease');
  fs.mkdirSync(sourceRoot);
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), path.join(sourceRoot, 'session.jsonl'));
  try {
    const failed = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink: new FakeRawEventSink({ fail: new Error('synthetic_outage') }) });
    await assert.rejects(runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor: failed, leasePath }), /synthetic_outage/);
    assert.equal(fs.existsSync(leasePath), false);
    assert.equal(tree.outbox.pendingIds().length, 1);
    const sink = new FakeRawEventSink();
    const recovered = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
    await runTranscriptBackfill({ rootPath: sourceRoot, runtime: 'claude', sourceInstanceId: 'synthetic-host', ingestor: recovered, leasePath });
    assert.equal(sink.deliveries.length, 2);
  } finally { tree.cleanup(); }
});

test('CLI backfill requires allowlisted source, lease root and source instance', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cli-backfill-'));
  const sources = path.join(root, 'sources');
  const leases = path.join(root, 'leases');
  fs.mkdirSync(sources); fs.mkdirSync(leases);
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), path.join(sources, 'session.jsonl'));
  try {
    const result = await ingestCli([
      '--backfill', '--allow-live-source', '--runtime', 'claude', '--root', sources, '--lease', path.join(leases, 'run.lease'),
      '--source-instance-id', 'synthetic-host', '--spool', path.join(root, 'spool'), '--cursors', path.join(root, 'cursors'), '--cursor-namespace', 'backfill'
    ], {
      AMF_OUTBOX_ENCRYPTION_KEY: KEY,
      AMF_INGEST_DIGEST_KEY: KEY,
      AMF_INGEST_ACTOR_ID: 'synthetic-actor',
      AMF_TRANSCRIPT_ALLOWED_ROOTS: JSON.stringify([sources]),
      AMF_TRANSCRIPT_LEASE_ROOTS: JSON.stringify([leases]),
      AMF_TRANSCRIPT_SOURCE_INSTANCES: JSON.stringify(['synthetic-host'])
    }, { sink: new FakeRawEventSink() });
    assert.equal(result.files.length, 1);
    assert.equal(result.totalEvents, 2);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('backfill lease records PID/host/nonce, heartbeats, and only takes over stale dead owners', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-lease-v2-'));
  const leasePath = path.join(root, 'lease.json');
  let now = 1000;
  try {
    const live = new BackfillLease({ leasePath, staleMs: 1000, clock: () => now });
    live.acquire();
    let record = JSON.parse(fs.readFileSync(leasePath, 'utf8'));
    assert.equal(record.pid, process.pid);
    assert.equal(record.host, os.hostname());
    assert.match(record.nonce, /^[a-f0-9-]{36}$/);
    now = 3000;
    assert.throws(() => new BackfillLease({ leasePath, staleMs: 1000, clock: () => now }).acquire(), /backfill_lease_held/, 'live local PID cannot be stolen even with a stale heartbeat');
    live.heartbeat();
    record = JSON.parse(fs.readFileSync(leasePath, 'utf8'));
    assert.equal(record.heartbeatAt, 3000);
    live.release();

    fs.writeFileSync(leasePath, JSON.stringify({ version: 2, pid: 2147483647, host: 'remote-host', nonce: crypto.randomUUID(), acquiredAt: 0, heartbeatAt: 0 }));
    assert.throws(() => new BackfillLease({ leasePath, staleMs: 1000, clock: () => now }).acquire(), /backfill_lease_held/, 'a remote PID cannot be declared dead from this host');
    fs.rmSync(leasePath);

    fs.writeFileSync(leasePath, JSON.stringify({ version: 2, pid: 2147483647, host: os.hostname(), nonce: crypto.randomUUID(), acquiredAt: 0, heartbeatAt: 0 }));
    const takeover = new BackfillLease({ leasePath, staleMs: 1000, clock: () => now });
    takeover.acquire();
    assert.equal(JSON.parse(fs.readFileSync(leasePath, 'utf8')).nonce, takeover.owner.nonce);
    takeover.release();
    assert.equal(fs.existsSync(leasePath), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('backfill lease rejects path replacement without touching the external target', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-lease-replacement-'));
  const leasePath = path.join(root, 'lease.json');
  const originalPath = path.join(root, 'original.json');
  const externalPath = path.join(root, 'external.txt');
  const lease = new BackfillLease({ leasePath });
  try {
    fs.writeFileSync(externalPath, 'external-immutable');
    lease.acquire();
    fs.renameSync(leasePath, originalPath);
    fs.symlinkSync(externalPath, leasePath);
    assert.throws(() => lease.heartbeat(), /backfill_lease_owner_mismatch/);
    assert.throws(() => lease.release(), /backfill_lease_owner_mismatch/);
    assert.equal(fs.readFileSync(externalPath, 'utf8'), 'external-immutable');
  } finally {
    if (lease.fd !== null) fs.closeSync(lease.fd);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('bounded polling checks fixed windows while explicit full audit detects old middle rewrites', async () => {
  const tree = tempTree();
  const file = path.join(tree.root, 'large-history.jsonl');
  const make = (uuid, fill) => JSON.stringify({ type: 'user', uuid, sessionId: 'large-session', message: { role: 'user', content: fill.repeat(80000) } });
  const first = make('large-first', 'a');
  const middleA = make('large-middle-a', 'b');
  const middleB = middleA.replace('large-middle-a', 'large-middle-b');
  const final = make('large-final', 'c');
  const original = `${first}\n${middleA}\n${final}\n`;
  const replacement = `${first}\n${middleB}\n${final}\n`;
  assert.equal(Buffer.byteLength(original), Buffer.byteLength(replacement));
  fs.writeFileSync(file, original);
  const sink = new FakeRawEventSink();
  const ingestor = new TranscriptIngestor({ outbox: tree.outbox, cursorStore: tree.cursors, sink });
  try {
    await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'large-history' });
    fs.writeFileSync(file, replacement);
    const bounded = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'large-history' });
    assert.equal(bounded.auditMode, 'bounded');
    assert.equal(bounded.rotated, false, 'bounded polling deliberately avoids scanning old history');
    const audited = await ingestor.ingestFile({ runtime: 'claude', filePath: file, logicalSource: 'large-history', fullAudit: true });
    assert.equal(audited.auditMode, 'full');
    assert.equal(audited.rotated, true);
    assert.equal(sink.deliveries.length, 4);
  } finally { tree.cleanup(); }
});

test('CLI builds the production HTTPS ciphertext sink only from explicit environment', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-cli-http-'));
  const file = path.join(root, 'synthetic.jsonl');
  fs.copyFileSync(path.join(fixtures, 'claude-synthetic.jsonl'), file);
  const outboxRing = path.join(root, 'outbox-ring.json');
  const cursorRing = path.join(root, 'cursor-ring.json');
  fs.writeFileSync(outboxRing, JSON.stringify({ currentKeyId: 'test-v2', keys: { 'test-v1': KEY, 'test-v2': KEY2 } }));
  fs.writeFileSync(cursorRing, JSON.stringify({ currentKeyId: 'cursor-v2', keys: { 'cursor-v1': KEY, 'cursor-v2': KEY2 } }));
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (endpoint, options) => {
    const body = JSON.parse(options.body);
    requests.push({ endpoint, options, body });
    assert.equal(options.body.includes('SYNTHETIC_PRIVATE_CLAUDE_TEXT'), false);
    return { ok: true, async json() { return { ok: true, data: { status: 'stored', eventId: body.projection.eventId, idempotencyKey: body.projection.eventId } }; } };
  };
  try {
    const baseArgs = [
      '--runtime', 'claude', '--file', file, '--allow-live-source',
      '--spool', path.join(root, 'spool'), '--cursors', path.join(root, 'cursors'), '--cursor-namespace', 'realtime'
    ];
    const env = {
      AMF_OUTBOX_KEY_RING_PATH: outboxRing, AMF_CURSOR_KEY_RING_PATH: cursorRing,
      AMF_INGEST_DIGEST_KEY: KEY, AMF_INGEST_CHECKPOINT_KEY: CHECKPOINT_KEY, AMF_INGEST_ACTOR_ID: 'synthetic-actor',
      AMF_INGEST_SOURCE_INSTANCE_ID: 'synthetic-host',
      AMF_INGEST_ENDPOINT: 'https://fabric.example.test/v2/ingest/raw-events', AMF_INGEST_TOKEN: 'synthetic-token',
      AMF_TRANSCRIPT_ALLOWED_ROOTS: JSON.stringify([root]), AMF_TRANSCRIPT_SOURCE_INSTANCES: JSON.stringify(['synthetic-host'])
    };
    const seeded = await ingestCli([...baseArgs, '--bootstrap-tail'], env);
    assert.equal(seeded.results.length, 0);
    fs.appendFileSync(file, '{"type":"user","uuid":"http-after-bootstrap","sessionId":"claude-session-synthetic","message":{"role":"user","content":"SYNTHETIC_PRIVATE_CLAUDE_TEXT"}}\n');
    const result = await ingestCli(baseArgs, env);
    assert.equal(result.results.length, 1);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].options.redirect, 'error');
    assert.equal(requests[0].body.envelope.actorId, 'synthetic-actor');
    assert.equal(requests[0].body.envelope.sourceInstanceId, 'synthetic-host');
  } finally { globalThis.fetch = originalFetch; fs.rmSync(root, { recursive: true, force: true }); }
});
