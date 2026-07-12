import fs from 'node:fs';
import path from 'node:path';

import { parseClaudeRecord, claudeSessionHint } from './claude.mjs';
import { parseCodexRecord, codexSessionHint } from './codex.mjs';
import { sourceCursorKey } from './cursor-store.mjs';
import { readCompleteJsonl } from './jsonl-tail.mjs';

const ADAPTERS = {
  codex: { parse: parseCodexRecord, sessionHint: codexSessionHint },
  claude: { parse: parseClaudeRecord, sessionHint: claudeSessionHint }
};

function pathResolveSafe(filePath) {
  const requested = path.resolve(filePath);
  const stat = fs.lstatSync(requested);
  if (stat.isSymbolicLink() || !stat.isFile() || fs.realpathSync(requested) !== requested) throw new Error('transcript_source_unsafe');
  return requested;
}

function fileIdentity(stat) { return `${stat.dev}:${stat.ino}`; }

function readRange(filePath, start, end) {
  const length = end - start;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || length <= 0) return null;
  const buffer = Buffer.allocUnsafe(length);
  const fd = fs.openSync(filePath, 'r');
  try {
    const read = fs.readSync(fd, buffer, 0, length, start);
    return read === length ? buffer : null;
  } finally { fs.closeSync(fd); }
}

function checkpointBytes(entry) {
  return Buffer.concat([entry.raw, Buffer.from(entry.lineEnding === 'crlf' ? '\r\n' : '\n')]);
}

function prefixCheckpoint(outbox, filePath, length) {
  if (length === 0) return null;
  const bytes = readRange(filePath, 0, length);
  return bytes ? outbox.checkpoint(bytes) : null;
}

function consumedCheckpoint(outbox, filePath, length) {
  let chain = outbox.chainSeed();
  if (length === 0) return chain;
  const fd = fs.openSync(filePath, 'r');
  let position = 0;
  let carry = Buffer.alloc(0);
  try {
    while (position < length) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, length - position));
      const bytesRead = fs.readSync(fd, chunk, 0, chunk.length, position);
      if (bytesRead === 0) throw new Error('transcript_checkpoint_short_read');
      position += bytesRead;
      const data = carry.length ? Buffer.concat([carry, chunk.subarray(0, bytesRead)]) : chunk.subarray(0, bytesRead);
      let start = 0;
      for (let index = 0; index < data.length; index += 1) {
        if (data[index] !== 0x0a) continue;
        chain = outbox.chainCheckpoint(chain, data.subarray(start, index + 1));
        start = index + 1;
      }
      carry = Buffer.from(data.subarray(start));
    }
  } finally { fs.closeSync(fd); }
  if (carry.length !== 0) throw new Error('transcript_checkpoint_not_line_aligned');
  return chain;
}

function tailWindow(outbox, filePath, offset) {
  if (offset === 0) return { tailWindowStart: 0, tailWindowCheckpoint: null };
  const tailWindowStart = Math.max(0, offset - 64 * 1024);
  const bytes = readRange(filePath, tailWindowStart, offset);
  return { tailWindowStart, tailWindowCheckpoint: bytes ? outbox.checkpoint(bytes) : null };
}

export class TranscriptIngestor {
  constructor({ outbox, cursorStore, sink, maxBytes }) {
    this.outbox = outbox;
    this.cursorStore = cursorStore;
    this.sink = sink;
    this.maxBytes = maxBytes;
  }

  async ingestFile({ runtime, filePath, logicalSource = filePath, sessionHint = null, fullAudit = false }) {
    const adapter = ADAPTERS[runtime];
    if (!adapter) throw new Error('transcript_runtime_unsupported');
    const resolvedPath = pathResolveSafe(filePath);
    filePath = resolvedPath;
    const stat = fs.statSync(filePath);
    const key = sourceCursorKey(runtime, logicalSource);
    const previous = this.cursorStore.read(key);
    const identity = fileIdentity(stat);
    let rotated = Boolean(previous && (previous.fileIdentity !== identity || stat.size < previous.offset));
    if (fullAudit && previous && !rotated && previous.consumedCheckpoint) {
      if (consumedCheckpoint(this.outbox, filePath, previous.offset) !== previous.consumedCheckpoint) rotated = true;
    }
    if (previous && !rotated && previous.tailWindowCheckpoint && previous.tailWindowStart < previous.offset) {
      const tail = readRange(filePath, previous.tailWindowStart, previous.offset);
      if (!tail || this.outbox.checkpoint(tail) !== previous.tailWindowCheckpoint) rotated = true;
    }
    if (previous && !rotated && previous.prefixLength > 0) {
      const currentPrefix = prefixCheckpoint(this.outbox, filePath, previous.prefixLength);
      if (!currentPrefix || currentPrefix !== previous.prefixCheckpoint) rotated = true;
    }
    if (previous && !rotated && previous.checkpoint && previous.checkpointStart < previous.offset) {
      const boundary = readRange(filePath, previous.checkpointStart, previous.offset);
      if (!boundary || this.outbox.checkpoint(boundary) !== previous.checkpoint) rotated = true;
    }
    const newCursor = generation => {
      const prefixLength = Math.min(stat.size, 4096);
      return {
        version: 1, runtime, generation, fileIdentity: identity, offset: 0, sessionHint,
        prefixLength, prefixCheckpoint: prefixCheckpoint(this.outbox, filePath, prefixLength),
        consumedCheckpoint: this.outbox.chainSeed()
      };
    };
    let cursor = rotated
      ? newCursor(previous.generation + 1)
      : previous || newCursor(0);
    if (!cursor.consumedCheckpoint) cursor = { ...cursor, consumedCheckpoint: consumedCheckpoint(this.outbox, filePath, cursor.offset) };
    if (!cursor.sessionHint && sessionHint) cursor.sessionHint = sessionHint;
    if (!previous || rotated) this.cursorStore.write(key, cursor);
    const batch = readCompleteJsonl(filePath, { offset: cursor.offset, maxBytes: this.maxBytes });
    const results = [];
    for (const entry of batch.entries) {
      if (entry.value === null) {
        cursor = {
          ...cursor, offset: entry.nextOffset, checkpointStart: entry.startOffset,
          checkpoint: this.outbox.checkpoint(checkpointBytes(entry)),
          consumedCheckpoint: this.outbox.chainCheckpoint(cursor.consumedCheckpoint, checkpointBytes(entry)),
          ...tailWindow(this.outbox, filePath, entry.nextOffset)
        };
        this.cursorStore.write(key, cursor);
        continue;
      }
      const discovered = adapter.sessionHint(entry.value);
      if (discovered) cursor = { ...cursor, sessionHint: discovered };
      const item = adapter.parse({
        value: entry.value, rawBytes: entry.raw, lineEnding: entry.lineEnding, sessionHint: cursor.sessionHint
      });
      const queued = this.outbox.enqueue(item);
      const delivered = queued.state === 'acknowledged'
        ? queued
        : await this.outbox.deliver(item.event.eventId, this.sink);
      cursor = {
        ...cursor, offset: entry.nextOffset, checkpointStart: entry.startOffset,
        checkpoint: this.outbox.checkpoint(checkpointBytes(entry)),
        consumedCheckpoint: this.outbox.chainCheckpoint(cursor.consumedCheckpoint, checkpointBytes(entry)),
        ...tailWindow(this.outbox, filePath, entry.nextOffset)
      };
      this.cursorStore.write(key, cursor);
      results.push({ eventId: item.event.eventId, projection: item.projection, delivered });
    }
    return {
      runtime, sourceKey: key, generation: cursor.generation, offset: cursor.offset,
      partialBytes: batch.partialBytes, rotated, auditMode: fullAudit ? 'full' : 'bounded', results
    };
  }
}
