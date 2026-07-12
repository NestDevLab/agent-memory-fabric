import fs from 'node:fs';

const utf8 = new TextDecoder('utf-8', { fatal: true });
export const MAX_TRANSCRIPT_JSONL_LINE_BYTES = 4 * 1024 * 1024;

function readWindow(filePath, start, length) {
  const buffer = Buffer.allocUnsafe(length);
  const fd = fs.openSync(filePath, 'r');
  try {
    const read = fs.readSync(fd, buffer, 0, length, start);
    return buffer.subarray(0, read);
  } finally { fs.closeSync(fd); }
}

export function tailBootstrapOffset(filePath, { maxLineBytes = MAX_TRANSCRIPT_JSONL_LINE_BYTES } = {}) {
  if (!Number.isSafeInteger(maxLineBytes) || maxLineBytes < 1 || maxLineBytes > MAX_TRANSCRIPT_JSONL_LINE_BYTES) throw new Error('transcript_line_limit_invalid');
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('transcript_source_not_file');
  if (stat.size === 0) return 0;
  const last = readWindow(filePath, stat.size - 1, 1);
  if (last[0] === 0x0a) return stat.size;
  const windowStart = Math.max(0, stat.size - maxLineBytes);
  const window = readWindow(filePath, windowStart, stat.size - windowStart);
  const newline = window.lastIndexOf(0x0a);
  if (newline >= 0) return windowStart + newline + 1;
  if (windowStart > 0) throw new Error('transcript_line_exceeds_batch_limit');
  return 0;
}

export function decodeJsonLine(bytes, { firstLine = false } = {}) {
  let text = utf8.decode(bytes);
  if (firstLine && text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  if (text.trim().length === 0) return null;
  try {
    return JSON.parse(text);
  } catch (cause) {
    const error = new Error('transcript_json_invalid', { cause });
    error.code = 'TRANSCRIPT_JSON_INVALID';
    throw error;
  }
}

export function readFirstCompleteJsonl(filePath, { maxBytes = MAX_TRANSCRIPT_JSONL_LINE_BYTES } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TRANSCRIPT_JSONL_LINE_BYTES) throw new Error('transcript_batch_limit_invalid');
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('transcript_source_not_file');
  const chunk = readWindow(filePath, 0, Math.min(stat.size, maxBytes));
  const newline = chunk.indexOf(0x0a);
  if (newline < 0) {
    if (stat.size >= maxBytes) throw new Error('transcript_line_exceeds_batch_limit');
    return null;
  }
  const crlf = newline > 0 && chunk[newline - 1] === 0x0d;
  const raw = Buffer.from(chunk.subarray(0, crlf ? newline - 1 : newline));
  return { raw, value: decodeJsonLine(raw, { firstLine: true }), startOffset: 0, nextOffset: newline + 1, lineEnding: crlf ? 'crlf' : 'lf' };
}

export function readCompleteJsonl(filePath, { offset = 0, maxBytes = MAX_TRANSCRIPT_JSONL_LINE_BYTES } = {}) {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('transcript_offset_invalid');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TRANSCRIPT_JSONL_LINE_BYTES) throw new Error('transcript_batch_limit_invalid');
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error('transcript_source_not_file');
  if (offset > stat.size) throw new Error('transcript_offset_past_end');
  const bytesToRead = Math.min(stat.size - offset, maxBytes);
  if (bytesToRead === 0) return { entries: [], offset, stat, partialBytes: 0 };
  const buffer = Buffer.allocUnsafe(bytesToRead);
  const fd = fs.openSync(filePath, 'r');
  let bytesRead;
  try {
    bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, offset);
  } finally {
    fs.closeSync(fd);
  }
  const chunk = buffer.subarray(0, bytesRead);
  const entries = [];
  let start = 0;
  for (let index = 0; index < chunk.length; index += 1) {
    if (chunk[index] !== 0x0a) continue;
    let end = index;
    if (end > start && chunk[end - 1] === 0x0d) end -= 1;
    const raw = Buffer.from(chunk.subarray(start, end));
    const lineStart = offset + start;
    const nextOffset = offset + index + 1;
    entries.push({
      raw,
      value: decodeJsonLine(raw, { firstLine: lineStart === 0 }),
      startOffset: lineStart,
      nextOffset,
      lineEnding: index > start && chunk[index - 1] === 0x0d ? 'crlf' : 'lf'
    });
    start = index + 1;
  }
  if (start === 0 && chunk.length === maxBytes && stat.size - offset > maxBytes) throw new Error('transcript_line_exceeds_batch_limit');
  return { entries, offset: offset + start, stat, partialBytes: chunk.length - start };
}
