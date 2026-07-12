import fs from 'node:fs';

const utf8 = new TextDecoder('utf-8', { fatal: true });

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

export function readCompleteJsonl(filePath, { offset = 0, maxBytes = 8 * 1024 * 1024 } = {}) {
  if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('transcript_offset_invalid');
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
