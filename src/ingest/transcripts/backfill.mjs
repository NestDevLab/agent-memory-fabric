import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function safeInstance(value) {
  const id = String(value || '');
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) throw new Error('source_instance_invalid');
  return id;
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function writeDurable(target, record, { exclusive = false } = {}) {
  const directory = path.dirname(target);
  const temp = path.join(directory, `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(record)); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    if (exclusive) fs.linkSync(temp, target); else fs.renameSync(temp, target);
    fsyncDirectory(directory);
  } finally { if (fd !== undefined) fs.closeSync(fd); fs.rmSync(temp, { force: true }); }
}

function readLease(target) {
  let record;
  try { record = JSON.parse(fs.readFileSync(target, 'utf8')); } catch { throw new Error('backfill_lease_invalid'); }
  return validateLease(record);
}

function validateLease(record) {
  if (record?.version !== 2 || !Number.isSafeInteger(record.pid) || typeof record.host !== 'string' || !/^[a-f0-9-]{36}$/.test(String(record.nonce)) || !Number.isFinite(record.heartbeatAt)) throw new Error('backfill_lease_invalid');
  return record;
}

function readLeaseFd(fd) {
  const stat = fs.fstatSync(fd);
  if (!stat.isFile() || stat.size < 2 || stat.size > 16 * 1024) throw new Error('backfill_lease_invalid');
  const bytes = Buffer.allocUnsafe(stat.size);
  if (fs.readSync(fd, bytes, 0, bytes.length, 0) !== bytes.length) throw new Error('backfill_lease_invalid');
  try { return validateLease(JSON.parse(bytes.toString('utf8'))); }
  catch { throw new Error('backfill_lease_invalid'); }
}

function sameLease(left, right) {
  return left.pid === right.pid && left.host === right.host && left.nonce === right.nonce
    && left.acquiredAt === right.acquiredAt && left.heartbeatAt === right.heartbeatAt;
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === 'EPERM'; }
}

export function discoverTranscriptFiles(rootPath) {
  const root = fs.realpathSync(rootPath);
  if (path.resolve(rootPath) !== root || !fs.statSync(root).isDirectory()) throw new Error('backfill_root_unsafe');
  const files = [];
  const visit = directory => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const target = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('backfill_symlink_forbidden');
      if (entry.isDirectory()) visit(target);
      else if (entry.isFile() && entry.name.endsWith('.jsonl')) files.push(target);
    }
  };
  visit(root);
  return files.sort((a, b) => path.relative(root, a).localeCompare(path.relative(root, b)));
}

export class BackfillLease {
  constructor({ leasePath, staleMs = 60000, clock = () => Date.now(), pid = process.pid, host = os.hostname(), nonce = crypto.randomUUID() }) {
    if (!Number.isSafeInteger(staleMs) || staleMs < 1000) throw new Error('backfill_lease_stale_invalid');
    this.leasePath = path.resolve(leasePath); this.staleMs = staleMs; this.clock = clock;
    this.owner = { pid, host, nonce }; this.held = false; this.fd = null; this.identity = null;
  }
  record(acquiredAt = this.clock()) { return { version: 2, ...this.owner, acquiredAt, heartbeatAt: this.clock() }; }
  bindAcquiredLease() {
    let fd;
    try {
      fd = fs.openSync(this.leasePath, fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0));
      const stat = fs.fstatSync(fd);
      if (!stat.isFile()) throw new Error('backfill_lease_owner_mismatch');
      const record = readLeaseFd(fd);
      if (record.nonce !== this.owner.nonce || record.pid !== this.owner.pid || record.host !== this.owner.host) throw new Error('backfill_lease_owner_mismatch');
      this.fd = fd; this.identity = { dev: stat.dev, ino: stat.ino }; this.held = true; fd = null;
    } catch (error) {
      if (error?.code === 'ELOOP') throw new Error('backfill_lease_owner_mismatch');
      throw error;
    } finally { if (fd !== undefined && fd !== null) fs.closeSync(fd); }
  }
  assertPathIdentity() {
    if (this.fd === null || !this.identity) throw new Error('backfill_lease_not_held');
    let pathStat;
    try { pathStat = fs.lstatSync(this.leasePath); }
    catch { throw new Error('backfill_lease_owner_mismatch'); }
    const fdStat = fs.fstatSync(this.fd);
    if (!pathStat.isFile() || pathStat.isSymbolicLink() || pathStat.dev !== this.identity.dev || pathStat.ino !== this.identity.ino
      || fdStat.dev !== this.identity.dev || fdStat.ino !== this.identity.ino) throw new Error('backfill_lease_owner_mismatch');
  }
  acquire() {
    const directory = path.dirname(this.leasePath);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    try {
      writeDurable(this.leasePath, this.record(), { exclusive: true });
      this.bindAcquiredLease(); return;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    const existing = readLease(this.leasePath);
    const stale = this.clock() - existing.heartbeatAt > this.staleMs;
    const localOwner = existing.host === this.owner.host;
    const provablyDead = localOwner && !pidAlive(existing.pid);
    if (!stale || !provablyDead) throw new Error('backfill_lease_held');
    const tombstone = `${this.leasePath}.stale.${existing.nonce}`;
    try { fs.renameSync(this.leasePath, tombstone); fsyncDirectory(directory); }
    catch (error) { if (error?.code === 'ENOENT') throw new Error('backfill_lease_race'); throw error; }
    try {
      const moved = readLease(tombstone);
      if (!sameLease(existing, moved)) {
        try { fs.linkSync(tombstone, this.leasePath); fsyncDirectory(directory); }
        catch (error) { if (error?.code !== 'EEXIST') throw error; }
        throw new Error('backfill_lease_race');
      }
      writeDurable(this.leasePath, this.record(), { exclusive: true }); this.bindAcquiredLease();
    }
    finally { fs.rmSync(tombstone, { force: true }); fsyncDirectory(directory); }
  }
  heartbeat() {
    if (!this.held) throw new Error('backfill_lease_not_held');
    this.assertPathIdentity();
    try {
      const current = readLeaseFd(this.fd);
      if (current.nonce !== this.owner.nonce || current.pid !== this.owner.pid || current.host !== this.owner.host) throw new Error('backfill_lease_owner_mismatch');
      const bytes = Buffer.from(JSON.stringify({ ...current, heartbeatAt: this.clock() }), 'utf8');
      fs.ftruncateSync(this.fd, 0); fs.writeSync(this.fd, bytes, 0, bytes.length, 0); fs.fsyncSync(this.fd);
    } catch (error) {
      if (error?.code === 'ENOENT') throw new Error('backfill_lease_owner_mismatch');
      throw error;
    }
  }
  release() {
    if (!this.held) return;
    this.assertPathIdentity();
    const record = readLeaseFd(this.fd);
    if (record.nonce !== this.owner.nonce || record.pid !== this.owner.pid || record.host !== this.owner.host) throw new Error('backfill_lease_owner_mismatch');
    fs.rmSync(this.leasePath); fsyncDirectory(path.dirname(this.leasePath));
    fs.closeSync(this.fd); this.fd = null; this.identity = null; this.held = false;
  }
}

export async function runTranscriptBackfill({ rootPath, runtime, sourceInstanceId, ingestor, leasePath, cursorNamespace = 'default', fullAudit = false }) {
  if (!['codex', 'claude'].includes(runtime)) throw new Error('transcript_runtime_unsupported');
  sourceInstanceId = safeInstance(sourceInstanceId);
  const root = fs.realpathSync(rootPath);
  const lease = new BackfillLease({ leasePath });
  lease.acquire();
  const results = [];
  try {
    lease.heartbeat();
    for (const filePath of discoverTranscriptFiles(root)) {
      const relative = path.relative(root, filePath);
      const chunks = [];
      const events = [];
      let previousOffset = -1;
      let latest;
      do {
        latest = await ingestor.ingestFile({ runtime, filePath, logicalSource: `${runtime}:${sourceInstanceId}:${relative}`, cursorNamespace, fullAudit });
        chunks.push({ offset: latest.offset, partialBytes: latest.partialBytes, events: latest.results.length });
        events.push(...latest.results);
        if (latest.offset === previousOffset) break;
        previousOffset = latest.offset;
        lease.heartbeat();
      } while (true);
      results.push({ file: relative, result: { ...latest, results: events, chunks } });
      lease.heartbeat();
    }
    return { runtime, sourceInstanceId, cursorNamespace, fullAudit, files: results, totalEvents: results.reduce((sum, entry) => sum + entry.result.results.length, 0) };
  } finally { lease.release(); }
}
