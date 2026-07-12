import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import Database from 'better-sqlite3';
import { validateAmfMemoryRecord } from './amf-memory-record-validator.mjs';

const ACTIVE = new Set(['active']);
const DECISION_STATUSES = new Set(['review_required', 'approved_pending_apply', 'rejected']);
const RECEIPT_FIELDS = {
  decision: ['kind', 'proposalId', 'decisionId', 'status', 'decisionDigest', 'proposalDigest', 'policyDigest', 'timestamp'],
  apply: ['kind', 'proposalId', 'decisionId', 'decisionDigest', 'policyDigestAtApply', 'canonicalRecordId', 'revision', 'canonicalLifecycleAtDecision', 'proposalDigest', 'archiveDigest', 'targetDigest', 'timestamp']
};

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function exactFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join('\0') === [...fields].sort().join('\0');
}

function digest(value) { return crypto.createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex'); }
function validDigest(value) { return /^[a-f0-9]{64}$/.test(String(value || '')); }
function validTimestamp(value) { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }

export function validateCuratorReceipt(receipt) {
  const fields = RECEIPT_FIELDS[receipt?.kind];
  if (!fields || !exactFields(receipt, fields)) throw new Error('receipt_invalid');
  if (!receipt.proposalId || !receipt.decisionId || !validTimestamp(receipt.timestamp)) throw new Error('receipt_invalid');
  if (receipt.kind === 'decision') {
    if (!DECISION_STATUSES.has(receipt.status) || ![receipt.decisionDigest, receipt.proposalDigest, receipt.policyDigest].every(validDigest)) throw new Error('receipt_invalid');
    if (receipt.decisionDigest !== digest({ proposalId: receipt.proposalId, decisionId: receipt.decisionId, status: receipt.status, proposalDigest: receipt.proposalDigest, policyDigest: receipt.policyDigest })) throw new Error('receipt_invalid');
  } else if (!receipt.canonicalRecordId || !Number.isSafeInteger(receipt.revision) || receipt.revision < 1 || !['active', 'superseded', 'revoked', 'expired'].includes(receipt.canonicalLifecycleAtDecision) || ![receipt.decisionDigest, receipt.policyDigestAtApply, receipt.proposalDigest, receipt.archiveDigest, receipt.targetDigest].every(validDigest)) throw new Error('receipt_invalid');
  return structuredClone(receipt);
}

export class MemoryReceiptLedger {
  constructor() { this.records = new Map(); }
  get(proposalId) { return this.records.get(proposalId) ? structuredClone(this.records.get(proposalId)) : null; }
  recordDecision(receipt) {
    const current = this.records.get(receipt.proposalId);
    if (current?.decision) {
      if (canonicalJson(current.decision) !== canonicalJson(receipt)) throw new Error('receipt_conflict');
      return { ...structuredClone(current), duplicate: true };
    }
    const record = { proposalId: receipt.proposalId, status: receipt.status, decision: structuredClone(receipt), apply: null };
    this.records.set(receipt.proposalId, record);
    return { ...structuredClone(record), duplicate: false };
  }
  recordApply(receipt) {
    const current = this.records.get(receipt.proposalId);
    if (!current?.decision || current.decision.status !== 'approved_pending_apply') throw new Error('receipt_transition_invalid');
    if (current.apply) {
      if (canonicalJson(current.apply) !== canonicalJson(receipt)) throw new Error('receipt_conflict');
      return { ...structuredClone(current), duplicate: true };
    }
    current.status = 'promoted'; current.apply = structuredClone(receipt);
    return { ...structuredClone(current), duplicate: false };
  }
  list() { return [...this.records.values()].map(item => structuredClone(item)); }
}

export class SqliteReceiptLedger {
  constructor({ databasePath }) {
    fs.mkdirSync(path.dirname(path.resolve(databasePath)), { recursive: true, mode: 0o700 });
    this.db = new Database(path.resolve(databasePath));
    this.db.pragma('journal_mode = WAL');
    this.db.exec('CREATE TABLE IF NOT EXISTS curator_receipt_state_v1 (proposal_id TEXT PRIMARY KEY, status TEXT NOT NULL, decision_json TEXT NOT NULL, apply_json TEXT)');
    this.insertDecision = this.db.transaction(receipt => {
      const current = this.get(receipt.proposalId);
      if (current) {
        if (canonicalJson(current.decision) !== canonicalJson(receipt)) throw new Error('receipt_conflict');
        return { ...current, duplicate: true };
      }
      this.db.prepare('INSERT INTO curator_receipt_state_v1(proposal_id,status,decision_json,apply_json) VALUES (?,?,?,NULL)').run(receipt.proposalId, receipt.status, JSON.stringify(receipt));
      return { ...this.get(receipt.proposalId), duplicate: false };
    });
    this.insertApply = this.db.transaction(receipt => {
      const current = this.get(receipt.proposalId);
      if (!current?.decision || current.decision.status !== 'approved_pending_apply') throw new Error('receipt_transition_invalid');
      if (current.apply) {
        if (canonicalJson(current.apply) !== canonicalJson(receipt)) throw new Error('receipt_conflict');
        return { ...current, duplicate: true };
      }
      this.db.prepare("UPDATE curator_receipt_state_v1 SET status='promoted',apply_json=? WHERE proposal_id=? AND apply_json IS NULL").run(JSON.stringify(receipt), receipt.proposalId);
      return { ...this.get(receipt.proposalId), duplicate: false };
    });
  }
  get(proposalId) { const row = this.db.prepare('SELECT * FROM curator_receipt_state_v1 WHERE proposal_id=?').get(proposalId); return row ? { proposalId: row.proposal_id, status: row.status, decision: JSON.parse(row.decision_json), apply: row.apply_json ? JSON.parse(row.apply_json) : null } : null; }
  recordDecision(receipt) { return this.insertDecision(receipt); }
  recordApply(receipt) { return this.insertApply(receipt); }
  list() { return this.db.prepare('SELECT * FROM curator_receipt_state_v1 ORDER BY proposal_id').all().map(row => ({ proposalId: row.proposal_id, status: row.status, decision: JSON.parse(row.decision_json), apply: row.apply_json ? JSON.parse(row.apply_json) : null })); }
  close() { this.db.close(); }
}

export class CuratorReceiptCoordinator {
  constructor({ ledger, canonicalStore, proposalStore = null }) { this.ledger = ledger; this.canonicalStore = canonicalStore; this.proposalStore = proposalStore; }
  async record(receipt) {
    const valid = validateCuratorReceipt(receipt);
    if (valid.kind === 'decision') {
      if (this.proposalStore) {
        const proposal = await this.proposalStore.readProposal(valid.proposalId);
        if (!proposal?.payload || digest(proposal.payload) !== valid.proposalDigest) throw new Error('receipt_proposal_unverified');
      }
      return this.ledger.recordDecision(valid);
    }
    const current = this.ledger.get(valid.proposalId);
    if (!current?.decision || current.decision.decisionId !== valid.decisionId || current.decision.decisionDigest !== valid.decisionDigest || current.decision.proposalDigest !== valid.proposalDigest || current.decision.policyDigest !== valid.policyDigestAtApply) throw new Error('receipt_transition_invalid');
    const record = await this.canonicalStore.read({ id: valid.canonicalRecordId });
    if (!record || record.id !== valid.canonicalRecordId || record.revision !== valid.revision || record.lifecycle?.status !== valid.canonicalLifecycleAtDecision || digest(record) !== valid.targetDigest) throw new Error('canonical_apply_unverified');
    if (this.canonicalStore.verifyApplyReceipt && !(await this.canonicalStore.verifyApplyReceipt(valid))) throw new Error('canonical_apply_unverified');
    return this.ledger.recordApply(valid);
  }
  async reconcile() {
    const findings = [];
    for (const row of this.ledger.list()) {
      if (row.status === 'promoted') {
        try { await this.canonicalStore.read({ id: row.apply.canonicalRecordId }); }
        catch { findings.push({ proposalId: row.proposalId, code: 'canonical_target_missing' }); }
      } else if (row.status === 'approved_pending_apply') findings.push({ proposalId: row.proposalId, code: 'apply_receipt_pending' });
    }
    return { ok: findings.length === 0, findings };
  }
}

function unwrapToolResult(result) {
  const text = result?.content?.find(item => item?.type === 'text')?.text;
  if (typeof text !== 'string') throw new Error('pam_response_invalid');
  try { return JSON.parse(text); } catch { throw new Error('pam_response_invalid'); }
}

export class PamMcpProcessClient {
  constructor({ serverPath, workspace, nodePath = process.execPath, timeoutMs = 5000, maxResponseBytes = 1024 * 1024 }) {
    this.serverPath = serverPath; this.workspace = workspace; this.nodePath = nodePath; this.timeoutMs = timeoutMs; this.maxResponseBytes = maxResponseBytes;
    this.nextId = 1; this.pending = new Map(); this.buffer = ''; this.started = false;
  }
  async start() {
    if (this.started) return;
    this.child = spawn(this.nodePath, [this.serverPath, '--workspace', this.workspace], { stdio: ['pipe', 'pipe', 'pipe'], shell: false });
    this.started = true;
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', chunk => this._data(chunk));
    this.child.on('exit', () => { for (const entry of this.pending.values()) entry.reject(new Error('pam_process_exited')); this.pending.clear(); this.started = false; });
    await this._request('initialize', { protocolVersion: '2024-11-05' });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }
  _data(chunk) {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer, 'utf8') > this.maxResponseBytes) { this.child.kill(); return; }
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline); this.buffer = this.buffer.slice(newline + 1);
      if (!line.trim()) continue;
      let frame; try { frame = JSON.parse(line); } catch { this.child.kill(); return; }
      const pending = this.pending.get(frame.id); if (!pending) continue;
      clearTimeout(pending.timer); this.pending.delete(frame.id);
      frame.error ? pending.reject(new Error(frame.error.message || 'pam_call_failed')) : pending.resolve(frame.result);
    }
  }
  _request(method, params = undefined) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('pam_call_timeout')); this.child?.kill(); }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) })}\n`);
    });
  }
  async callTool(name, args) { await this.start(); return unwrapToolResult(await this._request('tools/call', { name, arguments: args })); }
  async close() { if (!this.child) return; this.child.stdin.end(); this.child.kill(); this.started = false; }
}

export class CanonicalPamBridge {
  constructor({ callTool, index }) { this.callTool = callTool; this.index = index || { records: {} }; this.configured = true; }
  async read({ id }) {
    const entry = this.index.records?.[id];
    if (!entry?.path) throw Object.assign(new Error('memory_not_found'), { status: 404 });
    const result = await this.callTool('memory_read', { path: entry.path });
    const record = result.record || (typeof result.content === 'string' ? JSON.parse(result.content) : null);
    if (!record || record.id !== id || !validateAmfMemoryRecord(record).ok) throw new Error('pam_record_binding_invalid');
    return structuredClone(record);
  }
  async search({ query, scopes, limit = 20 }) {
    const allowed = new Set(scopes);
    const entries = Object.entries(this.index.records || {}).filter(([, entry]) => allowed.has(entry.scope)).slice(0, 1000);
    const paths = [...new Set(entries.map(([, entry]) => entry.path))];
    if (!paths.length) return { items: [], nextCursor: null };
    const result = await this.callTool('memory_search', { query, paths, maxResults: Math.min(limit * 4, 100) });
    const ids = new Set((result.results || result.items || []).flatMap(hit => entries.filter(([, entry]) => entry.path === hit.path).map(([id]) => id)));
    const records = [];
    for (const id of ids) {
      const record = await this.read({ id });
      const now = Date.now(); const validFrom = Date.parse(record.lifecycle?.validFrom || '1970-01-01T00:00:00Z'); const validTo = record.lifecycle?.validTo ? Date.parse(record.lifecycle.validTo) : Infinity;
      if (ACTIVE.has(record.lifecycle?.status) && validFrom <= now && validTo > now) records.push(record);
      if (records.length >= limit) break;
    }
    return { items: records, nextCursor: null };
  }
}

export function createUnconfiguredCanonicalStore() {
  const fail = async () => { throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 }); };
  return { configured: false, search: fail, read: fail };
}

export function createCanonicalPamBridgeFromEnv(env = process.env) {
  const serverPath = String(env.AMF_PAM_MCP_SERVER_PATH || '').trim();
  const workspace = String(env.AMF_PAM_WORKSPACE || '').trim();
  const indexPath = String(env.AMF_PAM_RECORD_INDEX_PATH || '').trim();
  if (!serverPath || !workspace || !indexPath) return createUnconfiguredCanonicalStore();
  let index;
  try { index = JSON.parse(fs.readFileSync(path.resolve(indexPath), 'utf8')); } catch { throw new Error('pam_record_index_invalid'); }
  if (!index?.records || typeof index.records !== 'object') throw new Error('pam_record_index_invalid');
  const client = new PamMcpProcessClient({ serverPath: path.resolve(serverPath), workspace: path.resolve(workspace) });
  const bridge = new CanonicalPamBridge({ callTool: client.callTool.bind(client), index });
  bridge.kind = 'pam-stdio';
  bridge.close = () => client.close();
  return bridge;
}

export function createReceiptCoordinatorFromEnv({ env = process.env, canonicalStore, proposalStore }) {
  const databasePath = String(env.AMF_RECEIPT_LEDGER_PATH || '').trim();
  if (!databasePath) return null;
  const ledger = new SqliteReceiptLedger({ databasePath });
  const coordinator = new CuratorReceiptCoordinator({ ledger, canonicalStore, proposalStore });
  coordinator.close = () => ledger.close();
  return coordinator;
}
