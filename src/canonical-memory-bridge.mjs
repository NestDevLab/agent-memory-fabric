import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { validateAmfMemoryRecord } from './amf-memory-record-validator.mjs';
import { normalizeOpaqueTagMap } from './access-contract.mjs';
import { createSemanticIndexFromEnv } from './semantic-index.mjs';

const ACTIVE = new Set(['active']);
const DECISION_STATUSES = new Set(['review_required', 'approved_pending_apply', 'rejected']);
const RECONCILE_MAX_PAGE_SIZE = 100;
const RECEIPT_FIELDS = {
  decision: ['kind', 'proposalId', 'proposalScope', 'decisionId', 'status', 'decisionDigest', 'proposalDigest', 'policyDigest', 'timestamp'],
  apply: ['kind', 'proposalId', 'proposalScope', 'decisionId', 'decisionDigest', 'policyDigestAtApply', 'canonicalRecordId', 'revision', 'canonicalLifecycleAtDecision', 'proposalDigest', 'archiveDigest', 'targetDigest', 'timestamp']
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

const CONTEXT_REF_KEYS = new Set(['conversation', 'room', 'person', 'relationship', 'thread']);

function secureJsonFile(filename, label) {
  const absolute = path.resolve(filename);
  const parent = path.dirname(absolute);
  const basename = path.basename(absolute);
  let parentFd; let fd;
  try {
    parentFd = fs.openSync(parent, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
    const parentStat = fs.fstatSync(parentFd);
    const parentHandle = `/proc/self/fd/${parentFd}`;
    if (!parentStat.isDirectory() || (parentStat.mode & 0o022) !== 0
        || (typeof process.geteuid === 'function' && parentStat.uid !== process.geteuid())
        || fs.realpathSync(parentHandle) !== parent) throw new Error('unsafe_parent');
    fd = fs.openSync(`${parentHandle}/${basename}`, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600
        || (typeof process.geteuid === 'function' && stat.uid !== process.geteuid())) throw new Error('unsafe_file');
    if (stat.size < 2 || stat.size > 8 * 1024 * 1024) throw new Error('unsafe_size');
    return JSON.parse(fs.readFileSync(fd, 'utf8'));
  } catch {
    throw new Error(`${label}_invalid`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (parentFd !== undefined) fs.closeSync(parentFd);
  }
}

function normalizeRoutingKeyRing(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.currentKeyVersion !== 'string' || !value.keys || typeof value.keys !== 'object' || Array.isArray(value.keys)) throw new Error('pam_routing_key_ring_invalid');
  const keys = new Map();
  for (const [version, encoded] of Object.entries(value.keys)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(version) || typeof encoded !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(encoded)) throw new Error('pam_routing_key_ring_invalid');
    const key = Buffer.from(encoded, 'base64');
    if (key.length !== 32 || key.toString('base64') !== encoded) throw new Error('pam_routing_key_ring_invalid');
    keys.set(version, key);
  }
  if (!keys.has(value.currentKeyVersion)) throw new Error('pam_routing_key_ring_invalid');
  return { currentKeyVersion: value.currentKeyVersion, keys };
}

function normalizeContextRefs(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('pam_record_index_invalid');
  const result = {};
  for (const key of Object.keys(value).sort()) {
    const refs = value[key];
    if (!CONTEXT_REF_KEYS.has(key) || !Array.isArray(refs) || refs.length < 1
        || refs.some(ref => typeof ref !== 'string' || ref.length < 1 || ref.length > 256 || /[\r\n\0]/.test(ref))) throw new Error('pam_record_index_invalid');
    const normalized = [...new Set(refs)].sort();
    if (canonicalJson(normalized) !== canonicalJson(refs)) throw new Error('pam_record_index_invalid');
    result[key] = normalized;
  }
  if (!Object.keys(result).length) throw new Error('pam_record_index_invalid');
  return result;
}

function deriveContextTags(refs, routingKeys) {
  if (!routingKeys) throw new Error('pam_routing_key_ring_unconfigured');
  const tags = {};
  for (const [namespace, literals] of Object.entries(normalizeContextRefs(refs))) {
    tags[namespace] = [...routingKeys.keys.entries()].flatMap(([version, key]) => literals.map(literal => {
      const digestValue = crypto.createHmac('sha256', key).update(canonicalJson([namespace, literal]), 'utf8').digest('hex');
      return `hmac-sha256:${version}:${digestValue}`;
    })).sort();
  }
  return normalizeOpaqueTagMap(tags);
}

function normalizeRecordIndex(value, routingKeys, { allowLegacyContextTags = false } = {}) {
  if (!value?.records || typeof value.records !== 'object' || Array.isArray(value.records)) throw new Error('pam_record_index_invalid');
  const records = {};
  for (const [id, input] of Object.entries(value.records)) {
    if (!input || typeof input !== 'object' || Array.isArray(input) || typeof input.path !== 'string' || typeof input.scope !== 'string'
        || path.isAbsolute(input.path) || input.path.split(/[\\/]/).includes('..')) throw new Error('pam_record_index_invalid');
    const allowed = new Set(['path', 'scope', 'contextRefs', 'contextTags']);
    if (Object.keys(input).some(key => !allowed.has(key)) || (input.contextRefs && input.contextTags)) throw new Error('pam_record_index_invalid');
    const entry = { path: input.path, scope: input.scope };
    if (input.contextRefs) { entry.contextRefs = normalizeContextRefs(input.contextRefs); entry.contextTags = deriveContextTags(entry.contextRefs, routingKeys); }
    else if (input.contextTags && allowLegacyContextTags) entry.contextTags = normalizeOpaqueTagMap(input.contextTags);
    else if (input.contextTags) throw new Error('pam_record_index_legacy_context_tags_forbidden');
    if (/^(?:person|relationship|room):/.test(input.scope) && !input.contextRefs && !(allowLegacyContextTags && input.contextTags)) throw new Error('pam_record_index_sensitive_context_refs_required');
    records[id] = entry;
  }
  return { records };
}

function decodeCursor(cursor, binding) {
  if (!cursor) return 0;
  if (typeof cursor !== 'string' || !cursor.startsWith('amf-cur-v1.')) throw Object.assign(new Error('invalid_request'), { status: 400 });
  let parsed;
  try { parsed = JSON.parse(Buffer.from(cursor.slice(11), 'base64url').toString('utf8')); } catch { throw Object.assign(new Error('invalid_request'), { status: 400 }); }
  if (!exactFields(parsed, ['offset', 'binding']) || !Number.isSafeInteger(parsed.offset) || parsed.offset < 0 || parsed.binding !== binding) throw Object.assign(new Error('invalid_request'), { status: 400 });
  return parsed.offset;
}

function encodeCursor(offset, binding) { return `amf-cur-v1.${Buffer.from(JSON.stringify({ offset, binding })).toString('base64url')}`; }

export function validateCuratorReceipt(receipt) {
  const fields = RECEIPT_FIELDS[receipt?.kind];
  if (!fields || !exactFields(receipt, fields)) throw new Error('receipt_invalid');
  if (!receipt.proposalId || !receipt.decisionId || typeof receipt.proposalScope !== 'string' || receipt.proposalScope.length < 3
      || receipt.proposalScope.length > 256 || /[\r\n\0]/.test(receipt.proposalScope) || !validTimestamp(receipt.timestamp)) throw new Error('receipt_invalid');
  if (receipt.kind === 'decision') {
    if (!DECISION_STATUSES.has(receipt.status) || ![receipt.decisionDigest, receipt.proposalDigest, receipt.policyDigest].every(validDigest)) throw new Error('receipt_invalid');
    if (receipt.decisionDigest !== digest({ proposalId: receipt.proposalId, proposalScope: receipt.proposalScope, decisionId: receipt.decisionId, status: receipt.status, proposalDigest: receipt.proposalDigest, policyDigest: receipt.policyDigest })) throw new Error('receipt_invalid');
  } else if (!receipt.canonicalRecordId || !Number.isSafeInteger(receipt.revision) || receipt.revision < 1 || !['active', 'superseded', 'revoked', 'expired'].includes(receipt.canonicalLifecycleAtDecision) || ![receipt.decisionDigest, receipt.policyDigestAtApply, receipt.proposalDigest, receipt.archiveDigest, receipt.targetDigest].every(validDigest)) throw new Error('receipt_invalid');
  return structuredClone(receipt);
}

export class MemoryReceiptLedger {
  constructor() { this.records = new Map(); }
  get(proposalId) { return this.records.get(proposalId) ? structuredClone(this.records.get(proposalId)) : null; }
  recordDecision(receipt) {
    const current = this.records.get(receipt.proposalId);
    if (current?.decision) {
      if (canonicalJson(current.decision) === canonicalJson(receipt)) return { ...structuredClone(current), duplicate: true };
      // A post-review decision supersedes an earlier review_required one; no
      // other decision transition may ever be rewritten.
      if (current.decision.status === 'review_required' && !current.apply
          && ['approved_pending_apply', 'rejected'].includes(receipt.status)) {
        const superseding = { proposalId: receipt.proposalId, status: receipt.status, decision: structuredClone(receipt), apply: null };
        this.records.set(receipt.proposalId, superseding);
        return { ...structuredClone(superseding), duplicate: false, superseded: true };
      }
      throw new Error('receipt_conflict');
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
  list({ authorization, offset = 0, limit = RECONCILE_MAX_PAGE_SIZE + 1 } = {}) {
    const allowed = new Set(authorization?.allowedScopes || []);
    if (!authorization || typeof authorization.allowAll !== 'boolean' || !Array.isArray(authorization.allowedScopes)) throw new Error('memory_not_found');
    return [...this.records.values()]
      .filter(row => authorization.allowAll || allowed.has(row?.decision?.proposalScope))
      .sort((left, right) => String(left.proposalId).localeCompare(String(right.proposalId)))
      .slice(offset, offset + limit)
      .map(item => structuredClone(item));
  }
}

export class FabricReceiptLedger {
  constructor({ fabricStore }) { this.fabricStore = fabricStore; }
  get(proposalId) { return this.fabricStore.getCuratorReceipt(proposalId); }
  list(options) { return this.fabricStore.listCuratorReceiptsAuthorized(options); }
  recordDecision(receipt, context) { return this.fabricStore.recordCuratorReceiptAtomic(receipt, context); }
  recordApply(receipt, context) { return this.fabricStore.recordCuratorReceiptAtomic(receipt, context); }
}

export class CuratorReceiptCoordinator {
  constructor({ ledger, canonicalStore, proposalStore = null }) { this.ledger = ledger; this.canonicalStore = canonicalStore; this.proposalStore = proposalStore; }
  async record(receipt, context = {}) {
    const valid = validateCuratorReceipt(receipt);
    const authorization = context.authorization;
    if (!authorization || typeof this.proposalStore?.readProposalForReceiptAuthorized !== 'function') throw new Error('memory_not_found');
    const proposal = await this.proposalStore.readProposalForReceiptAuthorized(valid, authorization);
    if (proposal?.terminalReplay === true) return this.ledger.recordDecision(valid, context);
    if (!proposal?.payload || proposal.scope !== valid.proposalScope || digest(proposal.payload) !== valid.proposalDigest) throw new Error('memory_not_found');
    if (valid.kind === 'decision') {
      return this.ledger.recordDecision(valid, context);
    }
    const current = await this.ledger.get(valid.proposalId);
    if (!current?.decision || current.decision.decisionId !== valid.decisionId || current.decision.decisionDigest !== valid.decisionDigest
        || current.decision.proposalScope !== valid.proposalScope || current.decision.proposalDigest !== valid.proposalDigest
        || current.decision.policyDigest !== valid.policyDigestAtApply) throw new Error('receipt_transition_invalid');
    if (typeof this.proposalStore?.assertPromotionEligible !== 'function') throw new Error('canonical_apply_unverified');
    await this.proposalStore.assertPromotionEligible(valid.proposalId, { ...context, authorization });
    const record = await this.canonicalStore.read({ id: valid.canonicalRecordId });
    if (!record || record.id !== valid.canonicalRecordId || record.revision !== valid.revision || record.lifecycle?.status !== valid.canonicalLifecycleAtDecision || digest(record) !== valid.targetDigest) throw new Error('canonical_apply_unverified');
    if (typeof this.canonicalStore.verifyApplyReceipt !== 'function') throw new Error('canonical_apply_unverified');
    const verification = await this.canonicalStore.verifyApplyReceipt(valid);
    if (!verification || verification.verified !== true || verification.archiveDigest !== valid.archiveDigest || verification.targetDigest !== valid.targetDigest || verification.revision !== valid.revision) throw new Error('canonical_apply_unverified');
    return this.ledger.recordApply(valid, context);
  }
  async reconcile({ authorization, offset = 0, limit = 50 } = {}) {
    if (!authorization || typeof authorization.actor !== 'string' || authorization.actor.length < 1 || authorization.actor.length > 192
        || typeof authorization.allowAll !== 'boolean' || !Array.isArray(authorization.allowedScopes) || authorization.allowedScopes.length > 512
        || authorization.allowedScopes.some(scope => typeof scope !== 'string' || scope.length < 1 || scope.length > 256 || /[\r\n\0]/.test(scope))
        || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > RECONCILE_MAX_PAGE_SIZE) {
      throw Object.assign(new Error('invalid_request'), { status: 400 });
    }
    const allowedScopes = new Set(authorization.allowedScopes);
    const findings = [];
    let invalidRows = 0;
    const rows = await this.ledger.list({ authorization, offset, limit: limit + 1 });
    const page = rows.slice(0, limit);
    for (const row of page) {
      let validDecision; let validApply = null;
      try {
        validDecision = validateCuratorReceipt(row?.decision);
        if (typeof row.proposalId !== 'string' || row.proposalId.length < 1 || row.proposalId.length > 128 || /[\r\n\0]/.test(row.proposalId)
            || row.proposalId !== validDecision.proposalId
            || !['review_required', 'approved_pending_apply', 'rejected', 'promoted'].includes(row.status)
            || (row.status === 'promoted' ? validDecision.status !== 'approved_pending_apply' || !row.apply : row.status !== validDecision.status || row.apply)) {
          throw new Error('receipt_invalid');
        }
        if (row.apply) {
          validApply = validateCuratorReceipt(row.apply);
          if (validApply.proposalId !== row.proposalId || validApply.proposalScope !== validDecision.proposalScope) throw new Error('receipt_invalid');
        }
      } catch {
        invalidRows += 1;
        continue;
      }
      if (!authorization.allowAll && !allowedScopes.has(validDecision.proposalScope)) continue;
      if (row.status === 'promoted') {
        try {
          const target = await this.canonicalStore.read({ id: validApply.canonicalRecordId });
          if (!target || target.id !== validApply.canonicalRecordId) throw new Error('canonical_target_missing');
        }
        catch { findings.push({ proposalId: row.proposalId, code: 'canonical_target_missing' }); }
      } else if (row.status === 'approved_pending_apply') findings.push({ proposalId: row.proposalId, code: 'apply_receipt_pending' });
    }
    if (invalidRows) findings.push({ code: 'receipt_binding_invalid', count: invalidRows });
    return {
      ok: findings.length === 0,
      findings,
      scanned: page.length,
      complete: rows.length <= limit,
      nextOffset: rows.length > limit ? offset + page.length : null
    };
  }
}

const SEARCH_STOPWORDS = new Set([
  'la', 'il', 'lo', 'le', 'gli', 'un', 'una', 'uno', 'di', 'da', 'del', 'della', 'dei', 'delle',
  'che', 'chi', 'con', 'per', 'tra', 'fra', 'mia', 'mio', 'mie', 'miei', 'tua', 'tuo', 'sua', 'suo',
  'the', 'a', 'an', 'of', 'to', 'in', 'on', 'and', 'or', 'is', 'are', 'my', 'your', 'her', 'his'
]);

function searchTokens(value) {
  return String(value ?? '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .split(/[^a-z0-9]+/)
    .filter(token => token.length >= 3 && !SEARCH_STOPWORDS.has(token));
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
  constructor({ callTool, index, indexPath = null, routingKeys = null, allowLegacyContextTags = false, allowPlainSensitiveClaims = false, semanticIndex = null }) {
    this.callTool = callTool; this.indexPath = indexPath; this.routingKeys = routingKeys; this.allowLegacyContextTags = allowLegacyContextTags;
    this.allowPlainSensitiveClaims = allowPlainSensitiveClaims;
    this.semanticIndex = semanticIndex;
    this.index = normalizeRecordIndex(index || { records: {} }, routingKeys, { allowLegacyContextTags }); this.configured = true;
  }
  refreshIndex() {
    if (this.indexPath) this.index = normalizeRecordIndex(secureJsonFile(this.indexPath, 'pam_record_index'), this.routingKeys, { allowLegacyContextTags: this.allowLegacyContextTags });
    return this.index;
  }
  routingContext(id) {
    const tags = this.refreshIndex().records?.[id]?.contextTags;
    return tags ? structuredClone(tags) : null;
  }
  async read({ id }) {
    const entry = this.refreshIndex().records?.[id];
    if (!entry?.path) throw Object.assign(new Error('memory_not_found'), { status: 404 });
    const result = await this.callTool('memory_record_validate', { path: entry.path });
    const record = result.status === 'valid' ? result.metadata : null;
    if (!record || record.id !== id || !validateAmfMemoryRecord(record, { allowPlainSensitiveClaims: this.allowPlainSensitiveClaims }).ok) throw new Error('pam_record_binding_invalid');
    return structuredClone(record);
  }
  async search({ query, scopes, limit = 20, cursor = null, from = null, to = null }) {
    this.refreshIndex();
    const allowed = new Set(scopes);
    const entries = Object.entries(this.index.records || {}).filter(([, entry]) => allowed.has(entry.scope)).slice(0, 1000);
    const paths = [...new Set(entries.map(([, entry]) => entry.path))];
    if (!paths.length) return { items: [], nextCursor: null };
    // Substring hits from the PAM tool are unioned with token-ranked matches so
    // multi-word natural queries ("la mia gatta") reach records that contain
    // any distinctive token rather than the exact phrase.
    const result = await this.callTool('memory_search', { query, paths, maxResults: Math.min(limit * 4, 100) });
    const ids = new Set((result.matches || result.results || result.items || []).flatMap(hit => entries.filter(([, entry]) => entry.path === hit.path).map(([id]) => id)));
    const queryTokens = searchTokens(query);
    if (queryTokens.length) {
      for (const [id, entry] of entries) {
        if (ids.has(id)) continue;
        try {
          const validated = await this.callTool('memory_record_validate', { path: entry.path });
          const text = validated?.status === 'valid' ? String(validated.metadata?.claim?.text ?? '') : '';
          if (!text) continue;
          const recordTokens = new Set(searchTokens(text));
          if (queryTokens.some(token => recordTokens.has(token))) ids.add(id);
        } catch { /* unreadable records simply stay out of the result */ }
      }
    }
    // Semantic recall reaches concept-level matches with no shared tokens; it
    // only adds candidates known to this scope's index, and privacy/scope
    // filters run downstream on every candidate.
    if (this.semanticIndex?.configured && query) {
      try {
        const known = new Map(entries.map(([id, entry]) => [id, entry]));
        for (const id of await this.semanticIndex.searchIds({ query, scopes: [...allowed] })) {
          if (known.has(id)) ids.add(id);
        }
      } catch { /* semantic backend degradation must not fail lexical search */ }
    }
    const records = [];
    for (const id of ids) {
      const record = await this.read({ id });
      const now = Date.now(); const validFrom = Date.parse(record.lifecycle?.validFrom || '1970-01-01T00:00:00Z'); const validTo = record.lifecycle?.validTo ? Date.parse(record.lifecycle.validTo) : Infinity;
      const updatedAt = Date.parse(record.updatedAt);
      if (ACTIVE.has(record.lifecycle?.status) && validFrom <= now && validTo > now && (!from || updatedAt >= Date.parse(from)) && (!to || updatedAt <= Date.parse(to))) records.push(record);
    }
    const binding = digest({ query, scopes: [...scopes].sort(), from: from || null, to: to || null });
    const offset = decodeCursor(cursor, binding);
    const items = records.slice(offset, offset + limit);
    return { items, nextCursor: offset + items.length < records.length ? encodeCursor(offset + items.length, binding) : null };
  }
  async verifyApplyReceipt(receipt) {
    const result = await this.callTool('memory_verify_apply_receipt', { receipt });
    return { verified: result?.verified === true, archiveDigest: result?.archiveDigest, targetDigest: result?.targetDigest, revision: result?.revision };
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
  const routingPath = String(env.AMF_PAM_ROUTING_KEY_RING_PATH || '').trim();
  const index = secureJsonFile(indexPath, 'pam_record_index');
  if (!routingPath) throw new Error('pam_routing_key_ring_unconfigured');
  const routingKeys = normalizeRoutingKeyRing(secureJsonFile(routingPath, 'pam_routing_key_ring'));
  const allowLegacyContextTags = String(env.AMF_PAM_ALLOW_LEGACY_CONTEXT_TAGS_SHADOW || '').trim() === 'true';
  const allowPlainSensitiveClaims = String(env.AMF_ALLOW_PLAIN_SENSITIVE_CLAIMS || '').trim() === 'true';
  const semanticIndex = createSemanticIndexFromEnv(env);
  const client = new PamMcpProcessClient({ serverPath: path.resolve(serverPath), workspace: path.resolve(workspace) });
  const bridge = new CanonicalPamBridge({ callTool: client.callTool.bind(client), index, indexPath: path.resolve(indexPath), routingKeys, allowLegacyContextTags, allowPlainSensitiveClaims, semanticIndex: semanticIndex.configured ? semanticIndex : null });
  bridge.kind = 'pam-stdio';
  bridge.semanticIndex = semanticIndex.configured ? semanticIndex : null;
  bridge.close = async () => { await client.close(); if (semanticIndex.configured) await semanticIndex.close(); };
  return bridge;
}

export function createReceiptCoordinatorFromEnv({ env = process.env, canonicalStore, proposalStore }) {
  if (!proposalStore?.recordCuratorReceiptAtomic) return null;
  return new CuratorReceiptCoordinator({ ledger: new FabricReceiptLedger({ fabricStore: proposalStore }), canonicalStore, proposalStore });
}
