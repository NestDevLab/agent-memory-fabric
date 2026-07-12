import crypto from 'node:crypto';
import http from 'node:http';
import { URL } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createBackendAdapter } from './backend.mjs';
import { createFabricStoreFromEnv, createUnconfiguredFabricStore } from './fabric-store.mjs';
import { validateAmfMemoryRecord } from './amf-memory-record-validator.mjs';
import { createCanonicalPamBridgeFromEnv, createReceiptCoordinatorFromEnv, createUnconfiguredCanonicalStore } from './canonical-memory-bridge.mjs';
import { createContextVerifierFromEnv, createUnconfiguredContextVerifier } from './context-token.mjs';
import { PURPOSES, buildContextRequest, exactContextIntersection, normalizeScopeList, scopeRequiresContext } from './access-contract.mjs';
import { RAW_EVENT_HTTP_MAX_BODY_BYTES } from './ingest/raw-event-contract.mjs';
import { validatePamRuntimePrivateDirFromEnv } from './operator/pam-runtime-private-dir.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
function envInteger(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`invalid_environment:${name}`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`invalid_environment:${name}`);
  return value;
}

const POLICY_PATH = process.env.AMF_POLICY_PATH || process.env.MEM0_GATEWAY_POLICY_PATH || '';
const SESSION_ROUTE_MANIFEST_PATH = process.env.AMF_SESSION_ROUTE_MANIFEST_PATH || '';
const PORT = envInteger('PORT', 8787, { min: 1, max: 65535 });
const SERVICE_NAME = 'agent-memory-fabric';
const SERVICE_VERSION = '0.5.5';
const LEGACY_SERVICE_ALIASES = ['mem0-gateway'];
const LIMITS = Object.freeze({
  bodyBytes: envInteger('AMF_MAX_BODY_BYTES', 262144, { min: 1024, max: 16 * 1024 * 1024 }),
  rawIngestBodyBytes: envInteger('AMF_MAX_RAW_INGEST_BODY_BYTES', RAW_EVENT_HTTP_MAX_BODY_BYTES, { min: RAW_EVENT_HTTP_MAX_BODY_BYTES, max: 16 * 1024 * 1024 }),
  queryChars: envInteger('AMF_MAX_QUERY_CHARS', 4096, { min: 1, max: 65536 }),
  proposalChars: envInteger('AMF_MAX_PROPOSAL_CHARS', 32768, { min: 1, max: 1048576 }),
  metadataBytes: envInteger('AMF_MAX_METADATA_BYTES', 16384, { min: 2, max: 1048576 }),
  idempotencyKeyChars: envInteger('AMF_MAX_IDEMPOTENCY_KEY_CHARS', 200, { min: 16, max: 1024 })
});
const AUTH_CACHE_TTL_MS = envInteger('MEM0_AUTH_CACHE_TTL_MS', 15000, { min: 0, max: 3600000 });
const AUDIT_TIMEOUT_MS = envInteger('AMF_AUDIT_TIMEOUT_MS', 2000, { min: 100, max: 30000 });
const CATALOG_HEALTH_TIMEOUT_MS = envInteger('AMF_CATALOG_HEALTH_TIMEOUT_MS', 3000, { min: 100, max: 30000 });
const BODY_READ_TIMEOUT_MS = envInteger('AMF_BODY_READ_TIMEOUT_MS', 10000, { min: 100, max: 120000 });
const MCP_SESSION_DEFAULTS = Object.freeze({
  ttlMs: envInteger('AMF_MCP_SESSION_TTL_MS', 900000, { min: 1000, max: 86400000 }),
  maxGlobal: envInteger('AMF_MCP_MAX_SESSIONS', 1000, { min: 1, max: 100000 }),
  maxPerActor: envInteger('AMF_MCP_MAX_SESSIONS_PER_ACTOR', 20, { min: 1, max: 1000 })
});
const authCache = { loadedAt: 0, rows: [], sourceKey: '', mtimeMs: 0 };
const AUTH_ID = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,191}$/;
const AUTH_MODES = new Set(['allow_all', 'scoped', 'read_only_scoped', 'deny']);
const PRIVATE_HEADERS = Object.freeze({
  'cache-control': 'no-store, private',
  pragma: 'no-cache',
  expires: '0',
  vary: 'authorization'
});
const V1_HEADERS = Object.freeze({
  deprecation: 'true',
  sunset: 'Thu, 31 Dec 2026 23:59:59 GMT',
  link: '</v2>; rel="successor-version"'
});
const PUBLIC_ERRORS = new Map([
  ['invalid_json', [400, 'invalid_json']], ['invalid_request', [400, 'invalid_request']], ['context_transport_invalid', [400, 'context_transport_invalid']], ['scope_required', [400, 'scope_required']], ['scope_unregistered', [400, 'scope_unregistered']],
  ['scope_unmapped', [400, 'scope_unmapped']], ['memory_text_required', [400, 'memory_text_required']], ['memory_id_required', [400, 'memory_id_required']],
  ['canonical_record_required', [400, 'canonical_record_required']], ['canonical_record_invalid', [400, 'canonical_record_invalid']], ['rationale_required', [400, 'rationale_required']],
  ['revision_invalid', [400, 'revision_invalid']], ['idempotency_key_required', [400, 'idempotency_key_required']], ['purpose_required', [400, 'purpose_required']],
  ['purpose_invalid', [400, 'purpose_invalid']], ['context_required', [403, 'context_required']], ['context_invalid', [403, 'context_invalid']], ['session_limit_invalid', [400, 'session_limit_invalid']], ['raw_content_id_invalid', [400, 'raw_content_id_invalid']],
  ['missing_token', [401, 'missing_token']], ['invalid_token', [401, 'invalid_token']], ['session_expired', [401, 'session_expired']], ['session_revoked', [401, 'session_revoked']],
  ['forbidden', [403, 'forbidden']], ['scope_forbidden', [403, 'scope_forbidden']], ['memory_search_forbidden', [403, 'memory_search_forbidden']],
  ['sessions_forbidden', [403, 'sessions_forbidden']], ['raw_decrypt_forbidden', [403, 'raw_decrypt_forbidden']],
  ['not_found', [404, 'not_found']], ['memory_not_found', [404, 'memory_not_found']], ['session_not_found', [404, 'session_not_found']], ['unknown_session', [404, 'unknown_session']],
  ['idempotency_key_conflict', [409, 'idempotency_key_conflict']], ['body_too_large', [413, 'body_too_large']], ['query_too_large', [413, 'query_too_large']],
  ['body_read_timeout', [408, 'body_read_timeout']],
  ['proposal_too_large', [413, 'proposal_too_large']], ['metadata_too_large', [413, 'metadata_too_large']], ['idempotency_key_too_large', [413, 'idempotency_key_too_large']],
  ['identity_invalid', [400, 'identity_invalid']], ['identity_kind_invalid', [400, 'identity_kind_invalid']], ['identity_external_key_invalid', [400, 'identity_external_key_invalid']],
  ['identity_scope_invalid', [400, 'identity_scope_invalid']], ['identity_evidence_invalid', [400, 'identity_evidence_invalid']], ['identity_evidence_type_invalid', [400, 'identity_evidence_type_invalid']],
  ['identity_evidence_timestamp_invalid', [400, 'identity_evidence_timestamp_invalid']], ['identity_merge_invalid', [400, 'identity_merge_invalid']], ['identity_split_invalid', [400, 'identity_split_invalid']],
  ['identity_target_required', [400, 'identity_target_required']], ['identity_evidence_strength_required', [400, 'identity_evidence_strength_required']],
  ['retention_plan_invalid', [400, 'retention_plan_invalid']], ['retention_apply_invalid', [400, 'retention_apply_invalid']], ['retention_as_of_invalid', [400, 'retention_as_of_invalid']],
  ['retention_limit_invalid', [400, 'retention_limit_invalid']], ['retention_candidates_invalid', [400, 'retention_candidates_invalid']], ['retention_reason_invalid', [400, 'retention_reason_invalid']],
  ['identity_auto_merge_forbidden', [403, 'identity_auto_merge_forbidden']], ['identity_not_found', [404, 'identity_not_found']], ['retention_not_found', [404, 'retention_not_found']],
  ['identity_already_exists', [409, 'identity_already_exists']], ['identity_state_conflict', [409, 'identity_state_conflict']], ['revision_conflict', [409, 'revision_conflict']],
  ['retention_plan_in_future', [409, 'retention_plan_in_future']],
  ['receipt_invalid', [400, 'invalid_request']], ['receipt_transition_invalid', [409, 'conflict']], ['receipt_conflict', [409, 'conflict']], ['receipt_proposal_unverified', [409, 'conflict']], ['canonical_apply_unverified', [409, 'conflict']],
  ['raw_reconcile_required', [409, 'raw_reconcile_required']],
  ['session_capacity_exceeded', [429, 'session_capacity_exceeded']], ['fabric_store_unconfigured', [503, 'fabric_store_unconfigured']],
  ['raw_projection_invalid', [400, 'raw_projection_invalid']], ['raw_envelope_invalid', [400, 'raw_envelope_invalid']], ['raw_envelope_binding_invalid', [400, 'raw_envelope_binding_invalid']],
  ['source_instance_invalid', [400, 'source_instance_invalid']], ['raw_event_conflict', [409, 'raw_event_conflict']], ['raw_ingest_key_unavailable', [503, 'raw_ingest_key_unavailable']],
    ['raw_session_binding_conflict', [409, 'raw_session_binding_conflict']], ['raw_envelope_authentication_failed', [400, 'raw_envelope_authentication_failed']],
    ['session_text_scan_bound_exceeded', [503, 'session_text_scan_bound_exceeded']],
  ['raw_ingest_unconfigured', [503, 'raw_ingest_unconfigured']],
  ['session_reader_unconfigured', [503, 'session_reader_unconfigured']], ['canonical_store_unconfigured', [503, 'canonical_store_unconfigured']], ['backend_not_configured', [503, 'backend_not_configured']],
  ['audit_unavailable', [503, 'audit_unavailable']], ['catalog_unavailable', [503, 'catalog_unavailable']], ['service_unavailable', [503, 'service_unavailable']]
]);

function loadPolicies(policyPath = POLICY_PATH) {
  if (!policyPath) return { actors: {}, scopes: {} };
  try {
    return JSON.parse(fs.readFileSync(policyPath, 'utf8'));
  } catch {
    return { actors: {}, scopes: {} };
  }
}

function loadSessionRouteManifest(manifestPath, contextVerifier) {
  if (!manifestPath || !contextVerifier?.verifySessionRouteBinding) {
    throw Object.assign(new Error('session_route_manifest_invalid'), { status: 500 });
  }
  let directoryFd; let fd;
  try {
    const absolutePath = path.resolve(manifestPath);
    const directoryPath = path.dirname(absolutePath); const childName = path.basename(absolutePath);
    if (!childName || childName === '.' || childName === '..' || childName.includes('/')) throw new Error();
    const directoryStat = fs.lstatSync(directoryPath);
    const ownerUid = typeof process.geteuid === 'function' ? process.geteuid() : directoryStat.uid;
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || (directoryStat.mode & 0o077) !== 0
      || ![0, ownerUid].includes(directoryStat.uid)) throw new Error();
    directoryFd = fs.openSync(directoryPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY
      | (fs.constants.O_NOFOLLOW || 0));
    const openedDirectory = fs.fstatSync(directoryFd);
    if (!openedDirectory.isDirectory() || openedDirectory.dev !== directoryStat.dev
      || openedDirectory.ino !== directoryStat.ino || (openedDirectory.mode & 0o077) !== 0
      || ![0, ownerUid].includes(openedDirectory.uid)) throw new Error();
    const procPath = `/proc/self/fd/${directoryFd}/${childName}`;
    const stat = fs.lstatSync(procPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600
      || ![0, ownerUid].includes(stat.uid) || stat.size < 2 || stat.size > 1024 * 1024) throw new Error();
    fd = fs.openSync(procPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== stat.dev || opened.ino !== stat.ino
      || (opened.mode & 0o777) !== 0o600 || ![0, ownerUid].includes(opened.uid)
      || opened.size !== stat.size) throw new Error();
    const parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).sort().join('\0') !== 'bindings\0schema'
      || parsed.schema !== 'amf.session-route-manifest/v1' || !Array.isArray(parsed.bindings)
      || !parsed.bindings.length || parsed.bindings.length > 10000) throw new Error();
    const seen = new Set();
    const bindings = parsed.bindings.map(item => {
      const binding = contextVerifier.verifySessionRouteBinding(item);
      const identity = `${binding.actor}\0${binding.conversationKind}\0${binding.canonicalScope}`;
      if (seen.has(identity)) throw new Error();
      seen.add(identity);
      return binding;
    });
    return bindings;
  } catch {
    throw Object.assign(new Error('session_route_manifest_invalid'), { status: 500 });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (directoryFd !== undefined) fs.closeSync(directoryFd);
  }
}

function json(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...PRIVATE_HEADERS, ...extraHeaders });
  res.end(JSON.stringify(body, null, 2));
}

function jsonNoStore(res, status, body) {
  return json(res, status, body);
}

function jsonV1(res, status, body) {
  return json(res, status, body, V1_HEADERS);
}

function v2Envelope(requestId, data) {
  return { ok: true, data, meta: { requestId, service: SERVICE_NAME, version: SERVICE_VERSION } };
}

function curationCursorMac(key, value) {
  return crypto.createHmac('sha256', key).update(JSON.stringify({ binding: value.binding, createdAt: value.createdAt, id: value.id }), 'utf8').digest('hex');
}

function decodeCurationCursor(value, binding, key) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || Object.keys(parsed).sort().join(',') !== 'binding,createdAt,id,mac'
        || parsed.binding !== binding
        || typeof parsed.createdAt !== 'string' || !Number.isFinite(Date.parse(parsed.createdAt))
        || typeof parsed.id !== 'string' || parsed.id.length < 1 || parsed.id.length > 128
        || !/^[a-f0-9]{64}$/.test(String(parsed.mac || ''))) throw new Error('invalid');
    const expected = curationCursorMac(key, parsed);
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parsed.mac, 'hex'))) throw new Error('invalid');
    return parsed;
  } catch {
    throw Object.assign(new Error('invalid_request'), { status: 400 });
  }
}

function encodeCurationCursor(value, binding, key) {
  if (!value) return null;
  const payload = { ...value, binding };
  return Buffer.from(JSON.stringify({ ...payload, mac: curationCursorMac(key, payload) }), 'utf8').toString('base64url');
}

function reconcileCursorMac(key, value) {
  return crypto.createHmac('sha256', key).update(JSON.stringify({ offset: value.offset, binding: value.binding }), 'utf8').digest('hex');
}

function decodeReconcileCursor(cursor, binding, key) {
  if (!cursor) return 0;
  try {
    if (typeof cursor !== 'string' || cursor.length > 2048) throw new Error('invalid');
    const decoded = Buffer.from(cursor, 'base64url');
    if (decoded.toString('base64url') !== cursor) throw new Error('invalid');
    const parsed = JSON.parse(decoded.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || Object.keys(parsed).sort().join(',') !== 'binding,mac,offset'
        || parsed.binding !== binding || !Number.isSafeInteger(parsed.offset) || parsed.offset < 0
        || !/^[a-f0-9]{64}$/.test(String(parsed.mac || ''))) throw new Error('invalid');
    const expected = reconcileCursorMac(key, parsed);
    if (!crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(parsed.mac, 'hex'))) throw new Error('invalid');
    return parsed.offset;
  } catch {
    throw Object.assign(new Error('invalid_request'), { status: 400 });
  }
}

function encodeReconcileCursor(offset, binding, key) {
  if (offset === null) return null;
  const payload = { offset, binding };
  return Buffer.from(JSON.stringify({ ...payload, mac: reconcileCursorMac(key, payload) }), 'utf8').toString('base64url');
}

function curationCursorBinding(actor, statuses, authorization) {
  const value = {
    actor,
    statuses: [...new Set(statuses)].sort(),
    allowAll: authorization.allowAll,
    allowedScopes: [...authorization.allowedScopes].sort()
  };
  return crypto.createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex');
}

function v2Error(requestId, error, fallbackStatus = 500) {
  const [mappedStatus, code] = PUBLIC_ERRORS.get(error?.message) || [fallbackStatus >= 500 ? 500 : fallbackStatus, fallbackStatus >= 500 ? 'internal_error' : 'request_failed'];
  return {
    status: mappedStatus,
    body: {
      ok: false,
      error: { code, message: code, details: null },
      meta: { requestId, service: SERVICE_NAME, version: SERVICE_VERSION }
    }
  };
}

function publicError(error, fallbackStatus = 500) {
  const [status, code] = PUBLIC_ERRORS.get(error?.message) || [fallbackStatus >= 500 ? 500 : fallbackStatus, fallbackStatus >= 500 ? 'internal_error' : 'request_failed'];
  return { status, code };
}

function nowIso() {
  return new Date().toISOString();
}

function safeError(error) {
  if (!error) return null;
  const sanitized = publicError(error, Number(error?.status || 500));
  return {
    code: sanitized.code,
    status: sanitized.status
  };
}

function logEvent(event, payload = {}) {
  try {
    console.log(JSON.stringify({ ts: nowIso(), event, ...payload }));
  } catch {
    console.log(JSON.stringify({ ts: nowIso(), event, payload_error: true }));
  }
}

async function boundedDependency(operation, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error(code), { status: 503 })), timeoutMs);
      })
    ]);
  } catch (error) {
    if (error?.message === code) throw error;
    throw Object.assign(new Error(code), { status: 503, cause: error });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function auditRequired(fabricStore, event) {
  return boundedDependency(() => fabricStore.audit(event), AUDIT_TIMEOUT_MS, 'audit_unavailable');
}

async function auditInternalFailure(fabricStore, { actor, action, requestId, targetId = null, error }) {
  if (error?.message === 'audit_unavailable') return error;
  const failure = publicError(error, Number(error?.status || 500));
  try {
    await auditRequired(fabricStore, { actor, action, outcome: failure.status < 500 ? 'denied' : 'failed', requestId, targetId, details: { code: failure.code } });
    return error;
  } catch (auditError) {
    return auditError;
  }
}

function healthRequired(fabricStore) {
  return boundedDependency(() => fabricStore.health?.(), CATALOG_HEALTH_TIMEOUT_MS, 'catalog_unavailable');
}

function getScopeConfig(scope, policies) {
  return policies.scopes?.[scope] || null;
}

function canReadScope(policy, scope) {
  if (policy.mode === 'allow_all') return true;
  if (policy.mode === 'scoped' || policy.mode === 'read_only_scoped') {
    return Array.isArray(policy.allowedScopes) && (policy.allowedScopes.includes(scope) || policy.allowedScopes.includes('*'));
  }
  return false;
}

function hasPermission(policy, permission) {
  const perms = Array.isArray(policy?.permissions) ? policy.permissions : [];
  return perms.includes('*') || perms.includes(permission);
}

function canProposeScope(policy, scope) {
  if (!hasPermission(policy, 'memory:propose') && !hasPermission(policy, 'memory:add')) return false;
  if (policy.mode === 'allow_all') return true;
  if (policy.mode === 'scoped') {
    return Array.isArray(policy.allowedScopes) && (policy.allowedScopes.includes(scope) || policy.allowedScopes.includes('*'));
  }
  return false;
}

function canReadSessions(policy) {
  return hasPermission(policy, 'sessions:read') || hasPermission(policy, '*');
}

function parseBody(req, { maxBytes = LIMITS.bodyBytes, timeoutMs = BODY_READ_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    let rejected = false;
    const timer = setTimeout(() => {
      if (rejected) return;
      rejected = true;
      req.pause();
      reject(Object.assign(new Error('body_read_timeout'), { status: 408 }));
    }, timeoutMs);
    req.on('data', c => {
      if (rejected) return;
      received += c.length;
      if (received > maxBytes) {
        const error = new Error('body_too_large');
        error.status = 413;
        rejected = true;
        clearTimeout(timer);
        reject(error);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (rejected) return;
      clearTimeout(timer);
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        const error = new Error('invalid_json');
        error.status = 400;
        reject(error);
      }
    });
    req.on('error', error => { clearTimeout(timer); reject(error); });
  });
}

function validateSearchInput(query) {
  if (query.length > LIMITS.queryChars) {
    const error = new Error('query_too_large');
    error.status = 413;
    error.data = { maxChars: LIMITS.queryChars };
    throw error;
  }
}

function validateProposalInput({ scope, text, metadata, idempotencyKey, requireIdempotencyKey }) {
  if (!scope) {
    const error = new Error('scope_required');
    error.status = 400;
    throw error;
  }
  if (!text.trim()) {
    const error = new Error('memory_text_required');
    error.status = 400;
    throw error;
  }
  if (text.length > LIMITS.proposalChars) {
    const error = new Error('proposal_too_large');
    error.status = 413;
    error.data = { maxChars: LIMITS.proposalChars };
    throw error;
  }
  if (Buffer.byteLength(JSON.stringify(metadata), 'utf8') > LIMITS.metadataBytes) {
    const error = new Error('metadata_too_large');
    error.status = 413;
    error.data = { maxBytes: LIMITS.metadataBytes };
    throw error;
  }
  if (requireIdempotencyKey && !idempotencyKey) {
    const error = new Error('idempotency_key_required');
    error.status = 400;
    throw error;
  }
  if (idempotencyKey.length > LIMITS.idempotencyKeyChars) {
    const error = new Error('idempotency_key_too_large');
    error.status = 413;
    error.data = { maxChars: LIMITS.idempotencyKeyChars };
    throw error;
  }
}

function validateCanonicalProposal(record, rationale, expectedRevision) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw Object.assign(new Error('canonical_record_required'), { status: 400 });
  const revision = Number(record.revision);
  const validation = validateAmfMemoryRecord(record);
  if (!validation.ok) throw Object.assign(new Error('canonical_record_invalid'), { status: 400 });
  const recordBytes = Buffer.byteLength(canonicalJson(record), 'utf8') + Buffer.byteLength(String(rationale || ''), 'utf8');
  if (recordBytes > LIMITS.proposalChars) throw Object.assign(new Error('proposal_too_large'), { status: 413 });
  if (typeof rationale !== 'string' || !rationale.trim()) throw Object.assign(new Error('rationale_required'), { status: 400 });
  if (expectedRevision != null && (!Number.isInteger(expectedRevision) || expectedRevision < 0 || expectedRevision !== revision - 1)) {
    throw Object.assign(new Error('revision_invalid'), { status: 400 });
  }
  return { scope: record.scope.id, revision };
}

function validateCanonicalProposalBody(body) {
  const allowed = new Set(['record', 'rationale', 'expectedRevision']);
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !allowed.has(key))) {
    throw Object.assign(new Error('invalid_request'), { status: 400 });
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function deriveV1IdempotencyKey({ actor, scope, text, metadata, infer }) {
  return `v1-${crypto.createHash('sha256').update(canonicalJson({ actor, scope, text, metadata, infer })).digest('hex')}`;
}

function sendSse(res, event, data) {
  res.write(`event: ${event}\n`);
  const payload = typeof data === 'string' ? data : JSON.stringify(data);
  for (const line of payload.split('\n')) {
    res.write(`data: ${line}\n`);
  }
  res.write('\n');
}

function createRpcResult(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function createRpcError(id, code, message, data = undefined) {
  return { jsonrpc: '2.0', id, error: { code, message, data } };
}

function createMcpSessionId() {
  return crypto.randomUUID().replace(/-/g, '');
}

function getMcpSessionHeader(req) {
  return String(req.headers['mcp-session-id'] || req.headers['Mcp-Session-Id'] || '').trim();
}

function buildInitializeResult(protocolVersion, sessionReader) {
  return {
    protocolVersion: protocolVersion || '2024-11-05',
    capabilities: { tools: {}, experimental: { sessionReader: Boolean(sessionReader?.configured), streamableHttpGet: false } },
    serverInfo: { name: SERVICE_NAME, version: SERVICE_VERSION }
  };
}

function buildToolsListResult() {
  return {
    tools: [
      {
        name: 'memory_search',
        description: 'Search memory within one or more allowed scopes.',
        inputSchema: {
          type: 'object',
          properties: {
            scope: { type: 'string' },
            scopes: { type: 'array', items: { type: 'string' } },
            query: { type: 'string' },
            purpose: { type: 'string' },
            contextToken: { type: 'string' }, cursor: { type: ['string', 'null'] }, limit: { type: 'integer', minimum: 1, maximum: 100 }, from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] }
          },
          required: ['query', 'purpose']
        }
      },
      {
        name: 'memory_candidates_search',
        description: 'Explicitly rank non-canonical Mem0 candidates for memory curation; results are never canonical records.',
        inputSchema: {
          type: 'object', additionalProperties: false,
          properties: { scope: { type: 'string' }, scopes: { type: 'array', items: { type: 'string' } }, query: { type: 'string' }, purpose: { const: 'memory_curation' }, contextToken: { type: 'string' } },
          required: ['query', 'purpose']
        }
      },
      {
        name: 'memory_read',
        description: 'Read an authorized canonical PAM record by canonical record id.',
        inputSchema: {
          type: 'object',
          properties: { id: { type: 'string' }, purpose: { type: 'string' }, contextToken: { type: 'string' } },
          required: ['id', 'purpose']
        }
      },
      {
        name: 'memory_propose',
        description: 'Queue a canonical, revision-aware memory proposal for later curation.',
        inputSchema: {
          type: 'object',
          properties: {
            record: { type: 'object' },
            rationale: { type: 'string' },
            expectedRevision: { type: ['integer', 'null'], minimum: 0 },
            idempotencyKey: { type: 'string', description: 'Optional transport retry key; derived deterministically when omitted.' }
          },
          required: ['record', 'rationale']
        }
      },
      {
        name: 'memory_proposal_status',
        description: 'Read proposal lifecycle status without decrypting the proposed record.',
        inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] }
      },
      {
        name: 'sessions_search',
        description: 'Search native session metadata through the configured session reader.',
        inputSchema: {
          type: 'object',
          properties: { query: { type: 'string' }, cursor: { type: ['string', 'null'] }, limit: { type: 'integer', minimum: 1, maximum: 100 }, from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] }, purpose: { type: 'string', enum: ['conversation_recall', 'continuity_resume', 'incident_debug', 'operator_review', 'memory_curation'] }, contextToken: { type: 'string' } },
          required: ['query', 'purpose']
        }
      },
      {
        name: 'session_get',
        description: 'Read one session metadata record.',
        inputSchema: { type: 'object', properties: { sessionId: { type: 'string' }, purpose: { type: 'string' }, contextToken: { type: 'string' } }, required: ['sessionId', 'purpose'] }
      },
      {
        name: 'session_transcript',
        description: 'Read a redacted transcript by default; original requires raw:decrypt.',
        inputSchema: {
          type: 'object',
          properties: { sessionId: { type: 'string' }, view: { type: 'string', enum: ['redacted', 'original'] }, query: { type: 'string' }, cursor: { type: ['string', 'null'] }, limit: { type: 'integer', minimum: 1, maximum: 100 }, from: { type: ['string', 'null'] }, to: { type: ['string', 'null'] }, purpose: { type: 'string' }, contextToken: { type: 'string' } },
          required: ['sessionId', 'purpose']
        }
      },
      {
        name: 'memory_status',
        description: 'Return fabric, backend, limits and compatibility status.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'list_scopes',
        description: 'Legacy alias: list scopes visible to the current actor.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'gateway_health',
        description: 'Legacy alias: return fabric health.',
        inputSchema: { type: 'object', properties: {} }
      }
    ]
  };
}

async function executeMcpMethod({ body, actor, policy, policies, backend, fabricStore, canonicalStore,
  contextVerifier, routeManifestPath, sessionReader, requestId, requestStartedAt, sourceIp, sessionId, clientName }) {
  const method = body.method;
  const id = body.id ?? null;

  if (method === 'initialize') {
    return createRpcResult(id, buildInitializeResult(body.params?.protocolVersion, sessionReader));
  }

  if (method === 'notifications/initialized') {
    return null;
  }

  if (method === 'tools/list') {
    return createRpcResult(id, buildToolsListResult());
  }

  if (method === 'tools/call') {
    const name = body.params?.name;
    const args = body.params?.arguments || {};

    if (name === 'list_scopes') {
      const scopes = getAllowedScopes(policy, policies);
      logEvent('mcp_tools_call', { requestId, actor, tool: 'list_scopes', sessionId, clientName, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return createRpcResult(id, {
        content: [{ type: 'text', text: JSON.stringify({ actor, scopes }, null, 2) }]
      });
    }

    if (name === 'gateway_health') {
      logEvent('mcp_tools_call', { requestId, actor, tool: 'gateway_health', sessionId, clientName, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return createRpcResult(id, {
        content: [{ type: 'text', text: JSON.stringify({ ok: true, service: SERVICE_NAME, version: SERVICE_VERSION }, null, 2) }]
      });
    }

    if (name === 'memory_status') {
      requirePermission(policy, 'memory:status');
      await healthRequired(fabricStore);
      const status = buildStatus({ backend, fabricStore, canonicalStore, contextVerifier, sessionReader });
      await auditRequired(fabricStore, { actor, action: 'memory_status', outcome: 'allowed', requestId });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(status, null, 2) }] });
    }

    if (name === 'memory_search') {
      const scope = typeof args.scope === 'string' ? args.scope : '';
      const scopes = Array.isArray(args.scopes) ? args.scopes : [];
      const query = String(args.query || '');
      validateSearchInput(query);
      const purpose = requirePurpose(args.purpose);
      if (!canonicalStore.configured) throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: args.contextToken, request: buildContextRequest('memory_search', args), required: purpose === 'conversation_recall' || scopeRequiresContext(normalizeScopeList(scope, scopes)) });
      const searchResult = await performCanonicalSearch({ actor, scope, scopes, query, policy, policies, canonicalStore, context, limit: args.limit, cursor: args.cursor, from: args.from, to: args.to });
      await auditRequired(fabricStore, { actor, action: 'memory_search', outcome: 'allowed', requestId, details: { resultCount: searchResult.items.length, transport: 'mcp' } });
      logEvent('mcp_tools_call', { requestId, actor, tool: 'memory_search', sessionId, clientName, requestedScope: scope || null, requestedScopes: scopes, resolvedScopes: searchResult.scopes, perScope: searchResult.result?.perScope, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return createRpcResult(id, {
        content: [{ type: 'text', text: JSON.stringify(searchResult, null, 2) }]
      });
    }

    if (name === 'memory_candidates_search') {
      requirePermission(policy, 'memory:candidates:search');
      const purpose = requirePurpose(args.purpose);
      if (purpose !== 'memory_curation') throw Object.assign(new Error('purpose_invalid'), { status: 400 });
      requirePurposePermission(policy, purpose);
      const result = await performScopedSearch({ actor, scope: String(args.scope || ''), scopes: Array.isArray(args.scopes) ? args.scopes : [], query: String(args.query || ''), policy, policies, backend, fabricStore });
      await auditRequired(fabricStore, { actor, action: 'memory_candidates_search', outcome: 'allowed', requestId, details: { resultCount: result.result.total, transport: 'mcp' } });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify({ canonical: false, candidates: result.result.items, scopes: result.scopes }, null, 2) }] });
    }

    if (name === 'memory_propose') {
      const validated = validateCanonicalProposal(args.record, args.rationale, args.expectedRevision ?? null);
      const derivedIdempotencyKey = `mcp-${crypto.createHash('sha256').update(canonicalJson({ actor, record: args.record, rationale: args.rationale, expectedRevision: args.expectedRevision ?? null })).digest('hex')}`;
      const proposal = await performMemoryProposal({
        actor,
        policy,
        policies,
        fabricStore,
        scope: validated.scope,
        record: args.record,
        rationale: args.rationale.trim(),
        expectedRevision: args.expectedRevision ?? null,
        idempotencyKey: String(args.idempotencyKey || derivedIdempotencyKey),
        source: 'mcp',
        requestId,
        requireIdempotencyKey: true
      });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify({ status: proposal.status, proposalId: proposal.id, duplicate: proposal.duplicate, idempotencyKey: String(args.idempotencyKey || derivedIdempotencyKey) }, null, 2) }] });
    }

    if (name === 'memory_proposal_status') {
      const status = await performMemoryProposalStatus({ actor, policy, policies, fabricStore, id: String(args.id || ''), requestId });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(status, null, 2) }] });
    }

    if (name === 'memory_read') {
      const purpose = requirePurpose(args.purpose);
      const targetId = String(args.id || '');
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: args.contextToken, request: buildContextRequest('memory_read', { id: targetId }), required: purpose === 'conversation_recall' });
      const memory = await performMemoryRead({ actor, policy, policies, fabricStore, canonicalStore, context, id: targetId, requestId });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(memory, null, 2) }] });
    }

    if (name === 'sessions_search') {
      requireSessionPermission(policy);
      const purpose = requirePurpose(args.purpose);
      const query = String(args.query || '');
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: args.contextToken, request: buildContextRequest('sessions_search', args), required: true });
      const routeScopes = requireSessionRouteScopes(context, actor, policy, policies, contextVerifier,
        routeManifestPath);
      validateSearchInput(query);
      const ownerActors = authorizedSessionOwners(actor, policy);
      const raw = await sessionReader.search({ actor, ownerActors, query, cursor: args.cursor || null,
        limit: normalizeSessionLimit(args.limit), from: args.from || null, to: args.to || null, purpose, context });
      const result = { ...raw, items: (raw?.items || []).filter(item => sessionVisible(item, actor, policy,
        policies, context, routeScopes, ownerActors)).map(item => exposeSession(item, routeScopes)),
      nextCursor: raw?.nextCursor || null };
      await auditRequired(fabricStore, { actor, action: 'sessions_search', outcome: 'allowed', requestId, details: { resultCount: result.items.length, purpose } });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
    }

    if (name === 'session_get') {
      requireSessionPermission(policy);
      const purpose = requirePurpose(args.purpose);
      const sessionTargetId = String(args.sessionId || args.id || '');
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: args.contextToken, request: buildContextRequest('session_get', { sessionId: sessionTargetId }), required: true });
      const result = await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
        routeManifestPath, id: sessionTargetId, purpose, context });
      await auditRequired(fabricStore, { actor, action: 'session_get', outcome: 'allowed', requestId, targetId: sessionTargetId, details: { purpose } });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
    }

    if (name === 'session_transcript') {
      requireSessionPermission(policy);
      const purpose = requirePurpose(args.purpose);
      const sessionTargetId = String(args.sessionId || args.id || '');
      const view = args.view === 'original' ? 'original' : 'redacted';
      const query = String(args.query || ''); validateSearchInput(query);
      if (view === 'original' && query) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: args.contextToken, request: buildContextRequest('session_transcript', { ...args, sessionId: sessionTargetId, view }), required: true });
      await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
        routeManifestPath, id: sessionTargetId, purpose, context });
      if (view === 'original' && !hasPermission(policy, 'raw:decrypt')) {
        await auditRequired(fabricStore, { actor, action: 'session_transcript', outcome: 'denied', requestId, targetId: sessionTargetId, details: { view, purpose } });
        const error = new Error('raw_decrypt_forbidden');
        error.status = 403;
        throw error;
      }
      if (view === 'original') await auditRequired(fabricStore, { actor, action: 'raw_decrypt_intent', outcome: 'authorized', requestId, targetId: sessionTargetId, details: { view, purpose, transport: 'mcp' } });
      const transcript = await sessionReader.transcript({ actor, ownerActors: authorizedSessionOwners(actor, policy),
        id: sessionTargetId, view, cursor: args.cursor || null, limit: normalizeSessionLimit(args.limit || 100),
        query, from: args.from || null, to: args.to || null, purpose, context });
      const result = { ...transcript, nextCursor: transcript?.nextCursor || null };
      await auditRequired(fabricStore, { actor, action: 'session_transcript', outcome: 'allowed', requestId, targetId: sessionTargetId, details: { view, purpose } });
      return createRpcResult(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
    }

    return createRpcError(id, -32601, 'Unknown tool');
  }

  return createRpcError(id, -32601, 'Unsupported method');
}

function normalizeSessionLimit(value) {
  const parsed = Number(value || 20);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100) {
    const error = new Error('session_limit_invalid');
    error.status = 400;
    error.data = { min: 1, max: 100 };
    throw error;
  }
  return parsed;
}

function requireSessionPermission(policy) {
  if (canReadSessions(policy)) return;
  const error = new Error('sessions_forbidden');
  error.status = 403;
  throw error;
}

function requirePermission(policy, permission) {
  if (hasPermission(policy, permission)) return;
  const error = new Error('forbidden');
  error.status = 403;
  throw error;
}

function requirePurpose(value) {
  const purpose = String(value || '').trim();
  if (!purpose) {
    const error = new Error('purpose_required');
    error.status = 400;
    throw error;
  }
  const allowed = new Set(PURPOSES);
  if (!allowed.has(purpose)) throw Object.assign(new Error('purpose_invalid'), { status: 400 });
  return purpose;
}

function requirePurposePermission(policy, purpose) {
  if (hasPermission(policy, `purpose:${purpose}`)) return;
  throw Object.assign(new Error('forbidden'), { status: 403 });
}

function requireAccessContext(contextVerifier, { actor, policy, purpose, token, request, required = false }) {
  requirePurposePermission(policy, purpose);
  if (!token) {
    if (required) throw Object.assign(new Error('context_required'), { status: 403 });
    return null;
  }
  return contextVerifier.verify(token, { actor, purpose, request,
    contextKeyVersions: policy.contextKeyVersions ?? null });
}

function authorizedSessionOwners(actor, policy) {
  return [...new Set([actor, ...(Array.isArray(policy?.sessionOwnerActors) ? policy.sessionOwnerActors : [])])].sort();
}

function validateContextActorBinding(actor, policy, policies, contextVerifier) {
  const registryVersions = Array.isArray(policy?.contextKeyVersions) ? [...policy.contextKeyVersions].sort() : [];
  const versionOwners = new Map();
  for (const [configuredActor, entry] of Object.entries(policies?.actors || {})) {
    for (const version of Array.isArray(entry?.contextKeyVersions) ? entry.contextKeyVersions : []) {
      const existing = versionOwners.get(version);
      if (existing && existing !== configuredActor) {
        const error = new Error('context_actor_binding_invalid'); error.status = 500; throw error;
      }
      versionOwners.set(version, configuredActor);
    }
  }
  const configured = policies?.actors?.[actor];
  const policyVersions = Array.isArray(configured?.contextKeyVersions)
    ? [...new Set(configured.contextKeyVersions)].sort() : [];
  if (registryVersions.join('\0') !== policyVersions.join('\0')
    || registryVersions.some(version => !contextVerifier?.keyRing?.keys?.has(version))) {
    const error = new Error('context_actor_binding_invalid'); error.status = 500; throw error;
  }
}

function requireSessionRouteScopes(context, actor, policy, policies, contextVerifier, routeManifestPath) {
  const scopes = Array.isArray(context?.canonicalScopes) ? [...context.canonicalScopes] : [];
  const kind = String(context?.conversationKind || '');
  if (!scopes.length || scopes.some(scope => !getScopeConfig(scope, policies) || !canReadScope(policy, scope))
    || (['group', 'channel', 'thread'].includes(kind) && !scopes.some(scope => scope.startsWith('room:')))) {
    const error = new Error('scope_forbidden'); error.status = 403; throw error;
  }
  const canonicalScope = primarySessionScope(scopes);
  const binding = loadSessionRouteManifest(routeManifestPath, contextVerifier).find(item => item.actor === actor
    && item.conversationKind === kind && item.canonicalScope === canonicalScope);
  if (!binding || binding.keyVersion !== context?.keyVersion
    || canonicalJson(binding.contextTags) !== canonicalJson(context?.contextTags)) {
    const error = new Error('scope_forbidden'); error.status = 403; throw error;
  }
  return scopes;
}

function primarySessionScope(scopes) {
  return scopes.find(scope => scope.startsWith('room:')) || scopes[0];
}

function exposeSession(session, routeScopes) {
  const { ownerActor: _ownerActor, ...visible } = session;
  return { ...visible, scope: primarySessionScope(routeScopes) };
}

function sessionVisible(session, actor, policy, policies, context, routeScopes,
  ownerActors = authorizedSessionOwners(actor, policy)) {
  if (!session || typeof session !== 'object') return false;
  if (!context || !session.contextTags || !exactContextIntersection(session.contextTags, context.contextTags)) return false;
  if (!Array.isArray(routeScopes) || !routeScopes.length
    || routeScopes.some(scope => !getScopeConfig(scope, policies) || !canReadScope(policy, scope))) return false;
  if (session.ownerSelf === true) return true;
  if (ownerActors.includes(String(session.ownerActor || ''))) return true;
  const scope = String(session.scope || '');
  if (!scope || !getScopeConfig(scope, policies)) return false;
  return canReadScope(policy, scope);
}

async function getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
  routeManifestPath, id, purpose, context = null }) {
  let session;
  const ownerActors = authorizedSessionOwners(actor, policy);
  const routeScopes = requireSessionRouteScopes(context, actor, policy, policies, contextVerifier, routeManifestPath);
  try { session = await sessionReader.get({ actor, ownerActors, id, purpose, context }); } catch (error) {
    if (error?.status === 404) {
      const hidden = new Error('session_not_found');
      hidden.status = 404;
      throw hidden;
    }
    throw error;
  }
  if (!sessionVisible(session, actor, policy, policies, context, routeScopes, ownerActors)) {
    const error = new Error('session_not_found');
    error.status = 404;
    throw error;
  }
  return exposeSession(session, routeScopes);
}

function createUnconfiguredSessionReader() {
  const fail = async () => {
    const error = new Error('session_reader_unconfigured');
    error.status = 503;
    throw error;
  };
  return { configured: false, kind: 'unconfigured', search: fail, get: fail, transcript: fail };
}

function buildStatus({ backend, fabricStore, canonicalStore = defaultCanonicalStore, contextVerifier = defaultContextVerifier, sessionReader }) {
  return {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    aliases: LEGACY_SERVICE_ALIASES,
    backend: { kind: backend.kind, configured: backend.configured },
    fabricStore: fabricStore.status(),
    canonicalStore: { kind: canonicalStore.kind || 'unconfigured', configured: Boolean(canonicalStore.configured) },
    contextTokens: { configured: Boolean(contextVerifier.configured), conversationRecallRequired: true },
    sessionReader: { kind: sessionReader.kind || 'custom', configured: Boolean(sessionReader.configured) },
    compatibility: { restV1: true, mcpSse: true, mcpStreamableHttp: true },
    limits: LIMITS
  };
}

function getAllowedScopes(policy, policies) {
  const registered = Object.keys(policies.scopes || {});
  if (policy.mode === 'allow_all') return registered;
  if (policy.mode === 'scoped' || policy.mode === 'read_only_scoped') {
    const configured = policy.allowedScopes || [];
    if (configured.includes('*')) return registered;
    return configured.filter(scope => registered.includes(scope));
  }
  return [];
}

function normalizeRequestedScopes(inputScope, inputScopes, policy, policies) {
  const availableScopes = Object.keys(policies.scopes || {});
  const allowedScopes = getAllowedScopes(policy, policies);
  const hasWildcardAccess = policy.mode === 'allow_all' || (policy.allowedScopes || []).includes('*');

  let requested = [];
  if (Array.isArray(inputScopes) && inputScopes.length) {
    requested = inputScopes.map(x => String(x).trim()).filter(Boolean);
  } else if (typeof inputScope === 'string' && inputScope.trim()) {
    requested = [inputScope.trim()];
  }

  if (!requested.length) {
    const err = new Error('scope_required');
    err.status = 400;
    throw err;
  }

  if (requested.length === 1 && requested[0] === '*') {
    return hasWildcardAccess ? availableScopes : availableScopes.filter(scope => allowedScopes.includes(scope));
  }

  const deduped = [...new Set(requested)];
  const forbidden = deduped.filter(scope => !availableScopes.includes(scope) || !canReadScope(policy, scope));
  if (forbidden.length) {
    const err = new Error('scope_forbidden');
    err.status = 403;
    err.data = { forbiddenScopes: forbidden };
    throw err;
  }
  return deduped;
}

function parseCsvList(value) {
  if (Array.isArray(value)) return value.map(x => String(x).trim()).filter(Boolean);
  const raw = String(value || '').trim();
  if (!raw) return [];
  if (raw === '*') return ['*'];
  return raw.split(',').map(x => x.trim()).filter(Boolean);
}

function strictAuthList(value, { wildcard = false, optional = false } = {}) {
  if (value === undefined && optional) return [];
  if (wildcard && value === '*') return ['*'];
  const values = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : null;
  if (!values || values.some(item => typeof item !== 'string')) throw new Error('auth_registry_invalid_row');
  const normalized = values.map(item => item.trim()).filter(Boolean);
  if (!normalized.length || normalized.some(item => !(wildcard && item === '*') && !AUTH_ID.test(item))
    || new Set(normalized).size !== normalized.length) throw new Error('auth_registry_invalid_row');
  return normalized;
}

function strictAuthArray(value, { optional = false } = {}) {
  if (value === undefined && optional) return [];
  if (!Array.isArray(value)) throw new Error('auth_registry_invalid_row');
  return strictAuthList(value);
}

function parseActive(value) {
  if (value === true) return true;
  if (value === false || value == null) return false;
  const raw = String(value).trim().toLowerCase();
  return raw === 'true' || raw === '1' || raw === 'yes';
}

function getAuthRegistrySource() {
  const localPath = String(process.env.AMF_AUTH_REGISTRY_PATH || process.env.MEM0_AUTH_REGISTRY_PATH || '').trim();
  if (localPath) {
    return {
      kind: 'local-json',
      path: path.resolve(ROOT, localPath),
      cacheKey: `local:${path.resolve(ROOT, localPath)}`
    };
  }

  if (process.env.N8N_API_BASE_URL && process.env.N8N_API_KEY && process.env.N8N_AUTH_TABLE_ID) {
    return {
      kind: 'n8n-data-table',
      cacheKey: `n8n:${process.env.N8N_API_BASE_URL}:${process.env.N8N_AUTH_TABLE_ID}`
    };
  }

  return { kind: 'unconfigured', cacheKey: 'unconfigured' };
}

function extractAuthRows(data, sourceKind) {
  const rows = Array.isArray(data) ? data : Array.isArray(data?.rows) ? data.rows : Array.isArray(data?.data) ? data.data : null;
  if (!rows) {
    const err = new Error(sourceKind === 'local-json' ? 'auth_registry_invalid_json_shape' : 'auth_registry_invalid_response_shape');
    err.status = 500;
    throw err;
  }
  return rows;
}

function validateAuthRows(rows, sourceKind) {
  if (!Array.isArray(rows)) {
    const err = new Error('auth_registry_rows_not_array');
    err.status = 500;
    throw err;
  }

  const credentials = new Set();
  const validated = rows.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      const err = new Error('auth_registry_invalid_row');
      err.status = 500;
      err.data = { source: sourceKind, index };
      throw err;
    }
    const tokenSha256 = row.tokenSha256;
    const token = row.token;
    const hasDigest = Object.hasOwn(row, 'tokenSha256'); const hasToken = Object.hasOwn(row, 'token');
    const validDigest = typeof tokenSha256 === 'string' && /^[a-f0-9]{64}$/.test(tokenSha256);
    const validToken = typeof token === 'string' && token.length > 0 && token.length <= 4096;
    const activePrimitive = typeof row.active === 'boolean'
      || (typeof row.active === 'string' && ['true', 'false', '1', '0', 'yes', 'no'].includes(row.active.trim().toLowerCase()));
    let valid = typeof row.actor === 'string' && AUTH_ID.test(row.actor)
      && activePrimitive && typeof row.mode === 'string' && AUTH_MODES.has(row.mode)
      && hasDigest !== hasToken && (hasDigest ? validDigest : validToken);
    try {
      strictAuthList(row.allowedScopes, { wildcard: true });
      strictAuthList(row.permissions, { wildcard: true });
      strictAuthArray(row.sessionOwnerActors, { optional: true });
      strictAuthArray(row.contextKeyVersions, { optional: true });
    } catch { valid = false; }
    const credential = validDigest ? tokenSha256 : validToken ? crypto.createHash('sha256').update(token, 'utf8').digest('hex') : '';
    if (!valid || credentials.has(credential)) {
      const err = new Error('auth_registry_invalid_row'); err.status = 500; err.data = { source: sourceKind, index }; throw err;
    }
    credentials.add(credential);
    return row;
  });
  const byActor = new Map();
  for (const row of validated) byActor.set(row.actor, [...(byActor.get(row.actor) || []), row]);
  const contextVersionOwners = new Map();
  for (let index = 0; index < validated.length; index += 1) {
    const row = validated[index]; const owners = strictAuthArray(row.sessionOwnerActors, { optional: true });
    for (const version of strictAuthArray(row.contextKeyVersions, { optional: true })) {
      const existing = contextVersionOwners.get(version);
      if (existing && existing !== row.actor) {
        const err = new Error('auth_registry_invalid_row'); err.status = 500; err.data = { source: sourceKind, index }; throw err;
      }
      contextVersionOwners.set(version, row.actor);
    }
    for (const owner of owners) {
      const targets = byActor.get(owner) || [];
      const targetCanIngest = targets.some(target => parseActive(target.active)
        && strictAuthList(target.permissions, { wildcard: true }).some(permission => permission === '*' || permission === 'raw:ingest'));
      const targetDelegates = targets.some(target => strictAuthArray(target.sessionOwnerActors, { optional: true }).length > 0);
      if (owner === row.actor || !targetCanIngest || targetDelegates) {
        const err = new Error('auth_registry_invalid_row'); err.status = 500; err.data = { source: sourceKind, index }; throw err;
      }
    }
  }
  return validated;
}

function getBearerToken(req, { allowQueryToken = false } = {}) {
  const auth = String(req.headers.authorization || req.headers.Authorization || '');
  if (auth.startsWith('Bearer ')) return auth.slice('Bearer '.length).trim();
  if (!allowQueryToken) return '';
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const q = url.searchParams.get('access_token');
  return q ? String(q) : '';
}

function getAccessContextToken(req, url, policy) {
  const header = req.headers['x-amf-context-token'];
  const headerToken = Array.isArray(header) ? '' : String(header || '').trim();
  const queryToken = String(url.searchParams.get('contextToken') || '').trim();
  if ((headerToken && queryToken) || (queryToken && Array.isArray(policy?.contextKeyVersions)
    && policy.contextKeyVersions.length > 0)) {
    const error = new Error('context_transport_invalid'); error.status = 400; throw error;
  }
  return headerToken || queryToken || '';
}

async function loadAuthRegistry({ forceRefresh = false } = {}) {
  const now = Date.now();
  const source = getAuthRegistrySource();

  if (source.kind === 'unconfigured') {
    const err = new Error('auth_registry_unconfigured');
    err.status = 500;
    throw err;
  }

  if (source.kind === 'local-json') {
    let stat;
    try {
      stat = fs.statSync(source.path);
    } catch (error) {
      const err = new Error('auth_registry_file_unreadable');
      err.status = 500;
      throw err;
    }

    if (
      authCache.sourceKey === source.cacheKey &&
      authCache.mtimeMs === stat.mtimeMs &&
      !forceRefresh && now - authCache.loadedAt < AUTH_CACHE_TTL_MS &&
      Array.isArray(authCache.rows)
    ) {
      return authCache.rows;
    }

    let data;
    try {
      data = JSON.parse(fs.readFileSync(source.path, 'utf8'));
    } catch (error) {
      const err = new Error('auth_registry_file_invalid_json');
      err.status = 500;
      throw err;
    }

    authCache.rows = validateAuthRows(extractAuthRows(data, source.kind), source.kind);
    authCache.loadedAt = now;
    authCache.sourceKey = source.cacheKey;
    authCache.mtimeMs = stat.mtimeMs;
    return authCache.rows;
  }

  if (!forceRefresh && now - authCache.loadedAt < AUTH_CACHE_TTL_MS && authCache.sourceKey === source.cacheKey && Array.isArray(authCache.rows)) {
    return authCache.rows;
  }

  const baseUrl = process.env.N8N_API_BASE_URL;
  const apiKey = process.env.N8N_API_KEY;
  const tableId = process.env.N8N_AUTH_TABLE_ID;
  const url = new URL(`/api/v1/data-tables/${tableId}/rows`, baseUrl);
  const res = await fetch(url, {
    headers: {
      'X-N8N-API-KEY': apiKey,
      'accept': 'application/json'
    }
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!res.ok) {
    const err = new Error(`auth_registry_http_${res.status}`);
    err.status = res.status;
    throw err;
  }
  authCache.rows = validateAuthRows(extractAuthRows(data, source.kind), source.kind);
  authCache.loadedAt = now;
  authCache.sourceKey = source.cacheKey;
  authCache.mtimeMs = 0;
  return authCache.rows;
}

function tokenDigest(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest();
}

function registryTokenDigest(row) {
  const configured = String(row.tokenSha256 || '').trim().toLowerCase();
  if (/^[a-f0-9]{64}$/.test(configured)) return Buffer.from(configured, 'hex');
  if (row.token) return tokenDigest(row.token);
  return Buffer.alloc(32);
}

async function authenticateRequest(req, { allowQueryToken = false } = {}) {
  const token = getBearerToken(req, { allowQueryToken });
  if (!token) {
    const err = new Error('missing_token');
    err.status = 401;
    throw err;
  }
  const rows = await loadAuthRegistry({ forceRefresh: true });
  const candidate = tokenDigest(token);
  return authenticateDigest(candidate, rows);
}

function authenticateDigest(candidate, rows) {
  let row = null;
  for (const current of rows) {
    const matches = crypto.timingSafeEqual(candidate, registryTokenDigest(current));
    if (matches && parseActive(current.active)) row = current;
  }
  if (!row) {
    const err = new Error('invalid_token');
    err.status = 401;
    throw err;
  }
  const policy = {
    mode: String(row.mode || 'deny'),
    allowedScopes: parseCsvList(row.allowedScopes),
    permissions: parseCsvList(row.permissions)
  };
  if (Object.hasOwn(row, 'sessionOwnerActors')) {
    policy.sessionOwnerActors = strictAuthArray(row.sessionOwnerActors);
  }
  if (Object.hasOwn(row, 'contextKeyVersions')) {
    policy.contextKeyVersions = strictAuthArray(row.contextKeyVersions);
  }
  return {
    actor: String(row.actor || 'anonymous'),
    tokenDigestHex: candidate.toString('hex'),
    policy
  };
}

async function revalidateSession(session) {
  try {
    return authenticateDigest(Buffer.from(session.tokenDigestHex, 'hex'), await loadAuthRegistry({ forceRefresh: true }));
  } catch {
    const error = new Error('session_revoked');
    error.status = 401;
    throw error;
  }
}

async function performScopedSearch({ actor, scope, scopes, query, policy, policies, backend, fabricStore }) {
  if (!hasPermission(policy, 'memory:search')) {
    const error = new Error('memory_search_forbidden');
    error.status = 403;
    error.data = { actor, permission: 'memory:search' };
    throw error;
  }
  validateSearchInput(query);
  const resolvedScopes = normalizeRequestedScopes(scope, scopes, policy, policies);
  const searchResults = [];
  const startedAt = Date.now();

  for (const resolvedScope of resolvedScopes) {
    const scopeConfig = getScopeConfig(resolvedScope, policies);
    if (!scopeConfig?.backendUserId) {
      const err = new Error('scope_unmapped');
      err.status = 400;
      err.data = { scope: resolvedScope };
      throw err;
    }
    const scopeStartedAt = Date.now();
    const result = await backend.search({ backendUserId: scopeConfig.backendUserId, query, scope: resolvedScope });
    const filteredItems = await fabricStore.filterRecallItems(result?.items || [], { allowedScopes: [resolvedScope] });
    const items = filteredItems.map(item => ({ ...item, scope: resolvedScope }));
    searchResults.push({
      scope: resolvedScope,
      backendUserId: scopeConfig.backendUserId,
      items,
      total: items.length,
      source: result?.source || backend.kind,
      latencyMs: Date.now() - scopeStartedAt
    });
  }

  const aggregatedItems = searchResults.flatMap(r => r.items || []);
  const sources = [...new Set(searchResults.map(r => r.source).filter(Boolean))];
  const backendUserIds = [...new Set(searchResults.map(r => r.backendUserId).filter(Boolean))];

  return {
    actor,
    scope: resolvedScopes.length === 1 ? resolvedScopes[0] : '*',
    scopes: resolvedScopes,
    backendUserId: backendUserIds.length === 1 ? backendUserIds[0] : '*',
    backendUserIds,
    result: {
      items: aggregatedItems,
      total: aggregatedItems.length,
      source: sources.length === 1 ? sources[0] : sources,
      perScope: searchResults.map(({ scope, backendUserId, total, source, latencyMs }) => ({ scope, backendUserId, total, source, latencyMs })),
      latencyMs: Date.now() - startedAt
    }
  };
}

async function performCanonicalSearch({ actor, scope, scopes, query, policy, policies, canonicalStore, context, limit = 20, cursor = null, from = null, to = null }) {
  if (!hasPermission(policy, 'memory:search')) throw Object.assign(new Error('memory_search_forbidden'), { status: 403 });
  validateSearchInput(query);
  const resolvedScopes = normalizeRequestedScopes(scope, scopes, policy, policies);
  const result = await canonicalStore.search({ query, scopes: resolvedScopes, limit: normalizeSessionLimit(limit), cursor, from, to, actor, context });
  const items = (result?.items || []).filter(record => resolvedScopes.includes(record?.scope?.id) && recordActiveNow(record) && contextAllowsRecord(record, context, canonicalStore));
  return { items, nextCursor: result?.nextCursor || null, scopes: resolvedScopes };
}

function recordActiveNow(record) {
  if (record?.lifecycle?.status !== 'active') return false;
  const now = Date.now();
  return (!record.lifecycle.validFrom || Date.parse(record.lifecycle.validFrom) <= now) && (!record.lifecycle.validTo || Date.parse(record.lifecycle.validTo) > now);
}

function contextAllowsRecord(record, context, canonicalStore) {
  const sensitiveScope = /^(?:person|relationship|room):/.test(String(record?.scope?.id || ''));
  let routingContext = null;
  try { routingContext = canonicalStore?.routingContext?.(record.id) || null; } catch { return false; }
  if (sensitiveScope && !routingContext) return false;
  if (routingContext && (!context || !exactContextIntersection(routingContext, context.contextTags))) return false;
  if (context && ['group', 'channel'].includes(context.conversationKind) && record.visibility !== 'shared') return false;
  return true;
}

async function performMemoryProposal({ actor, policy, policies, fabricStore, scope, text = '', metadata = {}, infer = false, record = null, rationale = null, expectedRevision = null, idempotencyKey, source, requestId, requireIdempotencyKey }) {
  if (record) validateCanonicalProposal(record, rationale, expectedRevision);
  else validateProposalInput({ scope, text, metadata, idempotencyKey, requireIdempotencyKey });
  if (requireIdempotencyKey && !idempotencyKey) throw Object.assign(new Error('idempotency_key_required'), { status: 400 });
  if (idempotencyKey.length > LIMITS.idempotencyKeyChars) throw Object.assign(new Error('idempotency_key_too_large'), { status: 413 });
  if (!getScopeConfig(scope, policies)) {
    const error = new Error('scope_unregistered');
    error.status = 400;
    throw error;
  }
  if (!canProposeScope(policy, scope)) {
    const error = new Error('scope_forbidden');
    error.status = 403;
    error.data = { actor, scope, permission: 'memory:propose' };
    await auditRequired(fabricStore, { actor, action: 'memory_propose', outcome: 'denied', requestId, scope });
    throw error;
  }
  let proposal;
  try {
    proposal = await fabricStore.propose({ actor, scope, text, metadata, infer, record, rationale, expectedRevision, source, idempotencyKey });
  } catch (error) {
    await auditRequired(fabricStore, { actor, action: 'memory_propose', outcome: 'failed', requestId, scope, details: { code: publicError(error).code } });
    throw error;
  }
  await auditRequired(fabricStore, {
    actor,
    action: 'memory_propose',
    outcome: proposal.duplicate ? 'duplicate' : 'queued',
    requestId,
    targetId: proposal.id,
    scope,
    details: { source, contentId: proposal.contentId }
  });
  return proposal;
}

function authorizationFor(actor, policy, policies) {
  return {
    actor,
    allowedScopes: policy.mode === 'allow_all' ? [] : getAllowedScopes(policy, policies),
    allowAll: policy.mode === 'allow_all'
  };
}

async function performMemoryProposalStatus({ actor, policy, policies, fabricStore, id, requestId }) {
  if (!id) throw Object.assign(new Error('memory_id_required'), { status: 400 });
  if (!hasPermission(policy, 'memory:read')) throw Object.assign(new Error('memory_not_found'), { status: 404 });
  const status = await fabricStore.getProposalStatusAuthorized(id, authorizationFor(actor, policy, policies));
  await auditRequired(fabricStore, { actor, action: 'memory_proposal_status', outcome: 'allowed', requestId, targetId: id });
  return status;
}

async function performMemoryRead({ actor, policy, policies, fabricStore, canonicalStore, context = null, id, requestId }) {
  if (!id) {
    const error = new Error('memory_id_required');
    error.status = 400;
    throw error;
  }
  if (!hasPermission(policy, 'memory:read')) {
    await auditRequired(fabricStore, { actor, action: 'memory_read', outcome: 'denied', requestId, targetId: id });
    const error = new Error('memory_not_found');
    error.status = 404;
    throw error;
  }
  if (canonicalStore?.configured) {
    let record;
    try { record = await canonicalStore.read({ id, actor, context }); } catch (error) {
      if (error?.status === 404 || error?.message === 'memory_not_found') throw Object.assign(new Error('memory_not_found'), { status: 404 });
      throw error;
    }
    if (!record || !canReadScope(policy, record.scope?.id) || !recordActiveNow(record) || !contextAllowsRecord(record, context, canonicalStore)) throw Object.assign(new Error('memory_not_found'), { status: 404 });
    await auditRequired(fabricStore, { actor, action: 'memory_read', outcome: 'allowed', requestId, targetId: id, scope: record.scope.id });
    return { record };
  }
  throw Object.assign(new Error('memory_not_found'), { status: 404 });
}

const defaultBackend = createBackendAdapter();
const defaultSessionReader = createUnconfiguredSessionReader();
const defaultCanonicalStore = createUnconfiguredCanonicalStore();
const defaultContextVerifier = createUnconfiguredContextVerifier();

function createAgentMemoryFabricServer({ backend = defaultBackend, fabricStore = createUnconfiguredFabricStore('fabric_store_not_injected'), canonicalStore = defaultCanonicalStore, contextVerifier = defaultContextVerifier, receiptCoordinator = null, sessionReader = null, sessionOptions = {}, bodyReadTimeoutMs = BODY_READ_TIMEOUT_MS, rawIngestBodyBytes = LIMITS.rawIngestBodyBytes, curationCursorKey = crypto.randomBytes(32), clock = () => Date.now(), policyPath = POLICY_PATH, routeManifestPath = SESSION_ROUTE_MANIFEST_PATH } = {}) {
  if (!Buffer.isBuffer(curationCursorKey) || curationCursorKey.length < 32) throw new Error('curation_cursor_key_invalid');
if (!Number.isSafeInteger(rawIngestBodyBytes) || rawIngestBodyBytes < 1024 || rawIngestBodyBytes > 16 * 1024 * 1024) throw new Error('raw_ingest_body_limit_invalid');
sessionReader = sessionReader || fabricStore.createSessionReader?.() || defaultSessionReader;
const sessions = new Map();
const sessionPolicy = { ...MCP_SESSION_DEFAULTS, ...sessionOptions };
function pruneSessions(now = clock()) {
  for (const [id, session] of sessions) {
    if (now - session.lastSeenAt >= sessionPolicy.ttlMs) {
      if (session.res && !session.res.destroyed) session.res.end();
      sessions.delete(id);
    }
  }
}
function registerSession(session) {
  pruneSessions();
  if (sessions.size >= sessionPolicy.maxGlobal || [...sessions.values()].filter(item => item.actor === session.actor).length >= sessionPolicy.maxPerActor) {
    throw Object.assign(new Error('session_capacity_exceeded'), { status: 429 });
  }
  const id = createMcpSessionId();
  sessions.set(id, { ...session, createdAt: clock(), lastSeenAt: clock() });
  return id;
}
const requestHandler = async (req, res) => {
  const requestId = crypto.randomUUID();
  const requestStartedAt = Date.now();
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathnameParts = url.pathname.split('/').filter(Boolean);
  const policies = loadPolicies(policyPath);
  const sourceIp = String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown');
  const isMcpMessagePost = url.pathname === '/mcp/messages/' && req.method === 'POST';
  const isLegacySsePath = pathnameParts[0] === 'mcp' && pathnameParts[2] === 'sse' && pathnameParts[3] && req.method === 'GET';
  const isStreamableMcpPath = pathnameParts[0] === 'mcp' && pathnameParts.length === 3 && pathnameParts[1] && pathnameParts[2] && pathnameParts[2] !== 'messages';
  const requestSessionId = isMcpMessagePost ? (url.searchParams.get('session_id') || '') : (isStreamableMcpPath ? getMcpSessionHeader(req) : '');
  pruneSessions();
  const requestSession = requestSessionId ? sessions.get(requestSessionId) : null;

  if (url.pathname === '/health') {
    logEvent('health_check', { requestId, method: req.method, path: url.pathname, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
    return json(res, 200, {
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION
    });
  }

  let authContext;
  try {
    if (requestSession) {
      let refreshed;
      try {
        refreshed = await revalidateSession(requestSession);
      } catch (error) {
        if (requestSession.res && !requestSession.res.destroyed) requestSession.res.end();
        sessions.delete(requestSessionId);
        throw error;
      }
      requestSession.actor = refreshed.actor;
      requestSession.policy = refreshed.policy;
      requestSession.lastSeenAt = clock();
      authContext = { ...refreshed, viaSession: true };
      logEvent('auth_ok', { requestId, method: req.method, path: url.pathname, sourceIp, actor: authContext.actor, viaSession: true, sessionId: requestSessionId });
    } else if (requestSessionId) {
      throw Object.assign(new Error('session_expired'), { status: 401 });
    } else {
      authContext = await authenticateRequest(req, { allowQueryToken: Boolean(isLegacySsePath) });
      logEvent('auth_ok', { requestId, method: req.method, path: url.pathname, sourceIp, actor: authContext.actor });
    }
    validateContextActorBinding(authContext.actor, authContext.policy, policies, contextVerifier);
  } catch (error) {
    logEvent('auth_failed', { requestId, method: req.method, path: url.pathname, sourceIp, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
    try {
      await auditRequired(fabricStore, { actor: 'anonymous', action: 'authenticate', outcome: 'denied', requestId, details: { code: publicError(error, 401).code } });
    } catch (auditError) {
      const failure = url.pathname.startsWith('/v2/')
        ? v2Error(requestId, auditError, 503)
        : { status: 503, body: { error: 'audit_unavailable' } };
      return url.pathname.startsWith('/v1/')
        ? jsonV1(res, failure.status, failure.body)
        : json(res, failure.status, failure.body);
    }
    if (url.pathname.startsWith('/v2/')) {
      const failure = v2Error(requestId, error, 401);
      return json(res, failure.status, failure.body);
    }
    const failure = publicError(error, 401);
    if (url.pathname.startsWith('/v1/')) return jsonV1(res, failure.status, { error: failure.code });
    return json(res, failure.status, { error: failure.code });
  }

  const actor = authContext.actor;
  const policy = authContext.policy;

  if (url.pathname === '/v2/status' && req.method === 'GET') {
    try {
      requirePermission(policy, 'memory:status');
      await healthRequired(fabricStore);
      const response = buildStatus({ backend, fabricStore, canonicalStore, contextVerifier, sessionReader });
      await auditRequired(fabricStore, { actor, action: 'memory_status', outcome: 'allowed', requestId });
      return json(res, 200, v2Envelope(requestId, response));
    } catch (error) {
      const failure = v2Error(requestId, error, 403);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/identities' && req.method === 'POST') {
    try {
      requirePermission(policy, 'identity:write');
      const body = await parseBody(req);
      if (Object.hasOwn(body, 'actor') || Object.hasOwn(body, 'idempotencyKey')) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const scope = String(body.scope || '');
      if (!getScopeConfig(scope, policies) || !canReadScope(policy, scope)) throw Object.assign(new Error('scope_forbidden'), { status: 403 });
      const result = await fabricStore.createIdentity({ ...body, actor, idempotencyKey: String(req.headers['idempotency-key'] || '') });
      await auditRequired(fabricStore, { actor, action: 'identity_create', outcome: result.duplicate ? 'duplicate' : 'created', requestId, targetId: result.id, scope });
      return jsonNoStore(res, result.duplicate ? 200 : 201, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'identity_create', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'internal' && pathnameParts[2] === 'identities' && pathnameParts[3] && pathnameParts.length === 4 && req.method === 'GET') {
    try {
      requirePermission(policy, 'identity:read');
      const result = await fabricStore.readIdentityAuthorized(pathnameParts[3], authorizationFor(actor, policy, policies));
      await auditRequired(fabricStore, { actor, action: 'identity_read', outcome: 'allowed', requestId, targetId: result.id });
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'identity_read', requestId, targetId: pathnameParts[3], error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'internal' && pathnameParts[2] === 'identities' && pathnameParts[3] && ['merge', 'split'].includes(pathnameParts[4]) && pathnameParts.length === 5 && req.method === 'POST') {
    const operation = pathnameParts[4];
    try {
      requirePermission(policy, 'identity:write');
      const body = await parseBody(req);
      if (Object.hasOwn(body, 'actor') || Object.hasOwn(body, 'idempotencyKey')) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const scope = String(body.scope || '');
      if (!getScopeConfig(scope, policies) || !canReadScope(policy, scope)) throw Object.assign(new Error('scope_forbidden'), { status: 403 });
      const input = { ...body, actor, idempotencyKey: String(req.headers['idempotency-key'] || '') };
      const result = operation === 'merge'
        ? await fabricStore.mergeIdentity(pathnameParts[3], input)
        : await fabricStore.splitIdentity(pathnameParts[3], input);
      await auditRequired(fabricStore, { actor, action: `identity_${operation}`, outcome: result.duplicate ? 'duplicate' : 'applied', requestId, targetId: result.id, scope });
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: `identity_${operation}`, requestId, targetId: pathnameParts[3], error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/retention/plan' && req.method === 'POST') {
    try {
      requirePermission(policy, 'retention:manage');
      const body = await parseBody(req);
      const result = await fabricStore.planRetention(body, authorizationFor(actor, policy, policies));
      await auditRequired(fabricStore, { actor, action: 'retention_plan', outcome: 'allowed', requestId, details: { resultCount: result.candidates.length } });
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'retention_plan', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/retention/apply' && req.method === 'POST') {
    try {
      requirePermission(policy, 'retention:manage');
      const body = await parseBody(req);
      if (Object.hasOwn(body, 'actor') || Object.hasOwn(body, 'idempotencyKey')) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const result = await fabricStore.applyRetention({ ...body, actor, idempotencyKey: String(req.headers['idempotency-key'] || '') }, authorizationFor(actor, policy, policies));
      await auditRequired(fabricStore, { actor, action: 'retention_apply', outcome: 'applied', requestId, details: { resultCount: result.results.length } });
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'retention_apply', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/curation/proposals' && req.method === 'GET') {
    try {
      requirePermission(policy, 'memory:curate');
      const statuses = url.searchParams.getAll('status');
      const limit = Number(url.searchParams.get('limit') || 50);
      const requestedStatuses = statuses.length ? statuses : ['queued'];
      const authorization = authorizationFor(actor, policy, policies);
      const binding = curationCursorBinding(actor, requestedStatuses, authorization);
      const result = await fabricStore.listProposalsForCuration({
        statuses: requestedStatuses,
        after: decodeCurationCursor(url.searchParams.get('cursor'), binding, curationCursorKey),
        limit
      }, authorization);
      await auditRequired(fabricStore, { actor, action: 'curation_proposal_list', outcome: 'allowed', requestId, details: { resultCount: result.items.length } });
      return jsonNoStore(res, 200, v2Envelope(requestId, { items: result.items, nextCursor: encodeCurationCursor(result.next, binding, curationCursorKey) }));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'curation_proposal_list', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'internal' && pathnameParts[2] === 'curation'
      && pathnameParts[3] === 'proposals' && pathnameParts.length === 5 && req.method === 'GET') {
    const proposalId = pathnameParts[4];
    try {
      requirePermission(policy, 'memory:curate');
      await auditRequired(fabricStore, { actor, action: 'curation_proposal_decrypt_intent', outcome: 'authorized', requestId, targetId: proposalId, details: { transport: 'rest' } });
      const proposal = await fabricStore.readProposalAuthorized(proposalId, authorizationFor(actor, policy, policies));
      await auditRequired(fabricStore, { actor, action: 'curation_proposal_read', outcome: 'allowed', requestId, targetId: proposalId });
      return jsonNoStore(res, 200, v2Envelope(requestId, {
        proposalId: proposal.id,
        status: proposal.status,
        createdAt: proposal.createdAt,
        payload: proposal.payload,
        proposalDigest: proposal.proposalDigest
      }));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'curation_proposal_read', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/curation/receipts' && req.method === 'POST') {
    try {
      if (!receiptCoordinator) throw Object.assign(new Error('service_unavailable'), { status: 503 });
      const body = await parseBody(req);
      requirePermission(policy, body?.kind === 'apply' ? 'memory:apply-receipt' : 'memory:curate');
      const result = await receiptCoordinator.record(body, { actor, requestId, authorization: authorizationFor(actor, policy, policies) });
      return jsonNoStore(res, result.duplicate ? 200 : 201, v2Envelope(requestId, result));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'curation_receipt', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/internal/curation/reconcile' && req.method === 'POST') {
    try {
      requirePermission(policy, 'memory:apply-receipt');
      if (!receiptCoordinator) throw Object.assign(new Error('service_unavailable'), { status: 503 });
      const body = await parseBody(req);
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !['cursor', 'limit'].includes(key))) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const limit = body.limit === undefined ? 50 : body.limit;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100
          || (body.cursor !== undefined && (typeof body.cursor !== 'string' || body.cursor.length < 1 || body.cursor.length > 2048))) throw Object.assign(new Error('invalid_request'), { status: 400 });
      const authorization = authorizationFor(actor, policy, policies);
      const binding = curationCursorBinding(actor, ['reconcile'], authorization);
      const result = await receiptCoordinator.reconcile({ authorization, offset: decodeReconcileCursor(body.cursor, binding, curationCursorKey), limit });
      const response = { ok: result.ok, findings: result.findings, scanned: result.scanned, complete: result.complete, nextCursor: encodeReconcileCursor(result.nextOffset, binding, curationCursorKey) };
      await auditRequired(fabricStore, { actor, action: 'curation_reconcile', outcome: result.ok ? 'clean' : 'findings', requestId, details: { resultCount: result.findings.length } });
      return jsonNoStore(res, result.ok ? 200 : 409, v2Envelope(requestId, response));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'curation_reconcile', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/memory/candidates/search' && req.method === 'POST') {
    try {
      requirePermission(policy, 'memory:candidates:search');
      const body = await parseBody(req);
      const purpose = requirePurpose(body.purpose);
      if (purpose !== 'memory_curation') throw Object.assign(new Error('purpose_invalid'), { status: 400 });
      requirePurposePermission(policy, purpose);
      const result = await performScopedSearch({ actor, scope: String(body.scope || ''), scopes: Array.isArray(body.scopes) ? body.scopes : [], query: String(body.query || ''), policy, policies, backend, fabricStore });
      const data = { canonical: false, candidates: result.result.items, scopes: result.scopes, nextCursor: null };
      await auditRequired(fabricStore, { actor, action: 'memory_candidates_search', outcome: 'allowed', requestId, details: { resultCount: data.candidates.length, transport: 'rest' } });
      return jsonNoStore(res, 200, v2Envelope(requestId, data));
    } catch (error) {
      const reported = await auditInternalFailure(fabricStore, { actor, action: 'memory_candidates_search', requestId, error });
      const failure = v2Error(requestId, reported, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/memory/search' && req.method === 'POST') {
    let body;
    try {
      body = await parseBody(req);
      const scope = typeof body.scope === 'string' ? body.scope : '';
      const scopes = Array.isArray(body.scopes) ? body.scopes : [];
      const query = String(body.query || '');
      validateSearchInput(query);
      const purpose = requirePurpose(body.purpose);
      if (!canonicalStore.configured) throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: body.contextToken, request: buildContextRequest('memory_search', body), required: purpose === 'conversation_recall' || scopeRequiresContext(normalizeScopeList(scope, scopes)) });
      const response = await performCanonicalSearch({ actor, scope, scopes, query, policy, policies, canonicalStore, context, limit: body.limit, cursor: body.cursor, from: body.from, to: body.to });
      await auditRequired(fabricStore, { actor, action: 'memory_search', outcome: 'allowed', requestId, details: { scopes: response.scopes, total: response.result?.total ?? response.items?.length ?? 0 } });
      return json(res, 200, v2Envelope(requestId, response));
    } catch (error) {
      if (error?.message !== 'audit_unavailable') {
        await auditRequired(fabricStore, { actor, action: 'memory_search', outcome: 'failed', requestId, details: { code: publicError(error).code } });
      }
      const failure = v2Error(requestId, error, 502);
      return json(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/memory/proposals' && req.method === 'POST') {
    try {
      const body = await parseBody(req, { timeoutMs: bodyReadTimeoutMs });
      validateCanonicalProposalBody(body);
      const validated = validateCanonicalProposal(body.record, body.rationale, body.expectedRevision ?? null);
      const idempotencyKey = String(req.headers['idempotency-key'] || '');
      const proposal = await performMemoryProposal({
        actor,
        policy,
        policies,
        fabricStore,
        scope: validated.scope,
        record: body.record,
        rationale: body.rationale.trim(),
        expectedRevision: body.expectedRevision ?? null,
        idempotencyKey,
        source: 'v2-rest',
        requestId,
        requireIdempotencyKey: true
      });
      return json(res, proposal.duplicate ? 200 : 202, v2Envelope(requestId, { status: proposal.status, proposalId: proposal.id, duplicate: proposal.duplicate, idempotencyKey }));
    } catch (error) {
      const failure = v2Error(requestId, error, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/ingest/raw-events' && req.method === 'POST') {
    try {
      requirePermission(policy, 'raw:ingest');
      const body = await parseBody(req, { maxBytes: rawIngestBodyBytes, timeoutMs: bodyReadTimeoutMs });
      if (!body || Object.keys(body).sort().join('\0') !== 'envelope\0projection\0sourceInstanceId') throw Object.assign(new Error('invalid_request'), { status: 400 });
      const result = await fabricStore.ingestRawEvent({ actor, sourceInstanceId: body.sourceInstanceId, projection: body.projection, envelope: body.envelope }, { requestId });
      return jsonNoStore(res, result.duplicate ? 200 : 201, v2Envelope(requestId, { ...result, idempotencyKey: result.eventId }));
    } catch (error) {
      if (error?.message !== 'audit_unavailable') {
        try { await auditRequired(fabricStore, { actor, action: 'raw_event_ingest', outcome: 'failed', requestId, details: { code: publicError(error).code } }); } catch (auditError) { if (auditError?.message === 'audit_unavailable') error = auditError; }
      }
      const failure = v2Error(requestId, error, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'memory' && pathnameParts[2] === 'proposals' && pathnameParts[3] && pathnameParts.length === 4 && req.method === 'GET') {
    try {
      const status = await performMemoryProposalStatus({ actor, policy, policies, fabricStore, id: pathnameParts[3], requestId });
      return jsonNoStore(res, 200, v2Envelope(requestId, status));
    } catch (error) {
      const failure = v2Error(requestId, error, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'memory' && pathnameParts[2] && pathnameParts.length === 3 && req.method === 'GET') {
    try {
      const purpose = requirePurpose(url.searchParams.get('purpose'));
      if (!canonicalStore.configured) throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose,
        token: getAccessContextToken(req, url, policy), request: buildContextRequest('memory_read', { id: pathnameParts[2] }), required: purpose === 'conversation_recall' });
      const memory = await performMemoryRead({ actor, policy, policies, fabricStore, canonicalStore, context, id: pathnameParts[2], requestId });
      return jsonNoStore(res, 200, v2Envelope(requestId, memory));
    } catch (error) {
      const failure = v2Error(requestId, error, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v2/sessions/search' && req.method === 'POST') {
    try {
      requireSessionPermission(policy);
      const body = await parseBody(req);
      const purpose = requirePurpose(body.purpose);
      const query = String(body.query || '');
      const limit = normalizeSessionLimit(body.limit);
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: body.contextToken, request: buildContextRequest('sessions_search', body), required: true });
      const routeScopes = requireSessionRouteScopes(context, actor, policy, policies, contextVerifier,
        routeManifestPath);
      validateSearchInput(query);
      const ownerActors = authorizedSessionOwners(actor, policy);
      const raw = await sessionReader.search({ actor, ownerActors, query, cursor: body.cursor || null, limit,
        from: body.from || null, to: body.to || null, purpose, context });
      const result = { ...raw, items: (raw?.items || []).filter(item => sessionVisible(item, actor, policy,
        policies, context, routeScopes, ownerActors)).map(item => exposeSession(item, routeScopes)),
      nextCursor: raw?.nextCursor || null };
      await auditRequired(fabricStore, { actor, action: 'sessions_search', outcome: 'allowed', requestId, details: { resultCount: result.items.length, purpose } });
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const failure = v2Error(requestId, error, 500);
      return jsonNoStore(res, failure.status, failure.body);
    }
  }

  if (pathnameParts[0] === 'v2' && pathnameParts[1] === 'sessions' && pathnameParts[2] && req.method === 'GET') {
    try {
      requireSessionPermission(policy);
      const sessionId = pathnameParts[2];
      const isTranscript = pathnameParts[3] === 'transcript';
      const purpose = requirePurpose(url.searchParams.get('purpose'));
      let result;
      if (isTranscript) {
        const view = url.searchParams.get('view') === 'original' ? 'original' : 'redacted';
        const transcriptInput = { sessionId, view, query: url.searchParams.get('query') || '',
          cursor: url.searchParams.get('cursor'), limit: url.searchParams.get('limit'),
          from: url.searchParams.get('from'), to: url.searchParams.get('to') };
        validateSearchInput(transcriptInput.query);
        if (view === 'original' && transcriptInput.query) throw Object.assign(new Error('invalid_request'), { status: 400 });
        const context = requireAccessContext(contextVerifier, { actor, policy, purpose,
          token: getAccessContextToken(req, url, policy), request: buildContextRequest('session_transcript', transcriptInput), required: true });
        await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
          routeManifestPath, id: sessionId, purpose, context });
        if (view === 'original' && !hasPermission(policy, 'raw:decrypt')) {
          await auditRequired(fabricStore, { actor, action: 'session_transcript', outcome: 'denied', requestId, targetId: sessionId, details: { view, purpose } });
          const error = new Error('raw_decrypt_forbidden');
          error.status = 403;
          throw error;
        }
        if (view === 'original') await auditRequired(fabricStore, { actor, action: 'raw_decrypt_intent', outcome: 'authorized', requestId, targetId: sessionId, details: { view, purpose, transport: 'rest' } });
        const transcript = await sessionReader.transcript({ actor, ownerActors: authorizedSessionOwners(actor, policy),
          id: sessionId, view, cursor: transcriptInput.cursor, limit: normalizeSessionLimit(transcriptInput.limit || 100),
          query: transcriptInput.query, from: transcriptInput.from, to: transcriptInput.to, purpose, context });
        result = { ...transcript, nextCursor: transcript?.nextCursor || null };
        await auditRequired(fabricStore, { actor, action: 'session_transcript', outcome: 'allowed', requestId, targetId: sessionId, details: { view, purpose } });
      } else if (pathnameParts.length === 3) {
        const context = requireAccessContext(contextVerifier, { actor, policy, purpose,
          token: getAccessContextToken(req, url, policy), request: buildContextRequest('session_get', { sessionId }), required: true });
        result = await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
          routeManifestPath, id: sessionId, purpose, context });
        await auditRequired(fabricStore, { actor, action: 'session_get', outcome: 'allowed', requestId, targetId: sessionId, details: { purpose } });
      } else {
        const error = new Error('not_found');
        error.status = 404;
        throw error;
      }
      return jsonNoStore(res, 200, v2Envelope(requestId, result));
    } catch (error) {
      const failure = v2Error(requestId, error, 500);
      return json(res, failure.status, failure.body);
    }
  }

  if (url.pathname === '/v1/memory/read' && req.method === 'POST') {
    try {
      const body = await parseBody(req);
      const purpose = requirePurpose(body.purpose);
      if (!canonicalStore.configured) throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 });
      const id = String(body.id || '');
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: body.contextToken, request: buildContextRequest('memory_read', { id }), required: purpose === 'conversation_recall' });
      return jsonV1(res, 200, await performMemoryRead({ actor, policy, policies, fabricStore, canonicalStore, context, id, requestId }));
    } catch (error) {
      const failure = publicError(error, 500); return jsonV1(res, failure.status, { error: failure.code });
    }
  }

  if (url.pathname === '/v1/sessions/search' && req.method === 'POST') {
    try {
      requireSessionPermission(policy);
      const body = await parseBody(req); const purpose = requirePurpose(body.purpose); const query = String(body.query || ''); const limit = normalizeSessionLimit(body.limit);
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: body.contextToken, request: buildContextRequest('sessions_search', body), required: true });
      const routeScopes = requireSessionRouteScopes(context, actor, policy, policies, contextVerifier,
        routeManifestPath);
      validateSearchInput(query);
      const ownerActors = authorizedSessionOwners(actor, policy);
      const raw = await sessionReader.search({ actor, ownerActors, query, cursor: body.cursor || null, limit,
        from: body.from || null, to: body.to || null, purpose, context });
      const result = { ...raw, items: (raw?.items || []).filter(item => sessionVisible(item, actor, policy,
        policies, context, routeScopes, ownerActors)).map(item => exposeSession(item, routeScopes)),
      nextCursor: raw?.nextCursor || null };
      await auditRequired(fabricStore, { actor, action: 'sessions_search', outcome: 'allowed', requestId, details: { resultCount: result.items.length, purpose, transport: 'v1' } });
      return jsonV1(res, 200, result);
    } catch (error) { const failure = publicError(error, 500); return jsonV1(res, failure.status, { error: failure.code }); }
  }

  if (pathnameParts[0] === 'v1' && pathnameParts[1] === 'sessions' && pathnameParts[2] && req.method === 'GET') {
    try {
      requireSessionPermission(policy); const id = pathnameParts[2]; const purpose = requirePurpose(url.searchParams.get('purpose')); const transcript = pathnameParts[3] === 'transcript';
      if (transcript) {
        const view = url.searchParams.get('view') === 'original' ? 'original' : 'redacted';
        const input = { sessionId: id, view, query: url.searchParams.get('query') || '',
          cursor: url.searchParams.get('cursor'), limit: url.searchParams.get('limit'),
          from: url.searchParams.get('from'), to: url.searchParams.get('to') };
        validateSearchInput(input.query);
        if (view === 'original' && input.query) throw Object.assign(new Error('invalid_request'), { status: 400 });
        const context = requireAccessContext(contextVerifier, { actor, policy, purpose,
          token: getAccessContextToken(req, url, policy), request: buildContextRequest('session_transcript', input), required: true });
        await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
          routeManifestPath, id, purpose, context });
        if (view === 'original' && !hasPermission(policy, 'raw:decrypt')) throw Object.assign(new Error('raw_decrypt_forbidden'), { status: 403 });
        if (view === 'original') await auditRequired(fabricStore, { actor, action: 'raw_decrypt_intent', outcome: 'authorized', requestId, targetId: id, details: { view, purpose, transport: 'v1' } });
        const result = await sessionReader.transcript({ actor, ownerActors: authorizedSessionOwners(actor, policy),
          id, view, cursor: input.cursor, limit: normalizeSessionLimit(input.limit || 100), from: input.from,
          to: input.to, query: input.query, purpose, context });
        await auditRequired(fabricStore, { actor, action: 'session_transcript', outcome: 'allowed', requestId, targetId: id, details: { view, purpose, transport: 'v1' } });
        return jsonV1(res, 200, result);
      }
      if (pathnameParts.length !== 3) throw Object.assign(new Error('not_found'), { status: 404 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose,
        token: getAccessContextToken(req, url, policy), request: buildContextRequest('session_get', { sessionId: id }), required: true });
      const result = await getAuthorizedSession(sessionReader, { actor, policy, policies, contextVerifier,
        routeManifestPath, id, purpose, context });
      await auditRequired(fabricStore, { actor, action: 'session_get', outcome: 'allowed', requestId, targetId: id, details: { purpose, transport: 'v1' } });
      return jsonV1(res, 200, result);
    } catch (error) { const failure = publicError(error, 500); return jsonV1(res, failure.status, { error: failure.code }); }
  }

  if (url.pathname === '/v1/policies/resolve') {
    const scope = url.searchParams.get('scope') || '';
    const response = {
      actor,
      scope,
      allowed: canReadScope(policy, scope),
      policy,
      scopeConfig: getScopeConfig(scope, policies)
    };
    logEvent('resolve_policy', { requestId, actor, path: url.pathname, scope, allowed: response.allowed, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
    return jsonV1(res, 200, response);
  }

  if (url.pathname === '/v1/memory/search' && req.method === 'POST') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return jsonV1(res, 400, { error: 'invalid_json' });
    const scope = typeof body.scope === 'string' ? body.scope : '';
    const scopes = Array.isArray(body.scopes) ? body.scopes : [];
    const query = String(body.query || '');
    try {
      validateSearchInput(query);
      const purpose = requirePurpose(body.purpose);
      if (!canonicalStore.configured) throw Object.assign(new Error('canonical_store_unconfigured'), { status: 503 });
      const context = requireAccessContext(contextVerifier, { actor, policy, purpose, token: body.contextToken, request: buildContextRequest('memory_search', body), required: purpose === 'conversation_recall' || scopeRequiresContext(normalizeScopeList(scope, scopes)) });
      const response = await performCanonicalSearch({ actor, scope, scopes, query, policy, policies, canonicalStore, context, limit: body.limit, cursor: body.cursor, from: body.from, to: body.to });
      await auditRequired(fabricStore, { actor, action: 'memory_search', outcome: 'allowed', requestId, details: { total: response.items.length, transport: 'v1' } });
      logEvent('memory_search', { requestId, actor, path: url.pathname, requestedScope: scope || null, requestedScopes: scopes, resolvedScopes: response.scopes, total: response.items.length, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return jsonV1(res, 200, response);
    } catch (error) {
      const status = error?.status === 403 ? 403 : error?.status === 400 ? 400 : 502;
      logEvent('memory_search_failed', { requestId, actor, path: url.pathname, requestedScope: scope || null, requestedScopes: scopes, sourceIp, statusCode: status, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      const failure = publicError(error, status);
      return jsonV1(res, failure.status, { error: failure.code });
    }
  }

  if (url.pathname === '/v1/memory/add' && req.method === 'POST') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return jsonV1(res, 400, { error: 'invalid_json' });
    const scope = String(body.scope || '');
    const text = String(body.text || '');
    const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};
    const infer = Boolean(body.infer);
    try {
      const proposal = await performMemoryProposal({
        actor,
        policy,
        policies,
        fabricStore,
        scope,
        text,
        metadata,
        infer,
        idempotencyKey: String(req.headers['idempotency-key'] || body.idempotencyKey || deriveV1IdempotencyKey({ actor, scope, text, metadata, infer })),
        source: 'v1-memory-add',
        requestId,
        requireIdempotencyKey: false
      });
      const response = {
        ok: true,
        accepted: true,
        status: 'queued',
        state: 'queued',
        queued: true,
        promoted: false,
        proposalId: proposal.id,
        actor,
        scope,
        proposal,
        result: {
          status: 'queued',
          proposalId: proposal.id,
          canonical: false
        }
      };
      logEvent('memory_add_queued', { requestId, actor, path: url.pathname, scope, infer, metadataKeys: Object.keys(metadata || {}), proposalId: proposal.id, duplicate: proposal.duplicate, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return jsonV1(res, 200, response);
    } catch (error) {
      const status = error?.status || 500;
      logEvent('memory_add_failed', { requestId, actor, path: url.pathname, scope, infer, sourceIp, statusCode: status, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      const failure = publicError(error, status);
      return jsonV1(res, failure.status, { error: failure.code });
    }
  }

  if (pathnameParts[0] === 'mcp' && pathnameParts[2] === 'sse' && pathnameParts[3] && req.method === 'GET') {
    const clientName = String(pathnameParts[1]);
    const identity = String(pathnameParts[3]);
    let sessionId;
    try {
      sessionId = registerSession({ res, actor, policy, tokenDigestHex: authContext.tokenDigestHex, clientName, identity, transport: 'sse' });
    } catch (error) {
      const failure = publicError(error, 429);
      return json(res, failure.status, { error: failure.code });
    }
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      ...PRIVATE_HEADERS,
      'cache-control': 'no-store, private, no-transform',
      connection: 'keep-alive'
    });
    sendSse(res, 'endpoint', `/mcp/messages/?session_id=${sessionId}`);
    req.on('close', () => {
      sessions.delete(sessionId);
    });
    return;
  }

  if (isStreamableMcpPath && req.method === 'GET') {
    res.writeHead(405, { ...PRIVATE_HEADERS, allow: 'POST, DELETE' });
    res.end();
    return;
  }

  if (isStreamableMcpPath && req.method === 'POST') {
    const clientName = String(pathnameParts[1]);
    const identity = String(pathnameParts[2]);
    const body = await parseBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'invalid_json' });

    let sessionId = requestSessionId;
    let session = requestSession;
    if (!session) {
      try {
        sessionId = registerSession({ actor, policy, tokenDigestHex: authContext.tokenDigestHex, clientName, identity, transport: 'streamable-http' });
        session = sessions.get(sessionId);
      } catch (error) {
        const failure = publicError(error, 429);
        return json(res, failure.status, { error: failure.code });
      }
      if (body.method !== 'initialize') {
        logEvent('mcp_session_recreated', { requestId, actor, clientName, identity, sourceIp, oldSessionId: requestSessionId || null, sessionId });
      }
    }

    try {
      const responseBody = await executeMcpMethod({
        body,
        actor: session.actor,
        policy: session.policy,
        policies,
        backend,
        fabricStore,
        canonicalStore,
        contextVerifier,
        routeManifestPath,
        sessionReader,
        requestId,
        requestStartedAt,
        sourceIp,
        sessionId,
        clientName: session.clientName
      });

      if (responseBody === null) {
        res.writeHead(202, {
          ...PRIVATE_HEADERS,
          'mcp-session-id': sessionId
        });
        res.end();
        return;
      }

      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        ...PRIVATE_HEADERS,
        'mcp-session-id': sessionId
      });
      res.end(JSON.stringify(responseBody, null, 2));
      return;
    } catch (error) {
      logEvent('mcp_tools_call_failed', { requestId, actor: session.actor, sessionId, clientName: session.clientName, sourceIp, statusCode: 500, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      const failure = publicError(error, 500);
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        ...PRIVATE_HEADERS,
        'mcp-session-id': sessionId
      });
      res.end(JSON.stringify(createRpcError(body.id ?? null, -32000, failure.code), null, 2));
      return;
    }
  }

  if (isStreamableMcpPath && req.method === 'DELETE') {
    if (!requestSession) return json(res, 404, { error: 'unknown_session' });
    sessions.delete(requestSessionId);
    res.writeHead(204, PRIVATE_HEADERS);
    res.end();
    return;
  }

  if (url.pathname === '/mcp/messages/' && req.method === 'POST') {
    const sessionId = requestSessionId;
    const session = requestSession;
    if (!session) return json(res, 404, { error: 'unknown_session' });
    const body = await parseBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'invalid_json' });

    const currentActor = session.actor;
    const currentPolicy = session.policy;

    try {
      const responseBody = await executeMcpMethod({
        body,
        actor: currentActor,
        policy: currentPolicy,
        policies,
        backend,
        fabricStore,
        canonicalStore,
        contextVerifier,
        routeManifestPath,
        sessionReader,
        requestId,
        requestStartedAt,
        sourceIp,
        sessionId,
        clientName: session.clientName
      });
      if (responseBody !== null) {
        sendSse(session.res, 'message', responseBody);
      }
      res.writeHead(200, PRIVATE_HEADERS).end();
      return;
    } catch (error) {
      logEvent('mcp_tools_call_failed', { requestId, actor: currentActor, sessionId, clientName: session.clientName, sourceIp, statusCode: 500, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      const failure = publicError(error, 500);
      sendSse(session.res, 'message', createRpcError(body.id ?? null, -32000, failure.code));
      res.writeHead(200, PRIVATE_HEADERS).end();
      return;
    }
  }

  if (url.pathname.startsWith('/v2/')) {
    const error = new Error('not_found');
    error.status = 404;
    const failure = v2Error(requestId, error, 404);
    return json(res, failure.status, failure.body);
  }
  return json(res, 404, { error: 'not_found' });
};
const applicationServer = http.createServer((req, res) => {
  requestHandler(req, res).catch((error) => {
    logEvent('request_handler_failed', {
      method: req.method,
      path: String(req.url || ''),
      error: safeError(error),
      statusCode: 503
    });
    if (res.headersSent || res.writableEnded) {
      if (!res.destroyed) res.destroy();
      return;
    }
    const requestId = crypto.randomUUID();
    const pathname = String(req.url || '').split('?', 1)[0];
    if (pathname.startsWith('/v2/')) {
      const failure = v2Error(requestId, Object.assign(new Error('service_unavailable'), { status: 503 }), 503);
      json(res, failure.status, failure.body);
      return;
    }
    if (pathname.startsWith('/v1/')) {
      jsonV1(res, 503, { error: 'service_unavailable' });
      return;
    }
    json(res, 503, { error: 'service_unavailable' });
  });
});
applicationServer.on('close', () => {
  Promise.resolve(fabricStore.close?.()).catch((error) => {
    logEvent('fabric_store_close_failed', { error: safeError(error) });
  });
  Promise.resolve(canonicalStore.close?.()).catch((error) => {
    logEvent('canonical_store_close_failed', { error: safeError(error) });
  });
  Promise.resolve(receiptCoordinator?.close?.()).catch((error) => {
    logEvent('receipt_coordinator_close_failed', { error: safeError(error) });
  });
});
return applicationServer;
}

if (process.argv.includes('--check')) {
  const checkStore = createUnconfiguredFabricStore('check_only');
  console.log(JSON.stringify({ ok: true, service: SERVICE_NAME, aliases: LEGACY_SERVICE_ALIASES, policyPath: POLICY_PATH, port: PORT, backend: defaultBackend.kind, configured: defaultBackend.configured, fabricStore: checkStore.status(), authRegistry: getAuthRegistrySource().kind }, null, 2));
  process.exit(0);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isMain) {
  if (process.env.AMF_SERVER_ENABLED !== 'true') {
    console.error('agent-memory-fabric disabled: set AMF_SERVER_ENABLED=true explicitly');
    process.exitCode = 78;
  } else if (!POLICY_PATH) {
    console.error('agent-memory-fabric disabled: AMF_POLICY_PATH must reference an explicit production policy');
    process.exitCode = 78;
  } else {
    let runtimeFabricStore;
    let runtimeCanonicalStore;
    let runtimeReceiptCoordinator;
    let runtimeServer;
    try {
      validatePamRuntimePrivateDirFromEnv(process.env);
      runtimeFabricStore = createFabricStoreFromEnv({ rootPath: ROOT });
      runtimeCanonicalStore = createCanonicalPamBridgeFromEnv(process.env);
      const runtimeContextVerifier = createContextVerifierFromEnv(process.env);
      runtimeReceiptCoordinator = createReceiptCoordinatorFromEnv({ canonicalStore: runtimeCanonicalStore, proposalStore: runtimeFabricStore });
      runtimeServer = createAgentMemoryFabricServer({ fabricStore: runtimeFabricStore, canonicalStore: runtimeCanonicalStore, contextVerifier: runtimeContextVerifier, receiptCoordinator: runtimeReceiptCoordinator });
    } catch (error) {
      console.error(`agent-memory-fabric disabled: configuration failed: ${safeError(error)?.code || 'internal_error'}`);
      process.exitCode = 78;
    }
    Promise.resolve(runtimeFabricStore?.ready?.()).then(() => {
      if (!runtimeServer) return;
      runtimeServer.listen(PORT, () => {
        console.log(`${SERVICE_NAME} listening on :${PORT}`);
        console.log(`policy path: ${POLICY_PATH}`);
        console.log(`backend kind: ${defaultBackend.kind}`);
        console.log(`auth registry: ${getAuthRegistrySource().kind}`);
      });
    }).catch(async (error) => {
      console.error(`agent-memory-fabric disabled: catalog initialization failed: ${safeError(error)?.code || 'internal_error'}`);
      try { await runtimeFabricStore?.close?.(); } catch {}
      try { await runtimeCanonicalStore?.close?.(); } catch {}
      try { await runtimeReceiptCoordinator?.close?.(); } catch {}
      process.exitCode = 78;
    });
  }
}

export {
  authenticateRequest,
  createAgentMemoryFabricServer,
  getAuthRegistrySource,
  loadAuthRegistry,
  parseActive,
  parseCsvList,
  validateContextActorBinding
};
