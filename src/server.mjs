import crypto from 'node:crypto';
import http from 'node:http';
import { URL } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import { createBackendAdapter } from './backend.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const POLICY_PATH = process.env.MEM0_GATEWAY_POLICY_PATH || path.join(ROOT, 'config', 'policies.example.json');
const PORT = Number(process.env.PORT || 8787);
const sessions = new Map();
const AUTH_CACHE_TTL_MS = Number(process.env.MEM0_AUTH_CACHE_TTL_MS || '15000');
const authCache = { loadedAt: 0, rows: [] };

function loadPolicies() {
  try {
    return JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  } catch {
    return { actors: {}, scopes: {} };
  }
}

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body, null, 2));
}

function nowIso() {
  return new Date().toISOString();
}

function safeError(error) {
  if (!error) return null;
  return {
    message: error?.message || String(error),
    status: error?.status,
    data: error?.data || error?.body || null
  };
}

function logEvent(event, payload = {}) {
  try {
    console.log(JSON.stringify({ ts: nowIso(), event, ...payload }));
  } catch {
    console.log(JSON.stringify({ ts: nowIso(), event, payload_error: true }));
  }
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

function canWriteScope(policy, scope) {
  if (!hasPermission(policy, 'memory:add')) return false;
  if (policy.mode === 'allow_all') return true;
  if (policy.mode === 'scoped') {
    return Array.isArray(policy.allowedScopes) && (policy.allowedScopes.includes(scope) || policy.allowedScopes.includes('*'));
  }
  return false;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
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

function buildInitializeResult(protocolVersion) {
  return {
    protocolVersion: protocolVersion || '2024-11-05',
    capabilities: { tools: {} },
    serverInfo: { name: 'mem0-gateway', version: '0.1.0' }
  };
}

function buildToolsListResult() {
  return {
    tools: [
      {
        name: 'memory_search',
        description: 'Search memory within an allowed scope through the custom Mem0 gateway.',
        inputSchema: {
          type: 'object',
          properties: {
            scope: { type: 'string' },
            query: { type: 'string' }
          },
          required: ['scope', 'query']
        }
      },
      {
        name: 'list_scopes',
        description: 'List scopes visible to the current actor.',
        inputSchema: { type: 'object', properties: {} }
      },
      {
        name: 'gateway_health',
        description: 'Return health and backend information for the custom gateway.',
        inputSchema: { type: 'object', properties: {} }
      }
    ]
  };
}

async function executeMcpMethod({ body, actor, policy, policies, backend, requestId, requestStartedAt, sourceIp, sessionId, clientName }) {
  const method = body.method;
  const id = body.id ?? null;

  if (method === 'initialize') {
    return createRpcResult(id, buildInitializeResult(body.params?.protocolVersion));
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
        content: [{ type: 'text', text: JSON.stringify({ backend: backend.kind, configured: backend.configured }, null, 2) }]
      });
    }

    if (name === 'memory_search') {
      const scope = typeof args.scope === 'string' ? args.scope : '';
      const scopes = Array.isArray(args.scopes) ? args.scopes : [];
      const query = String(args.query || '');
      const searchResult = await performScopedSearch({ actor, scope, scopes, query, policy, policies, backend });
      logEvent('mcp_tools_call', { requestId, actor, tool: 'memory_search', sessionId, clientName, requestedScope: scope || null, requestedScopes: scopes, resolvedScopes: searchResult.scopes, perScope: searchResult.result?.perScope, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return createRpcResult(id, {
        content: [{ type: 'text', text: JSON.stringify(searchResult, null, 2) }]
      });
    }

    return createRpcError(id, -32601, 'Unknown tool');
  }

  return createRpcError(id, -32601, `Unsupported method: ${method}`);
}

function getAllowedScopes(policy, policies) {
  if (policy.mode === 'allow_all') return Object.keys(policies.scopes || {});
  if (policy.mode === 'scoped' || policy.mode === 'read_only_scoped') return policy.allowedScopes || [];
  return [];
}

function normalizeRequestedScopes(inputScope, inputScopes, policy, policies) {
  const availableScopes = Object.keys(policies.scopes || {});
  const allowedScopes = getAllowedScopes(policy, policies);
  const hasWildcardAccess = allowedScopes.includes('*');

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
  const raw = String(value || '').trim();
  if (!raw) return [];
  if (raw === '*') return ['*'];
  return raw.split(',').map(x => x.trim()).filter(Boolean);
}

function getBearerToken(req) {
  const auth = String(req.headers.authorization || req.headers.Authorization || '');
  if (auth.startsWith('Bearer ')) return auth.slice('Bearer '.length).trim();
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const q = url.searchParams.get('access_token');
  return q ? String(q) : '';
}

async function loadAuthRegistry() {
  const now = Date.now();
  if (now - authCache.loadedAt < AUTH_CACHE_TTL_MS && Array.isArray(authCache.rows) && authCache.rows.length) {
    return authCache.rows;
  }
  const baseUrl = process.env.N8N_API_BASE_URL;
  const apiKey = process.env.N8N_API_KEY;
  const tableId = process.env.N8N_AUTH_TABLE_ID;
  if (!baseUrl || !apiKey || !tableId) {
    throw new Error('auth_registry_unconfigured');
  }
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
    err.body = data ?? text;
    throw err;
  }
  authCache.rows = data?.data || [];
  authCache.loadedAt = now;
  return authCache.rows;
}

async function authenticateRequest(req) {
  const token = getBearerToken(req);
  if (!token) {
    const err = new Error('missing_token');
    err.status = 401;
    throw err;
  }
  const rows = await loadAuthRegistry();
  const row = rows.find(r => String(r.token || '') === token && Boolean(r.active));
  if (!row) {
    const err = new Error('invalid_token');
    err.status = 401;
    throw err;
  }
  return {
    token,
    actor: String(row.actor || 'anonymous'),
    policy: {
      mode: String(row.mode || 'deny'),
      allowedScopes: parseCsvList(row.allowedScopes),
      permissions: parseCsvList(row.permissions)
    }
  };
}

async function performScopedSearch({ actor, scope, scopes, query, policy, policies, backend }) {
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
    const items = (result?.items || []).map(item => ({ ...item, scope: resolvedScope }));
    searchResults.push({
      scope: resolvedScope,
      backendUserId: scopeConfig.backendUserId,
      items,
      total: result?.total || items.length,
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

async function performScopedAdd({ actor, scope, text, metadata, infer, policy, policies, backend }) {
  if (!canWriteScope(policy, scope)) {
    const err = new Error('scope_forbidden');
    err.status = 403;
    err.data = { actor, scope, permission: 'memory:add' };
    throw err;
  }
  const scopeConfig = getScopeConfig(scope, policies);
  if (!scopeConfig?.backendUserId) {
    const err = new Error('scope_unmapped');
    err.status = 400;
    err.data = { scope };
    throw err;
  }
  const result = await backend.add({
    backendUserId: scopeConfig.backendUserId,
    text,
    metadata,
    infer
  });
  return {
    ok: true,
    actor,
    scope,
    backendUserId: scopeConfig.backendUserId,
    result
  };
}

const backend = createBackendAdapter();

const server = http.createServer(async (req, res) => {
  const requestId = crypto.randomUUID();
  const requestStartedAt = Date.now();
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathnameParts = url.pathname.split('/').filter(Boolean);
  const policies = loadPolicies();
  const sourceIp = String(req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown');
  const isMcpMessagePost = url.pathname === '/mcp/messages/' && req.method === 'POST';
  const isStreamableMcpPath = pathnameParts[0] === 'mcp' && pathnameParts.length === 3 && pathnameParts[1] && pathnameParts[2] && pathnameParts[2] !== 'messages';
  const requestSessionId = isMcpMessagePost ? (url.searchParams.get('session_id') || '') : (isStreamableMcpPath ? getMcpSessionHeader(req) : '');
  const requestSession = requestSessionId ? sessions.get(requestSessionId) : null;

  if (url.pathname === '/health') {
    logEvent('health_check', { requestId, method: req.method, path: url.pathname, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
    return json(res, 200, {
      ok: true,
      service: 'mem0-gateway',
      backend: {
        kind: backend.kind,
        configured: backend.configured
      },
      auth: {
        registry: process.env.N8N_AUTH_TABLE_ID ? 'n8n-data-table' : 'unconfigured'
      }
    });
  }

  let authContext;
  try {
    if (requestSession) {
      authContext = {
        token: 'session',
        actor: requestSession.actor,
        policy: requestSession.policy,
        viaSession: true
      };
      logEvent('auth_ok', { requestId, method: req.method, path: url.pathname, sourceIp, actor: authContext.actor, viaSession: true, sessionId: requestSessionId });
    } else {
      authContext = await authenticateRequest(req);
      logEvent('auth_ok', { requestId, method: req.method, path: url.pathname, sourceIp, actor: authContext.actor });
    }
  } catch (error) {
    logEvent('auth_failed', { requestId, method: req.method, path: url.pathname, sourceIp, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
    return json(res, error?.status || 401, { error: error?.message || 'unauthorized' });
  }

  const actor = authContext.actor;
  const policy = authContext.policy;

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
    return json(res, 200, response);
  }

  if (url.pathname === '/v1/memory/search' && req.method === 'POST') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'invalid_json' });
    const scope = typeof body.scope === 'string' ? body.scope : '';
    const scopes = Array.isArray(body.scopes) ? body.scopes : [];
    const query = String(body.query || '');
    try {
      const response = await performScopedSearch({ actor, scope, scopes, query, policy, policies, backend });
      logEvent('memory_search', { requestId, actor, path: url.pathname, requestedScope: scope || null, requestedScopes: scopes, resolvedScopes: response.scopes, total: response.result?.total, perScope: response.result?.perScope, sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return json(res, 200, response);
    } catch (error) {
      const status = error?.status === 403 ? 403 : error?.status === 400 ? 400 : 502;
      logEvent('memory_search_failed', { requestId, actor, path: url.pathname, requestedScope: scope || null, requestedScopes: scopes, sourceIp, statusCode: status, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      return json(res, status, {
        error: error?.message || 'backend_error',
        details: error?.data || error?.body || null
      });
    }
  }

  if (url.pathname === '/v1/memory/add' && req.method === 'POST') {
    const body = await parseBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'invalid_json' });
    const scope = String(body.scope || '');
    const text = String(body.text || '');
    const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};
    const infer = Boolean(body.infer);
    try {
      const response = await performScopedAdd({ actor, scope, text, metadata, infer, policy, policies, backend });
      logEvent('memory_add', { requestId, actor, path: url.pathname, scope, infer, metadataKeys: Object.keys(metadata || {}), sourceIp, statusCode: 200, latencyMs: Date.now() - requestStartedAt });
      return json(res, 200, response);
    } catch (error) {
      const status = error?.status === 403 ? 403 : error?.status === 400 ? 400 : 502;
      logEvent('memory_add_failed', { requestId, actor, path: url.pathname, scope, infer, sourceIp, statusCode: status, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      return json(res, status, {
        error: error?.message || 'backend_error',
        details: error?.data || error?.body || null
      });
    }
  }

  if (pathnameParts[0] === 'mcp' && pathnameParts[2] === 'sse' && pathnameParts[3] && req.method === 'GET') {
    const clientName = String(pathnameParts[1]);
    const identity = String(pathnameParts[3]);
    const sessionId = createMcpSessionId();
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive'
    });
    sessions.set(sessionId, { res, actor, policy, clientName, identity });
    sendSse(res, 'endpoint', `/mcp/messages/?session_id=${sessionId}`);
    req.on('close', () => {
      sessions.delete(sessionId);
    });
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
      sessionId = createMcpSessionId();
      session = { actor, policy, clientName, identity, transport: 'streamable-http' };
      sessions.set(sessionId, session);
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
        requestId,
        requestStartedAt,
        sourceIp,
        sessionId,
        clientName: session.clientName
      });

      if (responseBody === null) {
        res.writeHead(202, {
          'cache-control': 'no-cache',
          'mcp-session-id': sessionId
        });
        res.end();
        return;
      }

      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-cache',
        'mcp-session-id': sessionId
      });
      res.end(JSON.stringify(responseBody, null, 2));
      return;
    } catch (error) {
      logEvent('mcp_tools_call_failed', { requestId, actor: session.actor, sessionId, clientName: session.clientName, sourceIp, statusCode: 500, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-cache',
        'mcp-session-id': sessionId
      });
      res.end(JSON.stringify(createRpcError(body.id ?? null, -32000, error?.message || 'gateway_error', error?.data || error?.body || null), null, 2));
      return;
    }
  }

  if (isStreamableMcpPath && req.method === 'DELETE') {
    if (!requestSession) return json(res, 404, { error: 'unknown_session' });
    sessions.delete(requestSessionId);
    res.writeHead(204);
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
        requestId,
        requestStartedAt,
        sourceIp,
        sessionId,
        clientName: session.clientName
      });
      if (responseBody !== null) {
        sendSse(session.res, 'message', responseBody);
      }
      res.writeHead(200).end();
      return;
    } catch (error) {
      logEvent('mcp_tools_call_failed', { requestId, actor: currentActor, sessionId, clientName: session.clientName, sourceIp, statusCode: 500, error: safeError(error), latencyMs: Date.now() - requestStartedAt });
      sendSse(session.res, 'message', createRpcError(id, -32000, error?.message || 'gateway_error', error?.data || error?.body || null));
      res.writeHead(200).end();
      return;
    }
  }

  return json(res, 404, { error: 'not_found', path: url.pathname });
});

if (process.argv.includes('--check')) {
  console.log(JSON.stringify({ ok: true, policyPath: POLICY_PATH, port: PORT, backend: backend.kind, configured: backend.configured, authRegistry: process.env.N8N_AUTH_TABLE_ID || null }, null, 2));
  process.exit(0);
}

server.listen(PORT, () => {
  console.log(`mem0-gateway listening on :${PORT}`);
  console.log(`policy path: ${POLICY_PATH}`);
  console.log(`backend kind: ${backend.kind}`);
});
