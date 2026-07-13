const OPAQUE_TAG = /^hmac-sha256:[A-Za-z0-9._-]{1,128}:[a-f0-9]{64}$/;
const CONTEXT_KEYS = new Set(['actor', 'sender', 'conversation', 'room', 'person', 'relationship', 'thread']);
export const PURPOSES = Object.freeze(['conversation_recall', 'continuity_resume', 'incident_debug', 'operator_review', 'memory_curation']);

export function normalizeOpaqueTagMap(value, { required = true } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('context_invalid');
  const result = {};
  for (const key of Object.keys(value).sort()) {
    const tags = value[key];
    if (!CONTEXT_KEYS.has(key) || !Array.isArray(tags) || tags.length === 0 || tags.some(tag => !OPAQUE_TAG.test(tag))) throw new Error('context_invalid');
    const normalized = [...new Set(tags)].sort();
    if (normalized.length !== tags.length || normalized.some((tag, index) => tag !== tags[index])) throw new Error('context_invalid');
    result[key] = normalized;
  }
  if (required && Object.keys(result).length === 0) throw new Error('context_invalid');
  return result;
}

export function exactContextIntersection(stored, presented) {
  let left;
  let right;
  try {
    left = normalizeOpaqueTagMap(stored);
    right = normalizeOpaqueTagMap(presented);
  } catch {
    return false;
  }
  const routingKeys = Object.keys(left).filter(key => ['conversation', 'room', 'person', 'relationship', 'thread'].includes(key));
  if (!routingKeys.length) return false;
  return routingKeys.every(key => Array.isArray(right[key]) && left[key].some(tag => right[key].includes(tag)));
}

export function normalizeScopeList(scope, scopes) {
  const requested = Array.isArray(scopes) && scopes.length ? scopes : (scope ? [scope] : []);
  return [...new Set(requested.map(value => String(value).trim()).filter(Boolean))].sort();
}

export function scopeRequiresContext(scopes) {
  return scopes.some(scope => /^(?:person|relationship|room):/.test(scope));
}

export function buildContextRequest(operation, input = {}) {
  if (operation === 'memory_search') return { operation, query: String(input.query || ''), scopes: normalizeScopeList(input.scope, input.scopes), cursor: input.cursor || null, limit: Number(input.limit || 20), from: input.from || null, to: input.to || null };
  if (operation === 'memory_read') return { operation, id: String(input.id || '') };
  if (operation === 'documents_search') return { operation, query: String(input.query || ''), vaultIds: [...new Set((Array.isArray(input.vaultIds) ? input.vaultIds : []).map(String))].sort(), cursor: input.cursor || null, limit: Number(input.limit || 20) };
  if (operation === 'document_read') return { operation, documentId: String(input.documentId || ''), revision: input.revision == null ? null : Number(input.revision) };
  if (operation === 'context_search') return { operation, query: String(input.query || ''), scopes: normalizeScopeList(input.scope, input.scopes),
    vaultIds: [...new Set((Array.isArray(input.vaultIds) ? input.vaultIds : []).map(String))].sort(), limit: Number(input.limit || 20) };
  if (operation === 'sessions_search') return { operation, query: String(input.query || ''), cursor: input.cursor || null, limit: Number(input.limit || 20), from: input.from || null, to: input.to || null };
  if (operation === 'session_get') return { operation, sessionId: String(input.sessionId || '') };
  if (operation === 'session_transcript') return { operation, sessionId: String(input.sessionId || ''),
    view: input.view === 'original' ? 'original' : 'redacted', query: String(input.query || ''),
    cursor: input.cursor || null, limit: Number(input.limit || 100), from: input.from || null, to: input.to || null };
  throw new Error('context_operation_invalid');
}
