export const CONVERSATION_EVENT_V3_PATH = '/v3/ingest/conversation-events';
const EVENT_ID = /^cevt_[a-z0-9][a-z0-9_-]{7,127}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const REQUEST_AUTH = new Set(['conversation_event_http_request_auth_invalid', 'conversation_event_http_request_stale', 'conversation_event_http_request_future', 'conversation_event_http_request_nonce_replay']);
const REQUEST_UNAVAILABLE = new Set(['conversation_event_http_request_nonce_store_unavailable', 'nonce_store_unavailable']);
const EVENT_AUTH = new Set(['conversation_event_receiver_auth_invalid', 'conversation_event_receiver_stale', 'conversation_event_receiver_future', 'conversation_event_receiver_nonce_replay']);
const EVENT_UNAVAILABLE = new Set(['conversation_event_receiver_nonce_store_unavailable', 'nonce_store_unavailable']);

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function archiveKey(eventId) { return `cai_${eventId.slice(5)}`; }
function reply(res, status, body) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }
function statusFor(code) {
  if (code === 'conflict_visible') return 409;
  if (['audit_unavailable', 'transaction_rolled_back', 'archive_unconfigured'].includes(code)) return 503;
  if (['body_too_large'].includes(code)) return 413;
  if (['body_timeout'].includes(code)) return 408;
  if (['invalid_content_type'].includes(code)) return 415;
  if (['request_auth_invalid', 'event_auth_invalid', 'request_auth_stale', 'request_auth_future', 'request_auth_replay', 'event_auth_stale', 'event_auth_future', 'event_auth_replay'].includes(code)) return 401;
  if (['request_auth_unavailable', 'event_auth_unavailable', 'source_auth_unavailable'].includes(code)) return 503;
  if (code === 'forbidden') return 403;
  return 400;
}
function mapVerifierError(error, kind) {
  const code = error?.code;
  if ((kind === 'request' ? REQUEST_UNAVAILABLE : EVENT_UNAVAILABLE).has(code)) fail(`${kind}_auth_unavailable`);
  if ((kind === 'request' ? REQUEST_AUTH : EVENT_AUTH).has(code)) fail(`${kind}_auth_invalid`);
  fail(`${kind}_auth_invalid`);
}
function boundedBody(req, { maxBytes, timeoutMs }) {
  const declared = req.headers['content-length'];
  if (declared !== undefined && !/^\d+$/.test(String(declared))) return Promise.reject(Object.assign(new Error(), { code: 'invalid_request' }));
  if (declared !== undefined && Number(declared) > maxBytes) return Promise.reject(Object.assign(new Error(), { code: 'body_too_large' }));
  return new Promise((resolve, reject) => {
    let done = false; let bytes = 0; const chunks = [];
    const finish = (error, value) => { if (done) return; done = true; clearTimeout(timer); req.removeListener('data', onData); req.removeListener('end', onEnd); req.removeListener('error', onError); req.removeListener('aborted', onAbort); if (error) reject(error); else resolve(value); };
    const onData = chunk => { bytes += chunk.length; if (bytes > maxBytes) finish(Object.assign(new Error(), { code: 'body_too_large' })); else chunks.push(chunk); };
    const onEnd = () => finish(null, Buffer.concat(chunks, bytes)); const onError = () => finish(Object.assign(new Error(), { code: 'body_invalid' })); const onAbort = () => finish(Object.assign(new Error(), { code: 'body_timeout' }));
    const timer = setTimeout(() => finish(Object.assign(new Error(), { code: 'body_timeout' })), timeoutMs);
    req.on('data', onData); req.once('end', onEnd); req.once('error', onError); req.once('aborted', onAbort);
  });
}
function conflict(result) {
  const value = result?.conflict;
  if (!value || !EVENT_ID.test(value.eventId) || !DIGEST.test(value.logicalDigest) || !DIGEST.test(value.existingPayloadDigest) || !DIGEST.test(value.receivedPayloadDigest)) return null;
  return { eventId: value.eventId, logicalDigest: value.logicalDigest, existingPayloadDigest: value.existingPayloadDigest, receivedPayloadDigest: value.receivedPayloadDigest };
}
export function createConversationEventV3IngestHandler({ archive, replayVerifier, authorizeSource, requestHmacVerifier = null, maxBodyBytes = 262144, bodyTimeoutMs = 10000 } = {}) {
  if (!archive || typeof archive.append !== 'function' || typeof archive.tombstone !== 'function' || typeof replayVerifier?.verify !== 'function' || typeof authorizeSource !== 'function') fail('conversation_event_ingest_unconfigured');
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > 16 * 1024 * 1024 || !Number.isSafeInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 120000) fail('conversation_event_ingest_config_invalid');
  return async (req, res, url, { actor } = {}) => {
    if (url.pathname !== CONVERSATION_EVENT_V3_PATH) return false;
    if (req.method !== 'POST' || url.search) { reply(res, 400, { error: 'invalid_request' }); return true; }
    if (req.headers['content-type'] !== 'application/json') { reply(res, 415, { error: 'invalid_content_type' }); return true; }
    try {
      const raw = await boundedBody(req, { maxBytes: maxBodyBytes, timeoutMs: bodyTimeoutMs });
      const hasRequestAuth = Object.keys(req.headers).some(key => key.toLowerCase().startsWith('x-amf-auth-'));
      if (!requestHmacVerifier && hasRequestAuth) fail('request_auth_invalid');
      if (requestHmacVerifier) { try { await requestHmacVerifier.verify({ method: 'POST', path: CONVERSATION_EVENT_V3_PATH, headers: req.headers, body: raw }); } catch (error) { mapVerifierError(error, 'request'); } }
      let parsed;
      try { parsed = JSON.parse(raw.toString('utf8')); } catch { fail('invalid_request'); }
      let event; try { event = await replayVerifier.verify(parsed); } catch (error) { mapVerifierError(error, 'event'); }
      if (!EVENT_ID.test(event.eventId) || req.headers['idempotency-key'] !== event.eventId) fail('invalid_request');
      let allowed; try { allowed = await authorizeSource({ actor, sourceInstanceId: event.sourceInstanceId, requestKeyId: hasRequestAuth ? req.headers['x-amf-auth-key-id'] || null : null }); } catch { fail('source_auth_unavailable'); }
      if (allowed !== true) fail('forbidden');
      let result;
      try { result = await (event.state === 'tombstone' ? archive.tombstone(event, archiveKey(event.eventId)) : archive.append(event, archiveKey(event.eventId))); }
      catch { fail('transaction_rolled_back'); }
      if (result?.outcome === 'stored' || result?.outcome === 'duplicate') { reply(res, result.outcome === 'stored' ? 201 : 200, { acknowledged: true, eventId: event.eventId, payloadDigest: event.integrity.payloadDigest, status: result.outcome }); return true; }
      if (result?.outcome === 'conflict_visible') { const metadata = conflict(result); if (!metadata) fail('transaction_rolled_back'); reply(res, 409, { error: 'conflict_visible', conflict: metadata }); return true; }
      if (result?.outcome === 'request_invalid') fail('invalid_request');
      fail(['audit_unavailable', 'transaction_rolled_back', 'archive_unconfigured'].includes(result?.outcome) ? result.outcome : 'transaction_rolled_back');
    } catch (error) { const status = statusFor(error?.code); reply(res, status, { error: status === 503 ? (error.code || 'transaction_rolled_back') : status === 403 ? 'forbidden' : status === 415 ? 'invalid_content_type' : status === 413 ? 'body_too_large' : status === 408 ? 'body_timeout' : status === 401 ? 'unauthorized' : 'invalid_request' }); return true; }
  };
}
