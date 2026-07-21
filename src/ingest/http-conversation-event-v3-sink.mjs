import crypto from 'node:crypto';

import {
  isConversationEventUtcTimestamp,
  validateConversationEvent
} from '../conversation-event-v3.mjs';
import { canonicalJson } from './transcripts/canonical.mjs';

const ENDPOINT_PATH = '/v3/ingest/conversation-events';
const REQUEST_AUTH_DOMAIN = 'amf.conversation-event/v3/http-auth';
const ACK_KEYS = ['acknowledged', 'eventId', 'payloadDigest', 'status'];
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{43}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function positiveLimit(value, minimum, maximum, code) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}

function requestAuthKey(config) {
  if (config === null || config === undefined) return null;
  if (!exactKeys(config, ['keyId', 'key']) ||
      !KEY_ID.test(String(config.keyId)) ||
      !Buffer.isBuffer(config.key) || config.key.length !== 32) {
    fail('conversation_event_http_auth_invalid');
  }
  return { keyId: config.keyId, key: Buffer.from(config.key) };
}

function abortRace(promise, signal) {
  if (signal.aborted) return Promise.reject(Object.assign(new Error('conversation_event_http_timeout'), { code: 'conversation_event_http_timeout' }));
  return new Promise((resolve, reject) => {
    const aborted = () => reject(Object.assign(new Error('conversation_event_http_timeout'), { code: 'conversation_event_http_timeout' }));
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
  });
}

function parseResponse(bytes, maximum) {
  if (bytes.length > maximum) fail('conversation_event_http_response_too_large');
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail('conversation_event_http_ack_invalid'); }
}

async function boundedResponse(response, maximum, signal) {
  const header = response?.headers?.get?.('content-length');
  if (header !== null && header !== undefined && header !== '') {
    const declared = Number(header);
    if (!Number.isSafeInteger(declared) || declared < 0) fail('conversation_event_http_ack_invalid');
    if (declared > maximum) fail('conversation_event_http_response_too_large');
  }
  if (response?.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const { done, value } = await abortRace(reader.read(), signal);
        if (done) break;
        const chunk = Buffer.from(value || []);
        length += chunk.length;
        if (length > maximum) fail('conversation_event_http_response_too_large');
        chunks.push(chunk);
      }
    } catch (error) {
      try { await reader.cancel(); } catch {}
      throw error;
    } finally {
      try { reader.releaseLock(); } catch {}
    }
    return parseResponse(Buffer.concat(chunks, length), maximum);
  }
  fail('conversation_event_http_ack_invalid');
}

function normalizeEndpoint(endpoint) {
  let url;
  try { url = new URL(endpoint); }
  catch { fail('conversation_event_http_endpoint_invalid'); }
  if (String(endpoint).includes('?') || String(endpoint).includes('#') ||
      url.protocol !== 'https:' || url.pathname !== ENDPOINT_PATH || url.username || url.password ||
      url.search || url.hash) fail('conversation_event_http_endpoint_invalid');
  return { endpoint: url.toString(), authority: url.host };
}

function normalizeAuthority(authority) {
  if (typeof authority !== 'string' || authority.length < 1 || authority.includes('/') ||
      authority.includes('@') || authority.includes('?') || authority.includes('#')) {
    fail('conversation_event_http_verifier_authority_invalid');
  }
  let url;
  try { url = new URL(`https://${authority}/`); }
  catch { fail('conversation_event_http_verifier_authority_invalid'); }
  if (!url.host || url.pathname !== '/' || url.search || url.hash) {
    fail('conversation_event_http_verifier_authority_invalid');
  }
  return url.host;
}

function sha256(body) {
  return `sha256:${crypto.createHash('sha256').update(body).digest('hex')}`;
}

function requestSignatureInput(authority, bodyDigest, idempotencyKey, keyId, sentAt, nonce) {
  return canonicalJson([
    REQUEST_AUTH_DOMAIN,
    authority,
    'POST',
    ENDPOINT_PATH,
    bodyDigest,
    idempotencyKey,
    keyId,
    sentAt,
    nonce
  ]);
}

function requestHmacHeaders(auth, body, { authority, idempotencyKey, clock, nonceFactory }) {
  if (!auth) return {};
  const now = clock();
  const nonce = nonceFactory();
  if (!Number.isFinite(now) || !NONCE.test(String(nonce))) fail('conversation_event_http_auth_invalid');
  const sentAt = new Date(now).toISOString();
  const bodyDigest = sha256(body);
  const input = requestSignatureInput(authority, bodyDigest, idempotencyKey, auth.keyId, sentAt, nonce);
  const signature = crypto.createHmac('sha256', auth.key).update(input, 'utf8').digest('base64url');
  return {
    'x-amf-auth-key-id': auth.keyId,
    'x-amf-auth-sent-at': sentAt,
    'x-amf-auth-nonce': nonce,
    'x-amf-auth-signature': signature
  };
}

export class HttpConversationEventV3Sink {
  constructor({
    endpoint,
    bearerToken = null,
    requestHmac = null,
    mtlsDispatcher = null,
    resolveIntegrityKey,
    timeoutMs = 10_000,
    maxRequestBytes = 256 * 1024,
    maxResponseBytes = 16 * 1024,
    testFetchImpl = null,
    allowTestFetch = false,
    clock = () => Date.now(),
    nonceFactory = () => crypto.randomBytes(18).toString('base64url')
  } = {}) {
    const normalizedEndpoint = normalizeEndpoint(endpoint);
    this.endpoint = normalizedEndpoint.endpoint;
    this.authority = normalizedEndpoint.authority;
    if (bearerToken !== null && (typeof bearerToken !== 'string' || bearerToken.length < 1 ||
        bearerToken.length > 4096 || !/^[\x21-\x7e]+$/.test(bearerToken))) {
      fail('conversation_event_http_auth_invalid');
    }
    if (typeof resolveIntegrityKey !== 'function') fail('conversation_event_http_integrity_key_required');
    if (typeof clock !== 'function' || typeof nonceFactory !== 'function') fail('conversation_event_http_auth_invalid');
    if (mtlsDispatcher !== null && typeof mtlsDispatcher?.dispatch !== 'function') {
      fail('conversation_event_http_auth_invalid');
    }
    this.bearerToken = bearerToken;
    this.requestHmac = requestAuthKey(requestHmac);
    this.mtlsDispatcher = mtlsDispatcher;
    this.resolveIntegrityKey = resolveIntegrityKey;
    this.clock = clock;
    this.nonceFactory = nonceFactory;
    if (!this.bearerToken && !this.requestHmac && !this.mtlsDispatcher) fail('conversation_event_http_auth_required');
    this.timeoutMs = positiveLimit(timeoutMs, 50, 120_000, 'conversation_event_http_timeout_invalid');
    this.maxRequestBytes = positiveLimit(maxRequestBytes, 1024, 16 * 1024 * 1024, 'conversation_event_http_request_limit_invalid');
    this.maxResponseBytes = positiveLimit(maxResponseBytes, 128, 1024 * 1024, 'conversation_event_http_response_limit_invalid');
    if (testFetchImpl !== null && (!allowTestFetch || typeof testFetchImpl !== 'function')) {
      fail('conversation_event_http_test_fetch_forbidden');
    }
    this.fetchImpl = testFetchImpl ?? globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') fail('conversation_event_http_transport_unavailable');
  }

  async deliver(event, { idempotencyKey, payloadDigest } = {}) {
    let validated;
    try { validated = validateConversationEvent(event, { resolveIntegrityKey: this.resolveIntegrityKey }); }
    catch { fail('conversation_event_http_event_invalid'); }
    if (validated.eventId !== idempotencyKey || validated.integrity.payloadDigest !== payloadDigest) {
      fail('conversation_event_http_idempotency_invalid');
    }
    const body = canonicalJson(validated);
    const bytes = Buffer.byteLength(body, 'utf8');
    if (bytes > this.maxRequestBytes) fail('conversation_event_http_request_too_large');
    const headers = {
      'content-type': 'application/json',
      'content-length': String(bytes),
      'idempotency-key': idempotencyKey,
      ...requestHmacHeaders(this.requestHmac, body, {
        authority: this.authority,
        idempotencyKey,
        clock: this.clock,
        nonceFactory: this.nonceFactory
      })
    };
    if (this.bearerToken) headers.authorization = `Bearer ${this.bearerToken}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    let ack;
    try {
      response = await abortRace(this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
        redirect: 'error',
        ...(this.mtlsDispatcher ? { dispatcher: this.mtlsDispatcher } : {})
      }), controller.signal);
      if (!response || response.redirected === true) fail('conversation_event_http_redirect_invalid');
      if (!response.ok || response.status < 200 || response.status > 299) fail('conversation_event_http_status_error');
      ack = await boundedResponse(response, this.maxResponseBytes, controller.signal);
    } catch (error) {
      if (error?.code?.startsWith?.('conversation_event_http_')) throw error;
      if (controller.signal.aborted || error?.name === 'AbortError') fail('conversation_event_http_timeout');
      fail('conversation_event_http_delivery_failed');
    } finally {
      clearTimeout(timer);
    }
    if (!exactKeys(ack, ACK_KEYS) || ack.acknowledged !== true || ack.eventId !== idempotencyKey ||
        ack.payloadDigest !== payloadDigest || !['stored', 'duplicate'].includes(ack.status)) {
      fail('conversation_event_http_ack_invalid');
    }
    return ack;
  }
}

export class ConversationEventV3ReplayVerifier {
  constructor({
    resolveIntegrityKey,
    consumeNonce,
    clock = () => Date.now(),
    maxPastMs = 5 * 60_000,
    maxFutureMs = 30_000
  } = {}) {
    if (typeof resolveIntegrityKey !== 'function' || typeof consumeNonce !== 'function' || typeof clock !== 'function') {
      fail('conversation_event_receiver_config_invalid');
    }
    this.resolveIntegrityKey = resolveIntegrityKey;
    this.consumeNonce = consumeNonce;
    this.clock = clock;
    this.maxPastMs = positiveLimit(maxPastMs, 1000, 24 * 60 * 60_000, 'conversation_event_receiver_window_invalid');
    this.maxFutureMs = positiveLimit(maxFutureMs, 1000, 5 * 60_000, 'conversation_event_receiver_window_invalid');
  }

  async verify(event) {
    let validated;
    try { validated = validateConversationEvent(event, { resolveIntegrityKey: this.resolveIntegrityKey }); }
    catch { fail('conversation_event_receiver_auth_invalid'); }
    const now = this.clock();
    if (!Number.isFinite(now)) fail('conversation_event_receiver_config_invalid');
    const sentAt = Date.parse(validated.integrity.sentAt);
    if (sentAt < now - this.maxPastMs) fail('conversation_event_receiver_stale');
    if (sentAt > now + this.maxFutureMs) fail('conversation_event_receiver_future');
    let consumed;
    try {
      consumed = await this.consumeNonce({
        namespace: 'conversation-event-v3-integrity',
        keyId: validated.integrity.keyId,
        nonce: validated.integrity.nonce,
        eventId: validated.eventId,
        payloadDigest: validated.integrity.payloadDigest,
        expiresAt: sentAt + this.maxPastMs + 1
      });
    } catch { fail('conversation_event_receiver_nonce_store_unavailable'); }
    if (consumed !== true) fail('conversation_event_receiver_nonce_replay');
    return validated;
  }
}

function headerValue(headers, name) {
  let value;
  if (headers && typeof headers.get === 'function') value = headers.get(name);
  else if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
    const matches = Object.entries(headers).filter(([key]) => key.toLowerCase() === name);
    if (matches.length !== 1) return null;
    value = matches[0][1];
  }
  return typeof value === 'string' ? value : null;
}

export class ConversationEventV3HttpRequestVerifier {
  constructor({
    expectedAuthority,
    resolveRequestHmacKey,
    consumeNonce,
    clock = () => Date.now(),
    maxPastMs = 5 * 60_000,
    maxFutureMs = 30_000,
    maxBodyBytes = 256 * 1024
  } = {}) {
    if (typeof resolveRequestHmacKey !== 'function' || typeof consumeNonce !== 'function' ||
        typeof clock !== 'function') fail('conversation_event_http_verifier_config_invalid');
    this.expectedAuthority = normalizeAuthority(expectedAuthority);
    this.resolveRequestHmacKey = resolveRequestHmacKey;
    this.consumeNonce = consumeNonce;
    this.clock = clock;
    this.maxPastMs = positiveLimit(maxPastMs, 1000, 24 * 60 * 60_000, 'conversation_event_http_verifier_window_invalid');
    this.maxFutureMs = positiveLimit(maxFutureMs, 1000, 5 * 60_000, 'conversation_event_http_verifier_window_invalid');
    this.maxBodyBytes = positiveLimit(maxBodyBytes, 1024, 16 * 1024 * 1024, 'conversation_event_http_verifier_body_limit_invalid');
  }

  async verify({ method, path, headers, body } = {}) {
    if (method !== 'POST' || path !== ENDPOINT_PATH || (!Buffer.isBuffer(body) && typeof body !== 'string')) {
      fail('conversation_event_http_request_auth_invalid');
    }
    const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    if (bodyBytes.length > this.maxBodyBytes) fail('conversation_event_http_request_too_large');
    const keyId = headerValue(headers, 'x-amf-auth-key-id');
    const sentAt = headerValue(headers, 'x-amf-auth-sent-at');
    const nonce = headerValue(headers, 'x-amf-auth-nonce');
    const signature = headerValue(headers, 'x-amf-auth-signature');
    const idempotencyKey = headerValue(headers, 'idempotency-key');
    if (!KEY_ID.test(String(keyId)) || !isConversationEventUtcTimestamp(sentAt) ||
        !NONCE.test(String(nonce)) || !SIGNATURE.test(String(signature)) ||
        !/^cevt_[a-z0-9][a-z0-9_-]{7,127}$/.test(String(idempotencyKey))) {
      fail('conversation_event_http_request_auth_invalid');
    }
    let key;
    try { key = this.resolveRequestHmacKey(keyId); }
    catch { fail('conversation_event_http_request_auth_invalid'); }
    if (!Buffer.isBuffer(key) || key.length !== 32) fail('conversation_event_http_request_auth_invalid');
    const bodyDigest = sha256(bodyBytes);
    if (!DIGEST.test(bodyDigest)) fail('conversation_event_http_request_auth_invalid');
    const expected = crypto.createHmac('sha256', key)
      .update(requestSignatureInput(this.expectedAuthority, bodyDigest, idempotencyKey, keyId, sentAt, nonce), 'utf8')
      .digest('base64url');
    const actualBytes = Buffer.from(signature, 'utf8');
    const expectedBytes = Buffer.from(expected, 'utf8');
    if (actualBytes.length !== expectedBytes.length || !crypto.timingSafeEqual(actualBytes, expectedBytes)) {
      fail('conversation_event_http_request_auth_invalid');
    }
    const now = this.clock();
    if (!Number.isFinite(now)) fail('conversation_event_http_verifier_config_invalid');
    const sentAtMs = Date.parse(sentAt);
    if (sentAtMs < now - this.maxPastMs) fail('conversation_event_http_request_stale');
    if (sentAtMs > now + this.maxFutureMs) fail('conversation_event_http_request_future');
    let consumed;
    try {
      consumed = await this.consumeNonce({
        namespace: 'conversation-event-v3-http-auth',
        keyId,
        nonce,
        idempotencyKey,
        bodyDigest,
        expiresAt: sentAtMs + this.maxPastMs + 1
      });
    } catch { fail('conversation_event_http_request_nonce_store_unavailable'); }
    if (consumed !== true) fail('conversation_event_http_request_nonce_replay');
    return { keyId, idempotencyKey, bodyDigest };
  }
}
