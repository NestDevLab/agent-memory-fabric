import { validateClientCiphertext } from './raw-event-contract.mjs';

function abortRace(promise, signal) {
  if (signal.aborted) return Promise.reject(new Error('raw_event_http_timeout'));
  return new Promise((resolve, reject) => {
    const aborted = () => reject(new Error('raw_event_http_timeout'));
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
  });
}

function parseJsonBytes(bytes, maxBytes) {
  if (bytes.length > maxBytes) throw new Error('raw_event_http_response_too_large');
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error('raw_event_http_ack_invalid'); }
}

async function readBoundedJson(response, { maxBytes, signal }) {
  const contentLength = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) throw new Error('raw_event_http_response_too_large');
  if (response?.body && typeof response.body.getReader === 'function') {
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    try {
      while (true) {
        const { done, value } = await abortRace(reader.read(), signal);
        if (done) break;
        const chunk = Buffer.from(value || []);
        received += chunk.length;
        if (received > maxBytes) throw new Error('raw_event_http_response_too_large');
        chunks.push(chunk);
      }
    } catch (error) {
      try { await reader.cancel(error); } catch {}
      throw error;
    } finally { try { reader.releaseLock(); } catch {} }
    return parseJsonBytes(Buffer.concat(chunks, received), maxBytes);
  }
  if (typeof response?.text === 'function') {
    const text = await abortRace(response.text(), signal);
    return parseJsonBytes(Buffer.from(String(text), 'utf8'), maxBytes);
  }
  if (typeof response?.json === 'function') {
    const value = await abortRace(response.json(), signal);
    if (Buffer.byteLength(JSON.stringify(value), 'utf8') > maxBytes) throw new Error('raw_event_http_response_too_large');
    return value;
  }
  throw new Error('raw_event_http_ack_invalid');
}

export class HttpRawEventSink {
  constructor({ endpoint = '', token = '', sourceInstanceId = '', actorId = '', timeoutMs = 10000, maxResponseBytes = 64 * 1024, fetchImpl = globalThis.fetch, allowInsecureTest = false } = {}) {
    this.configured = Boolean(endpoint && token && sourceInstanceId && actorId);
    this.endpoint = endpoint;
    this.token = token;
    this.sourceInstanceId = sourceInstanceId;
    this.actorId = actorId;
    this.timeoutMs = timeoutMs;
    this.maxResponseBytes = maxResponseBytes;
    this.fetchImpl = fetchImpl;
    this.allowInsecureTest = allowInsecureTest;
    if (this.configured) {
      const url = new URL(endpoint);
      if (url.pathname !== '/v2/ingest/raw-events' || url.username || url.password || url.search || url.hash || (url.protocol !== 'https:' && !allowInsecureTest)) throw new Error('raw_event_http_endpoint_invalid');
      if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw new Error('raw_event_http_timeout_invalid');
      if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 256 || maxResponseBytes > 1024 * 1024) throw new Error('raw_event_http_response_limit_invalid');
    }
  }
  async deliverCiphertext({ projection, envelope }, { idempotencyKey }) {
    if (!this.configured) throw new Error('raw_event_http_sink_unconfigured');
    if (idempotencyKey !== projection?.eventId) throw new Error('raw_event_http_idempotency_invalid');
    validateClientCiphertext({ actorId: this.actorId, sourceInstanceId: this.sourceInstanceId, projection, envelope });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    let body;
    try {
      response = await this.fetchImpl(this.endpoint, {
        method: 'POST', signal: controller.signal, redirect: 'error',
        headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json', 'idempotency-key': idempotencyKey },
        body: JSON.stringify({ sourceInstanceId: this.sourceInstanceId, projection, envelope })
      });
      body = await readBoundedJson(response, { maxBytes: this.maxResponseBytes, signal: controller.signal });
    } catch (cause) {
      throw Object.assign(new Error('raw_event_http_delivery_failed'), { cause });
    } finally { clearTimeout(timer); }
    const data = body?.data;
    if (!response.ok || body?.ok !== true || data?.eventId !== idempotencyKey || data?.idempotencyKey !== idempotencyKey || !['stored', 'duplicate'].includes(data?.status)) throw new Error('raw_event_http_ack_invalid');
    return { acknowledged: true, eventId: idempotencyKey, duplicate: data.status === 'duplicate' };
  }
}
