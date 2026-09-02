import { capsuleToPublicResource, createSessionContextCapsule, createSessionContextExpansionSnapshot, createSessionContextNotice, expandSessionContextTranscript } from './session-context-capsule.mjs';

function failure(code) { throw Object.assign(new Error(code), { code }); }
function freeze(value) { if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }

function dependencies(value) {
  if (!value?.conversationReader?.configured || typeof value.conversationReader.search !== 'function' || typeof value.conversationReader.transcript !== 'function' ||
    !value.referenceStore || typeof value.referenceStore.issueExpansion !== 'function' || typeof value.referenceStore.resolveExpansion !== 'function' ||
    typeof value.referenceStore.issueCursor !== 'function' || typeof value.referenceStore.resolveCursor !== 'function' || typeof value.now !== 'function') throw new TypeError('fabric_capability_provider_v2_invalid');
  return value;
}

function requestBinding(request) {
  return freeze({ query: request.query, kinds: [...request.kinds], scopes: request.scopes.map(scope => ({ tenantId: scope.tenantId, scopeId: scope.scopeId })), purpose: request.purpose, delivery: request.delivery, limit: request.limit });
}

function grantContext(grant) {
  if (!grant || typeof grant !== 'object') failure('fabric_capability_provider_v2_forbidden');
  const context = grant.context;
  if (!context || typeof context !== 'object') failure('fabric_capability_provider_v2_forbidden');
  return context;
}

export function createFabricCapabilityProviderV2Operations({ conversationReader, referenceStore, now = () => Date.now(), referenceTtlSeconds = 86_400 } = {}) {
  dependencies({ conversationReader, referenceStore, now });
  if (!Number.isSafeInteger(referenceTtlSeconds) || referenceTtlSeconds < 60 || referenceTtlSeconds > 2_592_000) throw new TypeError('fabric_capability_provider_v2_invalid');

  return freeze({
    async search(request, { grant } = {}) {
      if (!request || request.capability !== 'search' || request.purpose !== 'context_recall' || request.kinds.length !== 1 || request.kinds[0] !== 'conversation') failure('fabric_capability_provider_v2_invalid');
      const context = grantContext(grant);
      const binding = requestBinding(request);
      let readerCursor = null;
      if (request.cursor) {
        const continuation = await referenceStore.resolveCursor({ id: request.cursor, request: binding, scopes: request.scopes, purpose: request.purpose, grant });
        if (!continuation || Object.keys(continuation).sort().join('\0') !== 'readerCursor' || (continuation.readerCursor !== null && typeof continuation.readerCursor !== 'string')) failure('fabric_capability_provider_v2_invalid');
        readerCursor = continuation.readerCursor;
      }
      const readLimit = request.delivery === 'notice' ? 50 : Math.min(request.limit, 10);
      let page;
      try { page = await conversationReader.search({ query: request.query, cursor: readerCursor, limit: readLimit, from: null, to: null, context }); } catch { failure('fabric_capability_provider_v2_unavailable'); }
      if (!page || !Array.isArray(page.items) || page.items.length > readLimit || (page.nextCursor !== null && typeof page.nextCursor !== 'string')) failure('fabric_capability_provider_v2_unavailable');
      if (request.delivery === 'notice') return createSessionContextNotice(page.items.map(item => ({ freshness: { state: item?.expired ? 'expired' : 'fresh' } })));

      const items = [];
      for (const [index, session] of page.items.entries()) {
        if (!session || typeof session.id !== 'string') continue;
        let transcript;
        try { transcript = await conversationReader.transcript({ id: session.id, view: 'redacted', query: request.query, cursor: null, limit: 5, from: null, to: null, context }); } catch { continue; }
        // Construct both bounded projections before allocating an opaque
        // reference.  A malformed later candidate therefore cannot leave an
        // otherwise unusable expansion reference behind.
        let preparedCapsule; let sourceSnapshot;
        try {
          sourceSnapshot = createSessionContextExpansionSnapshot({ transcript });
          preparedCapsule = createSessionContextCapsule({ session, transcript, expansionRef: 'rid_pending_capsule0001', query: request.query, now: new Date(Number(now())).toISOString(), ttlSeconds: referenceTtlSeconds, position: index + 1, reasons: request.query ? ['hybrid_similarity', 'freshness'] : ['freshness'] });
        } catch { continue; }
        const expiresAt = new Date(Number(now()) + (referenceTtlSeconds * 1000)).toISOString();
        const expansionRef = await referenceStore.issueExpansion({ conversationId: session.id, capsuleId: preparedCapsule.id, query: request.query, scopes: request.scopes, purpose: request.purpose, grant, expiresAt, observedAt: preparedCapsule.provenance.observedAt, sourceSnapshot });
        const capsule = createSessionContextCapsule({ session, transcript, expansionRef, query: request.query, now: new Date(Number(now())).toISOString(), ttlSeconds: referenceTtlSeconds, position: index + 1, reasons: request.query ? ['hybrid_similarity', 'freshness'] : ['freshness'] });
        if (capsule.id !== preparedCapsule.id) failure('fabric_capability_provider_v2_invalid');
        items.push(capsuleToPublicResource(capsule, items.length + 1));
      }
      const nextCursor = page.nextCursor === null ? null : await referenceStore.issueCursor({ request: binding, scopes: request.scopes, purpose: request.purpose, grant, continuation: { readerCursor: page.nextCursor } });
      return freeze({ ok: true, outcome: items.length || page.nextCursor !== null ? 'found' : 'not_found', ...(items.length || page.nextCursor !== null ? { items, nextCursor, coverage: { state: 'complete', requestedKinds: ['conversation'], coveredKinds: ['conversation'], uncoveredKinds: [], reasons: [] } } : {}) });
    },

    async read(request, { grant } = {}) {
      if (!request || request.capability !== 'read' || request.purpose !== 'context_recall') failure('fabric_capability_provider_v2_invalid');
      const context = grantContext(grant);
      let reference;
      try { reference = await referenceStore.resolveExpansion({ id: request.id, scopes: request.scopes, purpose: request.purpose, grant }); } catch { failure('fabric_capability_provider_v2_not_found'); }
      let transcript;
      try { transcript = await conversationReader.transcript({ id: reference.conversationId, view: 'redacted', query: reference.query, cursor: null, limit: 5, from: null, to: null, context }); } catch { failure('fabric_capability_provider_v2_not_found'); }
      let expansion;
      try {
        const sourceSnapshot = createSessionContextExpansionSnapshot({ transcript });
        referenceStore.assertExpansionSnapshot({ reference, sourceSnapshot });
        const capsule = createSessionContextCapsule({ session: { id: reference.conversationId, lastOccurredAt: reference.observedAt }, transcript, expansionRef: request.id, query: reference.query, now: new Date(Number(now())).toISOString(), ttlSeconds: referenceTtlSeconds });
        if (capsule.id !== reference.capsuleId) failure('fabric_capability_provider_v2_not_found');
        expansion = expandSessionContextTranscript({ id: request.id, transcript });
      } catch { failure('fabric_capability_provider_v2_not_found'); }
      return freeze({ ok: true, outcome: 'found', resource: expansion.resource });
    }
  });
}
