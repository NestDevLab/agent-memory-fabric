import { exactContextIntersection } from './access-contract.mjs';

const CAPABILITIES = Object.freeze(['search', 'read', 'propose', 'proposal_status', 'status']);
const KINDS = new Set(['canonical_memory', 'document', 'conversation']);
const SENSITIVE_SCOPE = /^(?:person|relationship|room):/;
const SCOPE = /^[a-z][a-z0-9_-]{1,31}:[a-z0-9._-]{1,96}$/;
const INVALID = Symbol('invalid');
const OWN_ERRORS = new WeakSet();

function error(code) {
  const value = Object.assign(new Error(code), { code });
  OWN_ERRORS.add(value);
  return value;
}

function fail(code = 'fabric_capability_provider_operations_failed') {
  throw error(code);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function record(value, keys = null) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) return null;
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some(key => typeof key !== 'string')
      || (keys && (ownKeys.length !== keys.length || !keys.every(key => ownKeys.includes(key))))) return null;
    const copy = {};
    for (const key of ownKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
      Object.defineProperty(copy, key, { value: descriptor.value, enumerable: true });
    }
    return copy;
  } catch {
    return null;
  }
}

function capture(value, options = {}) {
  const limits = {
    maxArray: options.maxArray ?? 128,
    maxBytes: options.maxBytes ?? 4 * 1024 * 1024,
    maxDepth: options.maxDepth ?? 8,
    maxKeys: options.maxKeys ?? 4096,
    maxString: options.maxString ?? 65536
  };
  const state = { keys: 0 };
  const visiting = new WeakSet();
  const copy = (item, depth) => {
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'string') return item.length <= limits.maxString ? item : INVALID;
    if (typeof item === 'number') return Number.isFinite(item) ? item : INVALID;
    if (!item || typeof item !== 'object' || depth >= limits.maxDepth || visiting.has(item)) return INVALID;
    try {
      visiting.add(item);
      const keys = Reflect.ownKeys(item);
      const descriptors = new Map(keys.map(key => [key, Object.getOwnPropertyDescriptor(item, key)]));
      if (keys.some(key => typeof key !== 'string') || (state.keys += keys.length) > limits.maxKeys) return INVALID;
      if (Array.isArray(item)) {
        const length = descriptors.get('length');
        if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value)
          || length.value < 0 || length.value > limits.maxArray || keys.length !== length.value + 1) return INVALID;
        const result = [];
        for (let index = 0; index < length.value; index += 1) {
          const descriptor = descriptors.get(String(index));
          if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return INVALID;
          const child = copy(descriptor.value, depth + 1);
          if (child === INVALID) return INVALID;
          result.push(child);
        }
        return result;
      }
      if (Object.getPrototypeOf(item) !== Object.prototype) return INVALID;
      const result = {};
      for (const key of [...keys].sort()) {
        const descriptor = descriptors.get(key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return INVALID;
        const child = copy(descriptor.value, depth + 1);
        if (child === INVALID) return INVALID;
        Object.defineProperty(result, key, { value: child, enumerable: true, writable: true, configurable: true });
      }
      return result;
    } catch {
      return INVALID;
    } finally {
      try { visiting.delete(item); } catch { /* best effort */ }
    }
  };
  const result = copy(value, 0);
  if (result === INVALID) return INVALID;
  try {
    return Buffer.byteLength(JSON.stringify(result), 'utf8') <= limits.maxBytes ? result : INVALID;
  } catch {
    return INVALID;
  }
}

function method(value, name) {
  try {
    for (let target = value; target; target = Object.getPrototypeOf(target)) {
      const descriptor = Object.getOwnPropertyDescriptor(target, name);
      if (descriptor) return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function'
        ? descriptor.value.bind(value) : null;
    }
  } catch { /* invalid dependency */ }
  return null;
}

function configured(value) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, 'configured');
    return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'boolean'
      ? descriptor.value : null;
  } catch {
    return null;
  }
}

function stringList(value, { max = 64, required = false, valid }) {
  const copy = capture(value, { maxArray: max, maxBytes: 32768, maxKeys: max + 1, maxString: 4096 });
  if (copy === INVALID || !Array.isArray(copy) || (required && copy.length === 0)
    || copy.length > max || new Set(copy).size !== copy.length || copy.some(item => !valid(item))) return null;
  return copy;
}

function normalizeGrantProjection(value) {
  const source = record(value, ['actor', 'allowedScopes', 'documentVaultIds', 'sessionOwnerActors', 'context']);
  if (!source || typeof source.actor !== 'string' || source.actor.length < 1 || source.actor.length > 192
    || /[\0\r\n]/.test(source.actor)) return null;
  const allowedScopes = stringList(source.allowedScopes, { required: true, valid: item => typeof item === 'string' && SCOPE.test(item) });
  const documentVaultIds = stringList(source.documentVaultIds, { valid: item => typeof item === 'string' && item.length > 0 && item.length <= 192 && !/[\0\r\n]/.test(item) });
  const sessionOwnerActors = stringList(source.sessionOwnerActors, { valid: item => typeof item === 'string' && item.length > 0 && item.length <= 192 && !/[\0\r\n]/.test(item) });
  const context = capture(source.context, { maxArray: 128, maxBytes: 16384, maxDepth: 8, maxKeys: 128, maxString: 4096 });
  if (!allowedScopes || !documentVaultIds || !sessionOwnerActors || context === INVALID
    || (context !== null && !record(context))) return null;
  return deepFreeze({ actor: source.actor, allowedScopes, documentVaultIds, sessionOwnerActors, context });
}

function exactRequest(value, required, optional = []) {
  const source = record(value);
  if (!source) return null;
  const keys = Object.keys(source);
  return required.every(key => Object.hasOwn(source, key))
    && keys.every(key => required.includes(key) || optional.includes(key)) ? source : null;
}

function sourceSnapshot(value) {
  const copy = capture(value);
  if (copy === INVALID) fail();
  return copy;
}

function errorField(cause, name) {
  try {
    if (!(cause instanceof Error)) return undefined;
    for (let target = cause; target; target = Object.getPrototypeOf(target)) {
      const descriptor = Object.getOwnPropertyDescriptor(target, name);
      if (descriptor) return Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    }
  } catch { /* hostile foreign error */ }
  return undefined;
}

function notFound(cause) {
  const status = errorField(cause, 'status');
  const message = errorField(cause, 'message');
  return status === 404 && ['memory_not_found', 'document_not_found', 'session_not_found'].includes(message);
}

async function callSource(action, { missing = false } = {}) {
  try {
    return sourceSnapshot(await action());
  } catch (cause) {
    if (missing && notFound(cause)) return null;
    fail();
  }
}

function liveCanonical(recordValue, { allowedScopes, context, routingContext, now }) {
  const value = record(recordValue);
  const scope = value && record(value.scope);
  const claim = value && record(value.claim);
  const lifecycle = value && record(value.lifecycle);
  if (!value || !scope || !claim || !lifecycle || typeof value.id !== 'string' || value.id.length < 1 || value.id.length > 4096
    || !Number.isSafeInteger(value.revision) || value.revision < 1 || typeof scope.id !== 'string'
    || !['plain', 'sealed'].includes(claim.encoding) || typeof lifecycle.status !== 'string') fail();
  if (lifecycle.status !== 'active' || !allowedScopes.includes(scope.id) || claim.encoding === 'sealed') return null;
  if (lifecycle.validFrom != null && typeof lifecycle.validFrom !== 'string'
    || lifecycle.validTo != null && typeof lifecycle.validTo !== 'string') fail();
  const validFrom = lifecycle.validFrom == null ? -Infinity : Date.parse(lifecycle.validFrom);
  const validTo = lifecycle.validTo == null ? Infinity : Date.parse(lifecycle.validTo);
  if (!Number.isFinite(validFrom) && validFrom !== -Infinity || !Number.isFinite(validTo) && validTo !== Infinity) fail();
  if (validFrom > now || validTo <= now) return null;
  if (typeof claim.text !== 'string' || claim.text.length < 1 || claim.text.length > 65536 || !/\S/.test(claim.text)) fail();
  let routing = null;
  try {
    routing = routingContext(value.id);
    if (routing !== null) {
      routing = capture(routing, { maxArray: 128, maxBytes: 16384, maxDepth: 8, maxKeys: 128, maxString: 4096 });
      if (routing === INVALID || !record(routing)) return null;
    }
  } catch {
    return null;
  }
  if (SENSITIVE_SCOPE.test(scope.id) && !routing) return null;
  if (routing && (!context || !exactContextIntersection(routing, context.contextTags))) return null;
  if (context && ['group', 'channel'].includes(context.conversationKind) && value.visibility !== 'shared') return null;
  return { kind: 'canonical_memory', locator: value.id, revision: value.revision, text: claim.text };
}

function liveDocument(documentValue, vaultIds) {
  const value = record(documentValue);
  if (!value || typeof value.documentId !== 'string' || value.documentId.length < 1 || value.documentId.length > 4096
    || typeof value.vaultId !== 'string' || typeof value.tombstone !== 'boolean'
    || !Number.isSafeInteger(value.revision) || value.revision < 1) fail();
  if (value.tombstone || !vaultIds.includes(value.vaultId) || value.text === null) return null;
  if (typeof value.text !== 'string' || value.text.length < 1 || value.text.length > 65536 || !/\S/.test(value.text)) fail();
  return { kind: 'document', locator: value.documentId, revision: value.revision, text: value.text };
}

function redactedConversationText(transcriptValue, expectedId) {
  const value = record(transcriptValue, ['id', 'view', 'items', 'nextCursor']);
  if (!value || value.id !== expectedId || value.view !== 'redacted'
    || (value.nextCursor !== null && (typeof value.nextCursor !== 'string' || value.nextCursor.length > 4096))) fail();
  const items = Array.isArray(value.items) ? value.items : null;
  if (!items || items.length > 100) fail();
  const parts = [];
  for (const itemValue of items) {
    const item = record(itemValue, ['eventId', 'occurredAt', 'role', 'content']);
    const content = item && record(item.content, ['redacted', 'contentType', 'parts', 'text']);
    if (!item || !content || typeof item.eventId !== 'string' || item.eventId.length < 1 || item.eventId.length > 4096
      || typeof item.occurredAt !== 'string' || !Number.isFinite(Date.parse(item.occurredAt))
      || !['user', 'assistant'].includes(item.role) || !Number.isSafeInteger(content.parts) || content.parts < 1
      || content.redacted !== true || content.contentType !== 'text' || typeof content.text !== 'string'
      || content.text.length > 4096) fail();
    if (/\S/.test(content.text)) parts.push(content.text);
  }
  const text = parts.join('\n').slice(0, 65536);
  return /\S/.test(text) ? text : null;
}

function interleave(kinds, buckets, limit) {
  const offsets = new Map(kinds.map(kind => [kind, 0]));
  const result = [];
  let progressed = true;
  while (result.length < limit && progressed) {
    progressed = false;
    for (const kind of kinds) {
      const bucket = buckets.get(kind) || [];
      const index = offsets.get(kind);
      if (index < bucket.length && result.length < limit) {
        result.push(bucket[index]);
        offsets.set(kind, index + 1);
        progressed = true;
      }
    }
  }
  return result;
}

function initialSearchState(kinds, limit) {
  const chunk = Math.max(1, Math.floor(limit / kinds.length));
  const sources = {};
  for (const kind of kinds) {
    sources[kind] = kind === 'document'
      ? { offset: 0, done: false }
      : { cursor: null, done: false };
  }
  return { version: 1, kinds: [...kinds], chunk, nextKindIndex: 0, sources };
}

function normalizeSearchState(value, kinds, limit) {
  if (value === null) return initialSearchState(kinds, limit);
  const copied = capture(value, { maxArray: 8, maxBytes: 16384, maxDepth: 6, maxKeys: 32, maxString: 4096 });
  const state = copied !== INVALID && record(copied, ['version', 'kinds', 'chunk', 'nextKindIndex', 'sources']);
  const stateKinds = state && stringList(state.kinds, { max: 3, required: true, valid: item => typeof item === 'string' && KINDS.has(item) });
  const sources = state && record(state.sources, kinds);
  const expectedChunk = Math.max(1, Math.floor(limit / kinds.length));
  if (!state || state.version !== 1 || !stateKinds || stateKinds.length !== kinds.length
    || stateKinds.some((kind, index) => kind !== kinds[index]) || state.chunk !== expectedChunk
    || !Number.isSafeInteger(state.nextKindIndex) || state.nextKindIndex < 0 || state.nextKindIndex >= kinds.length
    || !sources) fail();
  const normalizedSources = {};
  for (const kind of kinds) {
    const source = kind === 'document'
      ? record(sources[kind], ['offset', 'done'])
      : record(sources[kind], ['cursor', 'done']);
    if (!source || typeof source.done !== 'boolean') fail();
    if (kind === 'document') {
      if (!Number.isSafeInteger(source.offset) || source.offset < 0 || source.offset > 100) fail();
    } else if (source.cursor !== null && (typeof source.cursor !== 'string' || source.cursor.length < 1 || source.cursor.length > 4096)) fail();
    normalizedSources[kind] = kind === 'document'
      ? { offset: source.offset, done: source.done }
      : { cursor: source.cursor, done: source.done };
  }
  return {
    version: 1,
    kinds: [...stateKinds],
    chunk: state.chunk,
    nextKindIndex: state.nextKindIndex,
    sources: normalizedSources
  };
}

function selectSearchKinds(state, limit) {
  const maximum = Math.min(state.kinds.length, Math.max(1, Math.floor(limit / state.chunk)));
  const selected = [];
  let index = state.nextKindIndex;
  let inspected = 0;
  while (inspected < state.kinds.length && selected.length < maximum) {
    const kind = state.kinds[index];
    if (!state.sources[kind].done) selected.push(kind);
    index = (index + 1) % state.kinds.length;
    inspected += 1;
  }
  state.nextKindIndex = index;
  return selected;
}

export function createFabricCapabilityProviderOperations(config) {
  const source = record(config, ['canonicalStore', 'documentStore', 'conversationReader', 'fabricStore', 'resolveGrant']);
  if (!source || typeof source.resolveGrant !== 'function') fail('fabric_capability_provider_operations_config_invalid');

  const canonical = {
    configured: configured(source.canonicalStore),
    read: method(source.canonicalStore, 'read'),
    routingContext: method(source.canonicalStore, 'routingContext'),
    search: method(source.canonicalStore, 'search')
  };
  const documents = {
    configured: configured(source.documentStore),
    read: method(source.documentStore, 'read'),
    search: method(source.documentStore, 'search')
  };
  const conversations = {
    configured: configured(source.conversationReader),
    search: method(source.conversationReader, 'search'),
    transcript: method(source.conversationReader, 'transcript')
  };
  const fabric = {
    configured: configured(source.fabricStore),
    propose: method(source.fabricStore, 'propose'),
    proposalStatus: method(source.fabricStore, 'getProposalStatusAuthorized')
  };
  if ([canonical.configured, documents.configured, conversations.configured, fabric.configured].some(value => value === null)
    || !canonical.read || !canonical.search || (canonical.configured && !canonical.routingContext)
    || !documents.read || !documents.search || !conversations.search || !conversations.transcript
    || !fabric.propose || !fabric.proposalStatus) fail('fabric_capability_provider_operations_config_invalid');

  const resolveGrant = source.resolveGrant;
  const projectGrant = async (grant, capability, scopes, purpose) => {
    let projected;
    try {
      projected = normalizeGrantProjection(await resolveGrant(grant,
        deepFreeze({ capability, scopes: deepFreeze([...scopes]), purpose })));
    } catch { /* normalized below */ }
    if (!projected || scopes.some(scope => !projected.allowedScopes.includes(scope))) fail();
    return projected;
  };

  const search = async (request, context) => {
    const input = exactRequest(request, ['query', 'kinds', 'scopes', 'purpose', 'continuation'], ['limit']);
    const callContext = record(context, ['grant']);
    const kinds = input && stringList(input.kinds, { max: 3, required: true, valid: item => typeof item === 'string' && KINDS.has(item) });
    const scopes = input && stringList(input.scopes, { max: 16, required: true, valid: item => typeof item === 'string' && SCOPE.test(item) });
    const limit = input && (input.limit === undefined ? 20 : input.limit);
    if (!input || !callContext || !kinds || !scopes || typeof input.query !== 'string' || input.query.length < 1
      || input.query.length > 512 || !/\S/.test(input.query) || !['memory_recall', 'conversation_recall'].includes(input.purpose)
      || !Number.isSafeInteger(limit) || limit < 1 || limit > 50
      || (kinds.includes('conversation') && input.purpose !== 'conversation_recall')) fail();
    const grant = await projectGrant(callContext.grant, 'search', scopes, input.purpose);
    if (kinds.includes('conversation') && (!grant.context || grant.sessionOwnerActors.length === 0)) fail();
    const state = normalizeSearchState(input.continuation, kinds, limit);
    const selectedKinds = selectSearchKinds(state, limit);
    const buckets = new Map(selectedKinds.map(kind => [kind, []]));

    if (selectedKinds.includes('canonical_memory')) {
      const sourceState = state.sources.canonical_memory;
      const result = await callSource(() => canonical.search(deepFreeze({
        query: input.query, scopes: deepFreeze([...scopes]), limit: state.chunk, cursor: sourceState.cursor,
        actor: grant.actor, context: grant.context
      })));
      const envelope = record(result, ['items', 'nextCursor']);
      if (!envelope || !Array.isArray(envelope.items) || envelope.items.length > state.chunk
        || (envelope.nextCursor !== null && (typeof envelope.nextCursor !== 'string'
          || envelope.nextCursor.length < 1 || envelope.nextCursor.length > 4096))) fail();
      for (const value of envelope.items) {
        const item = liveCanonical(value, {
          allowedScopes: scopes,
          context: grant.context,
          routingContext: canonical.routingContext,
          now: Date.now()
        });
        if (item) buckets.get('canonical_memory').push(item);
      }
      sourceState.cursor = envelope.nextCursor;
      sourceState.done = envelope.nextCursor === null;
    }

    if (selectedKinds.includes('document')) {
      const sourceState = state.sources.document;
      const pageEnd = Math.min(100, sourceState.offset + state.chunk);
      const fetchLimit = Math.min(100, pageEnd + 1);
      const result = await callSource(() => documents.search(deepFreeze({
        query: input.query, vaultIds: deepFreeze([...grant.documentVaultIds]), limit: fetchLimit
      })));
      if (!Array.isArray(result) || result.length > fetchLimit || result.length < sourceState.offset) fail();
      for (const value of result.slice(sourceState.offset, pageEnd)) {
        const item = liveDocument(value, grant.documentVaultIds);
        if (item) buckets.get('document').push(item);
      }
      sourceState.offset = Math.min(result.length, pageEnd);
      sourceState.done = result.length <= pageEnd || sourceState.offset >= 100;
    }

    if (selectedKinds.includes('conversation')) {
      const sourceState = state.sources.conversation;
      const result = await callSource(() => conversations.search(deepFreeze({
        query: input.query, cursor: sourceState.cursor, limit: state.chunk, from: null, to: null,
        actor: grant.actor, ownerActors: deepFreeze([...grant.sessionOwnerActors]), context: grant.context
      })));
      const envelope = record(result, ['items', 'total', 'nextCursor']);
      if (!envelope || !Array.isArray(envelope.items) || envelope.items.length > state.chunk
        || !Number.isSafeInteger(envelope.total) || envelope.total < envelope.items.length
        || (envelope.nextCursor !== null && (typeof envelope.nextCursor !== 'string'
          || envelope.nextCursor.length < 1 || envelope.nextCursor.length > 4096))) fail();
      for (const value of envelope.items) {
        const session = record(value);
        if (!session || typeof session.id !== 'string' || session.id.length < 1 || session.id.length > 4096) fail();
        const transcript = await callSource(() => conversations.transcript(deepFreeze({
          id: session.id, view: 'redacted', query: input.query, cursor: null, limit: 100,
          from: null, to: null, actor: grant.actor,
          ownerActors: deepFreeze([...grant.sessionOwnerActors]), context: grant.context
        })));
        const text = redactedConversationText(transcript, session.id);
        if (text) buckets.get('conversation').push({ kind: 'conversation', locator: session.id, revision: null, text });
      }
      sourceState.cursor = envelope.nextCursor;
      sourceState.done = envelope.nextCursor === null;
    }

    const items = interleave(selectedKinds, buckets, limit);
    const identities = new Set();
    for (const item of items) {
      const identity = `${item.kind}\0${item.locator}\0${item.revision ?? ''}`;
      if (identities.has(identity)) fail();
      identities.add(identity);
    }
    const continuation = Object.values(state.sources).every(sourceState => sourceState.done) ? null : state;
    return deepFreeze({ items, continuation });
  };

  const read = async (reference, context) => {
    const input = record(reference, ['kind', 'locator', 'revision']);
    const callContext = record(context, ['grant']);
    if (!input || !callContext || !KINDS.has(input.kind) || typeof input.locator !== 'string'
      || input.locator.length < 1 || input.locator.length > 4096
      || (input.revision !== null && (!Number.isSafeInteger(input.revision) || input.revision < 1))) fail();
    const grant = await projectGrant(callContext.grant, 'read', [], null);

    if (input.kind === 'canonical_memory') {
      const value = await callSource(() => canonical.read(deepFreeze({ id: input.locator, actor: grant.actor, context: grant.context })), { missing: true });
      if (value === null) return null;
      const item = liveCanonical(value, {
        allowedScopes: grant.allowedScopes,
        context: grant.context,
        routingContext: canonical.routingContext,
        now: Date.now()
      });
      return !item || (input.revision !== null && item.revision !== input.revision)
        ? null : deepFreeze({ kind: input.kind, text: item.text });
    }
    if (input.kind === 'document') {
      const value = await callSource(() => documents.read(deepFreeze({ documentId: input.locator, revision: input.revision })), { missing: true });
      if (value === null) return null;
      const item = liveDocument(value, grant.documentVaultIds);
      return item ? deepFreeze({ kind: input.kind, text: item.text }) : null;
    }
    if (!grant.context || grant.sessionOwnerActors.length === 0) return null;
    const value = await callSource(() => conversations.transcript(deepFreeze({
      id: input.locator, view: 'redacted', query: '', cursor: null, limit: 100,
      from: null, to: null, actor: grant.actor,
      ownerActors: deepFreeze([...grant.sessionOwnerActors]), context: grant.context
    })), { missing: true });
    if (value === null) return null;
    const text = redactedConversationText(value, input.locator);
    return text ? deepFreeze({ kind: input.kind, text }) : null;
  };

  const propose = async (request, context) => {
    const input = record(request, ['scope', 'claim', 'purpose', 'idempotencyKey']);
    const callContext = record(context, ['grant']);
    if (!input || !callContext || typeof input.scope !== 'string' || !SCOPE.test(input.scope)
      || typeof input.claim !== 'string' || input.claim.length < 1 || input.claim.length > 4096 || !/\S/.test(input.claim)
      || input.purpose !== 'memory_curation' || typeof input.idempotencyKey !== 'string') fail();
    const grant = await projectGrant(callContext.grant, 'propose', [input.scope], input.purpose);
    const result = await callSource(() => fabric.propose(deepFreeze({
      actor: grant.actor, scope: input.scope, text: input.claim, metadata: deepFreeze({}), infer: false,
      source: 'capability-mcp', idempotencyKey: input.idempotencyKey
    })));
    const output = record(result);
    if (!output || typeof output.id !== 'string' || output.id.length < 1 || output.id.length > 4096) fail();
    return deepFreeze({ locator: output.id, revision: null });
  };

  const proposalStatus = async (request, context) => {
    const input = record(request, ['locator', 'revision']);
    const callContext = record(context, ['grant']);
    if (!input || !callContext || typeof input.locator !== 'string' || input.locator.length < 1
      || input.locator.length > 4096 || input.revision !== null) fail();
    const grant = await projectGrant(callContext.grant, 'proposal_status', [], null);
    const result = await callSource(() => fabric.proposalStatus(input.locator, deepFreeze({
      actor: grant.actor, allowedScopes: deepFreeze([...grant.allowedScopes]), allowAll: false
    })), { missing: true });
    if (result === null) return null;
    const output = record(result);
    const state = output && typeof output.status === 'string' && ({
      queued: 'queued', review: 'review_required', promoted: 'applied', rejected: 'rejected', revoked: 'rejected'
    })[output.status];
    if (!state) fail();
    return deepFreeze({ state });
  };

  const readyForRead = canonical.configured && documents.configured && conversations.configured;
  const status = async () => deepFreeze({
    capabilities: CAPABILITIES.map(name => ({
      name,
      state: name === 'status' || (['propose', 'proposal_status'].includes(name) ? fabric.configured : readyForRead)
        ? 'ready' : 'unavailable'
    }))
  });

  const normalize = operation => async (...args) => {
    try {
      return await operation(...args);
    } catch (cause) {
      if (OWN_ERRORS.has(cause)) throw cause;
      fail();
    }
  };
  return deepFreeze({
    search: normalize(search),
    read: normalize(read),
    propose: normalize(propose),
    proposal_status: normalize(proposalStatus),
    status: normalize(status)
  });
}
