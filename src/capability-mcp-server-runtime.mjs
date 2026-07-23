import fs from 'node:fs';

function failure() {
  const error = new Error('capability_mcp_server_runtime_invalid');
  error.code = error.message;
  return error;
}

function fail() { throw failure(); }
function integer(value, fallback, min, max) {
  if (value === undefined) return fallback;
  const parsed = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : NaN;
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : null;
}
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}
function loadPolicy(filePath) {
  try {
    if (typeof filePath !== 'string' || !filePath.startsWith('/') || filePath.length > 4096 || filePath.includes('\0')) return null;
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return plain(parsed) && plain(parsed.actors) && plain(parsed.scopes) ? parsed : null;
  } catch {
    return null;
  }
}
async function closeResource(value) {
  try { await value?.close?.(); } catch { /* best-effort cleanup */ }
}
async function closeResources(values) {
  for (const value of [...values].reverse()) await closeResource(value);
}
async function closeServer(value) {
  if (!value) return;
  await new Promise(resolve => {
    let settled = false;
    const finish = () => { if (!settled) { settled = true; resolve(); } };
    try {
      const result = value.close(finish);
      if (result && typeof result.then === 'function') result.then(finish, finish);
    } catch { finish(); }
  });
}

/** Injectable source-only lifecycle coordinator for the capability MCP listener. */
export function createCapabilityMcpServerRuntime({ env = process.env, dependencies, installSignals = false } = {}) {
  const required = ['createFabricStore', 'createCanonicalStore', 'createDocumentStore', 'createContextVerifier',
    'createConversationRuntime', 'createOpaqueStore', 'createHttpServer', 'authenticateRequest',
    'validateContextActorBinding', 'createBridge', 'createComposition'];
  if (!plain(dependencies) || required.some(key => typeof dependencies[key] !== 'function')) fail();
  if (env.AMF_CAPABILITY_MCP_ENABLED !== 'true') fail();
  const host = env.AMF_CAPABILITY_MCP_HOST;
  const port = integer(env.AMF_CAPABILITY_MCP_PORT, null, 1, 65535);
  const policyPath = env.AMF_POLICY_PATH;
  if (!['127.0.0.1', '::1'].includes(host) || port === null || !policyPath) fail();
  const options = {
    cursorTtlMs: integer(env.AMF_CAPABILITY_MCP_CURSOR_TTL_MS, 900000, 1000, 3600000),
    maxBodyBytes: integer(env.AMF_CAPABILITY_MCP_MAX_BODY_BYTES, 131072, 1, 1048576),
    bodyTimeoutMs: integer(env.AMF_CAPABILITY_MCP_BODY_TIMEOUT_MS, 10000, 100, 60000),
    connectionTtlMs: integer(env.AMF_CAPABILITY_MCP_CONNECTION_TTL_MS, 300000, 1000, 3600000),
    maxConnections: integer(env.AMF_CAPABILITY_MCP_MAX_CONNECTIONS, 64, 1, 1024),
    maxConnectionsPerActor: integer(env.AMF_CAPABILITY_MCP_MAX_CONNECTIONS_PER_ACTOR, 8, 1, 1024)
  };
  if (Object.values(options).some(value => value === null)
    || options.maxConnectionsPerActor > options.maxConnections) fail();

  let resources = [];
  let server = null;
  let state = 'idle';
  let generation = 0;
  let startPromise = null;
  let closePromise = null;
  const listenCancellations = new Set();
  const signalListeners = [];

  const removeSignals = () => {
    for (const [signal, listener] of signalListeners) process.removeListener(signal, listener);
    signalListeners.length = 0;
  };
  const drain = async () => {
    const currentServer = server;
    const currentResources = resources;
    server = null;
    resources = [];
    await closeServer(currentServer);
    await closeResources(currentResources);
  };
  const assertCurrent = token => {
    if (token !== generation || state === 'closing') fail();
  };
  const own = async (token, value) => {
    if (token !== generation || state === 'closing') {
      await closeResource(value);
      fail();
    }
    resources.push(value);
    return value;
  };
  const listen = (candidate, token) => new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action, value) => {
      if (settled) return;
      settled = true;
      listenCancellations.delete(cancel);
      try { candidate.off('error', onError); } catch { /* normalized below */ }
      action(value);
    };
    const onError = () => finish(reject, failure());
    const cancel = () => finish(reject, failure());
    listenCancellations.add(cancel);
    try {
      candidate.once('error', onError);
      candidate.listen(port, host, () => finish(resolve));
      if (token !== generation || state === 'closing') cancel();
    } catch { finish(reject, failure()); }
  });
  const bootstrap = async token => {
    try {
      const fabricStore = await own(token, await dependencies.createFabricStore({ env }));
      assertCurrent(token);
      const canonicalStore = await own(token, await dependencies.createCanonicalStore({ env }));
      assertCurrent(token);
      const documentStore = await own(token, await dependencies.createDocumentStore({ env }));
      assertCurrent(token);
      const contextVerifier = await own(token, await dependencies.createContextVerifier({ env }));
      assertCurrent(token);
      const conversationRuntime = await own(token, await dependencies.createConversationRuntime({
        env, legacyReader: fabricStore.createSessionReader?.()
      }));
      assertCurrent(token);
      const opaqueReferenceStore = await own(token, await dependencies.createOpaqueStore({ env }));
      assertCurrent(token);
      const conversationReader = conversationRuntime?.reader;
      if (!fabricStore?.configured || !canonicalStore?.configured || !documentStore?.configured
        || !contextVerifier?.configured || !conversationReader?.configured || !opaqueReferenceStore) fail();
      for (const item of [fabricStore, canonicalStore, documentStore, contextVerifier, conversationRuntime, opaqueReferenceStore]) {
        if (typeof item.ready === 'function') await item.ready();
        assertCurrent(token);
      }
      const candidate = dependencies.createHttpServer({
        ...options,
        authenticate: request => dependencies.authenticateRequest(request, { allowQueryToken: false }),
        createComposition: async ({ authContext, requestArguments, contextToken }) => {
          const policies = loadPolicy(policyPath);
          if (!policies) throw failure();
          dependencies.validateContextActorBinding(authContext.actor, authContext.policy, policies, contextVerifier);
          const bridge = dependencies.createBridge({ authContext, requestArguments, contextToken, contextVerifier,
            policies, validateContextActorBinding: dependencies.validateContextActorBinding });
          return dependencies.createComposition({ canonicalStore, documentStore, conversationReader, fabricStore,
            resolveGrant: bridge.resolveGrant, authorize: bridge.authorize, opaqueReferenceStore,
            cursorTtlMs: options.cursorTtlMs });
        }
      });
      if (!candidate || typeof candidate.listen !== 'function' || typeof candidate.close !== 'function'
        || typeof candidate.once !== 'function' || typeof candidate.off !== 'function') fail();
      assertCurrent(token);
      server = candidate;
      await listen(candidate, token);
      assertCurrent(token);
      state = 'started';
      if (installSignals) {
        for (const signal of ['SIGINT', 'SIGTERM']) {
          const listener = () => { close().catch(() => {}); };
          signalListeners.push([signal, listener]);
          process.once(signal, listener);
        }
      }
      return candidate;
    } catch {
      await drain();
      if (state !== 'closing') state = 'idle';
      throw failure();
    }
  };
  const start = async () => {
    if (state !== 'idle' || startPromise || closePromise || !loadPolicy(policyPath)) fail();
    state = 'starting';
    const token = ++generation;
    const pending = bootstrap(token);
    startPromise = pending;
    try { return await pending; }
    finally { if (startPromise === pending) startPromise = null; }
  };
  const close = () => {
    if (closePromise) return closePromise;
    generation += 1;
    state = 'closing';
    for (const cancel of [...listenCancellations]) cancel();
    const pendingStart = startPromise;
    const pendingClose = (async () => {
      await drain();
      if (pendingStart) try { await pendingStart; } catch { /* expected cancellation */ }
      await drain();
      removeSignals();
      state = 'idle';
    })();
    closePromise = pendingClose.finally(() => { closePromise = null; });
    return closePromise;
  };
  return Object.freeze({ start, close, get server() { return server; } });
}
