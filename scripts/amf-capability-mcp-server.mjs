import { createCapabilityMcpServerRuntime } from '../src/capability-mcp-server-runtime.mjs';
import { createFabricStoreFromEnv } from '../src/fabric-store.mjs';
import { createCanonicalPamBridgeFromEnv } from '../src/canonical-memory-bridge.mjs';
import { createDocumentStoreFromEnv } from '../src/document-store.mjs';
import { createConversationSessionRuntimeFromEnv } from '../src/conversation-session-runtime.mjs';
import { createContextVerifierFromEnv } from '../src/context-token.mjs';
import { createCapabilityOpaqueReferenceStoreFromEnv } from '../src/capability-opaque-reference-store-env.mjs';
import { createCapabilityMcpHttpServer } from '../src/capability-mcp-http-server.mjs';
import { createCapabilityMcpAuthorizationBridge } from '../src/capability-mcp-auth-bridge.mjs';
import { createCapabilityMcpComposition } from '../src/capability-mcp-composition.mjs';
import { authenticateRequest, validateContextActorBinding } from '../src/server.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

try {
  const rootPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'); const runtime = createCapabilityMcpServerRuntime({ installSignals: true, dependencies: {
    createFabricStore: ({ env }) => createFabricStoreFromEnv({ env, rootPath }), createCanonicalStore: ({ env }) => createCanonicalPamBridgeFromEnv(env), createDocumentStore: ({ env }) => createDocumentStoreFromEnv(env),
    createContextVerifier: ({ env }) => createContextVerifierFromEnv(env), createConversationRuntime: ({ env, legacyReader }) => createConversationSessionRuntimeFromEnv({ env, rootPath, legacyReader }), createOpaqueStore: ({ env }) => createCapabilityOpaqueReferenceStoreFromEnv({ env }), createHttpServer: createCapabilityMcpHttpServer, authenticateRequest, validateContextActorBinding, createBridge: createCapabilityMcpAuthorizationBridge, createComposition: createCapabilityMcpComposition
  } }); await runtime.start();
} catch { process.stderr.write('capability_mcp_server_startup_failed\n'); process.exitCode = 78; }
