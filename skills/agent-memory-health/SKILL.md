---
name: agent-memory-health
description: Check Agent Memory Fabric storage, capture, collector, provider, and recall health. Use when asked whether memory works, is enabled, healthy, degraded, or available in Codex, Claude, OpenClaw, Hermes, or a specialized agent.
---

# Agent Memory Health

Run the bundled probe first:

```bash
cd <this-skill-directory>
node scripts/amf-health.mjs --json
```

Add `--deep` for local OpenClaw/Hermes probes. Use `--deployment-env <path>` only for an authorized AMF deployment file; the script reads the token without printing it. Never source or display secrets.

Interpret three independent layers:

1. **Capture:** collectors are recent, successful, and have no pending/dead events.
2. **Access:** the current session exposes `memory_status`, `memory_search`, `memory_read`, or equivalent native recall. Inspect the actual tool surface; the script cannot see tools injected into the session.
3. **Recall:** a fresh session retrieves a benign unique fact with correct scope and provenance.

Report `HEALTHY` only when every required layer passes. Storage without access is `DEGRADED`; capture alone never proves recall. Preserve script exit semantics: `0` healthy, `1` degraded, `2` critical.

For an end-to-end canary, store a random non-sensitive token through the runtime's supported proposal/native-memory path, open a new session, retrieve it without repeating it, verify source and scope, then revoke/delete it when supported. Do not write a canary unless the user authorizes that run.

Keep deployment topology outside this package. Fleet overlays may provide endpoint, token-file, collector, profile, and threshold configuration; never add private hosts, paths, actors, or credentials here.
