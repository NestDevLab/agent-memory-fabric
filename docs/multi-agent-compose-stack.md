# Legacy v2 multi-agent compose reference

Status: legacy v2 local/shadow reference.

This document describes the bounded example in `deploy/`. It is not a
production upgrade guide, operations runbook, topology description, or
data-migration procedure. Production updates belong in
[deployment-procedure.md](deployment-procedure.md); future work belongs in
[agent-memory-fabric-roadmap.md](agent-memory-fabric-roadmap.md).

## Preserved compatibility decisions

- PostgreSQL is the production relational option; SQLite remains the embedded
  fallback behind the same storage contract.
- The local reference uses PostgreSQL with pgvector for semantic search.
- Embeddings remain pinned so shadow comparisons use one vector space.
- Rollout remains shadow-first. This reference does not perform an active
  cutover and never copies live data.

## Example boundary

The stack is intentionally small: an AMF server, PostgreSQL with pgvector, and
a local embedding service. Its only published endpoint binds to loopback.
Values come from Compose `.env` substitution. There is no additional
environment file or runtime override layer.

All example inputs must be synthetic and disposable. Do not add real people,
addresses, private filesystem paths, operational actors, or environment
topology to this document or the example configuration.

## Storage and migration safety

Named volumes created by Compose start empty. They must never substitute for
an existing data or catalog store, and a new local volume is not a recovery
artifact.

Production migration requires exact manifests, reconciliation, rollback,
restore proof, and single-writer validation. It must not use this local/shadow
reference as a migration procedure. Follow the deployment procedure and the
roadmap before planning that work.

## MCP transition

The advertised capability MCP surface is exactly:

- `search`
- `read`
- `propose`
- `proposal_status`
- `status`

Product-specific `amf_*` adapter tools are temporary, unadvertised
compatibility aliases. They are not part of the advertised API for new
clients.
