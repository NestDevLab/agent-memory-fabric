# deploy/ — legacy v2 local/shadow reference

This directory is a legacy v2 local/shadow reference. It is not a production
upgrade guide, production runbook, or data-migration procedure. For production
updates, follow [the deployment procedure](../docs/deployment-procedure.md).
For future architecture and migration work, follow [the roadmap](../docs/agent-memory-fabric-roadmap.md).

The example keeps the compatible decisions: PostgreSQL remains the production
relational option, SQLite remains the embedded fallback, pgvector is used for
semantic search, embeddings are pinned, shadow-first remains the safe rollout
shape, and this reference never copies live data.

## Local example boundary

Copy `.env.example` to `.env` and supply only disposable, synthetic local
inputs. Compose reads `.env` for substitution; no additional environment file
or runtime override mechanism is supported. The server port is bound to
loopback by default.

`amf-data`, `pgdata`, and `ollama-models` are new named volumes. They start
empty and must never be substituted for an existing data or catalog store.
They are suitable only for a fresh local/shadow reference.

Do not use this reference to move data. A production migration requires exact
manifests, reconciliation, rollback, restore proof, and single-writer
validation before any cutover. The deployment procedure and roadmap are the
authoritative sources for that work.

## Local checks

For a disposable example, inspect the resolved configuration before starting
anything:

```sh
cp .env.example .env
docker compose config
```

The compose file includes PostgreSQL with pgvector and a local embedding
service. Keep the embedding digest pinned when comparing shadow results. This
reference intentionally makes no claim that a local configuration is ready for
production.

## MCP compatibility

The target advertised MCP tools are `search`, `read`, `propose`,
`proposal_status`, and `status`. Product-specific `amf_*` adapter tools are
temporary, unadvertised compatibility aliases only; new clients must use the
provider-neutral target tools.
