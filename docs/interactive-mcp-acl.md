# Interactive AMF MCP ACL

`amf` is one MCP contract shared by Codex and Claude. Each runtime has a
distinct identity and handoff (`client:mcp:codex` or `client:mcp:claude`), but
the provisioner requires the same complete tool surface for both. The local
bridge never accepts an actor, grant, vault, permission, or context token from
a tool call. Fabric re-authorizes its bearer token on every request.

## Operation grants

The registry, policy actor, and handoff carry four independent grants:

| Operation | Grant flag | Wildcard |
| --- | --- | --- |
| Memory search/read | `--read-scope` | Only `*`, resolved against registered scopes at request time |
| Memory proposal | `--propose-scope` | Never |
| Document search/read | `--read-vault` | Only `*`, resolved from Fabric's document catalog at request time |
| Document upsert/delete | `--write-vault` | Never |

An incomplete grant pair, an unregistered explicit scope, an unknown tool
surface, or a wildcard write grant is rejected before the transaction writes
anything. The compatibility `allowedScopes` and `allowedVaults` fields remain
the narrow write grants so an older server cannot accidentally reinterpret a
read wildcard as a write privilege.

Fabric persists the nine `--tool` values in both the registry row and policy
actor, filters `tools/list` from that server-side allowlist, and rejects an
unlisted `tools/call` before dispatch. A `client:mcp:*` row without a persisted
tool list receives no MCP tools: migrate it through the provisioner before it
can be used. Legacy `allowedScopes: ['*']` remains read-compatible but is never
a proposal grant; migrate proposal principals to an explicit non-wildcard
`proposeScopes` list.

`document_delete` appends a revisioned tombstone. Both document writes retain
the caller's expected revision and idempotency key; Fabric audits every allow,
denial, duplicate, and tombstone.

## Provisioning procedure

Use the actual private registry, policy, context-key ring, and service-owner
paths from the deployment runbook. The approved target is
`person:joseph` with the canonical vault ID `joseph-second-brain`; the
privileged preflight must still prove that both entries are registered. Do not
substitute a human-readable vault name. First preview the exact grant:

```bash
node scripts/amf-provision-interactive-mcp.mjs --dry-run \
  --runtime codex \
  --auth-registry /private/auth-registry.json \
  --policy /private/policy.json \
  --context-key-ring /private/context-key-ring.json \
  --handoff /private/handoffs/codex \
  --backup-root /private/backups \
  --backend-user-id unused-for-registered-scopes \
  --service-owner-uid 1234 \
  --policy-revision policy-revision-id \
  --endpoint https://amf.example.invalid/ \
  --read-scope '*' \
  --propose-scope person:joseph \
  --read-vault '*' \
  --write-vault joseph-second-brain \
  --tool memory_search \
  --tool memory_read \
  --tool memory_propose \
  --tool memory_proposal_status \
  --tool documents_search \
  --tool document_read \
  --tool document_upsert \
  --tool document_delete \
  --tool memory_status
```

The live invocation is a separate privileged operation: it updates the
registry, policy, key ring, and handoff as one rollback-capable transaction.
Provision Codex and Claude with the same four grants and tools, then install
their generated client configuration only after a conflict-free Agentwheel
dry-run.

Before enabling a client, verify `tools/list`, a read wildcard over registered
scopes, denied proposal outside `--propose-scope`, denied write outside
`--write-vault`, revision conflict, idempotent replay, tombstone, and audit
receipt. A live write/read/delete canary, token rotation, or runtime install is
not performed by this source procedure.
