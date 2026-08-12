# AMF Canonical Access Catalogue — 2026-08-12

Status: B1 design evidence. This document changes no registry, policy,
handoff, token, client, or runtime configuration.

## Evidence boundaries

The status principal was used only for read-only requests. It identifies as
`ct107-codex` and can read only `agent:ct107-codex`; this proves that the
current MCP/server policy is scoped, not globally accessible. The server's
`list_scopes` tool lists scopes visible to the current actor, not a global
catalogue. The production registry and policy files are privileged, so their
apply-time preflight remains mandatory.

| Scope | Registered live | Backend identity | Status-principal result | Lifecycle / owner disposition |
| --- | --- | --- | --- | --- |
| `agent:ct107-codex` | Yes | `ct107_codex` | Allowed | Active collector/status principal; not an interactive MCP write target. |
| `person:joseph` | Yes | `openmemory` | Denied | Canonical proposal scope for the two MCP principals. |
| `shared:global` | Yes | `amf-shadow` | Denied | Existing shared data scope; read wildcard may resolve it only when registered, but it is not a proposal grant. |
| `domain:tirrenia` | Yes | `openclaw_tirrenia` | Denied | Separate companion-client/owner lane; no Codex or Claude MCP grant. |
| `tirrenia` | No | — | Denied | Historical/example spelling only; it is not a current grant target. |
| `domain:odido` | No | — | Denied | Not registered on the live server; do not invent it or grant it. |

The last two rows are deliberate fail-closed results, not a statement that an
owner may never create a future scope. Any new scope needs its own owner,
registry/policy transaction, and review before it can be granted.

## Canonical Joseph document vault

| Field | Resolved value | Evidence | Boundary |
| --- | --- | --- | --- |
| Vault ID | `joseph-second-brain` | Fleet integration instance | This is the exact `--write-vault` target. |
| Vault path | `/home/administrator/env/obsidian-vaults/joseph-second-brain` | Fleet integration instance and existing systemd unit | Path is not a second vault identifier. |
| Obsidian actor | `client:obsidian:joseph-second-brain` | Fleet integration instance | It remains a distinct noninteractive client. |
| Runtime binding | `amf-obsidian-sync@joseph-second-brain.service` | Loaded unit; last execution succeeded | The unit was inactive between scheduled runs; this does not prove a sync canary. |

The interactive provisioner must still require this vault's entry in the
production policy at apply time. A missing or ambiguous entry aborts before
any write.

## Approved interactive MCP grant matrix

The two MCP principals are different identities with an identical nine-tool
surface. `*` is read-only and is resolved against the registered catalogue at
request time; it never makes an unregistered object readable.

| Principal | Tools | Read scopes | Proposal scopes | Read vaults | Write vaults |
| --- | --- | --- | --- | --- | --- |
| `client:mcp:codex` | `memory_search`, `memory_read`, `memory_propose`, `memory_proposal_status`, `documents_search`, `document_read`, `document_upsert`, `document_delete`, `memory_status` | `*` | `person:joseph` | `*` | `joseph-second-brain` |
| `client:mcp:claude` | Same nine tools | `*` | `person:joseph` | `*` | `joseph-second-brain` |

The policy must deny wildcard proposal or document-write grants, unknown
scope/vault IDs, incomplete four-grant profiles, revoked/inactive principals,
tools outside this exact surface, writes outside `joseph-second-brain`, and
proposals outside `person:joseph`.

Existing noninteractive clients keep their own contracts: `ct107-codex` is a
collector/status actor, Obsidian uses its distinct vault actor, the Vitae
recall profile has its own read-only scopes, and the Tirrenia client is an
owner-controlled companion migration. None inherits the MCP matrix.

## Provisioning transaction and rollback

`provisionInteractiveMcp` validates the complete profile before it mutates
anything: runtime is Codex or Claude, every grant is nonempty, only read
grants may use `*`, the tool set is the exact nine-tool set, and the explicit
proposal/vault targets are registered. The generic provisioner then pins the
parent directories, takes an exclusive lock, rejects conflicting actor/policy/
key state, creates a private backup, stages all replacements and the handoff,
fsyncs them, and commits context key ring, policy, registry, and handoff in
that order. A failure removes the staged/committed handoff, restores replaced
files in reverse order, fsyncs, and preserves the lock if rollback itself
fails.

`scripts/test-interactive-mcp.mjs` proves wildcard and invalid-grant rejection
before writing. `scripts/test-recall-consumer-provisioning.mjs` fault-injects
every replacement/handoff point and verifies byte-for-byte rollback, retained
backup, and lock behavior. B2 repeats these tests on the reconstructed source
head; G6 still requires a privileged dry run against the actual registry.
