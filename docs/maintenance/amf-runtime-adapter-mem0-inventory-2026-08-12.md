# AMF Runtime-Adapter / Mem0 Inventory — 2026-08-12

Status: B4.1 read-only evidence. No adapter, Fleet, runtime, worktree, branch,
manifest, token, or client configuration was changed while collecting this
inventory. It is a recovery envelope, not a cleanup or rollout authorization.

## Adapter source and Syncwheel state

| Item | Verified state | Disposition |
| --- | --- | --- |
| Source repository | `/home/administrator/env/workspace/itermodus/nestdevlab/mem0-scoped-agent-plugin`, `git-tracked`, remote `NestDevLab/mem0-scoped-agent-plugin` | This is the active adapter source to be renamed only under B4.3/G5. |
| Primary checkout | `main` at `f3f2b113018a0b390c85245772a1b3a7623fd2ed`, clean, three commits ahead of `origin/main` | Preserve. Its net diff removes the previously re-applied Claude multi-conversation session identity and its test, and deletes one stale manifest record. It is conflicting recovery evidence, not disposable residue. |
| Registered worktrees | 33 total, all clean; no stashes and no existing recovery/backup refs | Retain every worktree unchanged. Create a named recovery ref immediately before any B4.2 source transformation. |
| Syncwheel manifest | Tracked, 14 declared legacy stacks; `main-integration` is `0ef0219` | `syncwheel validate` fails only because the primary checkout is `main` rather than manifest-required `main-integration`. Its plan proposes broad primary restoration and integration refreshes. Do not apply it: that would exceed the per-object recovery classification. |
| Unselected local Syncwheel profiles | `amf-m4-projection-identity.local.json` and `amf-m4-native-openclaw.local.json`; the active selection is the shared manifest | Retain as historical local recovery metadata. They are not selected and must not be promoted or replayed incidentally. |
| Open GitHub PRs | None for the adapter remote | A new product/companion PR is required under B4.4 after the recovered source passes review. |

The three primary-only commits are `28a5f34` (revert of the Claude session
identity fix), `271171f` (reapply), and `f3f2b11` (revert of the reapply).
Their current net effect is intentionally retained for B4.2 comparison with
the separately preserved `fix/claude-conversation-session-identity` intent.

## Worktree and stack classification

| Class | Branches / stacks | Disposition |
| --- | --- | --- |
| Unique collector resilience | `fix/collector-record-errors`, `fix/collector-skip-oversized-body`, `fix/collector-skip-oversized-jsonl`, `fix/amf-collector-overstrict-predicates` | Recover intent onto one clean current-base lane; preserve the original branches first. |
| Unique Claude handling | `amf/claude-stale-transcript`, `fix/claude-conversation-session-identity` | Recover only after comparing the primary checkout's explicit reverts and current AMF session contract. |
| Declared, unabsorbed runtime work | `amf-runtime-adapters`, `amf-local-candidates`, `amf-runtime-raw-adapters`, `amf-runtime-purpose`, `amf-bootstrap-scheduler-progress`, `amf-codex-capture-triage`, `amf-claude-capture-regression`, `amf-claude-jsonl-lineage`, `amf-v3-m2-checkpoint`, `amf-v3-m2-openclaw-missing-references` | Treat as source candidates; retain their original branches and classify each patch against the recovery lane before replay. |
| Patch-equivalent / zero-unique candidates | `fix/amf-m4-preserved-reader-double-close`, `fix/amf-m4-checkpoint-capsule-cli`, `fix/amf-m4-checkpoint-capsule-defaults`, `fix/amf-m4-hermes-fractional-timestamp`, `fix/amf-m4-openclaw-index-identity`, `fix/amf-m4-hermes-replay-timestamps`, `fix/amf-m4-large-codex-records`, `feat/amf-m4-native-hermes`, `feat/amf-m4-native-openclaw`, `feat/amf-m4-projection-identity`, `feat/amf-v3-m4-preserved-queue-reader`, and checkpoint administrative branches | Do not replay by name and do not remove. Verify patch equivalence only when their owning recovery decision is made. |

This classification deliberately does not turn all 14 manifest entries into a
single integration replay. The existing manifest plan also contains work that
is already patch-equivalent or whose current primary branch deliberately
reverted it.

## Active Mem0 identities and owners

| Owner | Active source reference | B4/B5 disposition |
| --- | --- | --- |
| Adapter package | `openpack.json` names `NestDevLab/mem0-scoped-agent-plugin`; OpenClaw exposes `mem0-scoped` / `@yehonal/openclaw-mem0-scoped`; Hermes exposes `mem0_scoped` | B4.3 must rename the package/plugin/runtime IDs, paths, tests, documentation, and configuration schema together. No compatibility alias remains after the approved cutover. |
| Adapter client contract | OpenClaw source uses Mem0 gateway naming, including `MEM0_GATEWAY_TOKEN`, a Mem0 endpoint description, and `mem0` trigger wording | Replace in B4.3 only after B4.2 identifies the retained client behavior and current Fabric endpoint contract. |
| Fleet CT107 OpenClaw | `profiles/agent-memory-fabric-openclaw/.agentwheel/config.json` selects `plugins/mem0-scoped` from this adapter source | B5.2 migration owner. It is active source configuration; runtime installation remains G9. |
| Fleet CT107 Hermes | `profiles/agent-memory-fabric-hermes/.agentwheel/config.json` selects `plugins/mem0_scoped` from this adapter source | B5.2 migration owner. It is active source configuration; runtime installation remains G9. |
| Fleet CT107 main OpenClaw plugins | `profiles/openclaw-main-plugins/.agentwheel/config.json` independently selects `plugins/mem0-scoped` from the same source | B5.2 must include this overlapping active consumer; it cannot be treated as a historical CT110 lock. |
| Tirrenia companion | The source-owned runbook names `/home/openclaw-tirrenia/.openclaw/openclaw.json` and legacy key `mcp.servers.mem0gateway` | Owner/target, replacement configuration, rollback, and live canary remain B7.3/G9-G10 work. No runtime access or change occurred here. |
| Historical material | Git history, backup/recovery refs, generated Agentwheel locks, archival rollout notes, and personal historical-memory entries | Preserve. These are excluded from the active-source cutover scan and remain subject to G11 only if a later exact cleanup decision is approved. |

The private toolkit has no active-source `mem0` match under its normal source
exclusions. That observation does not authorize changing its dirty checkout;
B5.1 remains its separate ownership and recovery gate.

## Next recovery boundary

B4.2 has preserved `main` and every branch with unique current-base patches as
named `recovery/amf-adapter-b42-20260812-*` refs. `git cherry origin/main`
identifies only six non-equivalent source candidates: Claude stale-transcript,
three collector-resilience patches, over-strict collector predicates, and the
Claude conversation-session identity patch. All declared adapter/runtime/M4
stacks otherwise have zero unique patches against `origin/main` and must not
be replayed merely because the legacy manifest names them.

The clean primary cannot yet become the canonical `main-integration` lane:
that branch is held by a retained clean legacy worktree at
`var/syncwheel/main-integration`, while the primary is the protected local
`main` recovery branch. A broad `syncwheel reconcile --apply` would rewrite
both the primary projection and the legacy integration membership. B4.2
therefore stops before a branch/worktree change. It needs an exact
non-destructive integration-rotation decision that names how the retained
`main-integration` worktree/branch is preserved, released, or kept alongside
a temporary recovery lane.

No `syncwheel reconcile --apply`, worktree removal, branch deletion,
repository rename, runtime apply, or client configuration change is implied by
this inventory.
