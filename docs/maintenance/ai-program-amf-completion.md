# Agent Memory Fabric Completion Program

Status: EXECUTING
Authority: `MGT-0029` — Complete Agent Memory Fabric through M7; Joseph's direct request on 2026-08-12 to prepare and execute the completion program
Coordinator: im-coordinator / Codex standalone session `019feb61-5296-7192-ab65-0b781add0e84`
Last updated: 2026-08-12
Baseline: AMF primary checkout `main-integration` at local commit `97eb4350cd78e91bdb047c395cb0b62c4033dbe2`, clean and unpublished; other repositories retain the dirty state listed below

## Mission

### Outcome

Deliver a single AMF MCP surface named `amf`, with an operation-specific, fail-closed ACL; remove active Mem0 naming and compatibility behavior from the AMF product path; migrate the runtime adapters, private toolkit, and Fleet sources to that contract; and return the live AMF service and collectors to a healthy, independently proved state.

"Complete" means source delivery, Git absorption, approved runtime materialization, and fresh live proof. A passing unit suite, a committed change, a policy file, or a service shown as active is not completion by itself.

### Success evidence

- The AMF MCP exposes the same nine tools to Codex and Claude: `memory_search`, `memory_read`, `memory_propose`, `memory_proposal_status`, `documents_search`, `document_read`, `document_upsert`, `document_delete`, and `memory_status`; all requests are authorized by the same operation grant model.
- Read wildcards resolve only against the registered scope or vault catalogue. Proposal and document-write grants enumerate exact existing objects; unknown objects, incomplete grants, and write wildcards are rejected. Document deletes create revisioned tombstones and preserve idempotency and audit evidence.
- The official provisioner can create or revoke an MCP principal only through explicit grants: `--read-scope`, `--propose-scope`, `--read-vault`, `--write-vault`, and `--tool`. It validates the canonical catalogue before it changes registry, policy, or handoff state.
- Active source, generated source declarations, and live runtime configuration have no `mem0` identity, alias, directory, package, plugin, or MCP server key after their individually approved migration; Git history, backups, recovery refs, and dated forensic records remain preserved.
- Every unique local stack, worktree, stash, and recovery ref has a disposition. Normal Syncwheel replay uses the single-checkout/plumbing model; no routine persistent worktree remains as an operating mechanism.
- AMF health has a dedicated read-only status credential outside repositories, the active collector queues are empty, the 1,118 Claude dead letters have an approved receipt and checksum-backed retained disposition, and fresh status/collector probes pass.
- After an explicitly approved rollout, canaries prove principal-specific read, proposal, document upsert, document delete, denial, audit, idempotency, and revision-conflict behavior against the live service.

### Scope

- Product source: `/home/administrator/env/workspace/itermodus/nestdevlab/agent-memory-fabric`.
- Runtime-adapter source currently named `/home/administrator/env/workspace/itermodus/nestdevlab/mem0-scoped-agent-plugin`; its target product identity is `agent-memory-fabric-runtime-adapters`.
- Private source package: `/home/administrator/env/workspace/itermodus/nestdevlab/agent-core-toolkit-private`.
- Fleet source and Agentwheel configuration: `/home/administrator/env/workspace/itermodus/nestdevlab/fleet-control`.
- The legacy clone `/home/administrator/env/workspace/itermodus/nestdevlab/mem0-gateway`, which has the same `origin` URL as AMF, is an AMF clone to classify and retire, not a fifth product repository.
- Companion owner changes for active references in `brain-shared` runbooks and external runtime configurations, including the Tirrenia `mcp.servers.mem0gateway` entry, after their owner and runtime are verified.

### Non-goals

- Do not rewrite Git history, backups, cache directories, or dated incident evidence merely to remove a string.
- Do not infer the private Joseph vault identifier, invent scope names, or grant a wildcard write permission.
- Do not merge PR #49 — `feat: link-graph retrieval (Postgres engine) for /v2/context/search`; it is an unrelated, conflicting external-owner review lane.
- Do not execute registry changes, credential issuance, service deployment, restart, data replay, dead-letter movement, Agentwheel installation, live write/delete canaries, or cleanup without the exact approval gate below.

## Authority and evidence

| Claim or constraint | Footing | Source | Last verified |
|---|---|---|---|
| Joseph requested total AMF completion and this executable program | Verified | Current conversation and `MGT-0029` | 2026-08-12 |
| AMF source change exists locally and has a clean worktree | Verified | `git status`, `git show 97eb435`, `git diff --check 9592697..97eb435` | 2026-08-12 |
| AMF unified MCP and ACL implementation passed its complete local suite | Verified | `npm test` completed before commit `97eb435`; evidence recorded in the session handoff | 2026-08-12 |
| PR #158 — `chore(syncwheel): retire legacy stacks` is a clean draft against `main` | Verified | GitHub PR metadata, head `d30eb1001c05ea6c81016b3766e3844523794ce9` | 2026-08-12 |
| PR #49 is open, owned externally, and has a dirty merge state | Verified | GitHub PR metadata, head `2a9051cca8f22bac958c39addb05c7a599fb2837` | 2026-08-12 |
| AMF health is degraded only by 1,118 Claude dead letters; the read-only status credential, Fabric, and all other active collectors are healthy | Verified | `agent-memory-health` fleet-config JSON probe at 2026-08-12T15:58:31Z | 2026-08-12 |
| The canonical Joseph private vault identifier is `joseph-second-brain` | Verified | Fleet integration instance plus loaded `amf-obsidian-sync@joseph-second-brain.service` binding | 2026-08-12 |
| `person:joseph`, `shared:global`, and `domain:tirrenia` are registered live; `tirrenia` and `domain:odido` are not | Verified | Read-only `/v1/policies/resolve` comparison with the status principal | 2026-08-12 |
| The legacy `mem0-gateway` checkout and AMF use the same remote | Verified | `git remote get-url origin` in both checkouts | 2026-08-12 |
| Legacy Mem0 references remain in active owner documentation and runtime configuration | Source-backed | `brain-shared` AMF and Tirrenia runbooks; live target still requires owner verification | 2026-08-12 |
| Fleet/Agentwheel single-checkout migration has its own lossless program dossier | Source-backed | `fleet-control/docs/maintenance/ai-program-syncwheel-single-checkout-lossless-migration.md` | 2026-08-12 |
| `gpt-5.6-terra`, `gpt-5.6-sol`, and `gpt-5.5` are selectable in this Codex runtime | Verified | Current Codex model routing options | 2026-08-12 |
| Claude Haiku is only a bounded-review canary; Sonnet did not finish the recorded bounded review | Source-backed | `im-ai-program-plan/references/model-capability-ledger.md` | 2026-08-12 |

## Invariants and approval gates

| Gate | Exact scope | Owner | State | Evidence or next decision |
|---|---|---|---|---|
| G0 | Create and maintain this dossier and attach the current program to `MGT-0029` | Joseph / im-coordinator | PASSED | Direct request on 2026-08-12; ledger is reopened without rewriting history |
| G1 | Source edits, local tests, and local commits in AMF, runtime adapters, private toolkit, and Fleet | Joseph | APPROVED | Joseph approved all four named repositories on 2026-08-12; preserve unrelated dirty residue |
| G2 | B3.3 only: declare and capture the retained AMF primary commits in one draft stack, then rebuild `main-integration` from post-#158 `origin/main` through Syncwheel plumbing | Joseph | APPROVED (narrow) | Joseph's approved execution order explicitly requires B3.3. Exact target: `/home/administrator/env/workspace/itermodus/nestdevlab/agent-memory-fabric` on `main-integration`; retained commits `97eb435`, `8c43065`, and the B2.1 review record are captured into one local draft stack. No worktree move/removal, branch deletion, stash change, remote push, or operation in another repository is authorized. |
| G3 | Review and squash-merge PR #158 at exact head `d30eb100...` | Joseph | APPROVED | Merge only if independent review is READY and the head/base remain the reviewed revisions |
| G4 | Push and create or update each ready product or companion PR | Joseph | APPROVED | Joseph approved publication of ready stacks on 2026-08-12; every merge other than PR #158 remains a separate exact decision |
| G5 | Rename the GitHub repository and active source identity from `mem0-scoped-agent-plugin` to `agent-memory-fabric-runtime-adapters` | Joseph / repository owner | OPEN | Current consumers, redirects, and rollback record must be reviewed first |
| G6 | Apply AMF registry, policy, provisioner, token, scope, vault, or client configuration | Joseph / AMF operator | APPROVED | Apply only the catalogue-resolved, least-privilege diff after dry run and rollback proof |
| G7 | Issue the read-only health credential and add it to the approved secret store or runtime environment | Joseph / AMF operator | APPROVED | Apply only after credential scope, storage location, rotation, and non-repository proof are documented |
| G8 | Archive, classify, recover, or otherwise move the 1,118 Claude dead letters | Joseph / AMF operator | OPEN | Written runbook, receipt schema, checksum manifest, and exact target required |
| G9 | Agentwheel install, service deploy/reload/restart, or runtime configuration apply | Joseph / AMF operator | APPROVED | Apply only the reviewed intended-only plan with named target, rollback, and service-specific proof |
| G10 | Live MCP proposal/upsert/delete canaries or any tombstone creation | Joseph / AMF operator | APPROVED | Run only named redacted canaries after the grant matrix, target scope/vault, record, and recovery procedure are proved |
| G11 | Remove the legacy clone, local worktrees, branches, stashes, recovery refs, or remote branches | Joseph | OPEN | Absorption proof, retention decision, and exact destructive target list required |

## Workstreams and dependencies

| Batch | Deliverable | Depends on | Acceptance evidence |
|---|---|---|---|
| B0 | Current authority, source baseline, and completion dossier | none | Ledger and validated dossier identify all repositories, residue, gates, and next action |
| B1 | Canonical scope/vault catalogue and operation-grant design | B0 | Read-only catalogue inventory and reviewed grant matrix with no inferred identifiers |
| B2 | AMF single MCP and fail-closed ACL source delivery | B1 | Exact-head review, source tests, and PR absorption |
| B3 | AMF Syncwheel legacy-stack settlement | B0 | PR #158 disposition, rebuilt integration projection, no unexpected Syncwheel replay |
| B4 | Runtime-adapter source rename and contract migration | B1, B3 | Recovered unique adapter work, rename inventory, tests, and source PR absorption |
| B5 | Private toolkit and Fleet source migration | B4 | Source-owned package/configuration PRs and intended-only Agentwheel dry runs |
| B6 | Health credential and dead-letter operational recovery | B1, B5 | Approved runbook, receipt/checksum, empty active queue, and fresh healthy probe |
| B7 | Controlled rollout and live MCP verification | B2, B5, B6 | Approved install/deploy and per-principal live canaries |
| B8 | Completion review, documentation, and retention/cleanup decision | B3, B4, B5, B6, B7 | Independent reviewer READY verdict and explicit retained/removed object ledger |

## Team and routing

| Responsibility | Role skill | Runtime | Model | Effort | Selection reason | Escalation trigger |
|---|---|---|---|---|---|---|
| Program integration and checklist freshness | im-coordinator | Codex | gpt-5.6-terra | high | Balanced gate-sensitive coordination; current runtime availability is verified | Conflicting cross-repository intent or any unexplained recovery item |
| ACL, catalogue, and cutover design | im-architect | Codex | gpt-5.6-sol | xhigh | Critical authorization design needs maximum local reasoning | Any ambiguity between source, registry, and live runtime evidence |
| Source implementation and tests | im-developer | Codex | gpt-5.6-sol | high | Codex is the policy-backed implementation and Git-delivery default | Test failure, current-base conflict, or source ownership uncertainty |
| Exact-head security and release review | im-reviewer | Codex | gpt-5.5 | high | Independent from implementer; a separate model family is not currently proven available for release review | Any ACL/write/delete or secret-handling finding; re-probe Claude for a bounded second review |
| Runbooks and durable evidence | im-documenter | Codex | gpt-5.6-luna | medium | Lowest-cost route suitable for bounded factual documentation | Contradictory source evidence or security-sensitive procedure |
| Approved operational execution | im-operator | Codex | gpt-5.6-terra | high | Gate-oriented execution and evidence capture | Any command would modify runtime, data, credentials, or service availability |

## Mandatory implementation checklist

| ID | Deliverable | Depends on | Owner role/session | Runtime/model/effort | Status | Evidence | Updated and handoff comment |
|---|---|---|---|---|---|---|---|
| B0.1 | Record the current program baseline, exact AMF/PR state, and repository residue | none | im-coordinator / Codex | Codex/gpt-5.6-terra/high | DONE | This dossier; AMF `97eb435`, PR #158 and #49 metadata, four repository status probes | 2026-08-12 - baseline captured; refresh before each execution batch |
| B0.2 | Attach the program to the authoritative management item without rewriting prior history | B0.1 | im-coordinator / Codex | Codex/gpt-5.6-terra/high | DONE | `management/ledger/MGT-0029.md` state set to `in-progress` with append-only log | 2026-08-12 - dossier is execution context, not a competing work-item store |
| B0.3 | Classify the present AMF, adapter, toolkit, Fleet, and legacy-clone worktree/stack state into recovery envelopes | B0.1 | im-operator / recovery lane | Codex/gpt-5.6-terra/high | DONE | `docs/maintenance/amf-completion-recovery-inventory-2026-08-12.md`; Fleet's existing exact G1 envelope; retain-only disposition for every repository | 2026-08-12 - no checkout was moved, cleaned, reset, or replayed; per-object capture is required immediately before any future transformation |
| B1.1 | Produce the read-only canonical scope catalogue with owner, type, lifecycle, and registered backend identity | B0.1 | im-architect / ACL lane | Codex/gpt-5.6-sol/xhigh | DONE | `docs/maintenance/amf-canonical-access-catalogue-2026-08-12.md`; live read-only resolve comparison and source/runtime reconciliation | 2026-08-12 - current actor is scoped to `agent:ct107-codex`; no full-catalogue privilege was inferred |
| B1.2 | Resolve exactly one canonical Joseph private vault identifier or fail closed with an ambiguity report | B1.1 | im-architect / ACL lane | Codex/gpt-5.6-sol/xhigh | DONE | Canonical ID `joseph-second-brain`; Fleet instance and loaded Obsidian service binding | 2026-08-12 - privileged apply must still reject a missing policy-vault entry |
| B1.3 | Write the reviewed actor-operation-scope-vault-tool grant matrix for Codex, Claude, and existing noninteractive clients | B1.1, B1.2 | im-architect / ACL lane | Codex/gpt-5.6-sol/xhigh | DONE | Canonical catalogue grant matrix and `docs/interactive-mcp-acl.md` use `person:joseph` and `joseph-second-brain` | 2026-08-12 - exactly nine tools, identical Codex/Claude surface, wildcard reads only |
| B1.4 | Specify the atomic provisioner transaction and rollback semantics | B1.3 | im-architect / provisioning lane | Codex/gpt-5.6-sol/xhigh | DONE | Catalogue transaction section; existing fault-injection tests cover every replacement/handoff fault point | 2026-08-12 - live application remains behind G6 and its privileged dry run |
| B2.1 | Independently review local AMF commit `97eb435` for ACL, MCP, document-write, Mem0-cutover, and regression defects | B1.3 | im-reviewer / AMF review | Codex/gpt-5.5/high | DONE | NOT READY: independent review found two blockers — the nine-tool surface is enforced only by the local bridge while Fabric's generic MCP surface remains reachable; and legacy `allowedScopes: ['*']` can still authorize proposals through the operation-grant fallback. | 2026-08-12 - reviewer ran complete `npm test` (1123 pass, 0 fail, 7 skipped); fix server enforcement, legacy migration/rejection, and real-server negatives before re-review |
| B2.2 | Rebase or reconstruct the AMF feature change only onto an approved post-#158 current base | B2.1, B3.3 | im-developer / AMF lane | Codex/gpt-5.6-sol/high | IN_PROGRESS | B2.1 is complete with a NOT READY verdict. Draft `amf-unified-mcp-acl` declares the retained range on post-#158 base `540388a`. `reconcile --apply` stopped before mutation on a Syncwheel `Namespace.in_place` defect; the supported `stack rebuild` and `int rebuild` dry runs provide the bounded plumbing fallback. | 2026-08-12 - include this evidence commit, rebuild the draft with plumbing, then fix both server-authoritative ACL blockers before re-review |
| B2.3 | Add or correct source tests for catalogue-resolved wildcard reads, exact write grants, revoked principals, idempotency, revision conflict, audit, and tombstones | B1.4, B2.2 | im-developer / AMF lane | Codex/gpt-5.6-sol/high | TODO | Focused tests and full `npm test` pass; all test names map to grant-matrix rows | 2026-08-12 - unknown scope/vault and write-wildcard denial are mandatory negative cases |
| B2.4 | Deliver the reviewed AMF source through its approved PR and prove post-merge absorption | B2.3 | im-operator / AMF delivery | Codex/gpt-5.6-terra/high | TODO | Exact PR head, review, CI, merge record, `git merge-base` or `git cherry` proof | 2026-08-12 - G4 controls every push, PR update, and merge |
| B3.1 | Independently review PR #158 at `d30eb100...` and confirm it removes only stale stack metadata | B0.1 | im-reviewer / Syncwheel review | Codex/gpt-5.5/high | DONE | Independent reviewer READY at head `d30eb1001c05ea6c81016b3766e3844523794ce9` over base `959269736f71007bc8b77bf291c740e13f0edba3`; 24 absorbed, 1 squash-absorbed, 1 missing/empty, 0 live PR/worktree impact | 2026-08-12 - PR remains draft until the operator records the merge decision |
| B3.2 | Merge or explicitly retain PR #158 with an exact recorded decision | B3.1 | im-operator / GitHub delivery | Codex/gpt-5.6-terra/high | DONE | Squash-merged at `2026-08-12T16:04:04Z` as `540388a1fbe34447960a07bc3a2ae3dbb9509ed7`; exact reviewed head/base remained `d30eb1001c05ea6c81016b3766e3844523794ce9` / `959269736f71007bc8b77bf291c740e13f0edba3`; remote branch retained | 2026-08-12 - PR #49 was not changed |
| B3.3 | Rebuild AMF `main-integration` from the verified post-#158 `origin/main` using Syncwheel plumbing and validate convergence | B3.2 | im-operator / Syncwheel lane | Codex/gpt-5.6-terra/high | IN_PROGRESS | Recovery ref `refs/recovery/amf-b3-rebuild-input-20260812` -> `8c43065908389f02c97c41accdda07889c046127` retained. Post-#158 dry runs classify the retained feature as a draft stack and propose a separate integration rebuild to `origin/main`. The umbrella `reconcile --apply` has a local Syncwheel `Namespace.in_place` bug before execution, so B3 uses the equivalent supported `stack rebuild` / `int rebuild` plumbing operations. | 2026-08-12 - no guard bypass, worktree/stash/branch deletion, or remote push is in scope |
| B4.1 | Inventory all active Mem0 references and every adapter worktree/stack before rename or recovery | B0.3, B1.3 | im-coordinator / adapter inventory | Codex/gpt-5.6-terra/high | TODO | Path-by-path owner, consumer, active/historical classification, and recovery disposition | 2026-08-12 - adapter primary is `f3f2b11`, ahead 3, with 33 registered worktrees |
| B4.2 | Recover unique adapter intent onto a current-base AMF runtime-adapter lane without reviving obsolete behavior | B4.1 | im-developer / adapter lane | Codex/gpt-5.6-sol/high | TODO | Current-base tests, source review, and named retained recovery refs for ambiguous work | 2026-08-12 - session-identity regressions and MGT-0113 fixes require separate evidence |
| B4.3 | Rename adapter source, package, plugin, runtime IDs, documentation, and client references to `agent-memory-fabric-runtime-adapters` | B4.2, B1.3 | im-developer / adapter lane | Codex/gpt-5.6-sol/high | TODO | Active-source `mem0` scan is empty with documented history exclusions; package and integration tests pass | 2026-08-12 - GitHub repository rename and runtime apply remain G5/G9 actions |
| B4.4 | Deliver the adapter migration and prove its PR is absorbed before any active runtime alias is removed | B4.3 | im-operator / adapter delivery | Codex/gpt-5.6-terra/high | TODO | Exact PR/merge evidence, release source, and rollback-compatible consumer inventory | 2026-08-12 - no alias removal based only on a source scan |
| B5.1 | Recover and reconcile only AMF-relevant private-toolkit work from its dirty `main-integration` checkout | B0.3, B4.4 | im-developer / toolkit lane | Codex/gpt-5.6-sol/high | TODO | AMF-owned diff/PR plus preservation evidence for unrelated dirty manifest residue | 2026-08-12 - toolkit primary is behind 2 and has an unrelated modified manifest |
| B5.2 | Migrate Fleet source profiles, Agentwheel declarations, and MCP client provisioning to the single `amf` contract | B4.4, B5.1 | im-developer / Fleet lane | Codex/gpt-5.6-sol/high | TODO | Source-owned configuration diff, graph-lock regeneration, and affected-profile test evidence | 2026-08-12 - do not hand-edit generated runtime homes or graph locks |
| B5.3 | Reconcile this AMF work with the separate Fleet/Agentwheel single-checkout program before changing dirty Fleet state | B5.2 | im-coordinator / cross-program | Codex/gpt-5.6-terra/high | TODO | Shared dependency record and non-overlapping file ownership; no worktree is moved twice | 2026-08-12 - Fleet primary is behind 4, dirty, and has 68 registered worktrees |
| B5.4 | Produce intended-only Agentwheel dry runs for every affected profile and root `all` | B5.2, B5.3 | im-reviewer / Fleet review | Codex/gpt-5.5/high | TODO | Zero unexplained creates, updates, removals, drift, or conflicts; per-profile evidence | 2026-08-12 - G9 is required for any install after a fresh repeated dry run |
| B6.1 | Author and review the source-owned health-status credential and rotation runbook | B1.4 | im-documenter / health runbook | Codex/gpt-5.6-luna/medium | TODO | Least-privilege read-only capability, secret-store location, rotation/revocation, and no-repository proof | 2026-08-12 - current health reports unavailable `AMF_RAW_INGEST_TOKEN` |
| B6.2 | Author and review the dead-letter classification, archive, receipt, checksum, and recoverable-replay procedure | B4.2 | im-documenter / health runbook | Codex/gpt-5.6-luna/medium | TODO | Versioned procedure with exact source/target, aggregate and per-object checksums, and rollback/retention rules | 2026-08-12 - do not decrypt or move sealed events during documentation work |
| B6.3 | Apply approved credential and dead-letter procedures and record a non-secret evidence receipt | B6.1, B6.2 | im-operator / AMF operations | Codex/gpt-5.6-terra/high | TODO | G7/G8 approval record, archived classification receipt, active queues at zero, and fresh health JSON | 2026-08-12 - 1,118 Claude events remain historical evidence until approved handling |
| B6.4 | Diagnose and correct any remaining collector health degradation without lowering health semantics | B6.3 | im-architect / health lane | Codex/gpt-5.6-sol/xhigh | TODO | Root cause, source/runtime fix, non-regression tests, and healthy repeated probes | 2026-08-12 - a green timer or service state alone is insufficient |
| B7.1 | Apply the approved Fleet/Agentwheel and AMF service rollout with a named rollback path | B2.4, B5.4, B6.4 | im-operator / rollout | Codex/gpt-5.6-terra/high | TODO | G9 approval, immediately preceding dry run, installed-source inspection, and service-specific status | 2026-08-12 - deploy/reload/restart scope must be named separately |
| B7.2 | Run live principal-specific MCP read/proposal/document write/delete, denial, audit, idempotency, and revision-conflict canaries | B7.1 | im-reviewer / live verification | Codex/gpt-5.5/high | TODO | G10 approval; redacted transcript, audit IDs, tombstone proof, and no data beyond named canary records | 2026-08-12 - Codex and Claude must demonstrate the same allowed surface and the same denials |
| B7.3 | Verify all active clients no longer use Mem0 aliases and all approved companion migrations are live | B7.2 | im-reviewer / client verification | Codex/gpt-5.5/high | TODO | Runtime config inspection, client canaries, and active-reference scan with narrow historical exclusions | 2026-08-12 - Tirrenia runbook/config owner must be confirmed before a change |
| B8.1 | Perform independent critical-path completion review across source, Git, operational, and live evidence | B3.3, B4.4, B5.4, B6.4, B7.3 | im-reviewer / final review | Codex/gpt-5.5/high | TODO | READY/NOT READY verdict with all critical evidence tied to exact revisions and runtime timestamps | 2026-08-12 - no self-approval by the implementing lane |
| B8.2 | Decide retention or approved removal for legacy clone, worktrees, branches, stashes, and recovery refs | B8.1 | im-operator / cleanup | Codex/gpt-5.6-terra/high | TODO | G11 approval, exact target list, absorption/retention proof, and post-action inventory | 2026-08-12 - `mem0-gateway` remains preserved until consumer migration and proof complete |
| B8.3 | Refresh durable documents, ledger state, decision log, final handoff, and validate this dossier | B8.1, B8.2 | im-documenter / final handoff | Codex/gpt-5.6-luna/medium | TODO | Updated authoritative work item, final evidence index, and passing program-plan validator | 2026-08-12 - mark `MGT-0029` done only after B8.1 and all approved scope is proved |

## Validation matrix

| Requirement | Check | Owner | Result | Evidence |
|---|---|---|---|---|
| Dossier integrity | `python3 /home/administrator/.agents/skills/im-ai-program-plan/scripts/validate_ai_program_plan.py docs/maintenance/ai-program-amf-completion.md` | im-documenter | PENDING | Run immediately after this material B0/B1/B3.1 update |
| AMF baseline | `syncwheel repo tracking status`, `git status --short --branch`, exact `git show`, `git diff --check` | im-coordinator | PASS | `97eb435` clean local AMF baseline captured on 2026-08-12 |
| AMF source behavior | Focused ACL/MCP/document tests and complete `npm test` | im-developer | PASS at pre-plan baseline | Full local suite passed before `97eb435`; repeat on final reviewed head |
| Scope/vault proof | Read-only registry, policy, PAM, and client catalogue comparison | im-architect | PENDING | Must prove canonical IDs; textual source names are insufficient |
| Grant enforcement | Positive and negative tool tests for wildcard-read, exact-write, unknown, revoked, conflict, and audit behavior | im-reviewer | PENDING | Required before source delivery and live rollout |
| Syncwheel convergence | Per-repository `validate`, `status`, `plan`, dry-run reconcile, repeated no-op proof | im-reviewer | PENDING | No unexpected stack recreation, projection drift, or routine worktree |
| PR delivery | Exact SHA, current base, independent review, CI, merge/retention decision, and absorption proof | im-reviewer | PENDING | Required per PR; #49 excluded from this program |
| Active Mem0 retirement | Scan active source/config/runtime declarations, then per-client live verification | im-reviewer | PENDING | History, backups, and dated evidence are recorded exclusions, not false positives |
| Fleet materialization | `agentwheel install --profile all --dry-run` plus named profile dry runs | im-reviewer | PENDING | Zero unexplained drift or conflict immediately before approved install |
| AMF health | Health JSON, collector status, queue count, dead-letter receipt, status token read check | im-reviewer | PENDING | Healthy result must be repeated after approved operations |
| Live authorization | Named-principal MCP canaries for both Codex and Claude, including explicit denials | im-reviewer | PENDING | Requires G10 and redacted audit evidence |
| Completion review | Independent exact-head and live-state review | im-reviewer | PENDING | Required before closing `MGT-0029` or deleting recovery artifacts |

## Decisions

| Date | Decision | Rationale/evidence | Consequences | Owner |
|---|---|---|---|---|
| 2026-08-12 | Use one MCP named `amf` for Codex and Claude | Joseph explicitly requested one MCP with ACL; local AMF source implements one shared tool surface | Client identity is a principal policy concern, not a separate server feature | Joseph / im-architect |
| 2026-08-12 | Fail closed per operation rather than use a shared `allowedScopes` grant | Read access, proposal, and document mutations have different blast radii | Read wildcards require registered-object resolution; writes require exact grants | Joseph / im-architect |
| 2026-08-12 | Preserve proposal-only semantics for `memory_propose`; direct document mutations remain ACL-gated and revisioned | AMF canonical-memory writes and document workspace writes are distinct operations | `document_upsert` and tombstoning delete need audit/idempotency/conflict proof | Joseph / im-architect |
| 2026-08-12 | Treat the exact private vault and full scope catalogue as unresolved until live, read-only proof | Earlier sources contain divergent/historical scope labels and no unambiguous vault identity | No live policy or provisioner update may guess a Joseph vault | im-architect |
| 2026-08-12 | Retire Mem0 as an active identity, not as historical evidence | Joseph requested cutover; sources still contain owner-runbook/runtime aliases | Active paths migrate with rollback evidence; history/backups stay intact | Joseph / im-coordinator |
| 2026-08-12 | Fold the `mem0-gateway` clone into AMF disposition work | Both local checkouts share `git@github.com:NestDevLab/agent-memory-fabric.git` | It is not a fifth product PR; its work remains preserved until G11 | im-coordinator |
| 2026-08-12 | Keep PR #49 out of this program | It is externally authored, unrelated to the MCP/ACL cutover, and currently dirty | It receives its own owner review and no absorption/cleanup inference | Joseph / im-coordinator |
| 2026-08-12 | Use current Syncwheel plumbing only after object-level recovery proof | Legacy manifest replay would recreate stale stacks and may collide with current work | PR #158 and clean integration reconstruction precede feature-stack publication | im-architect |
| 2026-08-12 | Make health truth depend on read-only status access, collector queues, receipt evidence, and canaries | Current timer/service observations cannot establish end-to-end health | Credential, dead-letter handling, and runtime verification remain independent gates | im-architect |
| 2026-08-12 | Start execution from this dossier with staged source delivery and evidence-gated rollout | Joseph approved source work in all four repositories, publication of ready PRs, conditional PR #158 merge, and rollout after preconditions | Dead-letter movement and destructive cleanup retain exact-target gates | Joseph / im-coordinator |
| 2026-08-12 | Use the actual nine-tool MCP surface in execution evidence | Source `INTERACTIVE_MCP_TOOLS` contains nine names; the prior prose count was erroneous | All reviews and canaries use the explicit nine-name list | im-architect |
| 2026-08-12 | Retain `domain:tirrenia` as a separate companion scope and fail closed for `domain:odido` | Live read-only resolution proved the first is registered and the second is not | Neither becomes a Codex/Claude MCP proposal or write grant | im-architect |
| 2026-08-12 | Let Syncwheel capture the two retained AMF integration commits before it rebuilds the projection | The post-#158 dry run refused to align an integration checkout containing unmapped commits and prescribed declared-stack capture | No reset is used; B2 review completes before the captured stack is promoted or published | im-operator |
| 2026-08-12 | Block publication of `97eb435` pending server-authoritative ACL fixes | Independent B2.1 review found reachable generic MCP tools and a legacy proposal wildcard fallback | The feature is retained in a draft stack; no PR is created until a re-review is READY | im-reviewer |

## Risks and blockers

| ID | Risk/blocker | Impact | Owner | Resume/mitigation condition | Next safe action |
|---|---|---|---|---|---|
| R1 | The canonical scope/vault catalogue may diverge between server registry, policies, PAM, and client configuration | A wrong grant can disclose or mutate another tenant's data | im-architect | One catalogue reconciles every active authority or differences have approved owners | Run the read-only catalogue inventory in B1.1 |
| R2 | The current 1,118 sealed Claude dead letters cannot be safely classified by filename alone | Premature movement could lose evidence or mask a recoverable failure | im-documenter | Approved procedure defines receipts, checksums, retention, and recovery eligibility | Complete B6.2 before requesting G8 |
| R3 | Legacy Syncwheel metadata can recreate stale branches or conflict with current work | Recovery could regress source or multiply worktrees | im-operator | Each stack has an object-level disposition and PR #158 has an exact reviewed decision | Complete B0.3 and B3.1 |
| R4 | Adapter, toolkit, and Fleet primary checkouts contain concurrent or dirty state | A broad cleanup or manifest replay can lose unrelated work | im-coordinator | File ownership and recovery envelopes separate AMF work from foreign residue | Use clean administrative lanes only after G2 |
| R5 | Active Mem0 aliases exist outside the product repository, including a Tirrenia client configuration | Source-only cutover would leave an operational split brain | im-coordinator | Owner, live target, replacement configuration, rollback, and canary are verified | Inventory companion references in B4.1 and B7.3 |
| R6 | The current source commit has not yet received independent review or Git delivery | Local tests alone do not prove correct, current, or release-ready behavior | im-reviewer | Exact-head review and current-base reconstruction succeed | Perform B2.1 before any push/update request |
| R7 | Secret access and deployment may be unavailable to the source implementation lane | Completion could be incorrectly claimed from source-only evidence | Joseph / AMF operator | G7/G9 identify a credential owner, target, and rollback | Prepare source runbooks and request the exact operation only when ready |
| R8 | GitHub repository rename and active runtime identity rename have redirect and consumer effects | Clients may break if source, Fleet, package, and runtime are changed out of order | im-architect | Consumer inventory and compatible migration order are reviewed | Complete B4.1 and B4.3 before G5 |
| R9 | The local bridge's nine-tool contract is bypassable through Fabric's generic MCP endpoint, and legacy wildcard proposal authorization survives | A bearer could reach tools or proposal scopes outside the documented MCP contract | im-developer / AMF lane | Server-side allowlisting and legacy wildcard migration/rejection are implemented and independently re-reviewed | Do not publish `97eb435`; reconstruct the retained draft stack and add real-server negatives |
| R10 | The installed Syncwheel `reconcile --apply` dereferences an absent `Namespace.in_place` property | The umbrella reconcile cannot execute this checkout's otherwise valid dry-run plan | im-operator | Use the verified `stack rebuild` and `int rebuild` plumbing operations; report the tool defect separately from AMF source correctness | Do not retry the broken umbrella command or substitute manual Git recovery |

## Handoff snapshot

- As of: 2026-08-12T16:05:00+00:00
- Authoritative item state: `MGT-0029` is `in-progress`; its append-only log records this program.
- Revisions and dirty residue: AMF `main-integration` is at local `97eb435` with this uncommitted execution documentation; adapter `main` is `f3f2b11` with 33 clean worktrees; toolkit has 31 worktrees / 4 dirty; Fleet has 70 worktrees / 22 dirty and its own G1 envelope; legacy `mem0-gateway` has 10 worktrees / 5 dirty.
- Completed evidence: B0.1-B0.3, B1.1-B1.4, and B3.1; PR #158 is draft/clean at `d30eb100...` with independent READY; PR #49 is open/dirty and excluded; health is degraded only by the retained Claude dead letters.
- In progress: None.
- Blocked: None in the checklist; G8 dead-letter movement and G11 destructive cleanup remain intentionally open until exact targets exist.
- Open decisions/gates: G5 repository rename, G8 dead-letter target, G11 cleanup target list, and every feature-PR merge after independent review.
- Next safe action: Commit this B2.2 transition, declare the retained commit range in the existing draft stack, dry-run its plumbing reconstruction, and apply only the reviewed plan.
