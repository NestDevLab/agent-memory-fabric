# AMF Completion Recovery Inventory — 2026-08-12

Status: classified; retain-only. This is not an authorization to move, remove,
reset, switch, reconcile, or replay any checkout. Those actions remain limited
to the exact B3 target recorded in the completion program, and destructive
cleanup remains G11.

## Read-only snapshot

The snapshot was taken on 2026-08-12 with `git worktree list --porcelain`,
per-worktree `git status --porcelain`, `git stash list`, and `git for-each-ref`
over `refs/recovery`, `refs/heads/recovery`, and `refs/heads/backup`.

| Repository | Worktrees | Dirty worktrees | Stashes | Recovery / backup refs | Syncwheel stack records | Disposition |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `agent-memory-fabric` | 3 | 3 | 4 | 2 | 26 | Retain source commit `97eb435`, the two named backup refs, all stashes, and both secondary worktrees. B3 settles only stale manifest records; it does not clean a worktree. |
| `mem0-scoped-agent-plugin` | 33 | 0 | 0 | 0 | 14 | Retain all branches/worktrees unchanged. Capture a dedicated recovery envelope immediately before any B4 transformation; no unique work is classified as disposable. |
| `agent-core-toolkit-private` | 31 | 4 | 1 | 5 | 9 | Foreign dirty state. Retain and leave it to its owning lane until B5 identifies AMF-owned paths. |
| `fleet-control` | 70 | 22 | 0 | 209 | 7 | Covered by the existing G1 lossless envelope; do not duplicate, move, or replay its captured worktrees. |
| `mem0-gateway` | 10 | 5 | 0 | 5 | 21 | Legacy clone of the AMF remote. Retain in place until B8 receives a G11 target list and absorption proof. |

The count is evidence for this snapshot, not a deletion target. `git worktree
list --porcelain` and the repository manifest remain the per-object source for
each branch/path/HEAD; the exact Fleet and Agentwheel object ledger is already
captured in Fleet's `docs/maintenance/syncwheel-single-checkout-g1-recovery-envelope.md`.

## AMF-specific recovery anchors

| Object | Evidence | Disposition |
| --- | --- | --- |
| Feature implementation | `backup/amf-unified-mcp-acl-97eb435` -> `97eb4350cd78e91bdb047c395cb0b62c4033dbe2` | Preserve before and after reconstruction. |
| Pre-relocation base | `backup/amf-unified-mcp-acl-pre-relocation-20260812` -> `959269736f71007bc8b77bf291c740e13f0edba3` | Preserve as the independently comparable pre-feature base. |
| Legacy desks | `pr/error-causes` at `76cd2ac` and `pr/scope-prefix-grants` at `7948bfa` | Both are patch-equivalent to `origin/main`; retain until B8, do not recreate or remove now. |
| Legacy manifest | 26 records; PR #158 removes them without touching source or worktrees | Merge/rebuild only after the exact-head review; never run `reconcile --apply` against the stale manifest. |

## Recovery rule for the next mutation

Before a checkout is transformed, the operator must append that checkout's
path, branch, HEAD, upstream, dirty digest, recovery ref, owner, and intended
operation to this inventory or its owning recovery envelope. If that record is
missing, stop. No current clean state authorizes disposal.
