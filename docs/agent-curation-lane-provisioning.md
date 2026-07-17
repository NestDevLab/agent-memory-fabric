# Agent curation lane provisioning

Provisions a parallel bounded curation lane for one agent scope (default
`agent:vitae`), so autobiographical self-fact proposals queued by that agent
converge into canonical records without touching the existing bounded room
lane.

Design rules the provisioning enforces:

- One fabric curator actor per lane (`service:memory-curator-<lane>`), scoped
  to exactly the lane scope. Each lane's drain only ever sees its own
  proposals, so the room lane's bounded-scope invariant is preserved.
- The fabric applicator actor (`service:memory-applicator`) is shared; the
  lane scope is appended to its `allowedScopes`. Apply receipts are keyed by
  decision id, and each tick converges only decisions whose
  `fabricProposalScope` matches its own lane.
- PAM workspace policy is extended additively: `agent` joins
  `amfCurator.autoScopes`, `private` joins `amfCurator.autoVisibilities`, and a
  new reviewer entry (fresh token digest, lane curator actor id) joins
  `amfCurator.reviewers`. Existing tick scripts assert membership with
  `includes(...)`, so the room lane keeps passing its policy checks.
- Accepted trade-off: `autoScopes` × `autoVisibilities` are flat global
  arrays, so the extension also auto-promotes room-scoped `private` proposals
  and agent-scoped `shared` proposals (previously review-required). This is
  acceptable here because every proposing actor is scope-constrained in the
  auth registry, the confidence floor (0.98) and `rejectOnWarnings` still
  apply, and no current producer emits those combinations. Revisit if the
  policy model gains per-scope visibility pairs.
- Bind-mounted files (auth registry, PAM workspace config) are rewritten in
  place through an open file handle. Replacing them by rename would detach the
  running container from the updated inode.
- Fresh secrets per lane: fabric curator token, PAM reviewer token, PAM
  curator ledger key. The PAM applicator token, applicator state key and
  fabric applicator token file are reused from the reference worker env, since
  the lane shares the workspace applicator identity.
- The generated tick script mirrors the production room tick: bounded drain
  (limit 10, one page), policy and git-alignment assertions before any
  mutation, apply → fabric receipt → git delivery convergence, and a private
  last-tick summary.

## Usage

Run as root on the fabric host. Preconditions: `<curation-root>/secrets/`
exists (the tool refuses to run without it), and `--service-owner-uid/gid`
must be the uid/gid of `--service-user` (default `stt`) — the generated unit
runs as that user and its 0600 env/secret files are chowned to that uid/gid.

```sh
node scripts/amf-provision-agent-curation-lane.mjs \
  --auth-registry /opt/agent-memory-fabric/runtime/secrets/auth-registry.json \
  --reference-worker-env /opt/agent-memory-fabric/runtime/curation/worker.env \
  --curation-root /opt/agent-memory-fabric/runtime/curation \
  --backup-root /opt/agent-memory-fabric/runtime/curation/backups \
  --service-owner-uid <uid of stt> --service-owner-gid <gid of stt> \
  --dry-run
```

Review the dry-run report, then re-run without `--dry-run`. The PAM workspace
config path and the git workspace root are taken from the reference worker env
(`PAM_WORKSPACE_CONFIG`, `PAM_GIT_WRITER_REPO_ROOT`) — the config the workers
actually load, never a staging copy; passing `--pam-config` or
`--workspace-root` explicitly is allowed only when it matches the env value.
If any step fails after the live files were touched, both are restored from
the pristine in-memory copies, generated lane artifacts are removed, and the
error (`lane_provisioning_rolled_back`) carries the backup paths.

Afterwards:

```sh
systemctl daemon-reload
systemctl start amf-curation-<lane>.service   # one supervised tick
systemctl enable --now amf-curation-<lane>.timer
```

Verify the first tick summary in `<curation-root>/state-<lane>/last-tick.json`
and the new canonical records in the workspace record index.

## Rollback

Stop the lane timer and service, restore the two backups written by the
provisioning run (auth registry and PAM workspace config — copy contents back
in place, do not rename over the bind-mounted files), and remove the generated
lane files (secrets, worker env, tick script, state dir, units). The shared
room lane is untouched throughout.
