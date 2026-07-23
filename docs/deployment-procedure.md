# Release deployment procedure

Deploy releases with `deploy/amf-install-release.mjs`. The installer updates
tracked source in place and never moves, copies, restores, or deletes persistent
runtime or data trees.

The deployment root contains three classes of content:

| Content | Recovery source | Installer behavior |
|---|---|---|
| Tracked code | Git revision and image rebuild | Replaced in place |
| `.env`, `.env.runtime`, `runtime/` | Small deployment-owned configuration backup | Validated, bounded, preserved in place, and copied to the configuration backup |
| `var/` | Whole-host or infrastructure disaster-recovery backup | Preserved in place; rejected if present in a release archive |

Never rename or recursively copy the deployment root. In particular, never copy
`var/` into a pre-deploy directory or back into a new release directory. The RAW
store can be larger than the available free space, and a partial copy can leave
the live service pointing at a truncated store.

## Public release checklist

- [ ] Confirm the intended source revision and reviewed change scope.
- [ ] Run the relevant contract and fixture suites.
- [ ] Check documentation links and GitHub Mermaid rendering.
- [ ] Scan changed public files for private identifiers, addresses, paths,
  credentials, topology, and non-synthetic examples.
- [ ] Confirm roadmap checkboxes cite accepted source evidence only.
- [ ] Confirm any migration, rollback, recovery, or cleanup action has its own
  approval and evidence gate.
- [ ] Obtain separate approval before deployment, restart, migration, or data cleanup.

## Prepare and validate

Use an exact merged revision and create a Git archive locally. The archive
contains tracked code only. Set every `APPROVED_*` variable from the reviewed
deployment record before running these commands.

```sh
AMF_RELEASE_REVISION="${APPROVED_RELEASE_REVISION:?}"
AMF_RELEASE_ARCHIVE="${APPROVED_TEMP_DIR:?}/amf-release-${AMF_RELEASE_REVISION}.tar"
git archive --format=tar --output="$AMF_RELEASE_ARCHIVE" "$AMF_RELEASE_REVISION"
```

Copy the installer and archive to an owner-private temporary location on the
approved target. Transfer only these two non-secret files:

```sh
AMF_DEPLOY_TARGET="${APPROVED_DEPLOY_TARGET:?}"
scp deploy/amf-install-release.mjs "$AMF_DEPLOY_TARGET:$APPROVED_REMOTE_TEMP_DIR/amf-install-release.mjs"
scp "$AMF_RELEASE_ARCHIVE" "$AMF_DEPLOY_TARGET:$APPROVED_REMOTE_TEMP_DIR/amf-release.tar"
```

Run the dry-run before apply:

```sh
node "$APPROVED_REMOTE_TEMP_DIR/amf-install-release.mjs" \
  --dry-run \
  --archive "$APPROVED_REMOTE_TEMP_DIR/amf-release.tar" \
  --release-root "$APPROVED_RELEASE_ROOT" \
  --backup-root "$APPROVED_BACKUP_ROOT" \
  --revision "$AMF_RELEASE_REVISION"
```

The backup root must already exist as an ordinary, owner-private `0700`
directory outside the release tree. The dry-run fails unless the archive
excludes every persistent path, contains only ordinary single-link files and
directories, provides every required release file, the deployment root has the
expected owner, the configuration snapshot stays within 16 MiB and 4,096 files,
and enough space exists to stage code plus that snapshot. It does not create a
configuration backup or change the live release.

## Install

Run the same command without `--dry-run`. The installer:

1. takes an exclusive deploy lock and stages source in a unique directory
   outside the live release;
2. recursively validates `.env`, `.env.runtime`, and `runtime/`, rejecting
   aliases, special files, or a snapshot above the documented limits;
3. copies that bounded configuration snapshot without following links;
4. publishes tracked source with atomic file replacement without replacing the
   deployment root;
5. removes obsolete code only when it was listed in the previous release
   manifest;
6. rolls every source and manifest change back if any later installation check
   fails;
7. verifies that every persistent root inode, including the application data
   tree, is unchanged;
8. enforces exactly `0711 root:root` on the approved release root.

The JSON result records the configuration backup path, installed file count,
removed stale-file count, preserved data identity, and final root mode. Stop
before building or recreating the container if the installer exits non-zero.

If rollback itself fails, the installer returns `release_rollback_failed`,
preserves the deploy lock, and retains the owner-private same-filesystem staging
directory reported as `recovery_required`. Do not remove the lock or retry.
Inspect and restore the retained source and manifest evidence first, verify the
persistent roots, then clear the lock only through the reviewed recovery
procedure.

After installation, follow the release-specific build/recreate steps, install
the shipped tmpfiles policy, and run the deployment-mode guard described in
[`deployment-mode-invariant.md`](deployment-mode-invariant.md).

## Rollback

Code rollback uses the same installer with a Git archive for the previous
revision, followed by an image rebuild and controlled container recreation. Do
not restore `var/` during a code rollback. Restore a configuration backup only
when the rollback explicitly requires the earlier configuration and after
reviewing the small backup contents and permissions.

Whole-host or infrastructure backups remain the disaster-recovery path for loss
of persistent data. They are not duplicated during a release deployment.
