# Release deployment procedure

Deploy releases with `deploy/amf-install-release.mjs`. The installer updates
tracked source in place and never moves, copies, restores, or deletes the
persistent `runtime/` and `var/` trees.

The deployment root contains three classes of content:

| Content | Recovery source | Installer behavior |
|---|---|---|
| Tracked code | Git revision and image rebuild | Replaced in place |
| `.env`, `.env.runtime`, `runtime/` | Small deployment-owned config backup | Preserved in place and copied to the config backup |
| `var/` | Platform disaster-recovery backup | Preserved in place; rejected if present in a release archive |

Never rename or recursively copy the deployment root. In particular, never
copy `var/` into a pre-deploy directory or back into a new release directory.
The raw store can be larger than the host's remaining free space, and a partial
copy can leave the live service pointing at a truncated store.

## Prepare and validate

Use an exact merged revision and create a Git archive locally. The archive
contains tracked code only.

```sh
AMF_RELEASE_REVISION=<merged-sha>
AMF_RELEASE_ARCHIVE=/tmp/amf-release-${AMF_RELEASE_REVISION}.tar
git archive --format=tar --output="$AMF_RELEASE_ARCHIVE" "$AMF_RELEASE_REVISION"
```

Copy the installer and archive to an owner-private temporary location on the
target. For example, set `AMF_DEPLOY_TARGET` to the approved SSH target and
transfer only these two non-secret files:

```sh
AMF_DEPLOY_TARGET=root@example.internal
scp deploy/amf-install-release.mjs "$AMF_DEPLOY_TARGET:/tmp/amf-install-release.mjs"
scp "$AMF_RELEASE_ARCHIVE" "$AMF_DEPLOY_TARGET:/tmp/amf-release.tar"
```

Run the dry-run before apply:

```sh
node /tmp/amf-install-release.mjs \
  --dry-run \
  --archive /tmp/amf-release.tar \
  --release-root /opt/agent-memory-fabric \
  --backup-root /opt/backups/agent-memory-fabric \
  --revision <merged-sha>
```

The dry-run fails unless the archive excludes every persistent path, required
release files are present, the deployment root is the expected root-owned
directory, and there is enough space to stage code. It does not create a
configuration backup or change the live release.

## Install

Run the same command without `--dry-run`. The installer:

1. takes an exclusive deploy lock and stages source in a unique directory
   outside the live release;
2. backs up only `.env`, `.env.runtime`, and `runtime/`;
3. overlays tracked source without replacing the deployment root;
4. removes obsolete code only when it was listed in the previous release
   manifest;
5. verifies that every persistent root inode, including
   `var/agent-memory-fabric`, are unchanged;
6. enforces exactly `0711 root:root` on `/opt/agent-memory-fabric`.

The JSON result records the config backup path, installed file count, removed
stale-file count, preserved data identity, and final root mode. Stop before
building or recreating the container if the installer exits non-zero.

After installation, follow the release-specific build/recreate steps, install
the shipped tmpfiles policy, and run the deployment-mode guard described in
[`deployment-mode-invariant.md`](deployment-mode-invariant.md).

## Rollback

Code rollback uses the same installer with a Git archive for the previous
revision, followed by an image rebuild and controlled container recreation.
Do not restore `var/` during a code rollback. Restore a configuration backup
only when the rollback explicitly requires the earlier configuration and after
reviewing the small backup contents and permissions.

Whole-host backups remain the disaster-recovery path for loss of the
persistent data store; they are not duplicated during a release deployment.
