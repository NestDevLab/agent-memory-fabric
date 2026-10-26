# Host administration installation

The host administrator is a permanent local product installed from its source repository. It is independent of agent harnesses, profiles and skills. The installer prepares a user systemd service but never invokes systemctl, enables a unit, restarts a process or opens a network connection.

Requires Linux with `/proc/self/fd`, Git and Node.js 24 or newer. The runtime needs only Node built-ins. Configuration, policy, runtime state and plans belong in private operator storage; the source repository contains only generic implementation and templates.

## Trusted private inputs

Provide a nonsecret JSON configuration accepted by `validateHostAdminConfig` and a catalog policy with schema `amf.host-file-catalog-policy/v1`. Explicit source files may have mode 0644, must be owned by the installing user, must not be group/world writable or symlinks, and must be at most 1 MiB. Symlink ancestors and special files are rejected. Never place the bearer token value in either source file.

Configuration must bind to `127.0.0.1`. Its `policyPath` must equal `<runtimeRoot>/catalog-policy.json`, its `databasePath` must be strictly inside `<runtimeRoot>/database/`, and its `tokenFile` must be strictly inside `runtimeRoot`, outside managed release/database/configuration/manifest paths. A token path such as `<runtimeRoot>/auth/bearer.token` is suitable. Optional policy `metadataOnlyDirectoryNames` accepts safe single directory names (for example `node_modules` or `.git`) and preserves complete metadata traversal while disabling content reads beneath matching components. Add the entire runtime root to the private catalog policy's `excludePrefixes` to avoid inventorying the administrator's own state.

The runtime root and managed runtime subdirectories must be owned by the current user and private (0700). An existing unit directory may be owner-held 0755, but must not be group/world writable; its mode is preserved. Missing directories are created with mode 0700 only on apply. The installer never chmods existing directories or overwrites unowned targets.

## Plan, review and apply

Use an exact lowercase 40-character Git commit ID:

```sh
node scripts/amf-install-host-admin.mjs \
  --repo /srv/example-source \
  --revision 0123456789abcdef0123456789abcdef01234567 \
  --runtime-root /srv/private-example/host-admin \
  --config-source /srv/private-example/presets/admin-config.json \
  --policy-source /srv/private-example/presets/catalog-policy.json \
  --unit-directory /srv/private-example/user-units
```

The default operation is read-only: it creates no directories, files, tokens or Git refs. Its JSON plan binds the repository and revision, source blob hashes, nonsecret configuration/policy hashes, rendered unit, observed managed target hashes and token metadata (never token bytes or a token hash). Review its changes and retain the `planDigest`.

Repeat the same arguments with `--apply --plan-digest <reviewed-64-character-digest>`. Apply rebuilds the plan, rejects a stale digest and verifies that the revision is an ancestor of the local `refs/remotes/origin/main` **before writing**. Planning a detached revision is allowed; applying one outside that canonical history is refused. The installer does not fetch, and therefore relies on an operator-maintained trustworthy local remote-tracking ref. It does not prove the remote server's current state.

The installer reads these immutable Git blobs, without checkout, filters, dependencies or working-tree bytes:

- `src/host-file-catalog.mjs`
- `src/host-admin-server.mjs`
- `scripts/amf-host-admin.mjs`

They are copied byte-for-byte into `<runtimeRoot>/releases/<revision>/` with mode 0600. The pinned `deploy/systemd/amf-host-admin.service.in` blob is separately validated and rendered into `amf-host-admin.service` in the chosen unit directory. Its ExecStart uses the installer's known `process.execPath`, the fixed revision entry script and `<runtimeRoot>/config.json`. Paths are quoted for systemd, including literal percent signs. The unit uses `Restart=on-failure`, `NoNewPrivileges=true`, `UMask=0077` and the user target `default.target`.

The nonsecret sources are copied to stable `config.json` and `catalog-policy.json` paths. If the token is absent, apply creates 32 random bytes encoded as base64url, using exclusive creation with mode 0600 inside a private parent. Existing safe private token files are preserved without opening or hashing them. Token bytes and token hashes never appear in plans, receipts or errors.

The private `.installation.json` records the installed revision and owned target hashes, including retained previous release files. Managed file drift and unowned existing targets cause refusal, not force replacement or repair. Apply uses same-directory temporary files and atomic renames; token creation uses exclusive creation. It preserves previous releases and performs no deletion, token rotation, dependency installation or activation. An interrupted multi-file installation may leave a partial installation or temporary files; the next plan fails closed on unowned/drifted targets, requiring scoped operator investigation rather than automatic cleanup.

A repeat plan/application of the same revision and inputs is a no-op, preserving token and file timestamps. The JSON receipt reports the intended unit name and `activation: "not-requested"`; it is installation evidence only. Service reload, enable, start, authenticated HTTP proof and browser access are separate authorized operations.

Programmatic exports are `planHostAdminInstall(options)` and `applyHostAdminInstall({...options,planDigest})`, with camel-case options `repo`, `revision`, `runtimeRoot`, `configSource`, `policySource`, `unitDirectory`.

Run the focused, temporary-repository tests with:

```sh
node --test scripts/test-host-admin-install.mjs
```
