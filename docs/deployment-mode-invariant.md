# Deployment-root traversal invariant

`/opt/agent-memory-fabric` must be exactly `0711 root:root`.

The curation units run as `stt`. Their lock files and curation subtree remain
private (`0700 stt:stt`), but `stt` still needs execute/traverse permission on
the deployment root to reach that subtree. `0700 root:root` prevents that
traversal and makes every curation tick fail before its script starts. `0711`
does not grant `stt` directory listing or read access; it grants only the
required traversal permission.

Every deployment must install the shipped tmpfiles policy and run the checked
guard after the release directory has been recreated:

```sh
install -m 0644 deploy/tmpfiles.d/agent-memory-fabric.conf /etc/tmpfiles.d/
systemd-tmpfiles --create /etc/tmpfiles.d/agent-memory-fabric.conf
node /opt/agent-memory-fabric/scripts/amf-verify-deployment-mode.mjs
```

The tmpfiles rule corrects the mode at boot and whenever this deployment step
runs. The guard exits non-zero unless the root is an ordinary `0711 root:root`
directory, so a deploy cannot silently leave curation unable to open its lock.
Keep `.env.runtime` root-only and `runtime/curation` service-owned/private;
this invariant widens neither of those boundaries.
