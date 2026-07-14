# AMF optional integration framework

Agent Memory Fabric exposes optional, versioned integrations through the
`amf.integration/v1` catalog. An integration remains independently usable; AMF
owns only its host lifecycle, health contract, and connection to the fabric.

The first catalog entry is `obsidian-second-brain`. Agentwheel installs its
`obsidian-memory` skill in supported agent runtimes. AMF optionally installs a
Linux/systemd shadow poller. The poller is disabled after installation and only
becomes scheduled after an explicit, confirmed `enable` operation.

## CLI

An installed package uses the namespaced interface:

```text
amf integrations list
amf integrations describe obsidian-second-brain
amf integrations plan obsidian-second-brain [options]
amf integrations status obsidian-second-brain --instance INSTANCE
amf integrations install|adopt|run|enable|disable|uninstall \
  obsidian-second-brain --plan PLAN --confirm-sha256 SHA256
```

The source-tree equivalent is `node scripts/amf-integrations.mjs COMMAND ...`.
Both forms intentionally use the same implementation.

`plan` validates the vault, resolves the Agentwheel-installed client through a
known source layout without executing it, independently opens its files with
nofollow protections, and verifies them against the pinned release manifest.
It also validates rendered unit bytes and any recognizable legacy deployment. It writes a
deterministic owner-only JSON plan and prints its file SHA-256. The plan never
contains the bearer value. Every mutating command requires that exact file and
SHA-256.

For a new instance, provision the root-owned `0600` token at the secret path
reported by the plan before `install`. `install` atomically installs the pinned
client bytes, environment, wrapper and instance-specific units, then reloads
systemd. It does not create the enable marker or start a timer.

```bash
amf integrations plan obsidian-second-brain \
  --instance example-vault \
  --vault /srv/obsidian/example-vault \
  --vault-id example-vault \
  --actor client:obsidian:example-vault \
  --amf-url https://memory.example.invalid \
  --source-instance example-vault \
  --client-root /opt/agentwheel/skills/obsidian-memory \
  --service-user obsidian-sync \
  --service-group obsidian-sync \
  --interval-sec 600 \
  --jitter-sec 60 \
  --output /root/amf-plans/example-vault.plan.json
```

Legacy PR36 adoption is deliberately privileged even though it is read-only
until the final manifest write. The legacy configuration directory and files
are root-only. Run both `plan` and `adopt` through an approved root shell and
keep the output plan in a root-private directory. Adoption succeeds only when:

- the legacy environment identifies the planned shadow vault;
- wrapper and unit bytes match the pinned legacy hashes;
- exactly one matching instantiated timer exists and is enabled;
- the pinned Obsidian client release is independently byte-verified.

Adoption writes only AMF's installation manifest. It does not read or rotate the
token, alter the environment, wrapper, units, marker, vault or `.amf` state,
start a scan, reload systemd, or create a second timer. A legacy uninstall
removes only that AMF manifest.

## Status and preservation

An absent optional integration reports `health: skipped`. Installed status
verifies artifact parity, the pinned client bytes, timer state, and the real
client `status` result. `healthy: true` requires `mode=shadow` and exactly zero
pending, retrying, and quarantined outbox entries; the client's own `healthy`
flag is not trusted without those queue checks.

`run` performs one service canary without enabling its timer. `disable` removes
the activation marker only after stopping the timer. Managed uninstall removes
AMF-owned executable/configuration/unit/client copies while preserving the
vault, `.amf`, outbox, protected token and server-side actor.

All privileged lifecycle operations require a reviewed plan and explicit
operator approval. Fleet-specific hosts, vaults, actors, endpoints and secret
references belong in private fleet presets, not this public integration.
