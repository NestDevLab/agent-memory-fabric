# M4 route executor v1

The route executor applies the final M4 route change only after verifying the
signed cutover authorization and the independent selector-scope authority at
current UTC. It changes no archive data, policy, source transcript, proposal,
canonical memory, document, or deployment tree.

## Input and planning

`amf.m4-route-executor-input/v1` contains an execution ID and revision,
owner-private paths for the signed evidence and runtime configuration, two
owner-private output roots, and four registered adapter or hook identifiers.
It never accepts command text, command arguments, service names, topology, or
executable paths.

The two output locations are derived rather than caller-selected:

```text
<artifact-root>/m4/route-execution/<execution-id>-r<revision>.json
<backup-root>/m4/route-execution/<execution-id>-r<revision>/
```

Planning is read-only. It verifies both signatures, selector-scope freshness,
the exact runtime configuration bytes, route revisions, path ownership,
permissions, link count, and the selected in-process adapter. The confirmation
digest binds the input bytes and inode identities, root identities, evidence,
route revisions, hook identifiers, and derived locations. The current clock is
checked against the signed validity window but is not included in the digest,
so a confirmed plan remains reproducible during that window.
The authorization and selector-scope authorities must also have distinct key
identities and non-equivalent HMAC key material.

Plans and errors contain no paths, configuration values, keys, connection
details, observations, or topology. Native filesystem failures are normalized
before they cross the operator boundary.

## Deterministic route revisions

The executor parses the runtime configuration as UTF-8 bytes. It requires one
strict, unquoted assignment for each managed key:

```text
AMF_CONVERSATION_READER_MODE
AMF_CONVERSATION_EXTRACTOR_MODE
```

The current values must be `disabled` or `shadow` and `legacy`. The target
values are `active` and `v3`. Only those two value spans are replaced; every
other byte remains unchanged.

The target reader and extractor revisions are derived from the SHA-256 digest
of the exact target bytes. The rollback revision is derived from the exact
original bytes and original modes. These checkpoints must equal the revisions
inside the signed cutover authorization. A private assertion cannot substitute
for this deterministic binding.

## Confirmed execution

Run rebuilds the plan, acquires an exclusive owner-private lock, and then
re-verifies every signed input, inode, byte digest, root, route revision, and
the selector-scope clock window. It creates a new backup directory containing
only:

- the exact original runtime configuration bytes;
- bounded metadata with the backup ID, byte count, and digest.

It then atomically replaces the configuration, invokes the registered
post-commit hook, and invokes the registered readiness hook. The readiness hook
must return a strict pass result.

If either hook fails, the executor atomically restores the exact original
configuration and invokes the registered rollback hook. A successful recovery
writes a `rolled_back` result. Restore or rollback-hook failure writes
`rollback_failed` where possible and retains the exclusive lock. Any error
after configuration mutation also retains the lock, preventing an
unacknowledged retry.

The immutable `amf.m4-route-execution-result/v1` records only content-free
evidence, checkpoint digests, hook states, and a canonical SHA-256 integrity
digest. It does not claim that the subsequent active-route observation passed.

## Adapter boundary and canary order

The public CLI has an empty adapter registry and therefore fails closed. A
private, source-controlled release assembly must inject a fixed in-process
adapter map. The route executor never starts a shell or dynamically imports an
input-selected module.

The existing cutover canary is the pre-cutover candidate or shadow canary. The
complete order is:

```text
shadow canary and rollback drill
  -> signed cutover authorization
  -> confirmed route execution
  -> bounded active-route observation
```

The active-route observation is separate evidence. Destructive cleanup remains
separately authorized and cannot be triggered by this executor.
