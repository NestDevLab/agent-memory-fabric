# Conversation-memory extractor

This is the canonical extractor name.  It reads bounded conversation-v3 views
and can create shared-memory proposals only through the existing Fabric path.
The legacy `raw-memory-extractor` names remain compatibility aliases.

Production execution is explicitly scheduled and is quality-gated:

```text
--quality-eval          bounded aggregate-only sample; no state or proposals
--verify-quality-gate   local report verification only
--scheduled             verify first, then perform one normal tick
--dry-run [--session-id] compatibility read-only inspection
```

There is no bare non-dry-run mode.  `--scheduled` verifies policy, release,
configuration digest, signature, outcome, and report age before reading the
extractor token, creating a directory, fetching Fabric data, or spawning a
model.  Reports contain only fixed aggregate counters/rates and are atomically
written mode 0600.  The policy and HMAC key documents are external; the example
policy is non-normative and must not be treated as a live acceptance decision.

The shipped systemd timer files are templates only.  They are not enabled by
this source change. The deprecated raw-named timer targets the canonical
service, and the two timer names conflict so only one schedule can be active.
The templates use the generic `amf-extractor` service account; an installation
must provision that account and grant it only the documented configuration,
state, model-client, and HMAC-key access. The quality key is separate from the
Fabric token and must not be writable by the service account.
The example release digest is intentionally invalid and must be replaced with
the exact digest of the reviewed release before any evaluation can run.
