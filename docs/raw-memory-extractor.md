# RAW-to-memory extractor

## Purpose and boundary

The extractor turns eligible, completed RAW conversations into a *small* set of
`amf-memory/v1` proposals.  It is not a transcript archive, an incident log,
or a general event processor.  Its only eligible outputs are durable decisions,
preferences, commitments, and reusable conclusions.  Operational events,
failures, counters, deployment state, and metrics are rejected; they belong in
the operational ledger.

The extractor never reads RAW object files or keys.  It runs on CT107, where
Joseph's subscription-authenticated Codex login exists, and reads completed
sessions from the Fabric only through authenticated HTTPS extraction/session
endpoints.  The Fabric performs authorization,
decryption, redaction, auditing, and cursor binding.  Vitae scopes are not
granted to this service.  Extracted records are always
`{type:"shared",id:"shared:global"}` with `visibility:"shared"`.

## Continuous bounded execution

Run one `oneshot` systemd service from a timer on CT107.  The service
uses a non-blocking lock; a missed tick is harmless.  Defaults are deliberately
small and deployment-owned:

| Knob | Default | Hard bound | Meaning |
| --- | ---: | ---: | --- |
| `intervalSeconds` | 300 | 60..3600 | One eligible conversation attempt every five minutes. |
| `maxConversationsPerTick` | 1 | 1..3 | No batch catch-up. |
| `dailyInputTokens` | 20,000 | 1,000..100,000 | Audited Codex input-token ceiling. |
| `dailyOutputTokens` | 4,000 | 256..20,000 | Audited Codex output-token ceiling. |
| `maxInputTokensPerConversation` | 2,500 | 512..8,000 | Strict upper bound for extractor-controlled model input. |
| `maxOutputTokensPerConversation` | 350 | 64..1,000 | Schema-bounded claim output target. |
| `planMinRemainingPercent` | 25 | 1..100 | Pause before stage 2 when less than this subscription-plan percentage remains. |
| `maxClaimsPerConversation` | 2 | 1..3 | A conversation rarely creates more than one durable memory. |

Before every stage-2 invocation, the service asks the local subscription-authenticated
Codex app-server for `account/rateLimits/read`.  It examines every active primary
and secondary rate-limit window: a reported limit, or fewer than 25% remaining,
pauses the extractor without moving its cursor until a later probe reports enough
capacity.  If the probe fails or has no usable windows, it fails closed and pauses.
The result records the checked time, minimum remaining percentage and reset time,
but never an account token or reset-credit identifier.

The model call is `codex exec --ephemeral --ignore-user-config --ignore-rules
--json --skip-git-repo-check -m gpt-5.6-luna -c model_reasoning_effort="none"
-s read-only --output-schema ... --output-last-message ... -`.  It is a one-shot
headless execution, not an interactive TUI and does not persist a Codex session.
The output schema permits only zero to two bounded claims.  A hard timeout kills
the child process.

The transcript bound is not character slicing.  The fixed instruction, JSON output
schema, and a conservative 512-byte Codex transport envelope are counted in UTF-8
bytes, then the remaining transcript is clipped only at a UTF-8 boundary. UTF-8
bytes are a conservative upper bound on tokenizer tokens, so extractor-controlled
input never exceeds `maxInputTokensPerConversation`. Codex's private product/system
context is not estimable by the extractor; after the run, its JSONL
`turn.completed.usage` values are recorded exactly. Settlement never clamps actual
input or output usage to the reservation: if Codex reports more than reserved, the
ledger records more than reserved and the next reservation is rejected.

## Newest-first resumable cursor

The state file is private, atomic JSON:

```json
{
  "schema": "amf.raw-memory-extractor-state/v1",
  "stream": "shared:global",
  "phase": "newest-first",
  "cursor": "signed-newest-first-cursor",
  "inFlight": null,
  "days": {"2026-07-20": {"reservedInputTokens": 0, "reservedOutputTokens": 0, "usedInputTokens": 0, "usedOutputTokens": 0}},
  "version": 1
}
```

The server returns a signed newest-first keyset cursor.  The extractor first
persists `inFlight` with the session id and deterministic claim fingerprints,
then proposes with a deterministic idempotency key.  On restart it repeats that
same proposal and observes the Fabric duplicate acknowledgement before moving
the cursor.  A no-memory result also advances only after its triage/extraction
outcome has been persisted.  Once the present-day scan reaches its configured
history boundary, the same keyset ordering continues backward; it never swaps
to an unordered batch scan.

## Two-stage funnel

1. Free triage receives only bounded redacted user/assistant text.  It rejects
   empty, tool-only, short, operational, error/metric, and no-signal sessions.
   It passes a session only when durable-language heuristics find a decision,
   preference, commitment, or reusable conclusion.  A configured local Ollama
   classifier may make this pass stricter, but is advisory and may not promote a
   heuristic rejection.
2. Only survivors go to subscription-authenticated `gpt-5.6-luna` through
   headless Codex, with a JSON-only instruction to emit
   zero to two short claims or an empty list.  The prompt prohibits operational
   events, failures, metrics, secrets, personal/relationship claims, invented
   facts, and transcript summaries.  Empty output is success and is expected to
   be the dominant outcome.

## Record, deduplication, and activation

Each accepted claim is a complete `amf-memory/v1` record: shared/global scope,
shared visibility, plain claim text, bounded `decision`, `preference`,
`instruction` (commitment), or `summary` (reusable conclusion) claim type, a
confidence score with `basis:"inferred"`, and provenance bound to the source
session plus the decrypted transcript digest.

Before submission, comparison normalizes plaintext claim content and compares
it against authorized canonical record content returned by the Fabric/PAM
read path.  It never compares encrypted object bytes or ciphertext content ids.
The deterministic proposal idempotency key additionally binds extractor version,
session id and normalized plaintext claim digest, making retries safe even
across RAW key rotation.

The only write is the existing `POST /v2/memory/proposals` propose path.  The
existing authenticated curator and receipt applicator consume that proposal and
perform plaintext canonical deduplication before applying it.  The extractor
does not write PAM files, invoke a direct canonical writer, or create a third
write path.  Its dedicated shared/global curation lane uses the existing
automatic decision/apply receipt flow; lifecycle edits and supersessions remain
out of scope.

## Rollout

Source ships with the systemd unit/template disabled.  A live `--dry-run` reads
only a handful of newest sessions, emits redacted sample candidates and token
usage, writes no proposal, and does not move the production cursor.  Enabling
the credential, curation lane, service marker, or timer requires a separate
approval after that quality sample.

The deployment-owned extractor credential is a scoped
`service:raw-extractor` row with exactly `raw:extract`, `memory:search`,
`memory:propose`, `memory:status`, and `purpose:memory_curation`; its only
allowed scope is `shared:global`, and its `sessionOwnerActors` list is the
explicit captured-actor allowlist.  It must not receive `raw:decrypt`,
`raw:ingest`, wildcard scopes, or an interactive context-signing key.
