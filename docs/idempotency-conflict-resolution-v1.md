# Idempotency and conflict resolution v1

## Idempotency boundary

An exact retry has the same stable ID and the same full payload digest. It is
idempotent and returns the original accepted record. A received payload with an
existing stable ID but a different full payload digest is an immutable conflict:
the service must never overwrite it, select a silent winner, or auto-resolve it.

## Conflict quarantine and notification

An unresolved conflict is excluded from ordinary recall, extraction, retention
deletion, and canonical promotion. Authorized operators may inspect content-free
metadata: stable IDs, revision, state, timestamps, payload and logical digests,
and audit references. Content remains unavailable through this view.

The service appends a durable outbox notification for each conflict. Delivery
has bounded retries and a dead-letter outcome. A notification is not claimed as
delivered until an explicit acknowledgement is durably recorded; a transport
attempt is not an acknowledgement.

## Manual, append-only resolution

No automatic resolution exists. An authorized operator submits one of these
actions with an expected revision:

| Action | Result |
| --- | --- |
| `accept_existing` | Retains the existing immutable record and rejects the received variant. |
| `accept_received_as_replacement` | Appends the received variant as a replacement; the existing evidence remains. |
| `reject_received` | Retains the existing record and permanently marks the received variant rejected. |

The resolver verifies authorization, expected revision, the conflicting stable
ID, and both digests before appending exactly one deterministic resolution
record. Repeating the same request returns that record; a changed request is a
new conflict rather than a mutation. Resolution records reference preserved
evidence, action, actor scope, expected and resulting revisions, and audit
reference. An audit-store outage fails resolution closed. The original variants,
outbox history, acknowledgement, and resolution record are retained for audit.

## Verification and residual risk

Tests must prove exact retry acceptance, changed-payload conflict creation,
quarantine from every ordinary pipeline, acknowledgement-gated delivery,
revision guarding, idempotent replay, and audit-outage denial. Residual risk is
operator judgement; it is bounded by explicit authorization, immutable evidence,
and append-only audit rather than automated selection.
