# Curation rollout and rollback

The Fabric container reads the canonical PAM workspace at
`/srv/brain-shared` and the single record index at
`/srv/brain-shared/memory/amf/record-index.json`. Do not mount a second index
file. The workspace remains read-only inside Fabric; only the PAM applicator
updates the host workspace.

## Rollout

1. Back up the current auth registry, policy, PAM workspace, record index,
   catalog, curator/applicator state, and outboxes.
2. Provision separate curator/applicator actors and owner-only token files.
3. Mount the dedicated routing-tag key ring read-only and set
   `AMF_PAM_ROUTING_KEY_RING_PATH`. The key ring is mandatory. Canonical indexes
   use `contextRefs`; precomputed `contextTags` are rejected. The temporary
   `AMF_PAM_ALLOW_LEGACY_CONTEXT_TAGS_SHADOW=true` escape hatch is shadow-only,
   must never be used for promotion rollout, and should be removed after index
   conversion.
4. Start with metadata poll and one exact read. Run PAM intake without receipt
   dispatch, then replay the decision outbox.
5. Apply one synthetic sealed room record. Verify the index hot reload, exact
   context-token match, apply receipt, and `promoted` Fabric status.
6. Increase worker page size/page count only after audit and queue counts agree.

Decision and apply receipts include `proposalScope` in their authenticated
digest. The REST handler resolves the actor's current ACL before proposal
decryption; denied and missing proposals both return `memory_not_found`.
Curation also checks proposal lifecycle from safe catalog metadata before RAW
decryption and repeats the terminal-state check inside the catalog transaction.
A new decision can never move a `rejected` or `revoked` proposal back to review;
only an already-persisted byte-identical decision receipt may replay as a
duplicate, without decrypting the proposal.
Curation page cursors carry a server-side HMAC and become invalid after process
restart. Restart pagination from the first page instead of persisting cursors.

All mounted JSON/key/config files are regular owner-owned mode-`0600` files.
Their parent directories must be owned by the service user and not writable by
group or others; reads use a no-follow parent dirfd rather than a check-then-open
path.

## Rollback

Stop curator intake and applicator dispatch first. Preserve all outboxes and
canonical records. Restore the pre-rollout auth/policy and record-index snapshot,
then recreate only the Fabric container; do not rewrite the catalog or delete
receipts. If PAM apply completed but receipt delivery did not, keep the new
record/index and replay the authenticated apply outbox after recovery.
