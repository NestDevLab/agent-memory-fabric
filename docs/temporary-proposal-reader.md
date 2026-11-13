# Temporary proposal reader

The auth registry supports `proposal_read_only_scoped` for time-bounded review
of encrypted proposal payloads through the existing curation REST endpoints.
Provisioning a live credential requires separate operator authorization.

A synthetic registry row has this shape. Replace the digest, actor, explicit
registered scopes, and deadline through the approved credential procedure.
`expiresAt` must be a canonical UTC ISO timestamp with milliseconds.

```json
{
  "tokenSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "active": true,
  "actor": "service:temporary-proposal-reader",
  "mode": "proposal_read_only_scoped",
  "allowedScopes": ["domain:example"],
  "permissions": ["memory:proposal-read"],
  "expiresAt": "2030-01-01T12:00:00.000Z"
}
```

| Request | Result while active |
| --- | --- |
| `GET /v2/internal/curation/proposals` | Scoped lifecycle listing and cursor |
| `GET /v2/internal/curation/proposals/:id` | Scoped payload and digest, with required decrypt audit |
| Other authenticated routes and methods | HTTP 403 |
| Requests at or after `expiresAt` | HTTP 401 |

The registry rejects missing or malformed deadlines, wildcard scopes, additional
permissions, and operation-specific, session, vault, context or tool grants for
this mode. Authentication checks expiry on each request and session
revalidation, independently of registry cache lifetime. Existing curator actors
retain their current permissions. Proposal reads retain scope enforcement,
audit requirements, and `no-store` responses. Reading writes the normal audit
trail. Decision receipts, application receipts, reconciliation, proposals,
canonical memory, RAW sessions, document writes and permission management are
outside the temporary reader's route allowlist.

## Validate source

```sh
node --test scripts/test-auth-registry.mjs scripts/test-fabric-server.mjs
npm test
npm run check
```

## Approved deployment and code rollback

Follow [the release deployment procedure](deployment-procedure.md) for the
approved target, transfer, private temporary directory and configuration backup
preconditions. These commands use the shipped source installer. They require
separate runtime authorization and do not provision credentials.

Prepare each archive from an exact reviewed revision in the source checkout.

```sh
git archive --format=tar --output="${APPROVED_TEMP_DIR:?}/reader-release.tar" "${APPROVED_RELEASE_REVISION:?}"
git archive --format=tar --output="$APPROVED_TEMP_DIR/reader-rollback.tar" "${APPROVED_PREVIOUS_REVISION:?}"
scp deploy/amf-install-release.mjs "${APPROVED_DEPLOY_TARGET:?}:${APPROVED_REMOTE_TEMP_DIR:?}/amf-install-release.mjs"
scp "$APPROVED_TEMP_DIR/reader-release.tar" "$APPROVED_TEMP_DIR/reader-rollback.tar" "$APPROVED_DEPLOY_TARGET:$APPROVED_REMOTE_TEMP_DIR/"
```

On the approved target, dry-run and then install the release.

```sh
node "${APPROVED_REMOTE_TEMP_DIR:?}/amf-install-release.mjs" --dry-run \
  --archive "$APPROVED_REMOTE_TEMP_DIR/reader-release.tar" \
  --release-root "${APPROVED_RELEASE_ROOT:?}" --backup-root "${APPROVED_BACKUP_ROOT:?}" \
  --revision "${APPROVED_RELEASE_REVISION:?}"
node "$APPROVED_REMOTE_TEMP_DIR/amf-install-release.mjs" \
  --archive "$APPROVED_REMOTE_TEMP_DIR/reader-release.tar" \
  --release-root "$APPROVED_RELEASE_ROOT" --backup-root "$APPROVED_BACKUP_ROOT" \
  --revision "$APPROVED_RELEASE_REVISION"
```

Code rollback follows the same installer path with the prior revision.

```sh
node "${APPROVED_REMOTE_TEMP_DIR:?}/amf-install-release.mjs" --dry-run \
  --archive "$APPROVED_REMOTE_TEMP_DIR/reader-rollback.tar" \
  --release-root "${APPROVED_RELEASE_ROOT:?}" --backup-root "${APPROVED_BACKUP_ROOT:?}" \
  --revision "${APPROVED_PREVIOUS_REVISION:?}"
node "$APPROVED_REMOTE_TEMP_DIR/amf-install-release.mjs" \
  --archive "$APPROVED_REMOTE_TEMP_DIR/reader-rollback.tar" \
  --release-root "$APPROVED_RELEASE_ROOT" --backup-root "$APPROVED_BACKUP_ROOT" \
  --revision "$APPROVED_PREVIOUS_REVISION"
```

Stop on installer failure. The release-specific image rebuild, controlled
container recreation and deployment-mode guard remain required under the
approved environment runbook, as documented by the release procedure. The
repository's Compose example is a legacy local/shadow reference. Obtain those
environment-specific commands before a production deployment.

Before code rollback, deactivate temporary reader rows through the approved
registry procedure. Older source versions reject the new mode. Preserve all
proposal, catalog, audit and runtime data during rollback. Revocation during
normal operation uses `active: false` or the mandatory deadline, and is observed
on the next authenticated request.
