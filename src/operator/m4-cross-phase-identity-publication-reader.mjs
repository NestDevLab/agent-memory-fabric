import crypto from 'node:crypto';
import fs from 'node:fs';

import { canonicalJson } from '../ingest/transcripts/canonical.mjs';
import { verifyM4CrossPhaseIdentityTraversalCompletion } from '../migration/m4-cross-phase-identity-traversal-completion.mjs';
import { verifyM4CrossPhaseIdentityAuthority } from '../migration/m4-cross-phase-identity-registry.mjs';
import { openM4CrossPhaseIdentityPageReader } from './m4-cross-phase-identity-page-store.mjs';
import {
  artifactPath,
  assertPrivateFileIdentity,
  privateFileIdentity,
} from './private-artifacts.mjs';

const ID = /^[a-z][a-z0-9-]{2,79}$/;
const PUBLICATION_ERROR =
  'm4_cross_phase_identity_publication_reader_publication_invalid';

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plain(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exact(value, keys) {
  return (
    plain(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function copy(value, code) {
  try {
    return structuredClone(value);
  } catch {
    fail(code);
  }
}

function rootJson(target) {
  let identity;
  try {
    identity = privateFileIdentity(target, {
      code: PUBLICATION_ERROR,
      maxBytes: 8 * 1024 * 1024,
    });
    const before = fs.fstatSync(identity.descriptor, { bigint: true });
    if (before.nlink !== 1n) fail(PUBLICATION_ERROR);
    const value = JSON.parse(fs.readFileSync(identity.descriptor, 'utf8'));
    assertPrivateFileIdentity(identity, PUBLICATION_ERROR);
    const after = fs.fstatSync(identity.descriptor, { bigint: true });
    if (after.nlink !== 1n) fail(PUBLICATION_ERROR);
    return value;
  } catch (error) {
    if (error?.code === PUBLICATION_ERROR) throw error;
    fail(PUBLICATION_ERROR);
  } finally {
    if (identity !== undefined) fs.closeSync(identity.descriptor);
  }
}

export function createM4CrossPhaseIdentityPublicationReader(input = {}) {
  const inputError = 'm4_cross_phase_identity_publication_reader_input_invalid';
  const safe = copy(input, inputError);
  if (
    !exact(safe, [
      'artifactRoot',
      'manifestId',
      'revision',
      'traversalCompletionKeyDocument',
      'registrySecret',
    ]) ||
    !ID.test(safe.manifestId) ||
    !Number.isSafeInteger(safe.revision) ||
    safe.revision < 1 ||
    !(safe.registrySecret instanceof Uint8Array) ||
    safe.registrySecret.byteLength !== 32
  ) {
    fail(inputError);
  }
  const secret = Buffer.from(safe.registrySecret);
  let pages = null;
  let closed = false;
  try {
    const target = artifactPath(
      safe.artifactRoot,
      'cross-phase-identity',
      safe.manifestId,
      safe.revision,
    );
    const publication = rootJson(target);
    if (
      !exact(publication, [
        'schema',
        'state',
        'manifestId',
        'revision',
        'traversalCompletion',
        'registry',
      ]) ||
      publication.schema !==
        'amf.m4-cross-phase-identity-publication/v1' ||
      publication.state !== 'published' ||
      publication.manifestId !== safe.manifestId ||
      publication.revision !== safe.revision ||
      !exact(publication.registry, ['authority', 'coverage'])
    ) {
      fail(PUBLICATION_ERROR);
    }
    const completion = verifyM4CrossPhaseIdentityTraversalCompletion(
      publication.traversalCompletion,
      safe.traversalCompletionKeyDocument,
    );
    if (
      completion.manifestId !== safe.manifestId ||
      completion.revision !== safe.revision
    ) {
      fail('m4_cross_phase_identity_publication_reader_binding_invalid');
    }
    const signedAuthority = copy(publication.registry.authority, PUBLICATION_ERROR);
    const authority = verifyM4CrossPhaseIdentityAuthority(signedAuthority, secret);
    const commitment = `hmac-sha256:${crypto
      .createHmac('sha256', secret)
      .update(
        canonicalJson([
          'amf.m4-cross-phase-identity-traversal-completion/v1/registry-key',
          completion.registryKeyId,
        ]),
        'utf8',
      )
      .digest('base64url')}`;
    if (
      authority.coveredThrough !== completion.coveredThrough ||
      canonicalJson(authority.backfillBinding) !==
        canonicalJson(completion.archiveBinding) ||
      completion.registryKeyCommitment !== commitment ||
      !exact(publication.registry.coverage, [
        'acceptedBlockCount',
        'sessionCount',
        'eventCount',
        'pageCount',
      ]) ||
      publication.registry.coverage.acceptedBlockCount !==
        completion.traversalRecord.acceptedGroupCount ||
      publication.registry.coverage.sessionCount !==
        authority.coverage.sessionCount ||
      publication.registry.coverage.eventCount !==
        authority.coverage.eventCount ||
      publication.registry.coverage.pageCount !== authority.pages.length ||
      publication.registry.coverage.acceptedBlockCount !==
        completion.coverage.blockCount ||
      publication.registry.coverage.sessionCount !==
        completion.coverage.sessionCount ||
      publication.registry.coverage.eventCount !==
        completion.coverage.eventCount
    ) {
      fail('m4_cross_phase_identity_publication_reader_binding_invalid');
    }
    if (authority.pages.length > 0) {
      pages = openM4CrossPhaseIdentityPageReader({
        artifactRoot: safe.artifactRoot,
        manifestId: safe.manifestId,
        revision: safe.revision,
      });
    }
    const descriptors = new Map(
      authority.pages.map((item) => [
        item.pageKey,
        { pageKey: item.pageKey, digest: item.digest },
      ]),
    );
    for (const descriptor of descriptors.values()) pages.loadPage(descriptor);
    return Object.freeze({
      authority: signedAuthority,
      loadPage(pageKey) {
        if (closed)
          fail('m4_cross_phase_identity_publication_reader_closed');
        const descriptor = descriptors.get(pageKey);
        if (!descriptor)
          fail('m4_cross_phase_identity_publication_reader_page_unknown');
        return pages.loadPage(descriptor);
      },
      close() {
        if (!closed) {
          closed = true;
          try {
            pages?.close();
          } finally {
            secret.fill(0);
            safe.registrySecret.fill(0);
          }
        }
      },
    });
  } catch (error) {
    secret.fill(0);
    safe.registrySecret.fill(0);
    try {
      pages?.close();
    } catch {}
    if (error?.code?.startsWith?.('m4_cross_phase_identity_')) throw error;
    fail('m4_cross_phase_identity_publication_reader_invalid');
  }
}
