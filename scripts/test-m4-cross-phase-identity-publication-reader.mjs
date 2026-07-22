import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { fixture as completionFixture, key } from './helpers/m4-traversal-completion-fixtures.mjs';
import {
  createM4CrossPhaseIdentityRegistry,
} from '../src/migration/m4-cross-phase-identity-registry.mjs';
import {
  createM4PausedProjectionIdentityResolverFromPublication,
} from '../src/migration/m4-paused-projection-identity-resolver.mjs';
import { createM4PausedSourceTagAuthority } from '../src/migration/m4-paused-source-tag-authority.mjs';
import {
  deriveM4V3ConversationIdFromLegacySessionId,
  deriveM4V3EventIdFromLegacyEventId,
  deriveM4V3SourceInstanceIdFromLegacySession,
} from '../src/migration/m4-v2-conversation-projector.mjs';
import {
  createM4CrossPhaseIdentityPageStore,
  openM4CrossPhaseIdentityPageReader,
} from '../src/operator/m4-cross-phase-identity-page-store.mjs';
import { createM4CrossPhaseIdentityPublicationReader } from '../src/operator/m4-cross-phase-identity-publication-reader.mjs';
import { writePrivateArtifactIdempotent } from '../src/operator/private-artifacts.mjs';

const registrySecret = Buffer.alloc(32, 6);
const sourceTagSecret = Buffer.alloc(32, 7);
const hex = value => crypto.createHash('sha256').update(value).digest('hex');
const sessionId = `ses_${hex('publication-reader-session')}`;
const eventId = `evt_${hex('publication-reader-event')}`;
const conversationId = deriveM4V3ConversationIdFromLegacySessionId(sessionId);
const sourceTags = [`routing:${hex('publication-reader-route')}`];
const sourceInstanceId = deriveM4V3SourceInstanceIdFromLegacySession(sessionId, sourceTags);
const opaque = value => `hmac-sha256:routing-v1:${hex(value)}`;
const binding = {
  schema: 'amf.m4-paused-projection-binding/v1',
  runtime: 'hermes',
  sourceId: 'primary',
  digest: `sha256:${hex('publication-reader-binding')}`,
};

function temporaryRoot() {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-publication-reader-'));
  fs.chmodSync(value, 0o700);
  return value;
}

function content() {
  return {
    sessions: [{
      legacySessionId: sessionId,
      conversationId,
      conversationKind: 'dm',
      sessionContextTags: {
        conversation: [opaque('conversation')],
        room: [opaque('room')],
      },
    }],
    events: [{
      legacyEventId: eventId,
      legacySessionId: sessionId,
      eventId: deriveM4V3EventIdFromLegacyEventId(eventId),
      conversationId,
      sourceInstanceId,
      sourceTags,
      conversationKind: 'dm',
      authorizationContextTags: {
        sender: [opaque('sender')],
        conversation: [opaque('conversation')],
        room: [opaque('room')],
      },
      role: 'user',
      direction: 'inbound',
      state: 'active',
      revision: 1,
      replacesLegacyEventId: null,
      tombstonesLegacyEventId: null,
      conflictsWithLegacyEventIds: [],
    }],
  };
}

function pausedIdentity() {
  return {
    schema: 'amf.m4-paused-projection-identity/v1',
    binding,
    runtime: binding.runtime,
    sourceId: binding.sourceId,
    sourceKind: binding.runtime,
    observationClass: 'native',
    authoritativeDeletion: false,
    occurredAt: '2026-07-21T00:00:00Z',
    editedAt: null,
    legacy: { sessionId, eventId, priorEventId: null },
    routing: {
      role: 'user',
      direction: 'inbound',
      conversationKind: 'dm',
      authorizationContextTags: content().events[0].authorizationContextTags,
    },
    lifecycle: { change: 'new', nativeRevision: 1 },
  };
}

async function build({
  empty = false,
  completionSecret = registrySecret,
  authoritySecret = registrySecret,
  coveredThrough = '2026-07-22T00:00:00Z',
  authorityCoveredThrough = coveredThrough,
  authorityBinding = null,
  publicationMutation = null,
  writePages = true,
} = {}) {
  const artifactRoot = temporaryRoot();
  const coverage = {
    schema: 'amf.m4-cross-phase-identity-streaming-coverage/v1',
    state: 'open',
    expectedBlockCount: 1,
    blockCount: empty ? 0 : 1,
    sessionCount: empty ? 0 : 1,
    eventCount: empty ? 0 : 1,
  };
  const completion = completionFixture({
    coverage,
    registrySecret: completionSecret,
    groupCount: 1,
    coveredThrough,
  });
  const entries = empty ? { sessions: [], events: [] } : content();
  const registry = createM4CrossPhaseIdentityRegistry({
    coveredThrough: authorityCoveredThrough,
    backfillBinding: authorityBinding ?? completion.traversalCompletion.archiveBinding,
    ...entries,
  }, authoritySecret);
  if (writePages && registry.pages.length > 0) {
    const store = createM4CrossPhaseIdentityPageStore({
      artifactRoot,
      manifestId: completion.traversalCompletion.manifestId,
      revision: completion.traversalCompletion.revision,
    });
    try {
      for (const page of registry.pages) await store.writePage(page);
    } finally {
      store.close();
    }
  }
  const publication = {
    schema: 'amf.m4-cross-phase-identity-publication/v1',
    state: 'published',
    manifestId: completion.traversalCompletion.manifestId,
    revision: completion.traversalCompletion.revision,
    traversalCompletion: completion.traversalCompletion,
    registry: {
      authority: registry.authority,
      coverage: {
        acceptedBlockCount: coverage.blockCount,
        sessionCount: coverage.sessionCount,
        eventCount: coverage.eventCount,
        pageCount: registry.authority.pages.length,
      },
    },
  };
  if (publicationMutation) publicationMutation(publication);
  const publicationPath = writePrivateArtifactIdempotent(
    artifactRoot,
    'cross-phase-identity',
    completion.traversalCompletion.manifestId,
    completion.traversalCompletion.revision,
    publication,
  );
  const sourceTagAuthority = createM4PausedSourceTagAuthority({
    registryAuthority: registry.authority,
    backfillBinding: registry.authority.backfillBinding,
    mappings: [{
      runtime: binding.runtime,
      sourceId: binding.sourceId,
      projectionBindingDigest: binding.digest,
      sourceTags,
    }],
  }, { registrySecret: authoritySecret, sourceTagSecret });
  return {
    artifactRoot,
    publicationPath,
    publication,
    completion,
    registry,
    sourceTagAuthority,
  };
}

function readerInput(value, overrides = {}) {
  return {
    artifactRoot: value.artifactRoot,
    manifestId: value.completion.traversalCompletion.manifestId,
    revision: value.completion.traversalCompletion.revision,
    traversalCompletionKeyDocument: value.completion.completionKeyDocument,
    registrySecret,
    ...overrides,
  };
}

function pageFiles(value) {
  const directory = path.join(
    value.artifactRoot,
    'm4',
    'cross-phase-identity-pages',
    `${value.completion.traversalCompletion.manifestId}-r${value.completion.traversalCompletion.revision}`,
  );
  return { directory, files: fs.readdirSync(directory).map(name => path.join(directory, name)) };
}

test('read-only page reader never creates a missing namespace', () => {
  const artifactRoot = temporaryRoot();
  try {
    assert.throws(() => openM4CrossPhaseIdentityPageReader({
      artifactRoot,
      manifestId: 'reader-fixture',
      revision: 1,
    }), { code: 'm4_cross_phase_identity_page_reader_unsafe' });
    assert.equal(fs.existsSync(path.join(artifactRoot, 'm4')), false);
  } finally {
    fs.rmSync(artifactRoot, { recursive: true, force: true });
  }
});

test('loads every verified page, rejects unknown pages, and closes idempotently', async () => {
  const value = await build();
  const originalSecret = Buffer.from(registrySecret);
  try {
    const reader = createM4CrossPhaseIdentityPublicationReader(readerInput(value));
    for (const descriptor of reader.authority.pages) {
      assert.equal(reader.loadPage(descriptor.pageKey).digest, descriptor.digest);
    }
    assert.throws(() => reader.loadPage('ff-e-9999'), {
      code: 'm4_cross_phase_identity_publication_reader_page_unknown',
    });
    reader.close();
    reader.close();
    assert.throws(() => reader.loadPage(reader.authority.pages[0].pageKey), {
      code: 'm4_cross_phase_identity_publication_reader_closed',
    });
    assert.deepEqual(registrySecret, originalSecret);
  } finally {
    fs.rmSync(value.artifactRoot, { recursive: true, force: true });
  }
});

test('accepts an empty publication without creating or opening a page namespace', async () => {
  const value = await build({ empty: true, writePages: false });
  try {
    const pagesRoot = path.join(value.artifactRoot, 'm4', 'cross-phase-identity-pages');
    assert.equal(fs.existsSync(pagesRoot), false);
    const reader = createM4CrossPhaseIdentityPublicationReader(readerInput(value));
    assert.equal(reader.authority.pages.length, 0);
    assert.equal(fs.existsSync(pagesRoot), false);
    assert.throws(() => reader.loadPage('ff-e-9999'), {
      code: 'm4_cross_phase_identity_publication_reader_page_unknown',
    });
    reader.close();
  } finally {
    fs.rmSync(value.artifactRoot, { recursive: true, force: true });
  }
});

test('rejects wrong completion and registry keys plus a cross-key commitment mismatch', async () => {
  const valid = await build();
  const wrongCommitment = await build({
    completionSecret: Buffer.alloc(32, 8),
    authoritySecret: registrySecret,
  });
  try {
    assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(valid, {
      traversalCompletionKeyDocument: key('traversal-fixture-key', 99),
    })), { code: 'm4_cross_phase_identity_traversal_completion_signature_invalid' });
    assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(valid, {
      registrySecret: Buffer.alloc(32, 9),
    })), { code: 'm4_cross_phase_identity_authority_invalid' });
    assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(wrongCommitment)), {
      code: 'm4_cross_phase_identity_publication_reader_binding_invalid',
    });
  } finally {
    fs.rmSync(valid.artifactRoot, { recursive: true, force: true });
    fs.rmSync(wrongCommitment.artifactRoot, { recursive: true, force: true });
  }
});

test('rejects signed authority and unsigned publication coverage binding drift', async () => {
  const differentBinding = {
    completionDigest: `sha256:${hex('different-completion')}`,
    catalogRevisionDigest: `sha256:${hex('different-catalog')}`,
  };
  const cases = [
    () => build({ authorityCoveredThrough: '2026-07-23T00:00:00Z' }),
    () => build({ authorityBinding: differentBinding }),
    () => build({ publicationMutation: value => { value.registry.coverage.pageCount += 1; } }),
    () => build({ publicationMutation: value => { value.registry.coverage.sessionCount += 1; } }),
    () => build({ publicationMutation: value => { value.manifestId = 'different-manifest'; } }),
  ];
  for (const create of cases) {
    const value = await create();
    try {
      assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(value)), {
        code: value.publication.manifestId === 'different-manifest'
          ? 'm4_cross_phase_identity_publication_reader_publication_invalid'
          : 'm4_cross_phase_identity_publication_reader_binding_invalid',
      });
    } finally {
      fs.rmSync(value.artifactRoot, { recursive: true, force: true });
    }
  }
});

test('rejects missing, corrupt, linked, and permissive page files', async () => {
  const mutations = [
    ({ files }) => fs.unlinkSync(files[0]),
    ({ files }) => fs.writeFileSync(files[0], '{}\n', { mode: 0o600 }),
    ({ files }) => fs.writeFileSync(files[0], fs.readFileSync(files[1])),
    ({ directory, files }) => fs.linkSync(files[0], path.join(directory, 'alias.json')),
    ({ files }) => fs.chmodSync(files[0], 0o640),
    ({ directory, files }) => {
      const replacement = path.join(directory, 'replacement.json');
      fs.renameSync(files[0], replacement);
      fs.symlinkSync(replacement, files[0]);
    },
  ];
  for (const mutate of mutations) {
    const value = await build();
    try {
      mutate(pageFiles(value));
      assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(value)), {
        code: 'm4_cross_phase_identity_page_reader_invalid',
      });
    } finally {
      fs.rmSync(value.artifactRoot, { recursive: true, force: true });
    }
  }
});

test('rejects unsafe page namespaces and publication root files', async () => {
  const pageCases = [
    ({ directory }) => fs.chmodSync(path.dirname(directory), 0o755),
    ({ directory }) => {
      const moved = `${directory}.real`;
      fs.renameSync(directory, moved);
      fs.symlinkSync(moved, directory);
    },
  ];
  for (const mutate of pageCases) {
    const value = await build();
    try {
      mutate(pageFiles(value));
      assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(value)), {
        code: 'm4_cross_phase_identity_page_reader_unsafe',
      });
    } finally {
      fs.rmSync(value.artifactRoot, { recursive: true, force: true });
    }
  }
  const rootCases = [
    value => fs.chmodSync(value.publicationPath, 0o640),
    value => fs.linkSync(value.publicationPath, `${value.publicationPath}.alias`),
    value => {
      const real = `${value.publicationPath}.real`;
      fs.renameSync(value.publicationPath, real);
      fs.symlinkSync(real, value.publicationPath);
    },
  ];
  for (const mutate of rootCases) {
    const value = await build();
    try {
      mutate(value);
      assert.throws(() => createM4CrossPhaseIdentityPublicationReader(readerInput(value)), {
        code: 'm4_cross_phase_identity_publication_reader_publication_invalid',
      });
    } finally {
      fs.rmSync(value.artifactRoot, { recursive: true, force: true });
    }
  }
});

test('publication-backed paused resolver returns content-free identity and stays closed after cache warmup', async () => {
  const value = await build();
  try {
    const priorEventId = `evt_${hex('publication-reader-post-cutoff-prior')}`;
    const nextEventId = `evt_${hex('publication-reader-post-cutoff-next')}`;
    const resolver = createM4PausedProjectionIdentityResolverFromPublication({
      ...readerInput(value),
      sourceTagAuthority: value.sourceTagAuthority,
      sourceTagSecret,
      loadPostCutoffEvent(requestedEventId) {
        assert.equal(requestedEventId, priorEventId);
        return {
          legacyEventId: priorEventId,
          legacySessionId: sessionId,
          eventId: deriveM4V3EventIdFromLegacyEventId(priorEventId),
          conversationId,
          sourceInstanceId,
          sourceTags,
          observedAt: '2026-07-22T00:00:01Z',
        };
      },
    });
    const input = { identity: pausedIdentity(), attestation: binding };
    const resolved = resolver.resolve(input);
    assert.equal(resolved.covered, true);
    assert.equal(resolved.eventId, deriveM4V3EventIdFromLegacyEventId(eventId));
    assert.doesNotMatch(
      JSON.stringify(resolved),
      /visibleText|normalizedPayloadDigest|ciphertext|logicalMessageId/,
    );
    assert.deepEqual(resolver.resolve(input), resolved);
    const postCutoff = pausedIdentity();
    postCutoff.occurredAt = '2026-07-22T00:00:02Z';
    postCutoff.legacy = { sessionId, eventId: nextEventId, priorEventId };
    postCutoff.lifecycle = { change: 'changed', nativeRevision: 2 };
    const postCutoffResolved = resolver.resolve({
      identity: postCutoff,
      attestation: binding,
    });
    assert.equal(postCutoffResolved.covered, false);
    assert.equal(
      postCutoffResolved.priorEventId,
      deriveM4V3EventIdFromLegacyEventId(priorEventId),
    );
    resolver.close();
    resolver.close();
    assert.throws(() => resolver.resolve(input), {
      code: 'm4_paused_projection_identity_resolver_closed',
    });
    assert.throws(() => createM4PausedProjectionIdentityResolverFromPublication({
      ...readerInput(value),
      sourceTagAuthority: value.sourceTagAuthority,
      sourceTagSecret: registrySecret,
      loadPostCutoffEvent: null,
    }), { code: 'm4_paused_projection_identity_resolver_invalid' });
  } finally {
    fs.rmSync(value.artifactRoot, { recursive: true, force: true });
  }
});

test('publication reader snapshots hostile input getters exactly once', async () => {
  const value = await build();
  let reads = 0;
  try {
    const input = readerInput(value);
    const hostile = Object.fromEntries(Object.entries(input).map(([name, item]) => [name, {
      enumerable: true,
      get() {
        reads += 1;
        return item;
      },
    }]));
    const reader = createM4CrossPhaseIdentityPublicationReader(
      Object.defineProperties({}, hostile),
    );
    assert.equal(reads, Object.keys(input).length);
    reader.close();
  } finally {
    fs.rmSync(value.artifactRoot, { recursive: true, force: true });
  }
});
