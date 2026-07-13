import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const schema = JSON.parse(fs.readFileSync(new URL('../config/contracts/document-contract-v1.schema.json', import.meta.url), 'utf8'));
const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/contracts/obsidian-document-lifecycle.json', import.meta.url), 'utf8'));
const provider = JSON.parse(fs.readFileSync(new URL('../config/obsidian-provider.example.json', import.meta.url), 'utf8'));

test('document contract publishes lifecycle, API, and exclusive backend definitions', () => {
  const required = ['document', 'upsertRequest', 'deleteRequest', 'searchRequest', 'readRequest', 'backendSelection'];
  for (const name of required) assert.ok(schema.$defs[name], `missing schema definition: ${name}`);
  assert.equal(schema.$defs.document.additionalProperties, false);
  assert.deepEqual(schema.$defs.backendSelection.properties.backend.enum, ['direct_sqlite', 'amf_sqlite', 'amf_postgresql']);
  assert.equal(schema.$defs.backendSelection.properties.allowProviderFallback.const, false);
  assert.equal(provider.allowProviderFallback, false);
  assert.equal(provider.semanticOwner, 'amf');
});

test('rename preserves identity and advances revision without changing content identity', () => {
  const created = fixture.create.document;
  const renamed = fixture.rename.document;
  assert.equal(renamed.documentId, created.documentId);
  assert.equal(renamed.vaultId, created.vaultId);
  assert.equal(renamed.previousPath, created.path);
  assert.notEqual(renamed.path, created.path);
  assert.equal(renamed.revision, created.revision + 1);
  assert.equal(renamed.contentDigest, created.contentDigest);
  assert.equal(fixture.rename.expectedRevision, created.revision);
});

test('delete is a revisioned tombstone and cannot imply PAM revocation', () => {
  const renamed = fixture.rename.document;
  const deleted = fixture.delete.document;
  assert.equal(deleted.documentId, renamed.documentId);
  assert.equal(deleted.revision, renamed.revision + 1);
  assert.equal(deleted.tombstone, true);
  assert.equal(fixture.delete.expectedRevision, renamed.revision);
  assert.equal(JSON.stringify(fixture.delete).includes('memoryRevocation'), false);
});

test('idempotency keys bind vault, stable document identity, revision, and digest', () => {
  for (const operation of [fixture.create, fixture.rename, fixture.delete]) {
    const document = operation.document;
    const identity = document.documentId.slice(4);
    const digest = document.contentDigest.slice(7);
    assert.equal(operation.idempotencyKey, `doc:${document.vaultId}:${identity}:${document.revision}:${digest}`);
  }
  assert.equal(new Set([fixture.create.idempotencyKey, fixture.rename.idempotencyKey, fixture.delete.idempotencyKey]).size, 3);
});

test('contract rejects absolute and parent-traversal paths by construction', () => {
  const pattern = new RegExp(schema.$defs.relativePath.pattern);
  for (const valid of ['note.md', 'Folder/note.md', '.hidden/note.md']) assert.equal(pattern.test(valid), true);
  for (const invalid of ['/etc/passwd', '../secret.md', 'Folder/../../secret.md']) assert.equal(pattern.test(invalid), false);
});
