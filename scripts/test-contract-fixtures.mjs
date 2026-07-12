import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { buildContextRequest, normalizeOpaqueTagMap } from '../src/access-contract.mjs';

const schema = JSON.parse(fs.readFileSync(new URL('../config/contracts/agent-memory-fabric-v2.schema.json', import.meta.url), 'utf8'));
const fixture = JSON.parse(fs.readFileSync(new URL('./fixtures/contracts/principia-canonical-contract.json', import.meta.url), 'utf8'));

test('published canonical contract exposes every authoritative transport definition', () => {
  const required = ['successEnvelope', 'errorEnvelope', 'contextTokenPayload', 'memorySearchRequest', 'memorySearchData', 'memoryReadRequest', 'memoryReadData', 'sessionsSearchRequest', 'sessionsSearchData', 'sessionGetData', 'sessionTranscriptRequest', 'transcriptData'];
  for (const name of required) assert.ok(schema.$defs[name], `missing schema definition: ${name}`);
  assert.equal(schema.$defs.successEnvelope.additionalProperties, false);
  assert.equal(schema.$defs.transcriptData.oneOf.length, 2);
  assert.equal(JSON.stringify(schema.$defs.transcriptData).includes('"messages"'), false);
});

test('0.5.6 release identity is coordinated across package, server, image and fixtures', () => {
  const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const lock = JSON.parse(fs.readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  const server = fs.readFileSync(new URL('../src/server.mjs', import.meta.url), 'utf8');
  const compose = fs.readFileSync(new URL('../compose.agent-memory-fabric.yml', import.meta.url), 'utf8');
  assert.equal(packageJson.version, '0.5.6'); assert.equal(lock.version, '0.5.6');
  assert.equal(lock.packages[''].version, '0.5.6'); assert.match(server, /SERVICE_VERSION = '0\.5\.6'/);
  assert.match(compose, /agent-memory-fabric:0\.5\.6/);
  for (const response of [fixture.memorySearch.response, fixture.memoryRead.response,
    fixture.sessionsSearch.response, fixture.transcript.redacted]) assert.equal(response.meta.version, '0.5.6');
});

test('Principia fixture uses the executable request-digest shapes and canonical transcript items', () => {
  assert.deepEqual(fixture.context.memorySearchDigestInput, buildContextRequest('memory_search', fixture.memorySearch.request));
  assert.deepEqual(fixture.context.sessionsSearchDigestInput, buildContextRequest('sessions_search', fixture.sessionsSearch.request));
  assert.deepEqual(fixture.context.sessionTranscriptDigestInput, buildContextRequest('session_transcript', fixture.transcript.request));
  assert.equal(schema.$defs.sessionTranscriptRequest.required.includes('sessionId'), true);
  assert.equal(Object.hasOwn(schema.$defs.sessionTranscriptRequest.properties, 'id'), false);
  assert.deepEqual(schema.$defs.redactedTranscriptItem.properties.role.enum, ['user', 'assistant']);
  assert.deepEqual(normalizeOpaqueTagMap(fixture.context.payload.contextTags), fixture.context.payload.contextTags);
  assert.ok(Array.isArray(fixture.transcript.redacted.data.items));
  assert.equal(Object.hasOwn(fixture.transcript.redacted.data, 'messages'), false);
  assert.equal(fixture.transcript.redacted.data.items[0].content.text, 'Appointment confirmed.');
  assert.equal(fixture.transcript.rest.path.includes('contextToken'), false);
  assert.equal(fixture.transcript.rest.path.includes('room:'), false);
  assert.equal(fixture.transcript.rest.headers['X-AMF-Context-Token'], '<signed>');
  for (const response of [fixture.memorySearch.response, fixture.memoryRead.response, fixture.sessionsSearch.response, fixture.transcript.redacted]) {
    assert.deepEqual(Object.keys(response).sort(), ['data', 'meta', 'ok']);
    assert.equal(response.meta.service, 'agent-memory-fabric');
  }
});
