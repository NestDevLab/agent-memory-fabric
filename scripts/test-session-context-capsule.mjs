import assert from 'node:assert/strict';
import test from 'node:test';

import { capsuleToPublicResource, createSessionContextCapsule, createSessionContextNotice, expandSessionContextTranscript } from '../src/session-context-capsule.mjs';

const RID = 'rid_expansion0001';
const session = { id: 'ccon_capsule0001', firstOccurredAt: '2026-08-31T09:00:00Z', lastOccurredAt: '2026-09-01T09:00:00Z' };
const transcript = { id: session.id, view: 'redacted', items: [
  { eventId: 'cevt_capsule0001', occurredAt: '2026-09-01T08:00:00Z', role: 'user', content: { redacted: true, contentType: 'text', parts: 1, text: `Atlas ${'x'.repeat(600)}` } },
  { eventId: 'cevt_capsule0002', occurredAt: '2026-09-01T09:00:00Z', role: 'assistant', content: { redacted: true, contentType: 'text', parts: 1, text: 'Bounded answer' } }
] };

test('projects one bounded redacted capsule and public resource', () => {
  const capsule = createSessionContextCapsule({ session, transcript, expansionRef: RID, query: 'Atlas', now: '2026-09-01T10:00:00Z', reasons: ['exact_anchor', 'freshness'], contradiction: 'present' });
  assert.match(capsule.id, /^csc_/); assert.equal(capsule.snippets.length, 2); assert.ok(capsule.snippets.every(item => item.redacted && Array.from(item.text).length <= 512));
  assert.equal(capsule.provenance.sourceRef, RID); assert.equal(capsule.freshness.state, 'fresh'); assert.equal(capsule.contradiction, 'present'); assert.equal(Object.isFrozen(capsule), true);
  const resource = capsuleToPublicResource(capsule); assert.deepEqual(({ id: resource.id, kind: resource.kind, admission: resource.admission, contradiction: resource.contradiction }), ({ id: RID, kind: 'conversation', admission: 'authorized', contradiction: 'present' })); assert.equal(resource.text.includes('Atlas'), true);
});

test('stale state remains visible while future and non-redacted input fail closed', () => {
  const stale = createSessionContextCapsule({ session: { ...session, lastOccurredAt: '2026-08-01T09:00:00Z' }, transcript, expansionRef: RID, now: '2026-09-01T10:00:00Z' });
  assert.equal(stale.freshness.state, 'stale');
  assert.throws(() => createSessionContextCapsule({ session: { ...session, lastOccurredAt: '2026-09-02T09:00:00Z' }, transcript, expansionRef: RID, now: '2026-09-01T10:00:00Z' }), /session_context_capsule_invalid/);
  const raw = structuredClone(transcript); raw.items[0].content.redacted = false;
  assert.throws(() => createSessionContextCapsule({ session, transcript: raw, expansionRef: RID, now: '2026-09-01T10:00:00Z' }), /session_context_capsule_invalid/);
});

test('notice contains no IDs or snippets and expansion is capped and redacted', () => {
  const capsule = createSessionContextCapsule({ session, transcript, expansionRef: RID, now: '2026-09-01T10:00:00Z' });
  const notice = createSessionContextNotice([capsule]); assert.deepEqual(notice, { ok: true, outcome: 'notice', notice: { mode: 'notice_only', state: 'available', candidateCount: 1, expansionRequired: true } }); assert.equal(JSON.stringify(notice).includes('rid_'), false);
  assert.deepEqual(createSessionContextNotice([]), { ok: false, outcome: 'not_found' });
  const many = { ...transcript, items: Array.from({ length: 7 }, (_, index) => ({ eventId: `cevt_expand00${index}`, occurredAt: `2026-09-01T09:00:0${index}Z`, role: 'assistant', content: { redacted: true, contentType: 'text', parts: 1, text: `${index}${'y'.repeat(1100)}` } })) };
  const expansion = expandSessionContextTranscript({ id: RID, transcript: many }); assert.equal(expansion.excerpts.length, 5); assert.ok(expansion.excerpts.every(item => item.redacted && Array.from(item.text).length <= 1024)); assert.equal(expansion.resource.text.includes('yyyy'), true);
});
