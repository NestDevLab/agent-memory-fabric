import assert from 'node:assert/strict';
import test from 'node:test';
import { extractWikilinks } from '../src/link-parser.mjs';

test('extracts plain link', () => {
  assert.deepEqual(extractWikilinks('see [[Note A]] here'), [{ target: 'Note A', alias: null }]);
});

test('extracts alias', () => {
  assert.deepEqual(extractWikilinks('[[Projects/agentBerry|the bot]]'), [{ target: 'Projects/agentBerry', alias: 'the bot' }]);
});

test('strips heading anchor', () => {
  assert.deepEqual(extractWikilinks('[[Note B#Section]]'), [{ target: 'Note B', alias: null }]);
});

test('keeps folder path', () => {
  assert.deepEqual(extractWikilinks('[[Daily/2026-07-20]]'), [{ target: 'Daily/2026-07-20', alias: null }]);
});

test('ignores links inside fenced code blocks', () => {
  const md = 'real [[Kept]]\n```\ncode [[Ignored]]\n```\n';
  assert.deepEqual(extractWikilinks(md), [{ target: 'Kept', alias: null }]);
});

test('dedupes repeated pairs preserving order', () => {
  assert.deepEqual(extractWikilinks('[[A]] [[B]] [[A]]'), [{ target: 'A', alias: null }, { target: 'B', alias: null }]);
});

test('tolerates malformed brackets', () => {
  assert.deepEqual(extractWikilinks('[[unclosed and [[Good]]'), [{ target: 'Good', alias: null }]);
});

test('empty and non-string input', () => {
  assert.deepEqual(extractWikilinks(''), []);
  assert.deepEqual(extractWikilinks(null), []);
});
