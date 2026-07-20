import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const artifactPaths = [
  'deploy/docker-compose.yml',
  'deploy/.env.example',
  'deploy/README.md',
  'docs/multi-agent-compose-stack.md'
];

async function artifacts() {
  return Object.fromEntries(await Promise.all(artifactPaths.map(async path => [
    path,
    await readFile(new URL(path, root), 'utf8')
  ])));
}

test('legacy compose example remains public-safe and local-only', async () => {
  const files = await artifacts();
  const all = Object.values(files).join('\n');
  const compose = files['deploy/docker-compose.yml'];

  assert.doesNotMatch(all, /(^|[^\w])env_file\s*:/mi, 'runtime env_file support is forbidden');
  assert.doesNotMatch(all, /\.env\.runtime/i, 'runtime override files are forbidden');
  assert.doesNotMatch(compose, /\$\{[^}\n]*:-[^}\n]*\}/, 'Compose defaults are forbidden');
  assert.match(compose, /AMF_CATALOG_SSL_MODE:\s*disable/, 'the isolated local database must not inherit production TLS defaults');
  assert.doesNotMatch(all, /\b(?:10|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b/, 'private address examples are forbidden');
  assert.doesNotMatch(all, /\bproduction[- ]ready\b/i, 'the legacy example cannot claim production readiness');
  assert.match(all, /named volumes[\s\S]{0,220}start empty/i, 'empty-volume warning is required');
  assert.match(all, /exact\s+manifests,\s+reconciliation,\s+rollback,\s+restore\s+proof,\s+and\s+single-writer\s+validation/i, 'migration warning is required');
  assert.match(all, /target advertised MCP tools are `search`, `read`, `propose`,\s*`proposal_status`, and `status`/i, 'target MCP tools are required');
  assert.match(all, /amf_\*[\s\S]{0,100}unadvertised compatibility aliases/i, 'legacy MCP aliases must be unadvertised');
  assert.doesNotMatch(all, /\b(?:advertised|public)\b[^\n]*`amf_/i, 'legacy MCP names must not be advertised');
  assert.doesNotMatch(all, /`amf_[^`]*`[^\n]*\b(?:advertised|public)\b/i, 'legacy MCP names must not be advertised');
});

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  // node:test reports the result; this branch makes direct execution explicit.
}
