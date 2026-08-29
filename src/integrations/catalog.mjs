import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const INTEGRATION_IDS = Object.freeze(['obsidian-second-brain', 'harness-raw-capture']);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function loadDescriptor(id) {
  const descriptor = JSON.parse(fs.readFileSync(path.join(ROOT, 'integrations', id, 'descriptor.json'), 'utf8'));
  if (descriptor.schema !== 'amf.integration/v1' || descriptor.id !== id) {
    throw new Error('integration_descriptor_invalid');
  }
  return deepFreeze(descriptor);
}

const CATALOG = new Map(INTEGRATION_IDS.map(id => [id, loadDescriptor(id)]));

export function listIntegrations() {
  return [...CATALOG.values()].map(descriptor => structuredClone(descriptor));
}

export function describeIntegration(id) {
  const descriptor = CATALOG.get(id);
  if (!descriptor) throw new Error('integration_unknown');
  return structuredClone(descriptor);
}

export const INTEGRATION_ROOT = ROOT;
