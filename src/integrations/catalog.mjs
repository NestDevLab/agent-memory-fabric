import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DESCRIPTOR_PATH = path.join(ROOT, 'integrations', 'obsidian-second-brain', 'descriptor.json');

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function loadDescriptor() {
  const descriptor = JSON.parse(fs.readFileSync(DESCRIPTOR_PATH, 'utf8'));
  if (descriptor.schema !== 'amf.integration/v1' || descriptor.id !== 'obsidian-second-brain') {
    throw new Error('integration_descriptor_invalid');
  }
  return deepFreeze(descriptor);
}

const CATALOG = new Map([['obsidian-second-brain', loadDescriptor()]]);

export function listIntegrations() {
  return [...CATALOG.values()].map(descriptor => structuredClone(descriptor));
}

export function describeIntegration(id) {
  const descriptor = CATALOG.get(id);
  if (!descriptor) throw new Error('integration_unknown');
  return structuredClone(descriptor);
}

export const INTEGRATION_ROOT = ROOT;
