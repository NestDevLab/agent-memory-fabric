import crypto from 'node:crypto';

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256Id(namespace, ...parts) {
  const hash = crypto.createHash('sha256');
  hash.update(namespace, 'utf8');
  for (const part of parts) {
    hash.update('\0', 'utf8');
    hash.update(String(part ?? ''), 'utf8');
  }
  return hash.digest('hex');
}

export function strictIsoTimestamp(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? value : null;
}
