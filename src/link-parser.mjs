const FENCE = /```[\s\S]*?```/g;
const WIKILINK = /\[\[([^\[\]|#]+)(?:#[^\[\]|]*)?(?:\|([^\[\]]*))?\]\]/g;

export function extractWikilinks(text) {
  const source = typeof text === 'string' ? text : '';
  if (!source) return [];
  const stripped = source.replace(FENCE, '');
  const seen = new Set();
  const out = [];
  for (const match of stripped.matchAll(WIKILINK)) {
    const target = match[1].trim();
    if (!target) continue;
    const alias = match[2] !== undefined ? match[2].trim() : null;
    const key = `${target}|${alias || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ target, alias: alias || null });
  }
  return out;
}
