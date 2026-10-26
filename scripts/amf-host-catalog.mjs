#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { HostFileCatalog } from '../src/host-file-catalog.mjs';

let catalog;
try {
  const args = process.argv.slice(2), options = {}, commands = new Set(['scan','status','search','suggestions']);
  let command;
  for (let i=0;i<args.length;i++) {
    const arg = args[i];
    if (commands.has(arg) && !command) { command = arg; continue; }
    if (arg === '--restart') { options.restart = true; continue; }
    if (!['--config','--database','--query','--domain','--limit','--offset','--max-entries','--budget-ms'].includes(arg) || i+1 >= args.length) throw new Error('Invalid arguments');
    if (options[arg] !== undefined) throw new Error('Duplicate option');
    options[arg] = args[++i];
  }
  if (!command || !path.isAbsolute(options['--config'] ?? '') || !path.isAbsolute(options['--database'] ?? '')) throw new Error('Usage: --config ABSOLUTE_POLICY --database ABSOLUTE_DB scan|status|search|suggestions [--restart] [--max-entries N] [--budget-ms N] [--query TEXT] [--domain ID] [--limit N] [--offset N]');
  const policy = JSON.parse(fs.readFileSync(options['--config'],'utf8'));
  catalog = new HostFileCatalog({databasePath:options['--database'],policy});
  const number = (key,fallback) => options[key] === undefined ? fallback : Number(options[key]);
  const result = command === 'scan' ? await catalog.scan({maxEntries:number('--max-entries',10000),budgetMs:number('--budget-ms',2000),restart:options.restart ?? false})
    : command === 'status' ? catalog.status()
    : command === 'search' ? catalog.search({query:options['--query'] ?? '',domain:options['--domain'] ?? null,limit:number('--limit',50),offset:number('--offset',0)})
    : catalog.suggestions({limit:number('--limit',50)});
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({error:error.code ?? 'catalog-error',message:error.code ? 'Catalog operation failed; inspect configuration and private state permissions.' : error.message})}\n`);
  process.exitCode = 1;
} finally { catalog?.close(); }
