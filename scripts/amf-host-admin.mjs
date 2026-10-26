import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readPrivateFile, startHostAdmin } from '../src/host-admin-server.mjs';

export async function main(args = process.argv.slice(2)) {
  if (args.length !== 2 || args[0] !== '--config') throw new Error('Usage: node scripts/amf-host-admin.mjs --config /absolute/private-config.json');
  const handle = await startHostAdmin(JSON.parse(await readPrivateFile(args[1])));
  let closing = false;
  const close = async () => {if (closing) return;closing = true;await handle.close();};
  process.once('SIGTERM',() => {void close();});process.once('SIGINT',() => {void close();});
  process.stdout.write(JSON.stringify({service:'amf-host-admin',state:'listening',address:handle.address})+'\n');
  return handle;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {process.stderr.write('amf-host-admin: startup failed; verify private configuration and catalog state\n');process.exitCode = 1;});
}
