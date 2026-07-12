import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const PAM_RUNTIME_PRIVATE_FILES = Object.freeze({
  AMF_PAM_ROUTING_KEY_RING_PATH: 'agent-memory-fabric-routing-key-ring.json',
  PAM_WORKSPACE_CONFIG: 'pam-workspace-config.json',
  PAM_APPLICATOR_STATE_KEY_FILE: 'pam-applicator-state-key'
});

function invalid(reason) {
  const error = new Error(`pam_runtime_private_dir_invalid:${reason}`);
  error.code = 'pam_runtime_private_dir_invalid';
  return error;
}

function exactMode(stat, mode) { return (stat.mode & 0o777) === mode; }

export function validatePamRuntimePrivateDir({
  directory,
  environment = process.env,
  expectedUid = typeof process.geteuid === 'function' ? process.geteuid() : null,
  expectedGid = typeof process.getegid === 'function' ? process.getegid() : null
} = {}) {
  if (typeof directory !== 'string' || !directory.trim()
      || expectedUid === null || !Number.isSafeInteger(expectedUid) || expectedUid < 0
      || expectedGid === null || !Number.isSafeInteger(expectedGid) || expectedGid < 0) throw invalid('configuration');
  const absolute = path.resolve(directory);
  let directoryFd;
  try {
    const before = fs.lstatSync(absolute);
    if (!before.isDirectory() || before.isSymbolicLink() || before.uid !== expectedUid || before.gid !== expectedGid || !exactMode(before, 0o700)) throw invalid('parent');
    directoryFd = fs.openSync(absolute, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(directoryFd);
    const handle = `/proc/self/fd/${directoryFd}`;
    if (!opened.isDirectory() || opened.uid !== expectedUid || opened.gid !== expectedGid || !exactMode(opened, 0o700) || fs.realpathSync(handle) !== absolute) throw invalid('parent');
    const expectedFiles = Object.values(PAM_RUNTIME_PRIVATE_FILES).sort();
    if (fs.readdirSync(handle).sort().join('\0') !== expectedFiles.join('\0')) throw invalid('contents');

    for (const [variable, filename] of Object.entries(PAM_RUNTIME_PRIVATE_FILES)) {
      const expectedPath = path.join(absolute, filename);
      if (environment[variable] !== expectedPath) throw invalid('binding');
      let fd;
      try {
        fd = fs.openSync(`${handle}/${filename}`, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== expectedUid || stat.gid !== expectedGid || !exactMode(stat, 0o600) || stat.size < 1 || stat.size > 8 * 1024 * 1024) throw invalid('file');
        if (filename.endsWith('.json')) {
          const parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw invalid('json');
        }
      } catch (error) {
        if (error?.code === 'pam_runtime_private_dir_invalid') throw error;
        throw invalid('file');
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
      }
    }
    return { ok: true, uid: expectedUid, gid: expectedGid, files: Object.keys(PAM_RUNTIME_PRIVATE_FILES).length };
  } catch (error) {
    if (error?.code === 'pam_runtime_private_dir_invalid') throw error;
    throw invalid('parent');
  } finally {
    if (directoryFd !== undefined) fs.closeSync(directoryFd);
  }
}

export function validatePamRuntimePrivateDirFromEnv(environment = process.env) {
  const directory = String(environment.AMF_PAM_RUNTIME_PRIVATE_DIR || '').trim();
  if (!directory) throw invalid('configuration');
  return validatePamRuntimePrivateDir({ directory, environment });
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  try {
    const result = validatePamRuntimePrivateDirFromEnv(process.env);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error?.code || 'pam_runtime_private_dir_invalid'}\n`);
    process.exitCode = 78;
  }
}
