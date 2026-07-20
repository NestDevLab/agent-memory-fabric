#!/usr/bin/env node
import fs from 'node:fs';

export const DEPLOYMENT_ROOT = '/opt/agent-memory-fabric';
const EXPECTED_MODE = 0o711;

function error(code) {
  return new Error(code);
}

export function verifyDeploymentRoot(rootPath = DEPLOYMENT_ROOT, { uid = 0, gid = 0 } = {}) {
  const stat = fs.lstatSync(rootPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw error('amf_deployment_root_invalid');
  if ((stat.mode & 0o7777) !== EXPECTED_MODE) throw error('amf_deployment_root_mode_invalid');
  if (stat.uid !== uid || stat.gid !== gid) throw error('amf_deployment_root_owner_invalid');
  return { ok: true, path: rootPath, mode: '0711' };
}

function safeErrorCode(cause) {
  const code = String(cause?.message || 'amf_deployment_root_check_failed');
  return /^[a-z0-9_]{1,128}$/.test(code) ? code : 'amf_deployment_root_check_failed';
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    process.stdout.write(`${JSON.stringify(verifyDeploymentRoot())}\n`);
  } catch (cause) {
    process.stderr.write(`${JSON.stringify({ ok: false, error: safeErrorCode(cause) })}\n`);
    process.exitCode = 1;
  }
}
