import fs from 'node:fs';
import readline from 'node:readline';

import { createM4ReconciliationEventAccumulator } from '../migration/m4-reconciliation-snapshot.mjs';
import { assertPrivateFileIdentity, openPrivateDigest } from './private-artifacts.mjs';

const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;

function fail(code) { const error = new Error(code); error.code = code; throw error; }

export function openM4ReconciliationSnapshot(filePath, manifest) {
  const code = 'm4_live_operator_reconciliation_snapshot_invalid';
  const identity = openPrivateDigest(filePath, code, { minBytes: 0, maxBytes: MAX_SNAPSHOT_BYTES });
  if (identity.digest !== manifest.eventFileDigest) { fs.closeSync(identity.descriptor); fail('m4_live_operator_reconciliation_snapshot_changed'); }
  let stream = null; let iteratorStarted = false; let closed = false; let verified = false;
  const close = async () => {
    if (closed) return; closed = true;
    if (stream) {
      if (!stream.closed) await new Promise(resolve => { stream.once('close', resolve); stream.close(); });
    } else fs.closeSync(identity.descriptor);
  };
  const verifyComplete = () => { if (!verified) fail('m4_live_operator_reconciliation_snapshot_incomplete'); };
  const events = {
    async *[Symbol.asyncIterator]() {
      if (iteratorStarted || closed) fail('m4_live_operator_reconciliation_snapshot_invalid');
      iteratorStarted = true;
      const accumulator = createM4ReconciliationEventAccumulator();
      stream = fs.createReadStream(null, { fd: identity.descriptor, autoClose: false, start: 0, encoding: 'utf8' });
      const lines = readline.createInterface({ input: stream, crlfDelay: Infinity });
      try {
        for await (const line of lines) {
          if (!line || Buffer.byteLength(line, 'utf8') > MAX_LINE_BYTES) fail(code);
          let event; try { event = JSON.parse(line); } catch { fail(code); }
          accumulator.add(event);
          yield event;
        }
        const actual = accumulator.finish();
        assertPrivateFileIdentity(identity, 'm4_live_operator_reconciliation_snapshot_changed');
        if (actual.eventCount !== manifest.eventCount || actual.eventSetDigest !== manifest.eventSetDigest) {
          fail('m4_live_operator_reconciliation_snapshot_attestation_mismatch');
        }
        verified = true;
      } finally { lines.close(); }
    },
  };
  return { events, close, verifyComplete };
}
