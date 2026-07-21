import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { deflateRawSync } from 'node:zlib';

import Database from 'better-sqlite3';
import pg from 'pg';

import { protectContent } from '../src/content-protection-v1.mjs';

const CONTENT_CLASSES = ['conversation', 'proposal', 'canonical-memory', 'document'];
const VARIANTS = ['plaintext', 'aes', 'deflate-aes'];
const RECORDS_PER_CLASS = 16;
const QUERY_OPERATIONS = 64;
const NORMALIZED_BLOCK_BYTES = 4096;
const SOURCE_INSTANCE_ID = 'src_measurement0001';
const KEY_REFERENCE = 'key:measurement-v1';
const KEY_MATERIAL = Buffer.alloc(32, 31);
const DEFAULTS = Object.fromEntries(CONTENT_CLASSES.map(contentClass => [contentClass, 'plaintext']));
const TARGET_BYTES = {
  conversation: 2048,
  proposal: 1024,
  'canonical-memory': 1536,
  document: 8192
};
const TEMPLATES = {
  conversation: 'Synthetic participant message followed by a synthetic assistant response. ',
  proposal: 'Synthetic proposal with evidence, scope, confidence, and review state. ',
  'canonical-memory': 'Synthetic reviewed memory with lifecycle, provenance, and subject identifiers. ',
  document: 'Synthetic reference paragraph containing repeated explanatory prose and section context. '
};

function policy(variant, contentClass) {
  return {
    schema: 'amf.content-protection-policy/v1',
    revision: 'measurement-v1',
    defaults: DEFAULTS,
    rules: variant === 'plaintext'
      ? []
      : [{
          sourceInstanceId: SOURCE_INSTANCE_ID,
          contentClass,
          enabled: true,
          codec: 'aes-256-gcm',
          writeKeyRef: KEY_REFERENCE,
          readKeyRefs: [KEY_REFERENCE],
          ...(variant === 'deflate-aes' ? { compression: 'deflate-raw' } : {})
        }]
  };
}

function deterministicContent(contentClass, ordinal) {
  const targetBytes = TARGET_BYTES[contentClass];
  const repeated = Buffer.from(TEMPLATES[contentClass].repeat(Math.ceil(targetBytes / TEMPLATES[contentClass].length)));
  const noise = [];
  for (let index = 0; Buffer.byteLength(noise.join('')) < Math.ceil(targetBytes / 5); index += 1) {
    noise.push(crypto.createHash('sha256').update(`${contentClass}:${ordinal}:${index}`).digest('hex'));
  }
  const mixed = Buffer.concat([
    repeated.subarray(0, targetBytes - Math.ceil(targetBytes / 5)),
    Buffer.from(noise.join('')).subarray(0, Math.ceil(targetBytes / 5))
  ]);
  if (mixed.length !== targetBytes) throw new Error('content_protection_measurement_insufficient');
  return mixed;
}

function sourceRecords() {
  return CONTENT_CLASSES.flatMap(contentClass =>
    Array.from({ length: RECORDS_PER_CLASS }, (_, ordinal) => ({
      contentClass,
      ordinal,
      plaintext: deterministicContent(contentClass, ordinal)
    }))
  );
}

function serializeEnvelope(envelope) {
  return Buffer.from(JSON.stringify(envelope), 'utf8');
}

function compressionCandidate(record) {
  const compressed = deflateRawSync(record.plaintext, { level: 9 });
  return serializeEnvelope({
    v: 1,
    codec: 'aes-256-gcm',
    sourceInstanceId: SOURCE_INSTANCE_ID,
    contentClass: record.contentClass,
    keyRef: KEY_REFERENCE,
    compression: 'deflate-raw',
    metadata: { ordinal: record.ordinal },
    iv: Buffer.alloc(12).toString('base64'),
    ciphertext: Buffer.alloc(compressed.length).toString('base64'),
    tag: Buffer.alloc(16).toString('base64')
  });
}

function classStats(rows) {
  return Object.fromEntries(CONTENT_CLASSES.map(contentClass => {
    const selected = rows.filter(row => row.contentClass === contentClass);
    return [contentClass, {
      sampleCount: selected.length,
      logicalBytes: selected.reduce((sum, row) => sum + row.plaintext.length, 0),
      serializedBytes: selected.reduce((sum, row) => sum + row.serialized.length, 0)
    }];
  }));
}

function evidenceFromStats(uncompressed, compressed) {
  return Object.fromEntries(CONTENT_CLASSES.map(contentClass => {
    const uncompressedStats = uncompressed[contentClass];
    const compressedStats = compressed[contentClass];
    const savingsBytes = uncompressedStats.serializedBytes - compressedStats.serializedBytes;
    return [contentClass, {
      algorithm: 'deflate-raw',
      contentClass,
      sampleCount: uncompressedStats.sampleCount,
      uncompressedEnvelopeBytes: uncompressedStats.serializedBytes,
      compressedEnvelopeBytes: compressedStats.serializedBytes,
      savingsBytes,
      justified: uncompressedStats.sampleCount > 0 && savingsBytes >= 64
    }];
  }));
}

function buildMeasurementRows() {
  const source = sourceRecords();
  const plaintext = source.map(record => ({
    ...record,
    serialized: serializeEnvelope(protectContent({
      policy: policy('plaintext', record.contentClass),
      sourceInstanceId: SOURCE_INSTANCE_ID,
      contentClass: record.contentClass,
      plaintext: record.plaintext,
      metadata: { ordinal: record.ordinal }
    }))
  }));
  const aes = source.map(record => ({
    ...record,
    serialized: serializeEnvelope(protectContent({
      policy: policy('aes', record.contentClass),
      sourceInstanceId: SOURCE_INSTANCE_ID,
      contentClass: record.contentClass,
      plaintext: record.plaintext,
      metadata: { ordinal: record.ordinal },
      resolveKey: () => KEY_MATERIAL
    }))
  }));
  const candidates = source.map(record => ({ ...record, serialized: compressionCandidate(record) }));
  const evidence = evidenceFromStats(classStats(aes), classStats(candidates));
  const compressed = source.map((record, index) => {
    const serialized = serializeEnvelope(protectContent({
      policy: policy('deflate-aes', record.contentClass),
      sourceInstanceId: SOURCE_INSTANCE_ID,
      contentClass: record.contentClass,
      plaintext: record.plaintext,
      metadata: { ordinal: record.ordinal },
      resolveKey: () => KEY_MATERIAL
    }));
    if (serialized.length !== candidates[index].serialized.length) {
      throw new Error('content_protection_measurement_insufficient');
    }
    return { ...record, serialized };
  });
  return { rows: { plaintext, aes, 'deflate-aes': compressed }, evidence };
}

function queryEvidenceSqlite(database) {
  const plan = database.prepare(
    'EXPLAIN QUERY PLAN SELECT payload FROM evidence WHERE content_class=? AND ordinal=?'
  ).all('conversation', 0);
  const query = database.prepare('SELECT payload FROM evidence WHERE content_class=? AND ordinal=?');
  const started = process.hrtime.bigint();
  for (let index = 0; index < QUERY_OPERATIONS; index += 1) {
    const row = query.get(CONTENT_CLASSES[index % CONTENT_CLASSES.length], index % RECORDS_PER_CLASS);
    if (!row?.payload) throw new Error('content_protection_measurement_insufficient');
  }
  return {
    operations: QUERY_OPERATIONS,
    indexedPlan: plan.some(row => String(row.detail).includes('evidence_lookup')),
    observedMs: Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3)),
    nonNormative: true
  };
}

export function compressionEvidence(measurement) {
  return evidenceFromStats(
    measurement.sqlite.variants.aes.classes,
    measurement.sqlite.variants['deflate-aes'].classes
  );
}

export function measureSqliteEvidence() {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'amf-content-measurement-'));
  const built = buildMeasurementRows();
  const output = { version: 2, synthetic: true, sqlite: { variants: {} } };

  try {
    for (const variant of VARIANTS) {
      const databasePath = path.join(temporaryRoot, `${variant}.sqlite`);
      const database = new Database(databasePath);
      try {
        database.exec(`
          PRAGMA journal_mode=DELETE;
          CREATE TABLE evidence(
            content_class TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            payload BLOB NOT NULL
          );
          CREATE UNIQUE INDEX evidence_lookup ON evidence(content_class, ordinal);
        `);
        const insert = database.prepare(
          'INSERT INTO evidence(content_class,ordinal,payload) VALUES (?,?,?)'
        );
        database.transaction(() => {
          for (const row of built.rows[variant]) insert.run(row.contentClass, row.ordinal, row.serialized);
        })();

        const stored = database.prepare(`
          SELECT content_class, count(*) AS sample_count, sum(length(payload)) AS serialized_bytes
          FROM evidence GROUP BY content_class ORDER BY content_class
        `).all();
        const storedByClass = new Map(stored.map(row => [row.content_class, row]));
        const classes = classStats(built.rows[variant]);
        for (const contentClass of CONTENT_CLASSES) {
          const row = storedByClass.get(contentClass);
          if (!row || row.sample_count !== classes[contentClass].sampleCount ||
              row.serialized_bytes !== classes[contentClass].serializedBytes) {
            throw new Error('content_protection_measurement_insufficient');
          }
        }
        output.sqlite.variants[variant] = {
          classes,
          query: queryEvidenceSqlite(database)
        };
      } finally {
        database.close();
      }

      const stat = fs.statSync(databasePath);
      const allocatedBytes = Number.isSafeInteger(stat.blocks) ? stat.blocks * 512 : 0;
      if (allocatedBytes < 1) throw new Error('content_protection_measurement_insufficient');
      output.sqlite.variants[variant].filesystem = {
        normalizedBlockBytes: NORMALIZED_BLOCK_BYTES,
        allocatedBytes,
        allocatedBlocks4KiB: Math.ceil(allocatedBytes / NORMALIZED_BLOCK_BYTES)
      };
      if (!output.sqlite.variants[variant].query.indexedPlan) {
        throw new Error('content_protection_measurement_insufficient');
      }
    }
    output.compressionEvidence = compressionEvidence(output);
    if (JSON.stringify(output.compressionEvidence) !== JSON.stringify(built.evidence)) {
      throw new Error('content_protection_measurement_insufficient');
    }
    return output;
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

async function queryEvidencePostgres(client, table, indexName) {
  await client.query('SET enable_seqscan=off');
  try {
    const plan = await client.query(
      `EXPLAIN (FORMAT JSON) SELECT payload FROM ${table} WHERE content_class=$1 AND ordinal=$2`,
      ['conversation', 0]
    );
    const started = process.hrtime.bigint();
    for (let index = 0; index < QUERY_OPERATIONS; index += 1) {
      const result = await client.query(
        `SELECT payload FROM ${table} WHERE content_class=$1 AND ordinal=$2`,
        [CONTENT_CLASSES[index % CONTENT_CLASSES.length], index % RECORDS_PER_CLASS]
      );
      if (!result.rows[0]?.payload) throw new Error('content_protection_measurement_insufficient');
    }
    return {
      operations: QUERY_OPERATIONS,
      indexedPlan: JSON.stringify(plan.rows).includes(indexName),
      observedMs: Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3)),
      nonNormative: true
    };
  } finally {
    await client.query('RESET enable_seqscan');
  }
}

export async function measurePostgresEvidence(connectionString) {
  if (typeof connectionString !== 'string' || connectionString.length < 1) {
    throw new Error('content_protection_measurement_insufficient');
  }
  const pool = new pg.Pool({ connectionString, max: 1 });
  let client;
  try {
    client = await pool.connect();
    const built = buildMeasurementRows();
    const output = { variants: {}, filesystem: { measured: false, reason: 'sqlite_only' } };

    for (const variant of VARIANTS) {
      const normalizedVariant = variant.replaceAll('-', '_');
      const table = `content_protection_${normalizedVariant}`;
      const indexName = `${table}_lookup`;
      await client.query(`
        CREATE TEMP TABLE ${table}(
          content_class TEXT NOT NULL,
          ordinal INTEGER NOT NULL,
          payload BYTEA NOT NULL
        ) ON COMMIT PRESERVE ROWS
      `);
      await client.query(`CREATE UNIQUE INDEX ${indexName} ON ${table}(content_class, ordinal)`);
      for (const row of built.rows[variant]) {
        await client.query(
          `INSERT INTO ${table}(content_class,ordinal,payload) VALUES ($1,$2,$3)`,
          [row.contentClass, row.ordinal, row.serialized]
        );
      }

      const stored = await client.query(`
        SELECT content_class, count(*)::integer AS sample_count,
               sum(pg_column_size(payload))::bigint AS serialized_bytes
        FROM ${table} GROUP BY content_class ORDER BY content_class
      `);
      const storedByClass = new Map(stored.rows.map(row => [row.content_class, row]));
      const classes = classStats(built.rows[variant]);
      for (const contentClass of CONTENT_CLASSES) {
        const row = storedByClass.get(contentClass);
        classes[contentClass].sampleCount = Number(row?.sample_count);
        classes[contentClass].serializedBytes = Number(row?.serialized_bytes);
        if (!Number.isSafeInteger(classes[contentClass].serializedBytes) ||
            classes[contentClass].serializedBytes < 1) {
          throw new Error('content_protection_measurement_insufficient');
        }
      }
      output.variants[variant] = {
        classes,
        query: await queryEvidencePostgres(client, table, indexName)
      };
      if (!output.variants[variant].query.indexedPlan) {
        throw new Error('content_protection_measurement_insufficient');
      }
    }
    return output;
  } catch (error) {
    throw new Error('content_protection_measurement_insufficient', { cause: error });
  } finally {
    client?.release();
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const output = measureSqliteEvidence();
  if (process.env.AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL) {
    output.postgres = await measurePostgresEvidence(process.env.AMF_CONTENT_PROTECTION_POSTGRES_TEST_URL);
  }
  process.stdout.write(`${JSON.stringify(output)}\n`);
}
