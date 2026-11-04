// Derived, versioned accelerator. The files table remains authoritative.
export function initializePathIndex(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS catalog_path_index_v1_state (
      id INTEGER PRIMARY KEY CHECK(id=1), cursor TEXT COLLATE BINARY, complete INTEGER NOT NULL DEFAULT 0);
    INSERT OR IGNORE INTO catalog_path_index_v1_state(id) VALUES(1);
    CREATE TABLE IF NOT EXISTS catalog_path_index_v1_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE COLLATE BINARY);
    CREATE VIRTUAL TABLE IF NOT EXISTS catalog_path_index_v1 USING fts5(path, tokenize='trigram');
    CREATE TRIGGER IF NOT EXISTS catalog_path_index_v1_key_insert AFTER INSERT ON catalog_path_index_v1_keys BEGIN
      INSERT INTO catalog_path_index_v1(rowid,path) VALUES(new.id,new.path);
    END;
    CREATE TRIGGER IF NOT EXISTS catalog_path_index_v1_key_delete AFTER DELETE ON catalog_path_index_v1_keys BEGIN
      DELETE FROM catalog_path_index_v1 WHERE rowid=old.id;
    END;
    CREATE TRIGGER IF NOT EXISTS catalog_path_index_v1_file_insert AFTER INSERT ON files BEGIN
      INSERT OR IGNORE INTO catalog_path_index_v1_keys(path) VALUES(new.path);
    END;
    CREATE TRIGGER IF NOT EXISTS catalog_path_index_v1_file_delete AFTER DELETE ON files BEGIN
      DELETE FROM catalog_path_index_v1_keys WHERE path=old.path;
    END;
    CREATE TRIGGER IF NOT EXISTS catalog_path_index_v1_file_path_update AFTER UPDATE OF path ON files WHEN old.path IS NOT new.path BEGIN
      DELETE FROM catalog_path_index_v1_keys WHERE path=old.path;
      INSERT OR IGNORE INTO catalog_path_index_v1_keys(path) VALUES(new.path);
    END;
  `);
}

export function pathIndexState(db) {
  return {...db.prepare('SELECT cursor,complete FROM catalog_path_index_v1_state WHERE id=1').get()};
}

export function buildPathIndex(db, {maxEntries=1000,budgetMs=50}={}) {
  if (!Number.isInteger(maxEntries) || maxEntries<1 || maxEntries>10000 || !Number.isInteger(budgetMs) || budgetMs<1 || budgetMs>2000) throw new Error('Invalid path index batch');
  const started=Date.now();
  db.exec('BEGIN IMMEDIATE');
  try {
    const state=pathIndexState(db);
    let processed=0, cursor=state.cursor, complete=state.complete;
    if (!complete) {
      const rows=cursor===null
        ? db.prepare('SELECT path FROM files ORDER BY path COLLATE BINARY LIMIT ?').all(maxEntries)
        : db.prepare('SELECT path FROM files WHERE path>? COLLATE BINARY ORDER BY path COLLATE BINARY LIMIT ?').all(cursor,maxEntries);
      const insert=db.prepare('INSERT OR IGNORE INTO catalog_path_index_v1_keys(path) VALUES(?)');
      for (const row of rows) {
        insert.run(row.path); cursor=row.path; processed++;
        if (Date.now()-started>=budgetMs) break;
      }
      // A final empty batch proves exhaustion; new rows are already indexed by triggers.
      complete=rows.length===0 ? 1 : 0;
      db.prepare('UPDATE catalog_path_index_v1_state SET cursor=?,complete=? WHERE id=1').run(cursor,complete);
    }
    db.exec('COMMIT');
    return {processed,cursor,complete:Boolean(complete)};
  } catch(error) { db.exec('ROLLBACK'); throw error; }
}

export function pathCandidateMatch(db, query) {
  // Restrict v1 acceleration to printable ASCII. SQLite LIKE and the trigram
  // tokenizer have different Unicode folding rules; all other queries retain
  // the exact legacy predicate until a wider equivalence contract is proven.
  if (query.length<3 || /[^\x20-\x7e]/.test(query) || !pathIndexState(db).complete) return null;
  return `"${query.replaceAll('"','""')}"`;
}
