export function runGuardedQuery(db, threshold) {
  return db.raw(`SELECT * FROM stocks WHERE shares > '${threshold}'`);
}
