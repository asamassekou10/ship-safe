export function runTaintedQuery(db, threshold) {
  return db.raw(`SELECT * FROM stocks WHERE shares > '${threshold}'`);
}
