export async function search(req, db) {
  const parsedId = parseInt(req.params.id, 10);
  const parsedThreshold = parseInt(req.query.threshold, 10);
  const query = `SELECT * FROM stocks WHERE userId = ${parsedId} AND shares > ${parsedThreshold}`;
  return db.raw(query);
}
