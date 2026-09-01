export async function search(req, db) {
  const parsedId = parseInt(req.params.id, 10);
  const threshold = req.query.threshold;
  const query = `SELECT * FROM stocks WHERE userId = ${parsedId} AND shares > ${threshold}`;
  return db.raw(query);
}
