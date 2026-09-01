export async function loadUser(req, db) {
  const raw = req.params.id;
  const userId = raw;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.raw(query);
}
