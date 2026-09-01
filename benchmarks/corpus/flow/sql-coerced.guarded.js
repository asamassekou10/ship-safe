export async function loadUser(req, db) {
  const raw = req.params.id;
  const userId = parseInt(raw, 10);
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.raw(query);
}
