export async function loadSystemUser(db) {
  const userId = 'system';
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.raw(query);
}
