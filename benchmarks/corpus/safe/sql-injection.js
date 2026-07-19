const query = 'SELECT * FROM users WHERE id = ?';
db.execute(query, [userId]);
