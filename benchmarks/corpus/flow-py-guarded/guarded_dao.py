import sqlite3


def run_guarded_query(db, threshold):
    query = f"SELECT * FROM stocks WHERE shares > {threshold}"
    return db.execute(query).fetchall()
