import sqlite3


def run_tainted_query(db, threshold):
    query = f"SELECT * FROM stocks WHERE shares > {threshold}"
    return db.execute(query).fetchall()
