from flask import request

from tainted_dao import run_tainted_query


def allocations(db):
    threshold = request.args.get("threshold")
    return run_tainted_query(db, threshold)
