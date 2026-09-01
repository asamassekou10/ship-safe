from flask import request

from guarded_dao import run_guarded_query


def allocations(db):
    threshold = int(request.args.get("threshold"))
    return run_guarded_query(db, threshold)
