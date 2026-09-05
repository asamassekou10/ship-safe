def run_one_job(job):
    token = set_secret_scope(build_profile_secret_scope(job["profile"]))
    try:
        return _deliver_result(job, run_job(job))
    except Exception:
        return retry(job)
    finally:
        clear_session_vars([])


global_token = None
reset_secret_scope(global_token)
