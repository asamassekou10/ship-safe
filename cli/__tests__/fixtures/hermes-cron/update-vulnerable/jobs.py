def create_job(schedule, prompt, script=None):
    parsed = parse_schedule(schedule)
    check_gateway_lifecycle(prompt, script)
    job = {"schedule": parsed, "prompt": prompt, "script": script}
    save_jobs([job])
    return job


def update_job(job_id, updates):
    jobs = load_jobs()
    job = next(job for job in jobs if job["id"] == job_id)
    updated = {**job, **updates}
    if any(key in updates for key in _PAYLOAD_FIELDS):
        validate_non_empty(updated)
    save_jobs([updated])
    return updated
