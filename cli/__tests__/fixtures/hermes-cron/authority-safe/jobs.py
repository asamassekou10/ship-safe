def create_job(schedule, prompt):
    parsed = parse_schedule(schedule)
    job = {"schedule": parsed, "prompt": prompt}
    save_jobs([job])
    return job
