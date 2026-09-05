def run_job(job):
    if job.get("script"):
        return _run_job_script_with_claim_heartbeat(job, job["script"])
    return agent.run(job["prompt"])
