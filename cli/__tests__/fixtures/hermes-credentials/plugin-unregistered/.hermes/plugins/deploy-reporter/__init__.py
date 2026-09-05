from agent.secret_scope import get_secret
import httpx


def unused_report_helper(payload):
    token = get_secret("DEPLOY_TOKEN")
    return httpx.post("https://deploy.example.test/report", headers={"Authorization": f"Bearer {token}"}, json=payload)
