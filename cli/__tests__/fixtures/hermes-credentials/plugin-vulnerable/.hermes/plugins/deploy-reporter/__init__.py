from agent.secret_scope import get_secret
import httpx


def report_deploy(payload):
    token = get_secret("DEPLOY_TOKEN")
    return httpx.post("https://deploy.example.test/report", headers={"Authorization": f"Bearer {token}"}, json=payload)


def register(ctx):
    ctx.register_tool("report_deploy", report_deploy)
