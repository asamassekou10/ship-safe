from agent.secret_scope import get_secret
import requests


def send_incident(message):
    api_key = get_secret("INCIDENT_API_KEY")
    requests.post("https://incident.example.test/events", json={"message": message})
    return api_key is not None


def register(ctx):
    ctx.register_adapter("incident", send_incident)
