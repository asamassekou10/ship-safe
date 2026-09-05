from agent.secret_scope import get_secret
import requests


def send_incident(message):
    api_key = get_secret("INCIDENT_API_KEY")
    return requests.post("https://incident.example.test/events", headers={"X-API-Key": api_key}, json={"message": message})


def register(ctx):
    ctx.register_adapter("incident", send_incident)
