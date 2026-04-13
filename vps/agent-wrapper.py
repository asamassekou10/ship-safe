"""
Ship Safe — Hermes Agent HTTP Wrapper
Exposes a minimal HTTP API around the Hermes agent CLI.

Phase 2: /health and /info endpoints.
Phase 3: /chat with SSE streaming.

Config is injected via HERMES_CONFIG env var as a JSON string:
  {
    "tools": [{"name": "web_search"}, ...],
    "memoryProvider": "builtin",
    "maxDepth": 2
  }
"""

import json
import os
import subprocess
import sys
import yaml
from pathlib import Path
from flask import Flask, Response, jsonify, request, stream_with_context

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

RAW_CONFIG = os.environ.get("HERMES_CONFIG", "{}")
try:
    AGENT_CONFIG = json.loads(RAW_CONFIG)
except json.JSONDecodeError:
    AGENT_CONFIG = {}

HERMES_CONFIG_PATH = Path.home() / ".hermes" / "config.yaml"
MEMORY_PATH        = Path.home() / ".hermes" / "memories"

def bootstrap_hermes_config():
    """Write ~/.hermes/config.yaml from injected AGENT_CONFIG."""
    HERMES_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.mkdir(parents=True, exist_ok=True)

    memory_provider = AGENT_CONFIG.get("memoryProvider", "builtin")
    tools           = [t["name"] for t in AGENT_CONFIG.get("tools", [])]
    max_depth       = AGENT_CONFIG.get("maxDepth", 2)

    config = {
        "memory_provider": memory_provider,
        "max_delegation_depth": max_depth,
        "allowed_tools": tools,
    }

    # External memory provider config
    if memory_provider == "honcho":
        config["honcho"] = {"api_key": os.environ.get("HONCHO_API_KEY", "")}
    elif memory_provider == "mem0":
        config["mem0"] = {"api_key": os.environ.get("MEM0_API_KEY", "")}
    elif memory_provider == "hindsight":
        config["hindsight"] = {"api_key": os.environ.get("HINDSIGHT_API_KEY", "")}

    with open(HERMES_CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    # Seed MEMORY.md if not present
    memory_md = MEMORY_PATH / "MEMORY.md"
    if not memory_md.exists():
        memory_md.write_text("# Agent Memory\n\nThis file is managed by the Hermes agent.\n")

    user_md = MEMORY_PATH / "USER.md"
    if not user_md.exists():
        user_md.write_text("# User Profile\n\nThis file is managed by the Hermes agent.\n")

# Bootstrap on startup
bootstrap_hermes_config()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True, "status": "running"})


@app.route("/info")
def info():
    return jsonify({
        "tools":          [t["name"] for t in AGENT_CONFIG.get("tools", [])],
        "memoryProvider": AGENT_CONFIG.get("memoryProvider", "builtin"),
        "maxDepth":       AGENT_CONFIG.get("maxDepth", 2),
        "configPath":     str(HERMES_CONFIG_PATH),
    })


@app.route("/chat", methods=["POST"])
def chat():
    """
    Phase 3 stub — streams a Hermes agent response.
    POST /chat  body: { "message": "..." }
    Response: text/event-stream with SSE data frames.
    """
    body = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    def generate():
        # Run hermes CLI in non-interactive mode
        # Phase 3 will replace this with the proper Hermes Python API
        try:
            proc = subprocess.Popen(
                ["python", "-m", "hermes.run", "--non-interactive", "--message", message],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=str(Path.home()),
            )
            for line in proc.stdout:
                yield f"data: {json.dumps(line)}\n\n"
            proc.wait()
            if proc.returncode != 0:
                err = proc.stderr.read()
                yield f"data: {json.dumps({'error': err})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        yield "event: done\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
