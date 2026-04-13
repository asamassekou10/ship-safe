"""
Ship Safe — Hermes Agent HTTP Wrapper

Uses the `hermes chat -q MESSAGE -Q` CLI under the hood.
SSE event types emitted:
  event: token       data: "partial text..."
  event: tool_call   data: {"tool": "...", "args": {}}
  event: tool_result data: {"tool": "...", "result": "..."}
  event: error       data: {"message": "..."}
  event: done        data: {"tokensUsed": N}

Config injected via HERMES_CONFIG env var (JSON string).
"""

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from queue import Queue, Empty

import yaml
from flask import Flask, Response, jsonify, request, stream_with_context

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

RAW_CONFIG = os.environ.get("HERMES_CONFIG", "{}")
try:
    AGENT_CONFIG = json.loads(RAW_CONFIG)
except json.JSONDecodeError:
    AGENT_CONFIG = {}

HERMES_HOME   = Path.home() / ".hermes"
CONFIG_PATH   = HERMES_HOME / "config.yaml"
MEMORY_PATH   = HERMES_HOME / "memories"


def _detect_provider_and_model():
    """Return (provider, model, base_url) based on available env keys."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic", "claude-sonnet-4-6", "https://api.anthropic.com"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter", "openai/gpt-4o-mini", ""
    if os.environ.get("OPENAI_API_KEY"):
        # Hermes v0.8 forces the Responses API when base_url is api.openai.com,
        # which requires special encrypted content not supported by gpt-4o.
        # Signal this so the wrapper can emit a helpful error instead of silently failing.
        os.environ["_HERMES_OPENAI_UNSUPPORTED"] = "1"
        return "auto", "", ""
    return "auto", "", ""


def bootstrap_hermes_config():
    HERMES_HOME.mkdir(parents=True, exist_ok=True)
    MEMORY_PATH.mkdir(parents=True, exist_ok=True)

    provider, model, base_url = _detect_provider_and_model()
    memory_provider            = AGENT_CONFIG.get("memoryProvider", "builtin")
    max_depth                  = AGENT_CONFIG.get("maxDepth", 2)

    config: dict = {
        "memory_provider": memory_provider,
        "max_delegation_depth": max_depth,
    }
    if provider != "auto":
        config["model"] = {"provider": provider, "default": model}
        if base_url:
            config["model"]["base_url"] = base_url

    # Write hermes config.yaml
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    # Write ~/.hermes/.env so hermes's own credential resolver finds the keys.
    # This must happen AFTER _detect_provider_and_model() sets the bridged vars.
    env_path = HERMES_HOME / ".env"
    env_lines = []
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL"):
        val = os.environ.get(key)
        if val:
            env_lines.append(f"{key}={val}")
    env_path.write_text("\n".join(env_lines) + "\n")

    # Seed memory files
    for fname, heading in [("MEMORY.md", "# Agent Memory"), ("USER.md", "# User Profile")]:
        p = MEMORY_PATH / fname
        if not p.exists():
            p.write_text(f"{heading}\n\nThis file is managed by the Hermes agent.\n")


bootstrap_hermes_config()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sse(event: str, data) -> str:
    payload = data if isinstance(data, str) else json.dumps(data)
    return f"event: {event}\ndata: {payload}\n\n"


def _build_hermes_args(message: str, session_id: str) -> list:
    """Build the hermes CLI argument list."""
    # Provider was already resolved during bootstrap — use 'auto' here and
    # let hermes pick it up from config.yaml / .env.
    args = ["hermes", "chat", "-q", message, "-Q", "--source", "tool"]

    max_depth = AGENT_CONFIG.get("maxDepth", 2)
    if max_depth:
        args += ["--max-turns", str(max_depth * 10)]

    return args


# ── Streaming runner ──────────────────────────────────────────────────────────

def run_hermes_streaming(message: str, session_id: str, queue: Queue):
    tokens_used = 0

    try:
        # Check for unsupported key configuration before running hermes
        if os.environ.get("_HERMES_OPENAI_UNSUPPORTED"):
            queue.put(_sse("error", {
                "message": (
                    "OPENAI_API_KEY is not directly supported by Hermes v0.8. "
                    "Please use ANTHROPIC_API_KEY or OPENROUTER_API_KEY instead. "
                    "Get an OpenRouter key at openrouter.ai (it supports OpenAI models too)."
                )
            }))
            queue.put(_sse("done", {"tokensUsed": 0}))
            return

        env  = os.environ.copy()
        env["FORCE_COLOR"] = "1"   # make hermes output ANSI colors even in a pipe
        env["TERM"] = "xterm-256color"
        args = _build_hermes_args(message, session_id)

        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(Path.home()),
            env=env,
        )

        # Stream stdout line-by-line, emit each full line as one token so that
        # ANSI escape sequences (colors, box-drawing) are never split mid-sequence.
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip("\n")
            # Detect tool call lines
            if line.startswith("Calling tool:") or "→ tool:" in line.lower():
                parts = line.split(":", 1)
                tool_info = parts[1].strip() if len(parts) > 1 else line
                queue.put(_sse("tool_call", {"tool": tool_info, "args": {}}))
            elif line.startswith("Tool result:") or "← result:" in line.lower():
                queue.put(_sse("tool_result", {"tool": "unknown", "result": line.split(":", 1)[-1].strip()[:500]}))
            else:
                queue.put(_sse("token", line + "\n"))
                tokens_used += 1

        proc.wait()

        stderr_out = proc.stderr.read()
        if proc.returncode != 0 and tokens_used == 0:
            # Only surface stderr as error if we got no output at all
            queue.put(_sse("error", {"message": stderr_out[:400] if stderr_out else "Agent returned no output"}))

        queue.put(_sse("done", {"tokensUsed": tokens_used}))

    except FileNotFoundError:
        queue.put(_sse("error", {"message": "hermes CLI not found. Is hermes-agent installed?"}))
        queue.put(_sse("done", {"tokensUsed": 0}))
    except Exception as e:
        queue.put(_sse("error", {"message": str(e)}))
        queue.put(_sse("done", {"tokensUsed": 0}))
    finally:
        queue.put(None)  # sentinel


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
    })


@app.route("/chat", methods=["POST"])
def chat():
    """
    POST /chat  body: {"message": "...", "sessionId": "optional-run-id"}
    Streams SSE: token | tool_call | tool_result | error | done
    """
    body       = request.get_json(silent=True) or {}
    message    = (body.get("message") or "").strip()
    session_id = (body.get("sessionId") or "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    queue = Queue()

    t = threading.Thread(
        target=run_hermes_streaming,
        args=(message, session_id, queue),
        daemon=True,
    )
    t.start()

    def generate():
        while True:
            try:
                item = queue.get(timeout=120)
                if item is None:
                    break
                yield item
            except Empty:
                yield _sse("error", {"message": "Agent timed out after 2 minutes"})
                break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
