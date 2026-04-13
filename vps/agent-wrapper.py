"""
Ship Safe — Hermes Agent HTTP Wrapper
Phase 3: Full streaming chat with structured SSE events.

SSE event types:
  event: token       data: "partial text..."
  event: tool_call   data: {"tool": "web_search", "args": {...}}
  event: tool_result data: {"tool": "web_search", "result": "..."}
  event: error       data: {"message": "..."}
  event: done        data: {"tokensUsed": N}

Config injected via HERMES_CONFIG env var (JSON string).
"""

import json
import os
import sys
import threading
import time
import traceback
import yaml
from pathlib import Path
from queue import Queue, Empty
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

    if memory_provider == "honcho":
        config["honcho"] = {"api_key": os.environ.get("HONCHO_API_KEY", "")}
    elif memory_provider == "mem0":
        config["mem0"] = {"api_key": os.environ.get("MEM0_API_KEY", "")}
    elif memory_provider == "hindsight":
        config["hindsight"] = {"api_key": os.environ.get("HINDSIGHT_API_KEY", "")}

    with open(HERMES_CONFIG_PATH, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    memory_md = MEMORY_PATH / "MEMORY.md"
    if not memory_md.exists():
        memory_md.write_text("# Agent Memory\n\nThis file is managed by the Hermes agent.\n")

    user_md = MEMORY_PATH / "USER.md"
    if not user_md.exists():
        user_md.write_text("# User Profile\n\nThis file is managed by the Hermes agent.\n")

bootstrap_hermes_config()

# ── Hermes integration ────────────────────────────────────────────────────────

def _sse(event: str, data) -> str:
    payload = data if isinstance(data, str) else json.dumps(data)
    return f"event: {event}\ndata: {payload}\n\n"

def run_hermes_streaming(message: str, queue: Queue):
    """
    Run Hermes agent and push structured SSE events onto the queue.
    Tries direct Python API first; falls back to subprocess streaming.
    """
    tokens_used = 0

    try:
        # ── Attempt 1: Direct Python API ────────────────────────────────────
        from hermes.agent import create_agent
        from hermes.config import HermesConfig

        cfg = HermesConfig.from_file(str(HERMES_CONFIG_PATH))

        # Inject LLM API keys from environment
        for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"):
            val = os.environ.get(key)
            if val:
                os.environ[key] = val  # ensure it's set for sub-processes too

        agent = create_agent(cfg)

        # Patch tool registry to intercept tool calls
        original_dispatch = None
        try:
            from hermes.tools.registry import registry

            original_dispatch = registry.dispatch

            def patched_dispatch(tool_name, **kwargs):
                queue.put(_sse("tool_call", {"tool": tool_name, "args": kwargs}))
                result = original_dispatch(tool_name, **kwargs)
                queue.put(_sse("tool_result", {"tool": tool_name, "result": str(result)[:500]}))
                return result

            registry.dispatch = patched_dispatch
        except Exception:
            pass  # Tool interception optional

        # Stream tokens
        response_text = ""
        for chunk in agent.stream(message):
            if isinstance(chunk, str):
                queue.put(_sse("token", chunk))
                response_text += chunk
                tokens_used += len(chunk.split())

        if original_dispatch:
            registry.dispatch = original_dispatch

        queue.put(_sse("done", {"tokensUsed": tokens_used, "response": response_text}))

    except (ImportError, AttributeError):
        # ── Fallback: subprocess streaming ──────────────────────────────────
        import subprocess

        env = os.environ.copy()
        proc = subprocess.Popen(
            [sys.executable, "-m", "hermes.run", "--message", message],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(Path.home()),
            env=env,
        )

        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip("\n")
            if not line:
                continue

            # Try to detect tool call lines (e.g. "Calling tool: web_search(query=...)")
            if line.startswith("Calling tool:") or "registry.dispatch" in line:
                parts = line.split(":", 1)
                tool_info = parts[1].strip() if len(parts) > 1 else line
                queue.put(_sse("tool_call", {"tool": tool_info, "args": {}}))
            elif line.startswith("Tool result:"):
                queue.put(_sse("tool_result", {"tool": "unknown", "result": line[12:].strip()[:500]}))
            else:
                # Regular token output — emit word by word for better streaming feel
                for word in line.split(" "):
                    queue.put(_sse("token", word + " "))
                    tokens_used += 1
                queue.put(_sse("token", "\n"))

        proc.wait()

        if proc.returncode != 0:
            err = proc.stderr.read()
            queue.put(_sse("error", {"message": err[:300]}))

        queue.put(_sse("done", {"tokensUsed": tokens_used}))

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
    POST /chat  body: {"message": "...", "sessionId": "optional"}
    Streams SSE: token | tool_call | tool_result | error | done
    """
    body    = request.get_json(silent=True) or {}
    message = (body.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    queue = Queue()

    # Run Hermes in a background thread so we can stream
    t = threading.Thread(target=run_hermes_streaming, args=(message, queue), daemon=True)
    t.start()

    def generate():
        while True:
            try:
                item = queue.get(timeout=120)
                if item is None:
                    break
                yield item
            except Empty:
                yield _sse("error", {"message": "Agent timed out"})
                break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
