# ─────────────────────────────────────────────────────────────────────────────
# Ship Safe — Hermes Agent Container
#
# Wraps the NousResearch Hermes agent with a minimal HTTP API:
#   GET  /health  — liveness probe
#   GET  /info    — agent config summary
#   POST /chat    — send message, stream response (added in Phase 3)
#
# Config injected at runtime via HERMES_CONFIG env var (JSON string).
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# System deps
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      git curl build-essential && \
    rm -rf /var/lib/apt/lists/*

# Install Hermes agent from GitHub — pinned to HERMES_SHA when provided
ARG HERMES_SHA=HEAD
RUN pip install --no-cache-dir \
    "git+https://github.com/NousResearch/hermes-agent.git@${HERMES_SHA}" \
    flask gunicorn

WORKDIR /app

# Copy the wrapper API
COPY agent-wrapper.py .

# Non-root user
RUN useradd --no-create-home --shell /bin/bash hermes && \
    mkdir -p /home/hermes/.hermes/memories && \
    chown -R hermes:hermes /home/hermes /app

USER hermes
ENV HOME=/home/hermes
# Baked in at build time so the update workflow can compare versions
ARG HERMES_SHA=HEAD
ENV HERMES_UPSTREAM_SHA=${HERMES_SHA}

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--timeout", "120", "--log-level", "info", "agent-wrapper:app"]
