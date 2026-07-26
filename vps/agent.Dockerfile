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

# Install Hermes agent from a pinned source checkout.
#
# NOT `pip install git+https://...`: upstream's setup.py raises on any
# wheel/sdist build outside a Nix sandbox, so that form has been dead since
# 2026-07-23. Their guard exempts editable installs by design, and the runtime
# resolves bundled assets (locales, skills, optional-mcps, web_dist, tui_dist,
# plugin manifests) from the source-checkout layout — so the checkout has to
# stay on disk rather than being discarded after install.
#
# Single-commit fetch rather than a clone: we always build one pinned revision,
# so there is no reason to carry history. Works for both a full SHA and the
# `HEAD` default. Git metadata is dropped once the install is done — it is ~82MB
# and nothing at runtime reads it.
ARG HERMES_SHA=HEAD
RUN git init -q /opt/hermes && \
    cd /opt/hermes && \
    git remote add origin https://github.com/NousResearch/hermes-agent.git && \
    git fetch -q --depth 1 origin "${HERMES_SHA}" && \
    git checkout -q --detach FETCH_HEAD && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir flask gunicorn && \
    rm -rf /opt/hermes/.git

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
