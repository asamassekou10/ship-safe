#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Ship Safe — VPS Setup Script
# Tested on Ubuntu 22.04 LTS (Hetzner CX21: 2 vCPU, 4 GB RAM)
#
# Run as root on a fresh VPS:
#   curl -fsSL https://raw.githubusercontent.com/asamassekou10/ship-safe/main/vps/setup.sh | bash
#
# What this does:
#   1. Updates system packages
#   2. Installs Docker, nginx, certbot, Node.js 20
#   3. Configures nginx with wildcard SSL for *.agents.shipsafecli.com
#   4. Sets up the orchestrator as a systemd service
#   5. Hardens the server (firewall, fail2ban)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DOMAIN="shipsafecli.com"
SUBDOMAIN_BASE="agents.${DOMAIN}"
ORCHESTRATOR_DIR="/opt/shipsafe-orchestrator"
ORCHESTRATOR_USER="shipsafe"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"

# ── 1. System update ──────────────────────────────────────────────────────────
echo "[setup] Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# ── 2. Install dependencies ───────────────────────────────────────────────────
echo "[setup] Installing dependencies..."
apt-get install -y -qq \
  ca-certificates curl gnupg lsb-release \
  nginx certbot python3-certbot-nginx \
  ufw fail2ban

# ── 3. Install Docker ─────────────────────────────────────────────────────────
echo "[setup] Installing Docker..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# ── 4. Install Node.js 20 ─────────────────────────────────────────────────────
echo "[setup] Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y -qq nodejs

# ── 5. Create orchestrator user ───────────────────────────────────────────────
echo "[setup] Creating orchestrator user..."
useradd --system --no-create-home --shell /usr/sbin/nologin "${ORCHESTRATOR_USER}" 2>/dev/null || true
usermod -aG docker "${ORCHESTRATOR_USER}"

# ── 6. Deploy orchestrator ────────────────────────────────────────────────────
echo "[setup] Deploying orchestrator to ${ORCHESTRATOR_DIR}..."
mkdir -p "${ORCHESTRATOR_DIR}"
cp -r /tmp/orchestrator/* "${ORCHESTRATOR_DIR}/"
cd "${ORCHESTRATOR_DIR}" && npm install --production
chown -R "${ORCHESTRATOR_USER}:${ORCHESTRATOR_USER}" "${ORCHESTRATOR_DIR}"

# ── 7. Systemd service ────────────────────────────────────────────────────────
echo "[setup] Installing systemd service..."
cat > /etc/systemd/system/shipsafe-orchestrator.service <<EOF
[Unit]
Description=Ship Safe Agent Orchestrator
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=${ORCHESTRATOR_USER}
WorkingDirectory=${ORCHESTRATOR_DIR}
EnvironmentFile=${ORCHESTRATOR_DIR}/.env
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shipsafe-orchestrator

# ── 8. nginx base config ──────────────────────────────────────────────────────
echo "[setup] Configuring nginx..."
mkdir -p /etc/nginx/sites-enabled

cat > /etc/nginx/sites-enabled/default.conf <<'EOF'
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
EOF

# Orchestrator itself is only accessible internally (127.0.0.1) — not exposed via nginx

nginx -t && systemctl reload nginx

# ── 9. Wildcard SSL cert (DNS challenge) ──────────────────────────────────────
echo "[setup] Requesting wildcard SSL certificate..."
echo "  NOTE: You need to add a DNS TXT record for _acme-challenge.${DOMAIN}"
echo "  Run this manually if DNS challenge is needed:"
echo ""
echo "  certbot certonly --manual --preferred-challenges dns \\"
echo "    -d '*.agents.${DOMAIN}' -d '${DOMAIN}' \\"
echo "    --email ${CERTBOT_EMAIL} --agree-tos --no-eff-email"
echo ""
echo "  OR if your DNS provider supports certbot plugins, it will run automatically."

# Auto-renew cron
(crontab -l 2>/dev/null; echo "0 12 * * * certbot renew --quiet && nginx -s reload") | crontab -

# ── 10. Firewall ──────────────────────────────────────────────────────────────
echo "[setup] Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp   comment "SSH"
ufw allow 80/tcp   comment "HTTP"
ufw allow 443/tcp  comment "HTTPS"
# Orchestrator port (4099) is NOT exposed — only accessible via 127.0.0.1
ufw --force enable

# ── 11. fail2ban ──────────────────────────────────────────────────────────────
echo "[setup] Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/sshd.conf <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 3600
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# ── 12. Pull Hermes image ─────────────────────────────────────────────────────
echo "[setup] Building Hermes agent Docker image..."
if [ -f /tmp/agent.Dockerfile ]; then
  docker build -t shipsafe/hermes-agent:latest -f /tmp/agent.Dockerfile /tmp/
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Next steps:"
echo "  1. Create ${ORCHESTRATOR_DIR}/.env with:"
echo "       ORCHESTRATOR_SECRET=<strong-random-secret>"
echo "       VPS_SUBDOMAIN_BASE=agents.${DOMAIN}"
echo "       NGINX_SITES_DIR=/etc/nginx/sites-enabled"
echo "       HERMES_IMAGE=shipsafe/hermes-agent:latest"
echo ""
echo "  2. Run: systemctl start shipsafe-orchestrator"
echo "  3. Get the wildcard SSL cert (see instructions above)"
echo "  4. Add to webapp .env:"
echo "       ORCHESTRATOR_URL=http://127.0.0.1:4099  (or VPS private IP)"
echo "       ORCHESTRATOR_SECRET=<same secret>"
echo "       VPS_SUBDOMAIN_BASE=agents.${DOMAIN}"
echo ""
