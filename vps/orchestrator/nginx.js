/**
 * Nginx site config manager.
 * Each deployed agent gets its own nginx config + individual Let's Encrypt cert.
 * Certbot runs automatically on deploy — no wildcard cert needed.
 *
 * Subdomain format: {slug}.agents.shipsafecli.com
 */

const { execFile } = require('child_process');
const { promisify } = require('util');
const fs   = require('fs');
const path = require('path');

const exec = promisify(execFile);

const SITES_DIR   = process.env.NGINX_SITES_DIR || '/etc/nginx/sites-enabled';
const DOMAIN_BASE = process.env.VPS_SUBDOMAIN_BASE || 'agents.shipsafecli.com';
const CERTBOT_EMAIL = process.env.CERTBOT_EMAIL || 'alhassane.samassekou@gmail.com';

function siteFile(slug) {
  return path.join(SITES_DIR, `hermes-${slug}.conf`);
}

/** HTTP-only config written first — certbot upgrades it to HTTPS */
function httpConfig(slug, port) {
  const host = `${slug}.${DOMAIN_BASE}`;
  return `# Ship Safe — agent: ${slug}
# Auto-generated. Do not edit manually.

server {
    listen 80;
    server_name ${host};

    location / {
        proxy_pass         http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_buffering    off;
    }
}
`;
}

async function addSite(slug, port) {
  const host = `${slug}.${DOMAIN_BASE}`;
  const file = siteFile(slug);

  // 1. Write HTTP-only config
  fs.writeFileSync(file, httpConfig(slug, port), 'utf8');
  await exec('nginx', ['-t']);
  await exec('nginx', ['-s', 'reload']);

  // 2. Run certbot to get cert + auto-upgrade config to HTTPS
  try {
    await exec('certbot', [
      '--nginx',
      '-d', host,
      '--email', CERTBOT_EMAIL,
      '--agree-tos',
      '--no-eff-email',
      '--non-interactive',
      '--redirect',           // force HTTP→HTTPS redirect
    ]);
  } catch (e) {
    // Cert failed — agent still reachable over HTTP, log and continue
    console.error(`[nginx] certbot failed for ${host}:`, e.message);
  }
}

async function removeSite(slug) {
  const host = `${slug}.${DOMAIN_BASE}`;
  const file = siteFile(slug);
  if (fs.existsSync(file)) {
    fs.unlinkSync(file);
    // Also remove the certbot cert
    try {
      await exec('certbot', ['delete', '--cert-name', host, '--non-interactive']);
    } catch {}
    await exec('nginx', ['-s', 'reload']);
  }
}

module.exports = { addSite, removeSite };
