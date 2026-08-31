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
const CERTBOT_EMAIL = process.env.CERTBOT_EMAIL || null;

function assertValidSlug(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(slug)) {
    throw new Error('Invalid agent slug');
  }
  return slug;
}

function siteFile(slug) {
  assertValidSlug(slug);
  return path.join(SITES_DIR, `hermes-${slug}.conf`);
}

/** HTTP-only config written first — certbot upgrades it to HTTPS */
function httpConfig(slug, port) {
  assertValidSlug(slug);
  const host = `${slug}.${DOMAIN_BASE}`;
  return `# Ship Safe — agent: ${slug}
# Auto-generated. Do not edit manually.

server {
    listen 80;
    server_name ${host};

    location / {
        proxy_pass         http://127.0.0.1:${port}; # ship-safe-ignore — bounded loopback container proxy
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
  assertValidSlug(slug);
  const host = `${slug}.${DOMAIN_BASE}`;
  const file = siteFile(slug);

  // 1. Write HTTP-only config
  fs.writeFileSync(file, httpConfig(slug, port), 'utf8');
  await exec('sudo', ['nginx', '-t']);
  await exec('sudo', ['nginx', '-s', 'reload']);

  // 2. Run certbot to get cert + auto-upgrade config to HTTPS
  try {
    const certbotArgs = [
      'certbot', '--nginx',
      '-d', host,
      '--agree-tos',
      '--non-interactive',
      '--redirect',
    ];
    if (CERTBOT_EMAIL) {
      certbotArgs.push('--email', CERTBOT_EMAIL, '--no-eff-email');
    } else {
      certbotArgs.push('--register-unsafely-without-email');
    }
    await exec('sudo', certbotArgs);
  } catch (e) {
    // Cert failed — agent still reachable over HTTP, log and continue
    console.error(`[nginx] certbot failed for ${host}:`, e.message);
  }
}

async function removeSite(slug) {
  assertValidSlug(slug);
  const host = `${slug}.${DOMAIN_BASE}`;
  const file = siteFile(slug);
  if (fs.existsSync(file)) {
    fs.unlinkSync(file);
    try {
      await exec('sudo', ['certbot', 'delete', '--cert-name', host, '--non-interactive']);
    } catch {}
    await exec('sudo', ['nginx', '-s', 'reload']);
  }
}

module.exports = { addSite, removeSite };
