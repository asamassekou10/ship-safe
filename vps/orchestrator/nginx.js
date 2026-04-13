/**
 * Nginx site config manager.
 * Each deployed agent gets its own config file under /etc/nginx/sites-enabled/.
 *
 * Requires:
 *   - /etc/nginx/sites-enabled/ directory (created by setup.sh)
 *   - nginx service running with `nginx -s reload` capability
 *   - Wildcard SSL cert at /etc/letsencrypt/live/shipsafecli.com/
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
const SSL_CERT    = process.env.SSL_CERT || '/etc/letsencrypt/live/shipsafecli.com/fullchain.pem';
const SSL_KEY     = process.env.SSL_KEY  || '/etc/letsencrypt/live/shipsafecli.com/privkey.pem';

function siteFile(slug) {
  return path.join(SITES_DIR, `hermes-${slug}.conf`);
}

function siteConfig(slug, port) {
  const host = `${slug}.${DOMAIN_BASE}`;
  return `# Ship Safe — agent: ${slug}
# Auto-generated. Do not edit manually.

server {
    listen 80;
    server_name ${host};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${host};

    ssl_certificate     ${SSL_CERT};
    ssl_certificate_key ${SSL_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000" always;

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
  const file = siteFile(slug);
  fs.writeFileSync(file, siteConfig(slug, port), 'utf8');
  await exec('nginx', ['-t']);      // test config before reload
  await exec('nginx', ['-s', 'reload']);
}

async function removeSite(slug) {
  const file = siteFile(slug);
  if (fs.existsSync(file)) {
    fs.unlinkSync(file);
    await exec('nginx', ['-s', 'reload']);
  }
}

module.exports = { addSite, removeSite };
