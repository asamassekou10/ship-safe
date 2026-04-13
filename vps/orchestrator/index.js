/**
 * Ship Safe — Agent Orchestrator
 * Runs on the VPS. Manages Hermes agent Docker containers.
 *
 * Protected by bearer token (ORCHESTRATOR_SECRET env var).
 * All Docker commands use execFile with explicit arg arrays — no shell injection.
 *
 * Routes:
 *   POST /deploy         — start a new agent container
 *   POST /stop           — stop a running container
 *   GET  /status/:name   — container status
 *   GET  /logs/:name     — stream container logs
 *   GET  /health         — liveness probe
 */

const http    = require('http');
const { execFile } = require('child_process');
const { promisify } = require('util');
const fs      = require('fs');
const path    = require('path');
const nginx   = require('./nginx');

const exec = promisify(execFile);

const SECRET      = process.env.ORCHESTRATOR_SECRET;
const PORT        = parseInt(process.env.PORT || '4099', 10);
const PORT_START  = 4100;
const PORT_END    = 4250;
const PORTS_FILE  = path.join(__dirname, 'ports.json');
const HERMES_IMAGE = process.env.HERMES_IMAGE || 'shipsafe/hermes-agent:latest';
const MEMORY_MB   = parseInt(process.env.CONTAINER_MEMORY_MB || '512', 10);
const CPU_QUOTA   = process.env.CONTAINER_CPU_QUOTA || '50000'; // 50% of one core

if (!SECRET) {
  console.error('[orchestrator] ORCHESTRATOR_SECRET is required');
  process.exit(1);
}

// ── Port pool ─────────────────────────────────────────────────────────────────

function loadPorts() {
  try { return JSON.parse(fs.readFileSync(PORTS_FILE, 'utf8')); }
  catch { return {}; }
}

function savePorts(ports) {
  fs.writeFileSync(PORTS_FILE, JSON.stringify(ports, null, 2));
}

/** Get ports actually bound by running Docker containers — source of truth. */
async function getDockerBoundPorts() {
  try {
    const { stdout } = await exec('docker', [
      'ps', '--format', '{{.Ports}}',
    ]);
    const used = new Set();
    for (const line of stdout.split('\n')) {
      const m = line.match(/127\.0\.0\.1:(\d+)->/g);
      if (m) m.forEach(s => used.add(parseInt(s.match(/(\d+)->/)[1], 10)));
    }
    return used;
  } catch {
    return new Set();
  }
}

async function allocatePort(agentId) {
  const ports      = loadPorts();
  const fileUsed   = new Set(Object.values(ports));
  const dockerUsed = await getDockerBoundPorts();
  const used       = new Set([...fileUsed, ...dockerUsed]);

  for (let p = PORT_START; p <= PORT_END; p++) {
    if (!used.has(p)) {
      ports[agentId] = p;
      savePorts(ports);
      return p;
    }
  }
  throw new Error('No free ports available');
}

function releasePort(agentId) {
  const ports = loadPorts();
  delete ports[agentId];
  savePorts(ports);
}

// ── Docker helpers ────────────────────────────────────────────────────────────

function sanitizeContainerName(name) {
  return name.replace(/[^a-z0-9_-]/g, '-').slice(0, 63);
}

async function dockerRun({ containerName, port, envVars, agentConfig }) {
  const args = [
    'run', '-d',
    '--name', containerName,
    '--restart', 'unless-stopped',
    '--memory', `${MEMORY_MB}m`,
    '--memory-swap', `${MEMORY_MB}m`,
    '--cpu-quota', CPU_QUOTA,
    '--network', 'bridge',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '-p', `127.0.0.1:${port}:8080`,
    '-e', `HERMES_CONFIG=${JSON.stringify(agentConfig)}`,
    '-e', `PORT=8080`,
  ];

  // Inject per-agent env vars (tool API keys, etc.)
  for (const [key, value] of Object.entries(envVars || {})) {
    if (/^[A-Z0-9_]+$/.test(key)) {
      args.push('-e', `${key}=${value}`);
    }
  }

  args.push(HERMES_IMAGE);

  const { stdout } = await exec('docker', args);
  return stdout.trim(); // container ID
}

async function dockerStop(containerName) {
  await exec('docker', ['stop', containerName]);
  await exec('docker', ['rm', containerName]);
}

async function dockerStatus(containerName) {
  try {
    const { stdout } = await exec('docker', [
      'inspect', '--format',
      '{{.State.Status}}|{{.State.StartedAt}}|{{.State.FinishedAt}}',
      containerName,
    ]);
    const [status, startedAt, finishedAt] = stdout.trim().split('|');
    return { running: status === 'running', status, startedAt, finishedAt };
  } catch {
    return { running: false, status: 'removed', startedAt: null, finishedAt: null };
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────

function send(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 16384) reject(new Error('Body too large')); });
    req.on('end', () => {
      try { resolve(JSON.parse(data)); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function auth(req) {
  const header = req.headers['authorization'] || '';
  return header === `Bearer ${SECRET}`;
}

const server = http.createServer(async (req, res) => {
  if (!auth(req)) return send(res, 401, { error: 'Unauthorized' });

  const { method, url } = req;

  // GET /health
  if (method === 'GET' && url === '/health') {
    return send(res, 200, { ok: true, ts: new Date().toISOString() });
  }

  // POST /deploy
  if (method === 'POST' && url === '/deploy') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: e.message }); }

    const { agentId, slug, tools, memoryProvider, maxDepth, envVars } = body;
    if (!agentId || !slug) return send(res, 400, { error: 'agentId and slug are required' });

    const containerName = sanitizeContainerName(`hermes-${agentId}`);

    // Stop any existing container for this agent
    try { await dockerStop(containerName); } catch {}
    releasePort(agentId);

    let port;
    try { port = await allocatePort(agentId); } catch (e) { return send(res, 503, { error: e.message }); }

    const agentConfig = { tools, memoryProvider, maxDepth };

    try {
      const containerId = await dockerRun({ containerName, port, envVars, agentConfig });
      await nginx.addSite(slug, port);
      return send(res, 200, { containerId, containerName, port, subdomain: slug });
    } catch (e) {
      releasePort(agentId);
      console.error('[deploy]', e.message);
      return send(res, 500, { error: e.message });
    }
  }

  // POST /stop
  if (method === 'POST' && url === '/stop') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: e.message }); }

    const { agentId, slug, containerName } = body;
    if (!containerName) return send(res, 400, { error: 'containerName required' });

    try {
      await dockerStop(sanitizeContainerName(containerName));
      if (slug) await nginx.removeSite(slug);
      if (agentId) releasePort(agentId);
      return send(res, 200, { ok: true });
    } catch (e) {
      return send(res, 500, { error: e.message });
    }
  }

  // GET /status/:name
  const statusMatch = url.match(/^\/status\/([a-z0-9_-]+)$/);
  if (method === 'GET' && statusMatch) {
    const status = await dockerStatus(statusMatch[1]);
    return send(res, 200, status);
  }

  // GET /logs/:name  — streams last 100 lines + follows
  const logsMatch = url.match(/^\/logs\/([a-z0-9_-]+)(\?.*)?$/);
  if (method === 'GET' && logsMatch) {
    const name = logsMatch[1];
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });

    const child = require('child_process').spawn('docker', [
      'logs', '--follow', '--tail', '100', '--timestamps', name,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });

    function emit(data) {
      res.write(`data: ${JSON.stringify(data.toString())}\n\n`);
    }

    child.stdout.on('data', emit);
    child.stderr.on('data', emit);
    child.on('close', () => { res.write('event: close\ndata: {}\n\n'); res.end(); });
    req.on('close', () => child.kill());
    return;
  }

  // POST /chat/:port  — proxy SSE stream to agent container on 127.0.0.1:port
  const chatMatch = url.match(/^\/chat\/(\d+)$/);
  if (method === 'POST' && chatMatch) {
    const port = parseInt(chatMatch[1], 10);
    if (port < PORT_START || port > PORT_END) return send(res, 400, { error: 'Invalid port' });

    let body = '';
    req.on('data', c => { body += c; });
    req.on('end', async () => {
      try {
        const agentRes = await fetch(`http://127.0.0.1:${port}/chat`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        });

        if (!agentRes.ok || !agentRes.body) {
          return send(res, 502, { error: 'Agent error' });
        }

        res.writeHead(200, {
          'Content-Type':      'text/event-stream',
          'Cache-Control':     'no-cache',
          'Connection':        'keep-alive',
          'X-Accel-Buffering': 'no',
        });

        const reader = agentRes.body.getReader();
        const pump = async () => {
          while (true) {
            const { done, value } = await reader.read();
            if (done) { res.end(); break; }
            res.write(value);
          }
        };
        pump().catch(() => res.end());
        req.on('close', () => reader.cancel());
      } catch (e) {
        send(res, 502, { error: e.message });
      }
    });
    return;
  }

  send(res, 404, { error: 'Not found' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[orchestrator] listening on 0.0.0.0:${PORT}`);
});
