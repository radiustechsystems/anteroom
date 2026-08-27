// Stands up a deployment for the browser tier and waits for it to serve.
//
// Two properties matter and neither is the default: a short pass_ttl, so
// liveness is observable inside a test's patience; and a secure context, which
// over plain HTTP means reaching the gate at loopback and nowhere else.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const root = resolve(here, '../..');

// pass_ttl is 5s so a lapse can be waited out; max_session must be at least
// pass_ttl, and is 20s so the renewal chain can be seen both working and being
// capped inside one test.
const config = `listen = ":8080"
pass_ttl = "5s"
max_session = "20s"
difficulty = 12
renew_difficulty = 4
pages = "/etc/anteroom/pages"
inject = true
# Include the licensed JavaScript fallback so the browser tier can run its
# known-answer vectors. Loopback is still a secure context, so normal admission
# continues to exercise and prefer WebCrypto.
allow_insecure_context = true
trusted_proxies = []

[bypass]
paths = ["/robots.txt", "/sitemap.xml", "/feed.xml", "/.well-known/*", "/webhooks/*", "/healthz", "/app-sw.js"]
cidrs = []
`;

const compose = (root) => `services:
  anteroom:
    build:
      context: ${root}
      dockerfile: Dockerfile
    image: anteroom:local
    ports:
      - "\${GATE_PORT}:8080"
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
      - ./pages:/etc/anteroom/pages:ro
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=\${ANTEROOM_HMAC_KEY}
    depends_on:
      app:
        condition: service_started
  app:
    build: ${root}/examples/hello-app
    image: hello-app:local
    expose:
      - "3000"
    environment:
      - HELLO_LISTEN=:3000
`;

async function freePort() {
  const { createServer } = await import('node:net');
  return new Promise((res, rej) => {
    const srv = createServer();
    srv.on('error', rej);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => res(port));
    });
  });
}

export default async function globalSetup() {
  const dir = mkdtempSync(join(tmpdir(), 'anteroom-tier2-'));
  const port = await freePort();
  const key = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64');

  writeFileSync(join(dir, 'anteroom.toml'), config);
  writeFileSync(join(dir, 'compose.yaml'), compose(root));
  cpSync(join(root, 'examples/anteroomized/pages'), join(dir, 'pages'), { recursive: true });

  const project = `artier2-${port}`;
  const env = { ...process.env, GATE_PORT: String(port), ANTEROOM_HMAC_KEY: key };

  try {
    execFileSync('docker', ['compose', '-p', project, 'up', '-d', '--build'], {
      cwd: dir, env, stdio: 'inherit',
    });

    const base = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + 45_000;
    for (;;) {
      try {
        const r = await fetch(`${base}/.anteroom/healthz`);
        if (r.ok) break;
      } catch { /* not up yet */ }
      if (Date.now() > deadline) {
        throw new Error(`gate never became ready at ${base}`);
      }
      await new Promise((r) => setTimeout(r, 300));
    }

    process.env.ANTEROOM_BASE_URL = base;
    process.env.ANTEROOM_TIER2_PROJECT = project;
    process.env.ANTEROOM_TIER2_DIR = dir;
    console.log(`tier 2: gate ready at ${base} (project ${project})`);
  } catch (err) {
    // Global teardown is not called when setup fails. Recover the partial
    // Compose project here so a bad config or image cannot leak local state.
    try {
      execFileSync('docker', ['compose', '-p', project, 'down', '--volumes', '--remove-orphans'], {
        cwd: dir, env, stdio: 'inherit',
      });
    } catch (cleanupErr) {
      console.error('tier 2 setup cleanup failed:', cleanupErr.message);
    }
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}
