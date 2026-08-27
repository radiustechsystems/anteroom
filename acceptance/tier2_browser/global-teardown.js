import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';

export default async function globalTeardown() {
  const project = process.env.ANTEROOM_TIER2_PROJECT;
  const dir = process.env.ANTEROOM_TIER2_DIR;
  if (!project || !dir) return;
  let stopped = false;
  try {
    execFileSync('docker', ['compose', '-p', project, 'down', '--volumes', '--remove-orphans'], {
      cwd: dir, stdio: 'inherit',
    });
    stopped = true;
  } catch (err) {
    console.error('tier 2 teardown failed:', err.message);
  }
  // Keep the Compose files when teardown fails: they are the recovery handle
  // for the still-running project. A clean stop leaves no reason to retain the
  // temporary config, copied pages, or directory.
  if (stopped) rmSync(dir, { recursive: true, force: true });
}
