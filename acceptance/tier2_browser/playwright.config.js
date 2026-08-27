// Tier 2 supplies browser evidence. No Go test can register a service
// worker, observe bfcache, or exercise engine-specific fetch metadata.
//
// The deployment under test uses a deliberately short pass_ttl so that liveness
// properties — the pass lapsing when nobody is present, the renewal chain being
// capped — are observable in seconds rather than half an hour.
import { defineConfig, devices } from '@playwright/test';

// Firefox's service-worker fetches keep the browser's native User-Agent even
// when Playwright emulates another platform's UA on document requests. That
// artificial split is incompatible with Anteroom's intentional solver-UA
// binding: the worker earns a Linux-bound pass and the emulated Windows
// navigation cannot spend it. Keep the desktop viewport and input profile, but
// let both request paths use Firefox's real UA.
const { userAgent: _firefoxEmulatedUA, ...firefoxDesktop } = devices['Desktop Firefox'];

export default defineConfig({
  testDir: './tests',
  // Serial: these tests share one deployment and several of them depend on
  // whether a pass currently exists, which is global state by construction.
  workers: 1,
  fullyParallel: false,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  globalSetup: './global-setup.js',
  globalTeardown: './global-teardown.js',
  use: {
    baseURL: process.env.ANTEROOM_BASE_URL || 'http://127.0.0.1:8080',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      // Firefox rewrites service-worker navigation metadata differently from
      // Chromium, so both engines are required for coexistence coverage.
      name: 'firefox',
      use: { ...firefoxDesktop },
    },
    {
      // A phone profile, because the honest question about proof-of-work is
      // what it costs the visitor with the slowest device and the smallest
      // battery — not what it costs a laptop.
      name: 'mobile',
      use: { ...devices['Pixel 7'] },
    },
  ],
});
