// Tier 2: the parts only a real browser can answer.
//
// Everything here is either a service-worker property or a timing property of
// the renewal loop.
import { test, expect } from '@playwright/test';

const CONTENT = 'hello from the app';
const WAIT_PAGE = 'Pardon us for a moment';

// A fresh context per test: a pass is per-browser state, and a test that
// inherits one from its predecessor is not testing what it says it is.
test.beforeEach(async ({ context }) => {
  await context.clearCookies();
});

// The insecure-context fallback is a vendored implementation behind a tiny
// adapter. Exercise it directly even though loopback provides WebCrypto and the
// production solver correctly prefers that faster path.
test('T2.0 the JavaScript SHA-256 fallback passes known-answer vectors', async ({ page }) => {
  await page.route('**/.anteroom/answer', async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'known-answer test stops before admission' }),
    });
  });
  await page.goto('/', { waitUntil: 'domcontentloaded' });

  const digests = await page.evaluate(() => {
    const hex = (bytes) => Array.from(bytes, (b) =>
      b.toString(16).padStart(2, '0')).join('');
    const encode = new TextEncoder();
    return {
      empty: hex(anteroomSHA256(encode.encode(''))),
      abc: hex(anteroomSHA256(encode.encode('abc'))),
    };
  });

  expect(digests.empty).toBe(
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  expect(digests.abc).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

// T2.1 — the whole point, in one test. A visitor navigates and ends up at the
// content, unattended.
test('T2.1 a navigation reaches the content without interaction', async ({ page }) => {
  const started = Date.now();
  await page.goto('/');

  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
  console.log(`admitted in ${Date.now() - started} ms`);
});

// T2.2 — the wait page has to say something while it works. A blank
// interstitial is indistinguishable from a hung one.
test('T2.2 the wait page reports progress', async ({ page }) => {
  let releaseSolver;
  const solverHeld = new Promise((resolve) => { releaseSolver = resolve; });
  await page.route(/\/\.anteroom\/solver\.[0-9a-f]{32}\.js$/, async (route) => {
    await solverHeld;
    await route.continue();
  });

  await page.goto('/', { waitUntil: 'commit' });
  try {
    // Holding the deferred solver makes the initial state observable instead
    // of racing the fast solve and the navigation that replaces this document.
    await expect(page.locator('#anteroom-status')).toHaveText('Starting…');
  } finally {
    releaseSolver();
  }
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
});

// T2.3 — the worker's shape is a security property, not an implementation
// detail. A fetch handler would turn a renewal helper into a full-origin
// interception surface, and claiming "/" would evict an operator's own worker.
test('T2.3 the renewal worker is narrow and has no fetch handler', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });

  const scopes = await page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    return regs.map((r) => r.scope);
  });
  const ours = scopes.filter((s) => s.includes('/.anteroom/'));
  expect(ours.length, `no Anteroom worker registered; scopes: ${scopes}`).toBeGreaterThan(0);
  for (const scope of ours) {
    expect(scope.endsWith('/.anteroom/'), `worker scope ${scope} is wider than /.anteroom/`).toBeTruthy();
  }

  // The served script must contain no fetch handler at all. Reading the source
  // is the assertion: a handler that exists but is currently inert is still a
  // handler, and the rule is that it must never gain one.
  const src = await page.evaluate(async () => (await fetch('/.anteroom/sw.js')).text());
  expect(/addEventListener\(\s*["']fetch["']/.test(src),
    'the renewal worker registers a fetch handler').toBeFalsy();
  expect(/clients\.claim\(\)/.test(src),
    'the renewal worker calls clients.claim(), taking control of pages it has no need to control').toBeFalsy();
});

// T2.4 — the application registers its own root-scoped
// worker with a catch-all fetch handler; both must survive, and renewal must
// still work.
test('T2.4 coexists with the site\'s own root-scoped service worker', async ({ page }) => {
  // Install the application's worker first, so it is the incumbent.
  await page.goto('/sw-owner');
  await expect(page.locator('#marker')).toHaveText(/root-scoped service worker/, { timeout: 15_000 });
  await expect(page.locator('#sw-state')).toHaveText(/registered:/, { timeout: 20_000 });

  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });

  const scopes = await page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    return regs.map((r) => r.scope);
  });
  const rootScoped = scopes.filter((s) => new URL(s).pathname === '/');
  const anteroom = scopes.filter((s) => s.includes('/.anteroom/'));

  expect(rootScoped.length, `the application's own worker was evicted; scopes: ${scopes}`).toBeGreaterThan(0);
  expect(anteroom.length, `Anteroom's worker was evicted; scopes: ${scopes}`).toBeGreaterThan(0);

  // And the gate's endpoints still answer as the gate, rather than being
  // swallowed by the application's catch-all handler.
  const kind = await page.evaluate(async () => {
    const r = await fetch('/.anteroom/challenge');
    return (await r.json()).kind;
  });
  expect(['admit', 'renew']).toContain(kind);
});

// T2.12 / T2.5 — the visitor stays admitted while
// reading, past the point where the original pass would have lapsed.
test('T2.5 stays admitted past pass_ttl while the page is open', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });

  // pass_ttl is 5s in this deployment. Wait well past it with the page open.
  await page.waitForTimeout(12_000);

  await page.goto('/about');
  await expect(page.locator('#marker')).toHaveText('second document', { timeout: 15_000 });
  await expect(page.locator('body')).not.toContainText(WAIT_PAGE);
});

// T2.6 — a pass lapses after all pages close, rather than remaining live on an
// unattended device.
test('T2.6 the pass lapses once no page is open', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });

  const cookies = await context.cookies();
  const pass = cookies.find((c) => c.name === 'anteroom_pass');
  expect(pass, 'no pass cookie after admission').toBeTruthy();
  await page.close();

  // With no driver page, renewal stops — but not instantly, and the gap is the
  // point of this test. The worker treats three missed pings (DRIVER_STALE_MS,
  // 15s) as "every tab is gone", so the pass lapses within roughly
  // DRIVER_STALE_MS + pass_ttl of the last tab closing, not within pass_ttl.
  // Waiting only pass_ttl here would fail against a perfectly correct gate.
  const DRIVER_STALE_MS = 15_000;
  const PASS_TTL_MS = 5_000;
  await new Promise((r) => setTimeout(r, DRIVER_STALE_MS + PASS_TTL_MS + 5_000));

  const res = await context.request.get('/', {
    headers: { 'Sec-Fetch-Mode': 'navigate', Accept: 'text/html' },
    maxRedirects: 0,
  });
  const body = await res.text();
  expect(body, 'a pass outlived its TTL with no page open to renew it').not.toContain(CONTENT);
  await context.close();
});

// T2.8 — a service worker outlives the software that installed it, so the kill
// switch has to actually work.
test('T2.8 /.anteroom/uninstall removes the renewal worker', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });

  const before = await page.evaluate(async () =>
    (await navigator.serviceWorker.getRegistrations()).map((r) => r.scope));
  expect(before.some((s) => s.includes('/.anteroom/'))).toBeTruthy();

  await page.goto('/.anteroom/uninstall');
  await page.waitForTimeout(3_000);

  const after = await page.evaluate(async () =>
    (await navigator.serviceWorker.getRegistrations()).map((r) => r.scope));
  expect(after.some((s) => s.includes('/.anteroom/')),
    `the renewal worker survived uninstall; scopes: ${after}`).toBeFalsy();
});

// T2.9 — the failure users actually report is not "it did not work", it is "it
// never stopped trying". Bounding request counts catches spinning; bounding
// wall-clock only produces flake.
test('T2.9 a slow device does not spin', async ({ page, browserName }) => {
  // CPU throttling is a CDP capability, so this one is Chromium-only. The
  // property it checks — the solver abandons and refetches rather than looping
  // — is engine-independent, so checking it on one engine is honest here in a
  // way that T2.4b was not.
  test.skip(browserName !== 'chromium', 'CPU throttling requires CDP');
  const client = await page.context().newCDPSession(page);
  await client.send('Emulation.setCPUThrottlingRate', { rate: 6 });

  let challenges = 0;
  page.on('request', (req) => {
    if (req.url().includes('/.anteroom/challenge')) challenges += 1;
  });

  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 30_000 });

  // A handful of challenge fetches is normal: one to be admitted, plus
  // renewals. Dozens would mean the solver is abandoning and refetching in a
  // loop rather than making progress.
  expect(challenges, `${challenges} challenge fetches to get admitted once`).toBeLessThan(12);
  await client.send('Emulation.setCPUThrottlingRate', { rate: 1 });
});
