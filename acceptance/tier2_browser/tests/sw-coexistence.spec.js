// A site's root-scoped service worker may re-issue top-level navigations with
// different fetch metadata across browser engines:
//
//   Chromium: Sec-Fetch-Mode stays "navigate", Sec-Fetch-Dest becomes "empty"
//   Firefox:  Sec-Fetch-Mode becomes "same-origin", Sec-Fetch-Dest becomes "empty"
//
// The gate corroborates these shapes with Accept and User-Agent so they remain
// navigations without admitting ordinary same-origin fetches.
import { test, expect } from '@playwright/test';

const CONTENT = 'hello from the app';

test('T2.4b a site worker that re-issues navigations does not wall the visitor', async ({ browser, browserName }) => {

  const install = await browser.newContext();
  const p1 = await install.newPage();

  // Get admitted, then install the application's own root-scoped worker.
  await p1.goto('/');
  await expect(p1.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
  await p1.goto('/sw-owner');
  await expect(p1.locator('#sw-state')).toHaveText(/registered:/, { timeout: 20_000 });
  await p1.waitForTimeout(2_000);

  const scopes = await p1.evaluate(async () =>
    (await navigator.serviceWorker.getRegistrations()).map((r) => r.scope));
  expect(scopes.some((s) => new URL(s).pathname === '/'),
    `the application's worker did not take the root scope: ${scopes}`).toBeTruthy();

  // Now arrive as a first-time visitor would: same browser, no pass. The
  // application's worker is installed and will re-issue this navigation.
  await install.clearCookies();
  const p2 = await install.newPage();
  await p2.goto('/');
  await p2.waitForTimeout(5_000);

  const body = await p2.content();
  const lockedOut = /Pass required|a pass is required/i.test(body) && !body.includes(CONTENT);

  expect(lockedOut,
    `[${browserName}] the visitor received the machine-readable refusal instead of the wait page, ` +
    `so no solver ever runs and they can never get in. This is the Sec-Fetch-Mode rewrite ` +
    `described at the top of this file.`).toBeFalsy();

  // And they should actually end up on the content.
  await expect(p2.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
});

// Admission and renewal are separate properties: an admitted page behind the
// site worker must also receive the renewal driver and remain admitted.

async function installSiteWorker(page) {
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
  await page.goto('/sw-owner');
  await expect(page.locator('#sw-state')).toHaveText(/registered:/, { timeout: 20_000 });
  await page.waitForTimeout(2_000);
  const controller = await page.evaluate(() =>
    navigator.serviceWorker.controller && navigator.serviceWorker.controller.scriptURL);
  expect(controller, 'the site worker is not controlling this page').toBeTruthy();
}

test('T2.4d a pass behind a site worker survives repeated navigation', async ({ page, browserName }) => {
  await installSiteWorker(page);
  await page.goto('/');
  await expect(page.locator('#marker')).toHaveText(CONTENT, { timeout: 15_000 });
  const injected = await page.evaluate(() =>
    Boolean(document.querySelector('script[src="/.anteroom/renew.js"]')));
  expect(injected,
    `[${browserName}] the renewal driver was not injected behind the site worker`).toBeTruthy();

  // Reloads in quick succession are what surfaced this: each one tears the
  // renewal worker down, and without an injected driver nothing starts it again.
  for (let i = 0; i < 3; i++) {
    await page.reload();
    await page.waitForTimeout(500);
  }

  // Well past pass_ttl (5s in this deployment) and past the worker's 15s
  // staleness threshold: if renewal is running we are still admitted, and if it
  // is not we are back on the wait page.
  await page.waitForTimeout(18_000);
  await page.goto('/about');

  // Any page of the app will do — what matters is that this navigation was not
  // met by the wait page. Asserting on a marker rather than on specific copy:
  // the property is "still admitted", not "on the home page".
  await expect(page.locator('#marker'),
    `[${browserName}] the pass was not renewed while a site worker controlled the page`)
    .toBeVisible({ timeout: 15_000 });
  expect(await page.title(),
    `[${browserName}] challenged again — renewal stopped behind the site worker`)
    .not.toBe('One moment…');
});
