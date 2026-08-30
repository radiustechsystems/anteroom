// The traffic mix, as exec functions shared by load.js and smoke.js.
//
// Four populations, each a rung or two of the ladder (README.md, "How it
// works"; docs/operating.md, "Watching what the gate decides"):
//
//   bot            never earns a pass. Mostly refused (403), sometimes on a
//                  bypassed path (proxied). What a scrape looks like.
//   browserJourney a new visitor: lands on the wait page, solves, is proxied
//                  in with the renewal script injected, clicks around.
//   passholder     a returning visitor with a live pass: proxied HTML, JSON and
//                  a static file, re-solving only when the pass lapses.
//   download       a pass-holder pulling an 8 MiB file: bytes through the proxy.
//
// Each function does one visit-shaped unit of work per iteration and checks
// what the gate should have said, so `checks` doubles as a correctness signal
// under load.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { BOT, BOT_JSON, BROWSER, BROWSER_FETCH, anon, held, expecting, ensurePass, dropPass } from './clients.js';
import { solve } from './pow.js';

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:18080';

const INJECT_MARK = '/.anteroom/renew.js';
const WAIT_MARK = '/.anteroom/';

function pickWeighted(items) {
  let r = Math.random();
  for (const [w, v] of items) { if ((r -= w) < 0) return v; }
  return items[items.length - 1][1];
}

export function bot() {
  const what = pickWeighted([[0.7, 'api'], [0.2, 'html-json'], [0.1, 'bypass']]);
  if (what === 'bypass') {
    const r = http.get(BASE_URL + '/robots.txt', anon(BOT, { name: 'bypass', rung: 'bypass-path' }));
    check(r, { 'bot bypass 200': (x) => x.status === 200 });
    return;
  }
  const params = what === 'api'
    ? anon(BOT, { name: 'refusal', rung: 'refusal' })
    : anon(BOT_JSON, { name: 'refusal_json', rung: 'refusal' });
  const r = http.get(BASE_URL + (what === 'api' ? '/api/items' : '/'), expecting(403, params));
  check(r, {
    'bot refused 403': (x) => x.status === 403,
    'refusal is marked as the gate\'s': (x) => x.headers['X-Anteroom-Action'] === 'challenge',
  });
}

export function browserJourney() {
  // A new visitor: an empty jar that this iteration owns.
  const jar = new http.CookieJar();
  const nav = { headers: BROWSER, jar };
  // The interstitial is served as 403 (the visitor is not admitted yet); the
  // body is the page that solves the puzzle.
  const first = http.get(BASE_URL + '/', expecting(403, Object.assign({ tags: { name: 'wait_page', rung: 'wait-page' } }, nav)));
  check(first, {
    'wait page 403': (x) => x.status === 403,
    'wait page is the interstitial': (x) => x.status === 403 && x.body.includes(WAIT_MARK),
  });
  solve(BASE_URL, { headers: BROWSER, jar });
  const home = http.get(BASE_URL + '/', Object.assign({ tags: { name: 'pass_html', rung: 'pass-pow' } }, nav));
  check(home, {
    'admitted 200': (x) => x.status === 200,
    'renewal script injected': (x) => x.status === 200 && x.body.includes(INJECT_MARK),
  });
  sleep(0.5 + Math.random());
  const about = http.get(BASE_URL + '/about', Object.assign({ tags: { name: 'pass_html', rung: 'pass-pow' } }, nav));
  check(about, { 'about 200': (x) => x.status === 200 });
  const api = http.get(BASE_URL + '/api/items', { headers: BROWSER_FETCH, jar, tags: { name: 'pass_json', rung: 'pass-pow' } });
  check(api, { 'api 200': (x) => x.status === 200 });
}

const PASSHOLDER_PATHS = [
  [0.35, ['/', BROWSER, 'pass_html', true]],
  [0.20, ['/about', BROWSER, 'pass_html', true]],
  [0.25, ['/api/items', BROWSER_FETCH, 'pass_json', false]],
  [0.10, ['/echo', BROWSER_FETCH, 'pass_json', false]],
  [0.10, ['/static/big.txt', BROWSER_FETCH, 'pass_static', false]],
];

export function passholder() {
  ensurePass(BASE_URL);
  const [path, headers, name, html] = pickWeighted(PASSHOLDER_PATHS);
  const r = http.get(BASE_URL + path, held(headers, { name, rung: 'pass-pow' }));
  const ok = check(r, {
    'passholder 200': (x) => x.status === 200,
    'html injected iff navigation': (x) => x.status !== 200 || html === x.body.includes(INJECT_MARK),
  });
  if (r.status === 403) dropPass(BASE_URL);
  return ok;
}

export function download() {
  ensurePass(BASE_URL);
  const r = http.get(BASE_URL + '/download/big.bin', Object.assign(
    held(BROWSER_FETCH, { name: 'download', rung: 'pass-pow' }), { responseType: 'none' }));
  check(r, { 'download 200': (x) => x.status === 200 });
  if (r.status === 403) dropPass(BASE_URL);
  sleep(1);
}
