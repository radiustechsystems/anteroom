// The benchmark: what each rung of the ladder costs, one at a time.
//
// Scenarios run back to back, never together, so a row in the table is one
// kind of request against an otherwise idle gate. Each is a constant arrival
// rate (BENCH_RATE/s for BENCH_DURATION), which measures latency at a fixed
// offered load rather than throughput at saturation — the number an operator
// needs to size a deployment, and the one that stays comparable between runs.
// dropped_iterations must be zero: if k6 could not keep the rate, the row
// describes the generator, and the threshold says so.
//
// Some rows exist to be subtracted:
//   bypass_small − direct_small          = what the proxy hop costs
//   pass_html_inject − pass_html_noinject = what the HTML rewriter costs
//   pass_json − bypass_small             = what a cookie verify costs
//   {name:answer}                        = what verifying a solve costs
//
// Run: make bench  (or docs/benchmarking.md for a local k6 binary).

import http from 'k6/http';
import { check } from 'k6';
import { BOT, BOT_JSON, BROWSER, BROWSER_FETCH, anon, held, expecting, ensurePass } from './lib/clients.js';
import { solve } from './lib/pow.js';
import { waitReady, snapshot, delta, publish, describe } from './lib/stats.js';
import { makeHandleSummary, thresholdsFor, TREND_STATS } from './lib/summary.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:18080';
const NOINJECT_URL = __ENV.NOINJECT_URL || '';
const APP_URL = __ENV.APP_URL || '';
const RATE = Number(__ENV.BENCH_RATE || 200);
const DURATION = __ENV.BENCH_DURATION || '20s';
const GAP = 3; // seconds between scenarios: let in-flight work drain

const INJECT_MARK = '/.anteroom/renew.js';

function seconds(d) {
  const m = /^(\d+)(ms|s|m)$/.exec(d);
  if (!m) throw new Error(`BENCH_DURATION ${d}: want e.g. 20s`);
  return Number(m[1]) * ({ ms: 0.001, s: 1, m: 60 })[m[2]];
}
const DUR_S = seconds(DURATION);

// Display order and per-scenario duration for the summary.
export const plan = [];
let clock = 0;
function add(name, rung, exec, opts = {}) {
  // constant-vus for the downloads (a fixed number of concurrent streams is
  // the meaningful shape for an 8 MiB body); constant-arrival-rate otherwise.
  const base = opts.executor === 'constant-vus'
    ? { executor: 'constant-vus', vus: opts.vus, duration: DURATION }
    : {
      executor: 'constant-arrival-rate',
      rate: opts.rate || RATE, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: opts.preAllocatedVUs || 50, maxVUs: opts.maxVUs || 400,
    };
  const sc = Object.assign(base, { exec, startTime: `${clock}s`, gracefulStop: '5s', tags: { rung } });
  plan.push({ name, rung, seconds: DUR_S });
  clock += DUR_S + GAP;
  return sc;
}

const scenarios = {};
if (APP_URL) scenarios.direct_small = add('direct_small', 'none', 'directSmall');
scenarios.bypass_small = add('bypass_small', 'bypass-path', 'bypassSmall');
scenarios.refusal = add('refusal', 'refusal', 'refusal');
scenarios.refusal_json = add('refusal_json', 'refusal', 'refusalJSON');
scenarios.wait_page = add('wait_page', 'wait-page', 'waitPage');
scenarios.challenge_answer = add('challenge_answer', 'own-endpoint', 'challengeAnswer',
  { rate: Math.max(1, Math.round(RATE / 10)), preAllocatedVUs: 20, maxVUs: 200 });
scenarios.pass_json = add('pass_json', 'pass-pow', 'passJSON');
scenarios.pass_html_inject = add('pass_html_inject', 'pass-pow', 'passHTMLInject');
if (NOINJECT_URL) scenarios.pass_html_noinject = add('pass_html_noinject', 'pass-pow', 'passHTMLNoInject');
scenarios.download = add('download', 'pass-pow', 'download', { executor: 'constant-vus', vus: 4 });
if (APP_URL) scenarios.download_direct = add('download_direct', 'none', 'downloadDirect', { executor: 'constant-vus', vus: 4 });

export const options = {
  scenarios,
  discardResponseBodies: false,
  thresholds: thresholdsFor(Object.keys(scenarios), {
    'checks': ['rate>0.99'],
    'dropped_iterations': ['count==0'],
    'http_reqs{name:stats}': ['count>=0'],
    'anteroom_stats_upstream_errors': ['value==0'],
    'anteroom_stats_answers_bad_pow': ['value==0'],
    'anteroom_stats_answers_malformed': ['value==0'],
  }, ['challenge', 'answer']),
  summaryTrendStats: TREND_STATS,
};

export function setup() {
  waitReady(BASE_URL);
  if (NOINJECT_URL) waitReady(NOINJECT_URL);
  return { before: snapshot() };
}

export function teardown(data) {
  const d = publish(delta(data.before, snapshot()));
  console.log(describe(d));
}

// --- scenarios -------------------------------------------------------------

export function directSmall() {
  check(http.get(APP_URL + '/robots.txt', { headers: BOT }), { '200': (r) => r.status === 200 });
}

export function bypassSmall() {
  check(http.get(BASE_URL + '/robots.txt', { headers: BOT }), { '200': (r) => r.status === 200 });
}

export function refusal() {
  const r = http.get(BASE_URL + '/api/items', expecting(403, anon(BOT)));
  check(r, { '403': (x) => x.status === 403 });
}

export function refusalJSON() {
  const r = http.get(BASE_URL + '/api/items', expecting(403, anon(BOT_JSON)));
  check(r, {
    '403': (x) => x.status === 403,
    'json body': (x) => (x.headers['Content-Type'] || '').includes('json'),
  });
}

export function waitPage() {
  // Served as 403 — the visitor is not admitted yet — with the interstitial as body.
  const r = http.get(BASE_URL + '/', expecting(403, anon(BROWSER)));
  check(r, {
    '403': (x) => x.status === 403,
    'interstitial': (x) => x.status === 403 && x.body.includes('/.anteroom/'),
  });
}

export function challengeAnswer() {
  // A fresh jar per iteration: every iteration is a new admission, so the
  // gate verifies one solve per iteration and mints one pass.
  const got = solve(BASE_URL, { headers: BROWSER, jar: new http.CookieJar() });
  check(got, { 'pass minted': (g) => g.exp_unix_ms > Date.now() });
}

export function passJSON() {
  ensurePass(BASE_URL);
  check(http.get(BASE_URL + '/api/items', held(BROWSER_FETCH)), { '200': (r) => r.status === 200 });
}

export function passHTMLInject() {
  ensurePass(BASE_URL);
  const r = http.get(BASE_URL + '/', held(BROWSER));
  check(r, { '200': (x) => x.status === 200, 'injected': (x) => x.status === 200 && x.body.includes(INJECT_MARK) });
}

export function passHTMLNoInject() {
  ensurePass(NOINJECT_URL);
  const r = http.get(NOINJECT_URL + '/', held(BROWSER));
  check(r, { '200': (x) => x.status === 200, 'not injected': (x) => x.status === 200 && !x.body.includes(INJECT_MARK) });
}

export function download() {
  ensurePass(BASE_URL);
  const r = http.get(BASE_URL + '/download/big.bin', Object.assign(held(BROWSER_FETCH), { responseType: 'none' }));
  check(r, { '200': (x) => x.status === 200 });
}

export function downloadDirect() {
  const r = http.get(APP_URL + '/download/big.bin', { headers: BROWSER_FETCH, responseType: 'none' });
  check(r, { '200': (x) => x.status === 200 });
}

export const handleSummary = makeHandleSummary('benchmark', plan);
