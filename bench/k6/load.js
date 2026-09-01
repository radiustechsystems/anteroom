// The load test: the four populations from lib/traffic.js at once, ramping,
// for about five minutes, with thresholds that fail the run.
//
// This is the regression gate. The thresholds are loose on purpose — they are
// meant to catch a change that makes a rung several times slower or starts
// producing upstream errors, on a shared CI runner whose neighbours are
// unknown — and tight enough that a p95 of 150 ms for a 403 from a process
// that does one HMAC would be a real finding. Tighten them once a machine has
// a history (docs/benchmarking.md).
//
// LOAD_SCALE multiplies every rate. 1 is sized for a 4-vCPU runner with the
// gate, the app and k6 sharing it; a laptop can run 2-3 before the generator
// is the bottleneck. When that happens dropped_iterations rises first, and
// the summary says so.
//
// Run: make load

import { bot, browserJourney, passholder, download, BASE_URL } from './lib/traffic.js';
import { waitReady, snapshot, delta, publish, describe } from './lib/stats.js';
import { makeHandleSummary, thresholdsFor, TREND_STATS } from './lib/summary.js';

export { bot, browserJourney, passholder, download };

const SCALE = Number(__ENV.LOAD_SCALE || 1);
const s = (n) => Math.max(1, Math.round(n * SCALE));

// The shape: a minute up, two minutes level, a minute higher, thirty seconds
// down. 4m30s of traffic; downloads run the whole time at a fixed concurrency.
function ramp(start, level, peak) {
  return {
    executor: 'ramping-arrival-rate',
    startRate: s(start), timeUnit: '1s',
    preAllocatedVUs: s(20), maxVUs: s(300),
    stages: [
      { duration: '1m', target: s(level) },
      { duration: '2m', target: s(level) },
      { duration: '1m', target: s(peak) },
      { duration: '30s', target: 0 },
    ],
    gracefulStop: '10s',
  };
}

const NAMES = ['refusal', 'refusal_json', 'bypass', 'wait_page', 'challenge', 'answer', 'pass_html', 'pass_json', 'pass_static', 'download'];

export const plan = [
  { name: 'bots', rung: 'refusal', seconds: 270, note: '403s and the odd bypass' },
  { name: 'browsers', rung: 'wait→pass', seconds: 270, note: 'new visitors: wait page, solve, browse' },
  { name: 'passholders', rung: 'pass-pow', seconds: 270, note: 'returning visitors' },
  { name: 'downloads', rung: 'pass-pow', seconds: 270, note: '8 MiB through the proxy' },
];

export const options = {
  scenarios: {
    bots: Object.assign(ramp(20, 200, 400), { exec: 'bot' }),
    browsers: Object.assign(ramp(2, 10, 30), { exec: 'browserJourney', maxVUs: s(150) }),
    passholders: Object.assign(ramp(20, 150, 300), { exec: 'passholder' }),
    downloads: { executor: 'constant-vus', vus: s(2), duration: '4m30s', exec: 'download', gracefulStop: '10s' },
  },
  thresholds: thresholdsFor(plan.map((p) => p.name), {
    'http_req_failed': ['rate<0.01'],
    'checks': ['rate>0.99'],
    // Latency, per population. 150 ms for a refusal or a solve verification is
    // two orders of magnitude above what either costs on an idle gate.
    'http_req_duration{scenario:bots}': ['p(95)<150'],
    'http_req_duration{scenario:passholders}': ['p(95)<300'],
    'http_req_duration{scenario:browsers}': ['p(95)<500'],
    'http_req_duration{name:challenge}': ['p(95)<150'],
    'http_req_duration{name:answer}': ['p(95)<150'],
    'http_req_duration{name:wait_page}': ['p(95)<300'],
    'http_req_duration{name:refusal}': ['p(95)<150'],
    'http_req_duration{name:pass_html}': ['p(95)<300'],
    'http_req_duration{name:pass_json}': ['p(95)<300'],
    'http_req_duration{name:download}': ['p(99)<60000'],
    'http_reqs{name:stats}': ['count>=0'],
    // What the gate counted. These are the assertions that matter most: no
    // 502s, every solve verified, nothing malformed from our own solver.
    'anteroom_stats_upstream_errors': ['value==0'],
    'anteroom_stats_answers_bad_pow': ['value==0'],
    'anteroom_stats_answers_malformed': ['value==0'],
    'anteroom_stats_answers_window_elapsed': ['value<10'],
    'anteroom_stats_passes_minted_pow': ['value>0'],
    // Generator health. A few hundred dropped iterations over 270 s is noise;
    // thousands mean the numbers describe k6, not the gate.
    'dropped_iterations': ['count<500'],
  }, NAMES),
  summaryTrendStats: TREND_STATS,
};

export function setup() {
  waitReady(BASE_URL);
  return { before: snapshot() };
}

export function teardown(data) {
  console.log(describe(publish(delta(data.before, snapshot()))));
}

export const handleSummary = makeHandleSummary('load', plan, NAMES);
