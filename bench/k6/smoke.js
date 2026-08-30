// The smoke test: load.js's traffic at a trickle for under a minute, with
// only functional thresholds.
//
// This runs on every pull request (ci.yaml), and ci.yaml is what the release
// workflow calls to decide a tag is publishable. So nothing here depends on how
// fast the runner is: it asserts that the solver written from the served
// instructions still earns passes, that every population gets the answer the
// ladder promises it, and that the gate reached the upstream every time. A
// latency regression is load.js's job (bench.yaml, weekly and on demand).
//
// Run: make load-smoke

import { bot, browserJourney, passholder, download, BASE_URL } from './lib/traffic.js';
import { waitReady, snapshot, delta, publish, describe } from './lib/stats.js';
import { makeHandleSummary, thresholdsFor, TREND_STATS } from './lib/summary.js';

export { bot, browserJourney, passholder, download };

const DURATION = '45s';

const NAMES = ['refusal', 'bypass', 'wait_page', 'challenge', 'answer', 'pass_html', 'pass_json', 'download'];

export const plan = [
  { name: 'bots', rung: 'refusal', seconds: 45 },
  { name: 'browsers', rung: 'wait→pass', seconds: 45 },
  { name: 'passholders', rung: 'pass-pow', seconds: 45 },
  { name: 'downloads', rung: 'pass-pow', seconds: 45 },
];

const trickle = (rate, exec) => ({
  executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration: DURATION,
  preAllocatedVUs: 10, maxVUs: 60, exec, gracefulStop: '10s',
});

export const options = {
  scenarios: {
    bots: trickle(30, 'bot'),
    browsers: trickle(3, 'browserJourney'),
    passholders: trickle(30, 'passholder'),
    downloads: { executor: 'constant-vus', vus: 1, duration: DURATION, exec: 'download', gracefulStop: '10s' },
  },
  thresholds: thresholdsFor(plan.map((p) => p.name), {
    'http_req_failed': ['rate<0.01'],
    'checks': ['rate>0.99'],
    'http_reqs{name:stats}': ['count>=0'],
    'anteroom_stats_upstream_errors': ['value==0'],
    'anteroom_stats_answers_bad_pow': ['value==0'],
    'anteroom_stats_answers_malformed': ['value==0'],
    'anteroom_stats_passes_minted_pow': ['value>0'],
    'anteroom_stats_requests_refusal': ['value>0'],
    'anteroom_stats_requests_wait_page': ['value>0'],
    'anteroom_stats_requests_pass_pow': ['value>0'],
    'anteroom_stats_requests_bypass_path': ['value>0'],
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

export const handleSummary = makeHandleSummary('smoke', plan, NAMES);
