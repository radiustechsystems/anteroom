// What the gate itself counted.
//
// k6 measures from the outside; /stats on the admin listener is the gate's own
// account of the same run, and the two should agree. setup() takes a snapshot,
// teardown() takes another, and the difference goes into k6 gauges so it lands
// in the summary next to the latencies and can carry thresholds — "no upstream
// error", "no bad_pow", "passes were actually minted" are assertions about the
// gate's counters, not about k6's.
//
// Every counter is cumulative since process start (docs/operating.md,
// "Monitoring"), hence the diff. The JSON shape: scalars as numbers, labeled
// counters as {label: n}, histograms as {count, sum, buckets}.
//
// Gauge names must be static and declared in the init context, which is why
// the list below is spelled out rather than derived from the snapshot.

import http from 'k6/http';
import { sleep } from 'k6';
import { Gauge } from 'k6/metrics';
import { PATH_HEALTHZ, PATH_CHALLENGE, PATH_INSTRUCTIONS } from './pow.js';

const decisions = ['bypass_path', 'refusal', 'wait_page', 'pass_pow', 'own_endpoint',
  'non_canonical_path', 'cors_preflight', 'unknown_authority', 'bypass_ip'];
const outcomes = ['ok_admit', 'ok_renew', 'malformed', 'stale', 'bad_pow', 'window_elapsed', 'error'];

const gauges = {};
for (const d of decisions) gauges[`requests_${d}`] = new Gauge(`anteroom_stats_requests_${d}`);
for (const o of outcomes) gauges[`answers_${o}`] = new Gauge(`anteroom_stats_answers_${o}`);
gauges.http_requests_total = new Gauge('anteroom_stats_http_requests_total');
gauges.challenges_issued_admit = new Gauge('anteroom_stats_challenges_issued_admit');
gauges.challenges_issued_renew = new Gauge('anteroom_stats_challenges_issued_renew');
gauges.passes_minted_pow = new Gauge('anteroom_stats_passes_minted_pow');
gauges.upstream_errors = new Gauge('anteroom_stats_upstream_errors');
gauges.upstream_bytes = new Gauge('anteroom_stats_upstream_bytes');
gauges.challenge_bytes = new Gauge('anteroom_stats_challenge_bytes');
gauges.http_bytes = new Gauge('anteroom_stats_http_bytes');
gauges.solve_seconds_sum_admit = new Gauge('anteroom_stats_solve_seconds_sum_admit');

export const ADMIN_URL = __ENV.ADMIN_URL || '';

// Waits for the gate to answer, then checks the contract document is served —
// the solver in pow.js is written from it, so a run against a gate that no
// longer serves it is not measuring what this harness thinks it is.
export function waitReady(base, timeoutMs = 60000) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const r = http.get(base + PATH_HEALTHZ, { tags: { name: 'readiness' } });
    const a = ADMIN_URL ? http.get(ADMIN_URL + '/healthz', { tags: { name: 'readiness' } }) : { status: 200 };
    if (r.status === 200 && a.status === 200) break;
    if (Date.now() > until) throw new Error(`gate not ready after ${timeoutMs}ms: gate=${r.status} admin=${a.status}`);
    sleep(0.5);
  }
  const doc = http.get(base + PATH_INSTRUCTIONS, { tags: { name: 'readiness' } });
  if (doc.status !== 200 || !doc.body.includes(PATH_CHALLENGE)) {
    throw new Error(`${PATH_INSTRUCTIONS}: status ${doc.status}; the solver is written from this document`);
  }
}

// One /stats read, or null when there is no admin listener to ask (a local k6
// run against an arbitrary deployment).
export function snapshot() {
  if (!ADMIN_URL) return null;
  const r = http.get(ADMIN_URL + '/stats', { tags: { name: 'stats' } });
  if (r.status !== 200) throw new Error(`${ADMIN_URL}/stats: status ${r.status}`);
  return r.json();
}

// after − before, recursively, for every numeric leaf. Non-numeric leaves
// (build info) are dropped.
export function delta(before, after) {
  if (typeof after === 'number') return after - (typeof before === 'number' ? before : 0);
  if (after && typeof after === 'object') {
    const out = {};
    for (const k of Object.keys(after)) {
      const d = delta(before ? before[k] : undefined, after[k]);
      if (d !== undefined) out[k] = d;
    }
    return out;
  }
  return undefined;
}

// Sums every leaf of a labeled counter.
function total(m) {
  if (typeof m === 'number') return m;
  if (!m) return 0;
  return Object.values(m).reduce((a, v) => a + (typeof v === 'number' ? v : 0), 0);
}

function pick(m, label) {
  return m && typeof m[label] === 'number' ? m[label] : 0;
}

// Publishes the diff into the gauges and returns it, so teardown() can also log
// it. Prometheus label values use hyphens (`wait-page`); metric names cannot,
// hence the underscore forms.
export function publish(d) {
  if (!d) return null;
  const req = d.anteroom_http_requests_total || {};
  for (const name of decisions) {
    gauges[`requests_${name}`].add(pick(req, name.replace(/_/g, '-')));
  }
  const ans = d.anteroom_challenge_answers_total || {};
  for (const o of outcomes) gauges[`answers_${o}`].add(pick(ans, o));
  gauges.http_requests_total.add(total(req));
  gauges.challenges_issued_admit.add(pick(d.anteroom_challenges_issued_total, 'admit'));
  gauges.challenges_issued_renew.add(pick(d.anteroom_challenges_issued_total, 'renew'));
  gauges.passes_minted_pow.add(pick(d.anteroom_passes_minted_total, 'pow'));
  gauges.upstream_errors.add(d.anteroom_upstream_errors_total || 0);
  gauges.upstream_bytes.add(d.anteroom_upstream_bytes_total || 0);
  gauges.challenge_bytes.add(d.anteroom_challenge_bytes_total || 0);
  gauges.http_bytes.add(d.anteroom_http_bytes_total || 0);
  const solve = d.anteroom_challenge_solve_duration_seconds;
  gauges.solve_seconds_sum_admit.add(solve && solve.admit ? solve.admit.sum || 0 : 0);
  return d;
}

// A compact, greppable account of the run from the gate's side, for the log.
export function describe(d) {
  if (!d) return 'stats: no ADMIN_URL, gate-side counters not collected';
  const req = d.anteroom_http_requests_total || {};
  const ans = d.anteroom_challenge_answers_total || {};
  const line = (obj) => Object.entries(obj).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' ');
  return [
    `stats: requests ${total(req)} [${line(req)}]`,
    `stats: answers [${line(ans)}] minted pow=${pick(d.anteroom_passes_minted_total, 'pow')}`,
    `stats: upstream_errors=${d.anteroom_upstream_errors_total || 0} ` +
      `upstream_bytes=${d.anteroom_upstream_bytes_total || 0} challenge_bytes=${d.anteroom_challenge_bytes_total || 0}`,
  ].join('\n');
}
