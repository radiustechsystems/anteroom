// Peak finding: one rung of the ladder, offered load stepped up until the gate
// breaks, and a table of what happened at every step.
//
// benchmark.js measures latency at a load the gate handles easily. This script
// asks the other question — how much of one kind of request can it take — and
// answers it as a curve rather than a number, because the number depends on
// where you draw the line: the report marks both the *knee* (first step whose
// p99 crosses PEAK_P99_MS) and the *peak* (last step delivered in full, with no
// failures, below the knee). Read the curve; quote the peak with its p99.
//
// How it works. A ramping-arrival-rate scenario — an open model: requests are
// fired at the target rate whether or not earlier ones have returned, which is
// the only way to overload a server rather than wait politely for it — climbs a
// staircase from PEAK_START to PEAK_MAX in PEAK_STEP increments, each step a
// short ramp then a hold. Every request is tagged with its step and phase, so
// the summary can report the hold of each step on its own. A second, one-VU
// scenario samples /stats every two seconds for the gate's own view: requests
// it counted per second, requests in flight, goroutines. In-flight climbing
// while the rate holds is the shape of a queue forming.
//
// What stops it. The run ends early when requests fail, or when k6 drops
// iterations — meaning it had no free VU when the next request was due. Under
// saturation that is what the gate's rising latency looks like from the
// generator (VUs sit waiting), so it is the natural end of the climb. It is
// also what a CPU-starved k6 looks like. The CPU log `make peak` keeps
// alongside (bench/peak-cpu.sh) says which side was pegged; the summary cannot.
//
// Three containers share one machine here. BENCH_GATE_CPUS caps the gate's
// cores so it saturates first and the result is per core; run PEAK=direct
// first, because the gate's proxied peak cannot be measured above the app's.
//
// Run: PEAK=pass_json make peak   (docs/benchmarking.md, "Finding the peak")

import http from 'k6/http';
import exec from 'k6/execution';
import { check, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { BOT, BOT_JSON, BROWSER, BROWSER_FETCH, anon, held, expecting, ensurePass } from './lib/clients.js';
import { solve } from './lib/pow.js';
import { ADMIN_URL, waitReady, snapshot, delta, publish, describe } from './lib/stats.js';
import { TREND_STATS, val, fmtMs, fmtN, fmtRate, fmtPct } from './lib/summary.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:18080';
const APP_URL = __ENV.APP_URL || '';
const RESULTS_DIR = __ENV.RESULTS_DIR || '';

const num = (v, d) => (v === undefined || v === '' ? d : Number(v));
const RUNG = __ENV.PEAK || 'refusal';
const START = num(__ENV.PEAK_START, 500);
const STEP = num(__ENV.PEAK_STEP, 500);
const MAX = num(__ENV.PEAK_MAX, 15000);
const RAMP_S = num(__ENV.PEAK_RAMP_S, 5);
const HOLD_S = num(__ENV.PEAK_HOLD_S, 25);
const KNEE_MS = num(__ENV.PEAK_P99_MS, 50);
const MAX_VUS = num(__ENV.PEAK_VUS, 1000);
const MAX_DROPPED = num(__ENV.PEAK_MAX_DROPPED, 500);

const STEP_S = RAMP_S + HOLD_S;
const STEPS = Math.max(1, Math.min(80, Math.floor((MAX - START) / STEP) + 1));
const RATES = Array.from({ length: STEPS }, (_, i) => START + i * STEP);

// --- the rungs --------------------------------------------------------------

const INJECT_MARK = '/.anteroom/renew.js';
const probe = (headers, extra = {}) => Object.assign({ headers, tags: { name: 'probe' } }, extra);

const RUNGS = {
  direct: {
    decision: 'none', needs: APP_URL, note: 'the app alone, no gate: the ceiling the gate cannot exceed',
    run: () => check(http.get(APP_URL + '/robots.txt', probe(BOT)), { ok: (r) => r.status === 200 }),
  },
  bypass: {
    decision: 'bypass-path', note: 'the proxy hop with nothing else',
    run: () => check(http.get(BASE_URL + '/robots.txt', probe(BOT)), { ok: (r) => r.status === 200 }),
  },
  refusal: {
    decision: 'refusal', note: 'a scrape: 403 with the markdown instructions',
    run: () => check(http.get(BASE_URL + '/api/items', expecting(403, anon(BOT, { name: 'probe' }))), { ok: (r) => r.status === 403 }),
  },
  refusal_json: {
    decision: 'refusal', note: 'a scrape asking for JSON',
    run: () => check(http.get(BASE_URL + '/api/items', expecting(403, anon(BOT_JSON, { name: 'probe' }))), { ok: (r) => r.status === 403 }),
  },
  wait_page: {
    decision: 'wait-page', note: 'new visitors landing: a challenge and the interstitial each',
    run: () => check(http.get(BASE_URL + '/', expecting(403, anon(BROWSER, { name: 'probe' }))), { ok: (r) => r.status === 403 }),
  },
  answer: {
    decision: 'own-endpoint', probeName: 'answer', note: 'admissions verified per second (each iteration is challenge + answer)',
    run: () => solve(BASE_URL, { headers: BROWSER, jar: new http.CookieJar() }),
  },
  pass_json: {
    decision: 'pass-pow', note: 'admitted traffic, proxied, no rewriter',
    run: () => { ensurePass(BASE_URL); return check(http.get(BASE_URL + '/api/items', held(BROWSER_FETCH, { name: 'probe' })), { ok: (r) => r.status === 200 }); },
  },
  pass_html: {
    decision: 'pass-pow', note: 'admitted HTML through the rewriter',
    run: () => {
      ensurePass(BASE_URL);
      return check(http.get(BASE_URL + '/', held(BROWSER, { name: 'probe' })),
        { ok: (r) => r.status === 200 && r.body.includes(INJECT_MARK) });
    },
  },
};

const rung = RUNGS[RUNG];
if (!rung) throw new Error(`PEAK=${RUNG}: want one of ${Object.keys(RUNGS).join(', ')}`);
if (rung.needs === '') throw new Error(`PEAK=${RUNG} needs APP_URL`);
const PROBE = rung.probeName || 'probe';

// --- where are we on the staircase -----------------------------------------

function where() {
  const t = (Date.now() - exec.scenario.startTime) / 1000;
  const step = Math.min(STEPS - 1, Math.floor(t / STEP_S));
  const phase = t - step * STEP_S < RAMP_S ? 'ramp' : 'hold';
  return { step, phase };
}

function tagVU() {
  const w = where();
  exec.vu.tags.step = String(w.step);
  exec.vu.tags.phase = w.phase;
  return w;
}

// --- scenarios --------------------------------------------------------------

const stages = [];
for (const r of RATES) {
  stages.push({ duration: `${RAMP_S}s`, target: r });
  stages.push({ duration: `${HOLD_S}s`, target: r });
}

export const options = {
  scenarios: {
    peak: {
      executor: 'ramping-arrival-rate',
      startRate: START, timeUnit: '1s', stages,
      // Preallocate generously: k6 initialises VUs above this count on demand,
      // and drops the iterations due while it does — a generator artifact that
      // would read as saturation. 500 VUs cover 15k req/s at 30ms.
      preAllocatedVUs: Math.min(MAX_VUS, 500), maxVUs: MAX_VUS,
      exec: 'climb', gracefulStop: '10s',
    },
    sampler: {
      executor: 'constant-vus', vus: 1, duration: `${STEPS * STEP_S}s`,
      exec: 'sample', gracefulStop: '5s',
    },
  },
  thresholds: thresholds(),
  summaryTrendStats: TREND_STATS,
};

function thresholds() {
  const t = {
    // The stops. delayAbortEval spares the first step's warm-up.
    [`http_req_failed{scenario:peak,name:${PROBE}}`]: [{ threshold: 'rate<0.001', abortOnFail: true, delayAbortEval: `${STEP_S}s` }],
    'dropped_iterations': [{ threshold: `count<${MAX_DROPPED}`, abortOnFail: true, delayAbortEval: `${STEP_S}s` }],
    'checks{scenario:peak}': ['rate>0.99'],
    'anteroom_stats_upstream_errors': ['value==0'],
    'anteroom_stats_answers_bad_pow': ['value==0'],
    'http_reqs{name:stats}': ['count>=0'],
  };
  // Placeholders that make each step's hold reportable (summary.js explains).
  for (let i = 0; i < STEPS; i++) {
    t[`http_req_duration{scenario:peak,step:${i},phase:hold,name:${PROBE}}`] = ['p(99)<600000'];
    t[`http_req_failed{scenario:peak,step:${i},phase:hold,name:${PROBE}}`] = ['rate<=1'];
    t[`iterations{scenario:peak,step:${i},phase:hold}`] = ['count>=0'];
    t[`anteroom_gate_rps{step:${i},phase:hold}`] = ['max>=0'];
    t[`anteroom_in_flight{step:${i},phase:hold}`] = ['max>=0'];
    t[`anteroom_goroutines{step:${i},phase:hold}`] = ['max>=0'];
  }
  return t;
}

export function setup() {
  waitReady(BASE_URL);
  console.log(`peak: rung ${RUNG} (${rung.decision}); ${STEPS} steps of ${RAMP_S}s ramp + ${HOLD_S}s hold, ` +
    `${START} → ${RATES[STEPS - 1]} req/s by ${STEP}; knee at p99 ${KNEE_MS}ms; up to ${MAX_VUS} VUs`);
  return { before: snapshot() };
}

export function teardown(data) {
  console.log(describe(publish(delta(data.before, snapshot()))));
}

export function climb() {
  tagVU();
  rung.run();
}

// The gate's own view, sampled. Trends rather than gauges so each step keeps
// its own max; gate_rps is requests_total's rate between two samples.
const gateRps = new Trend('anteroom_gate_rps');
const inFlight = new Trend('anteroom_in_flight');
const goroutines = new Trend('anteroom_goroutines');
let last = null;

export function sample() {
  tagVU();
  if (!ADMIN_URL) { sleep(2); return; }
  const r = http.get(ADMIN_URL + '/stats', { tags: { name: 'stats' } });
  if (r.status === 200) {
    const s = r.json();
    const now = Date.now();
    const total = Object.values(s.anteroom_http_requests_total || {}).reduce((a, v) => a + v, 0);
    if (last) gateRps.add((total - last.total) / ((now - last.t) / 1000));
    last = { t: now, total };
    inFlight.add(s.anteroom_http_requests_in_flight || 0);
    goroutines.add(s.go_goroutines || 0);
  }
  sleep(2);
}

// --- the report -------------------------------------------------------------

export function handleSummary(data) {
  const rows = [];
  const head = `${'step'.padStart(4)} ${'target/s'.padStart(9)} ${'k6/s'.padStart(8)} ${'gate/s'.padStart(8)} ${'short'.padStart(6)} ` +
    `${'p50'.padStart(7)} ${'p95'.padStart(7)} ${'p99'.padStart(7)} ${'max'.padStart(7)} ${'fail'.padStart(6)} ${'inflight'.padStart(8)} ${'gorout'.padStart(6)}`;
  rows.push(head, '-'.repeat(head.length));

  let peak = null, knee = null, lastSeen = -1;
  for (let i = 0; i < STEPS; i++) {
    const sel = `{scenario:peak,step:${i},phase:hold`;
    const n = val(data, `iterations${sel}}`, 'count');
    if (!n) break; // a placeholder threshold creates the sub-metric; zero iterations means the step was never reached
    lastSeen = i;
    const dur = `http_req_duration${sel},name:${PROBE}}`;
    const achieved = n / HOLD_S;
    const short = Math.max(0, 1 - achieved / RATES[i]);
    const p99 = val(data, dur, 'p(99)');
    const fail = val(data, `http_req_failed${sel},name:${PROBE}}`, 'rate') || 0;
    const gate = val(data, `anteroom_gate_rps{step:${i},phase:hold}`, 'avg');
    const infl = val(data, `anteroom_in_flight{step:${i},phase:hold}`, 'max');
    const gor = val(data, `anteroom_goroutines{step:${i},phase:hold}`, 'max');
    const okStep = short < 0.02 && fail === 0 && p99 !== null && p99 < KNEE_MS;
    if (okStep) peak = i;
    if (knee === null && p99 !== null && p99 >= KNEE_MS) knee = i;
    rows.push(`${String(i).padStart(4)} ${fmtN(RATES[i], 9)} ${fmtRate(achieved, 8)} ${fmtRate(gate, 8)} ${fmtPct(short)} ` +
      `${fmtMs(val(data, dur, 'p(50)'))} ${fmtMs(val(data, dur, 'p(95)'))} ${fmtMs(p99)} ${fmtMs(val(data, dur, 'max'))} ` +
      `${fmtPct(fail)} ${fmtN(infl, 8)} ${fmtN(gor, 6)}${okStep ? '' : '  ◂'}`);
  }

  // The stop conditions are expected to trip — that is how a climb ends. The
  // gate-side thresholds are how it broke: 502s past the peak are the gate
  // failing under load, which is the finding; before the peak they mean the
  // measurement is not clean.
  const isStop = (name) => name === 'dropped_iterations' || name === `http_req_failed{scenario:peak,name:${PROBE}}`;
  const stops = [], problems = [];
  for (const [name, m] of Object.entries(data.metrics)) {
    for (const [expr, t] of Object.entries(m.thresholds || {})) {
      if (t.ok) continue;
      (isStop(name) ? stops : problems).push(`${name}: ${expr}`);
    }
  }
  const dropped = val(data, 'dropped_iterations', 'count') || 0;
  const aborted = stops.length > 0 || lastSeen < STEPS - 1;
  const verdict = [];
  verdict.push(peak === null
    ? `peak: none — no step was delivered in full below p99 ${KNEE_MS}ms (lower PEAK_START, or raise PEAK_P99_MS if that is the wrong knee)`
    : `peak: ${RATES[peak]} req/s (step ${peak}) — delivered in full, no failures, p99 ${fmtMs(val(data, `http_req_duration{scenario:peak,step:${peak},phase:hold,name:${PROBE}}`, 'p(99)')).trim()}ms`);
  verdict.push(knee === null
    ? `knee: not reached — p99 stayed under ${KNEE_MS}ms through step ${lastSeen}${aborted ? '' : ' (raise PEAK_MAX)'}`
    : `knee: step ${knee} at ${RATES[knee]} req/s — first p99 over ${KNEE_MS}ms`);
  verdict.push(aborted
    ? `stopped: during step ${Math.min(lastSeen + 1, STEPS - 1)} of ${STEPS - 1} (${RATES[Math.min(lastSeen + 1, STEPS - 1)]} req/s) — ${stops.join('; ') || 'the run ended early'}`
    : `stopped: ran to PEAK_MAX (${RATES[STEPS - 1]} req/s) without tripping a stop condition`);
  if (dropped) verdict.push(`dropped: ${dropped} iterations had no free VU. That is what a saturated gate looks like from k6 — and ` +
    `what a CPU-starved k6 looks like. bench/results/peak-cpu.log says which was pegged; PEAK_VUS=${MAX_VUS}.`);

  const text = [
    `anteroom peak — ${RUNG} (${rung.decision}) — ${new Date().toISOString()} — ${(data.state.testRunDurationMs / 1000).toFixed(0)}s`,
    `target ${BASE_URL}${APP_URL ? `  direct ${APP_URL}` : ''}  ·  ${rung.note}`,
    `steps of ${RAMP_S}s ramp + ${HOLD_S}s hold; columns describe the hold. "short" is the shortfall of delivered vs target; ◂ marks steps past the peak.`,
    '',
    rows.join('\n'),
    '',
    verdict.join('\n'),
    problems.length
      ? `gate-side signals during the climb (fine past the peak, a problem before it):\n  ${problems.join('\n  ')}\n  upstream_errors over the run: ${val(data, 'anteroom_stats_upstream_errors', 'value') || 0} (502s served)`
      : 'clean: no upstream errors, no bad answers, every check passed',
    '',
    'One machine, three containers. Quote the peak with its p99 and BENCH_GATE_CPUS — see docs/benchmarking.md.',
    '',
  ].join('\n');

  const out = { stdout: text + '\n' };
  if (RESULTS_DIR) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    out[`${RESULTS_DIR}/peak-${RUNG}-${stamp}.json`] = JSON.stringify(data, null, 1);
    out[`${RESULTS_DIR}/peak-${RUNG}-latest.json`] = JSON.stringify(data, null, 1);
    out[`${RESULTS_DIR}/peak-${RUNG}-latest.txt`] = text;
  }
  return out;
}
