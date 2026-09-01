// The report. k6's default end-of-test summary is organised by metric; a
// benchmark is read by scenario, so this rebuilds it that way: one row per
// scenario with request count, achieved rate, and the latency percentiles, then
// the solver's cost, then what the gate counted, then the thresholds.
//
// Everything is derived from the `data` object k6 hands handleSummary(); the
// full object is written as JSON alongside, so a number in the table can always
// be traced and a later tool (or a later run) can compare.
//
// One k6 detail matters here: a tag-scoped sub-metric such as
// http_req_duration{scenario:refusal} exists in `data.metrics` only if some
// threshold references it. The scripts declare a permissive threshold per
// scenario for exactly that reason; see thresholdsFor() below.
//
// No remote imports (jslib.k6.io) on purpose: a network dependency in the
// harness is a flake source in CI and a variable in a measurement.

const RESULTS_DIR = __ENV.RESULTS_DIR || '';

// The percentiles the tables show. Scripts set options.summaryTrendStats to
// this; k6's default set has no p(50) or p(99).
export const TREND_STATS = ['avg', 'min', 'med', 'max', 'p(50)', 'p(90)', 'p(95)', 'p(99)'];

// The per-scenario thresholds that make the sub-metrics appear. The p(99) bound
// is a minute — it will not fail; it exists to be referenced. The failure-rate
// bound is real: an unexpected status in a benchmark means the numbers describe
// the wrong thing.
//
// `names` are request classes (the `name` tag) to break out the same way; a
// real threshold in `extra` on the same metric wins over the placeholder.
export function thresholdsFor(scenarioNames, extra = {}, names = []) {
  const t = {};
  for (const s of scenarioNames) {
    t[`http_req_duration{scenario:${s}}`] = ['p(99)<60000'];
    t[`http_reqs{scenario:${s}}`] = ['count>0'];
    t[`http_req_failed{scenario:${s}}`] = ['rate<0.01'];
    t[`data_received{scenario:${s}}`] = ['count>=0'];
  }
  for (const n of names) {
    t[`http_req_duration{name:${n}}`] = ['p(99)<60000'];
    t[`http_reqs{name:${n}}`] = ['count>=0'];
  }
  return Object.assign(t, extra);
}

export function val(data, name, key) {
  const m = data.metrics[name];
  if (!m || !m.values) return null;
  if (m.values[key] === undefined && key === 'p(50)') key = 'med';
  if (m.values[key] === undefined) return null;
  return m.values[key];
}

export function fmtMs(v) {
  if (v === null) return '     -';
  if (v >= 1000) return (v / 1000).toFixed(2).padStart(5) + 's';
  return v.toFixed(v < 10 ? 2 : 1).padStart(6);
}
export function fmtN(v, w = 7) { return v === null ? '-'.padStart(w) : String(Math.round(v)).padStart(w); }
export function fmtRate(v, w = 7) { return v === null ? '-'.padStart(w) : v.toFixed(1).padStart(w); }
export function fmtPct(v) { return v === null ? '    -' : (v * 100).toFixed(2).padStart(5) + '%'; }
export function fmtBytes(v) {
  if (v === null) return '-';
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// scenarios: [{name, rung, seconds, note}] in display order. `seconds` is the
// scenario's own running time, so rps is per scenario and not diluted by the
// rest of the run the way k6's global rate is.
export function scenarioTable(data, scenarios) {
  const head = `${'scenario'.padEnd(20)} ${'rung'.padEnd(14)} ${'reqs'.padStart(7)} ${'req/s'.padStart(7)} ` +
    `${'p50'.padStart(7)} ${'p90'.padStart(7)} ${'p95'.padStart(7)} ${'p99'.padStart(7)} ${'max'.padStart(7)} ${'fail'.padStart(6)}  ${'recv'.padStart(9)}`;
  const rows = [head, '-'.repeat(head.length)];
  for (const s of scenarios) {
    const sel = `{scenario:${s.name}}`;
    const n = val(data, `http_reqs${sel}`, 'count');
    if (n === null) { rows.push(`${s.name.padEnd(20)} (skipped)`); continue; }
    const dur = `http_req_duration${sel}`;
    const rps = s.seconds ? n / s.seconds : val(data, `http_reqs${sel}`, 'rate');
    const recv = val(data, `data_received${sel}`, 'count');
    let recvS = fmtBytes(recv).padStart(9);
    const mibs = recv !== null && s.seconds ? recv / s.seconds / 1048576 : 0;
    if (mibs >= 0.5) recvS += ` ${mibs.toFixed(1)} MiB/s`;
    rows.push(`${s.name.padEnd(20)} ${(s.rung || '').padEnd(14)} ${fmtN(n)} ${fmtRate(rps)} ` +
      `${fmtMs(val(data, dur, 'p(50)'))} ${fmtMs(val(data, dur, 'p(90)'))} ${fmtMs(val(data, dur, 'p(95)'))} ` +
      `${fmtMs(val(data, dur, 'p(99)'))} ${fmtMs(val(data, dur, 'max'))} ${fmtPct(val(data, `http_req_failed${sel}`, 'rate'))}  ${recvS}`);
  }
  return rows.join('\n');
}

// The request classes the load test cares about regardless of scenario.
export function nameTable(data, names) {
  const rows = [];
  for (const nm of names) {
    const dur = `http_req_duration{name:${nm}}`;
    const n = val(data, `http_reqs{name:${nm}}`, 'count');
    if (n === null) continue;
    rows.push(`  ${nm.padEnd(12)} ${fmtN(n)} reqs   p50 ${fmtMs(val(data, dur, 'p(50)'))}  p95 ${fmtMs(val(data, dur, 'p(95)'))}  p99 ${fmtMs(val(data, dur, 'p(99)'))}`);
  }
  return rows.length ? 'by request class (ms):\n' + rows.join('\n') : null;
}

export function solverLines(data) {
  const hashes = val(data, 'anteroom_solve_hashes', 'count');
  const solves = val(data, 'anteroom_solve_ms', 'count');
  if (!solves) return null;
  return `solver: ${solves} solves, ${Math.round(hashes / solves)} hashes/solve avg, ` +
    `wall p50 ${fmtMs(val(data, 'anteroom_solve_ms', 'p(50)'))} p95 ${fmtMs(val(data, 'anteroom_solve_ms', 'p(95)'))} ms ` +
    `(includes both round trips)`;
}

export function gateLines(data) {
  const g = (n) => val(data, `anteroom_stats_${n}`, 'value');
  if (g('http_requests_total') === null) return 'gate: /stats not collected (no ADMIN_URL)';
  const rungs = ['bypass_path', 'refusal', 'wait_page', 'pass_pow', 'own_endpoint']
    .map((r) => `${r}=${g(`requests_${r}`)}`).join(' ');
  const answers = ['ok_admit', 'ok_renew', 'bad_pow', 'malformed', 'stale', 'window_elapsed', 'error']
    .map((o) => `${o}=${g(`answers_${o}`)}`).join(' ');
  const k6reqs = val(data, 'http_reqs', 'count');
  return [
    `gate: ${g('http_requests_total')} requests counted on the measured gate (k6 sent ${k6reqs} to all targets)`,
    `gate: by rung ${rungs}`,
    `gate: answers ${answers}; passes minted ${g('passes_minted_pow')}`,
    `gate: upstream_errors=${g('upstream_errors')} upstream_bytes=${fmtBytes(g('upstream_bytes'))} challenge_bytes=${fmtBytes(g('challenge_bytes'))}`,
  ].join('\n');
}

export function thresholdLines(data) {
  const rows = [];
  let failed = 0;
  for (const [name, m] of Object.entries(data.metrics)) {
    if (!m.thresholds) continue;
    for (const [expr, t] of Object.entries(m.thresholds)) {
      if (t.ok) continue;
      failed++;
      rows.push(`  ✗ ${name}: ${expr}`);
    }
  }
  const dropped = val(data, 'dropped_iterations', 'count');
  const head = failed ? `thresholds: ${failed} FAILED` : 'thresholds: all passed';
  const gen = dropped ? `\ngenerator: ${dropped} iterations dropped — k6 could not keep the requested rate; ` +
    `the numbers above are bounded by the load generator, not the gate` : '';
  return head + (rows.length ? '\n' + rows.join('\n') : '') + gen;
}

// Builds the handleSummary export for a script. `kind` names the files;
// `scenarios` is the display order and per-scenario durations; `names` the
// request classes to break out.
export function makeHandleSummary(kind, scenarios, names = ['challenge', 'answer']) {
  return function handleSummary(data) {
    const started = new Date(data.state.testRunDurationMs ? Date.now() - data.state.testRunDurationMs : Date.now());
    const text = [
      `anteroom ${kind} — ${started.toISOString()} — ${(data.state.testRunDurationMs / 1000).toFixed(0)}s`,
      `target ${__ENV.BASE_URL || '(BASE_URL unset)'}${__ENV.NOINJECT_URL ? `  noinject ${__ENV.NOINJECT_URL}` : ''}${__ENV.APP_URL ? `  direct ${__ENV.APP_URL}` : ''}`,
      '',
      scenarioTable(data, scenarios),
      '',
      nameTable(data, names),
      solverLines(data),
      gateLines(data),
      '',
      thresholdLines(data),
      '',
      'Latencies are k6-observed, in ms, over the compose bridge (or the host port for a local k6).',
      'Starting points on one machine, not a capacity claim — see docs/benchmarking.md.',
      '',
    ].filter((l) => l !== null && l !== undefined).join('\n');

    const out = { stdout: text + '\n' };
    if (RESULTS_DIR) {
      const stamp = started.toISOString().replace(/[:.]/g, '-');
      out[`${RESULTS_DIR}/${kind}-${stamp}.json`] = JSON.stringify(data, null, 1);
      out[`${RESULTS_DIR}/${kind}-latest.json`] = JSON.stringify(data, null, 1);
      out[`${RESULTS_DIR}/${kind}-latest.txt`] = text;
    }
    return out;
  };
}
