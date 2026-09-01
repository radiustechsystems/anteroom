// The proof-of-work solver, for k6.
//
// One rule governs this file, borrowed from acceptance/harness/solver.go: it is
// written from the instructions the gate serves at /.anteroom/instructions.md,
// not from the gate's source. Read that document, then read solve() — they must
// describe the same four steps. If the gate's contract ever drifts from its
// document, the drift shows up here as bad_pow answers failing a threshold,
// rather than as every automated client on the internet breaking quietly.
//
// k6/crypto rather than the WebCrypto global: its sha256 is synchronous and
// Go-backed, which is what a tight loop of a thousand-odd hashes per admission
// needs. crypto.subtle.digest returns a promise per hash and is the wrong tool.

import http from 'k6/http';
import crypto from 'k6/crypto';
import { Counter, Trend } from 'k6/metrics';

export const COOKIE_NAME = 'anteroom_pass';
export const PATH_CHALLENGE = '/.anteroom/challenge';
export const PATH_ANSWER = '/.anteroom/answer';
export const PATH_HEALTHZ = '/.anteroom/healthz';
export const PATH_INSTRUCTIONS = '/.anteroom/instructions.md';

// How much a solve cost the generator. anteroom_solve_hashes is the honest
// measure of client-side work (it is what `difficulty` prices); anteroom_solve_ms
// is wall time, which includes both HTTP round trips and so also reflects the
// gate. Neither is part of http_req_duration.
export const solveHashes = new Counter('anteroom_solve_hashes');
export const solveMs = new Trend('anteroom_solve_ms', true);

// Step 2 as documented: find a nonce such that sha256(challenge + nonce),
// compared as bytes, sorts strictly below the 64-hex-character threshold.
// Equal-length lowercase hex compares the same way the bytes do, so the string
// comparison below is the byte comparison the document asks for.
//
// Candidates are the decimal integers from 0, like the harness solver. The
// bound exists so a misconfigured difficulty fails loudly instead of spinning.
export function findNonce(challenge, threshold, maxAttempts = 1 << 22) {
  const t = String(threshold).toLowerCase();
  if (t.length !== 64) {
    throw new Error(`threshold is ${t.length} hex chars, want 64: ${t}`);
  }
  for (let n = 0; n < maxAttempts; n++) {
    const nonce = String(n);
    if (crypto.sha256(challenge + nonce, 'hex') < t) {
      return { nonce, attempts: n + 1 };
    }
  }
  throw new Error(`no nonce below ${t} in ${maxAttempts} attempts`);
}

// Steps 1 to 3. On success the pass cookie is in whichever jar `params` names
// (the VU's default jar unless params.jar is set), ready for step 4: retry the
// original request. Returns { exp_unix_ms, attempts, ms }.
//
// Retries once on a deadline overrun, which is what the document prescribes:
// a pass expires a fixed time after its challenge was *issued*, so a solve that
// finishes after deadline_unix_ms can only be refused. Abandon it and refetch.
export function solve(base, params = {}) {
  const started = Date.now();
  let last = 'no attempt made';
  for (let attempt = 0; attempt < 2; attempt++) {
    const cp = withTags(params, { name: 'challenge' });
    const cr = http.get(base + PATH_CHALLENGE, cp);
    if (cr.status !== 200) {
      throw new Error(`${PATH_CHALLENGE}: status ${cr.status}: ${cr.body}`);
    }
    const ch = cr.json();
    const { nonce, attempts } = findNonce(ch.challenge, ch.threshold);
    solveHashes.add(attempts);
    if (Date.now() > ch.deadline_unix_ms) {
      last = `solve overran the challenge deadline (attempt ${attempt + 1})`;
      continue;
    }
    const ap = withTags(params, { name: 'answer' });
    ap.headers = Object.assign({}, params.headers || {}, { 'Content-Type': 'application/json' });
    const ar = http.post(base + PATH_ANSWER,
      JSON.stringify({ challenge: ch.challenge, nonce }), ap);
    let res = null;
    try { res = ar.json(); } catch (e) { res = null; }
    if (!res || !res.ok) {
      last = `${PATH_ANSWER}: status ${ar.status}: ${res ? res.error : ar.body}`;
      continue;
    }
    const ms = Date.now() - started;
    solveMs.add(ms);
    return { exp_unix_ms: res.exp_unix_ms, attempts, ms };
  }
  throw new Error(`could not obtain a pass: ${last}`);
}

// Copies request params, merging extra tags. Tags are how the summary and the
// thresholds pick a request class out of the run (name:answer is the gate's
// verification cost, isolated).
export function withTags(params, tags) {
  const out = Object.assign({}, params);
  out.tags = Object.assign({}, params.tags || {}, tags);
  return out;
}
