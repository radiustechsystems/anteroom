// Who the traffic pretends to be, and how a VU keeps its pass.
//
// Two facts about passes shape this file (docs/operating.md, "Tuning the
// puzzle"; internal/gate: a pass binds to the authority that minted it, to the
// client's /24, and to a hash of its User-Agent):
//
//   * one User-Agent per persona, constant for the whole run. A pass earned
//     under one UA is refused under another, so rotating UAs would read as a
//     gate failure;
//   * passes are cached per VU and per base URL. k6 gives each VU its own copy
//     of module state, and a pass for http://anteroom:8080 is not valid at
//     http://anteroom-noinject:8080.
//
// The pass cookie lives in an explicit jar, not the VU's default one: k6
// resets the default jar after every iteration (unless noCookiesReset is set),
// and a cache that says "you hold a pass" beside a jar that has forgotten it is
// a 403 on every second request. HELD_JAR is module state, so it is per VU and
// lives for the whole run. Every request made as a pass holder passes it.
//
// All VUs share the k6 container's address, so the /24 binding is satisfied
// trivially. From a distributed generator it would not be — each node solves
// its own.

import http from 'k6/http';
import { solve } from './pow.js';

// Not a browser: no Sec-Fetch metadata, no text/html, no "Mozilla". The gate
// answers 403 with the markdown instructions (the `refusal` rung).
export const BOT = {
  'User-Agent': 'anteroom-bench-bot/1',
  'Accept': '*/*',
};

// Same, but asks for the JSON body ([triage].json_accept).
export const BOT_JSON = Object.assign({}, BOT, { 'Accept': 'application/json' });

// A top-level navigation: the only request shape the gate answers with the
// wait page (the `wait-page` rung) and, once a pass is held, the only one it
// injects the renewal script into.
export const BROWSER = {
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 anteroom-bench/1',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Site': 'none',
  'Sec-Fetch-User': '?1',
  'Upgrade-Insecure-Requests': '1',
};

// A subresource fetch from a page the visitor already holds a pass for: same
// UA (the pass is bound to it), but not a navigation, so never injected into.
export const BROWSER_FETCH = {
  'User-Agent': BROWSER['User-Agent'],
  'Accept': 'application/json, text/plain, */*',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Site': 'same-origin',
};

// Per-VU pass cache, keyed by base URL, and the jar the passes live in.
// Module scope is per VU in k6. Cookies are keyed by host, so one jar serves
// every base this VU holds a pass for.
const passes = {};
export const HELD_JAR = new http.CookieJar();

// Guarantees HELD_JAR holds a live pass for `base`, solving if it has none or
// the one it has is about to lapse. Re-solving near expiry is deliberate: it
// exercises the pass_ttl boundary the way a real visitor's renewal would, minus
// the service worker.
export function ensurePass(base, headers = BROWSER) {
  const have = passes[base];
  if (have && have.exp_unix_ms - Date.now() > 5000) {
    return have;
  }
  const got = solve(base, { headers, jar: HELD_JAR });
  passes[base] = got;
  return got;
}

// Request params for a request made as the pass holder: the held jar, so the
// pass goes along.
export function held(headers, tags = {}) {
  return { headers, jar: HELD_JAR, tags };
}

// Forgets the cached pass for `base` (after a 403 that should not have been).
export function dropPass(base) {
  delete passes[base];
}

// Request params for a client that must hold nothing: a fresh, throwaway jar,
// so a refusal or wait-page iteration on a VU that earned a pass in an earlier
// scenario is still measured as the anonymous request it claims to be.
export function anon(headers, tags = {}) {
  return { headers, jar: new http.CookieJar(), tags };
}

// Params for a request the VU expects to be refused. Without the callback k6
// counts every 4xx in http_req_failed, and a refusal is the correct answer.
export function expecting(status, params) {
  return Object.assign({}, params, { responseCallback: http.expectedStatuses(status) });
}
