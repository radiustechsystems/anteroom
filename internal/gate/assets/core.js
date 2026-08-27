/* Anteroom solver core — shared verbatim by the wait page, the service
 * worker, and the inline fallback. WebCrypto only, by design: the goal is to
 * minimize the attacker/defender gap, and crypto.subtle is the best primitive
 * every real browser already ships.
 */
"use strict";

function anteroomHexToBytes(hex) {
  var out = new Uint8Array(hex.length / 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(2 * i, 2), 16);
  }
  return out;
}

function anteroomLessThan(a, b) {
  for (var i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false; // equal is not below
}

/* anteroomDigest hashes bytes with WebCrypto when available, and otherwise with
 * the JS fallback (served only when the operator opts into insecure contexts).
 * WebCrypto is always preferred: it is far faster, which keeps the gap between
 * an honest visitor and a native attacker as small as a browser allows. */
function anteroomDigest(bytes) {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle.digest("SHA-256", bytes).then(function (buf) {
      return new Uint8Array(buf);
    });
  }
  if (typeof anteroomSHA256 === "function") {
    return Promise.resolve(anteroomSHA256(bytes));
  }
  return Promise.reject(new Error("no SHA-256 implementation available"));
}

/* anteroomSolve finds a nonce with sha256(challenge + nonce) < threshold.
 * onTick, if given, is awaited every `batch` attempts and receives
 * (attempts, challengeResponse) — the page uses it to paint progress, yield to
 * the event loop, and abandon work that has passed its deadline. Throwing from
 * onTick aborts the solve. */
async function anteroomSolve(challenge, thresholdHex, onTick, ch) {
  var enc = new TextEncoder();
  var threshold = anteroomHexToBytes(thresholdHex);
  /* The JS fallback is synchronous and ~10-50x slower per hash, so it yields
   * more often to keep the page responsive. */
  var batch =
    typeof crypto !== "undefined" && crypto.subtle ? 1024 : 128;
  for (var nonce = 0; ; nonce++) {
    var digest = await anteroomDigest(enc.encode(challenge + nonce));
    if (anteroomLessThan(digest, threshold)) return String(nonce);
    if (onTick && nonce % batch === 0) await onTick(nonce, ch);
  }
}

/* anteroomFetchAndSolve runs one full challenge round against the gate's API
 * and returns the answer response body ({ok, kind, exp_unix_ms}). */
async function anteroomFetchAndSolve(challengeURL, answerURL, onTick) {
  var res = await fetch(challengeURL, { cache: "no-store" });
  if (!res.ok) throw new Error("challenge fetch failed (" + res.status + ")");
  /* If another service worker on this origin has a catch-all fetch handler, our
   * request can be answered from its cache (typically an offline fallback page)
   * instead of by the gate. Detect that by content type rather than looping
   * forever on a JSON parse error, so the failure is diagnosable. */
  var ct = res.headers.get("Content-Type") || "";
  if (ct.indexOf("application/json") === -1) {
    throw new Error("__anteroom_intercepted__");
  }
  var ch = await res.json();
  var nonce = await anteroomSolve(ch.challenge, ch.threshold, onTick, ch);
  var ans = await fetch(answerURL, {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge: ch.challenge, nonce: nonce }),
  });
  var body = await ans.json();
  if (!ans.ok || !body.ok) {
    throw new Error(body.error || "answer rejected (" + ans.status + ")");
  }
  await anteroomConfirmPass(challengeURL);
  body.pass_ttl_ms = ch.pass_ttl_ms;
  return body;
}

/* HttpOnly correctly keeps the pass out of JavaScript, so the only portable way
 * to learn whether the browser retained it is to ask the gate which tier the
 * next challenge belongs to. Without this check a cookie-disabled browser
 * solves, reloads, and solves forever with no diagnosis. */
async function anteroomConfirmPass(challengeURL) {
  var res = await fetch(challengeURL, {
    credentials: "include",
    cache: "no-store",
  });
  if (!res.ok) throw new Error("pass confirmation failed (" + res.status + ")");
  var state = await res.json();
  if (state.kind !== "renew") throw new Error("__anteroom_cookies__");
}
