/* Anteroom worker (shell — the solver core is prepended at serve time).
 *
 * This worker exists for one reason beyond convenience: **a fetch initiated
 * inside a ServiceWorkerGlobalScope has its service-workers mode set to "none"**
 * (Fetch Standard), so it cannot be intercepted by any service worker — not the
 * site's own, and not this one. That matters because service-worker scope
 * selects which DOCUMENTS a worker controls, not which request URLs it sees: a
 * root-scoped worker controlling the visitor's page intercepts every fetch that
 * page makes, including ours, no matter what path we put our API on. Moving the
 * endpoint under /.anteroom/ does not help a page-level fetch; performing the
 * fetch in here does.
 *
 * So pages do not call the gate directly. They send an RPC over a MessagePort
 * and this worker performs the network I/O on their behalf.
 *
 * Registered at the default /.anteroom/ scope. It controls no page — messages
 * arrive from uncontrolled documents via registration.active — and it has NO
 * fetch handler. Never add one: with a fetch handler this stops being a renewal
 * helper and becomes an origin-wide interception surface.
 */
"use strict";

var CHALLENGE_URL = "/.anteroom/challenge";
var ANSWER_URL = "/.anteroom/answer";
/* A driver page pings every few seconds; three missed pings ≈ every tab is
 * gone (or the browser suspended us, which resolves the same way: lapse). */
var DRIVER_STALE_MS = 15000;

var lastPingAt = 0;
var timer = null;
/* One admission round per worker. Several tabs reaching the checkpoint at once
 * share it instead of each heating the same device with an independent solve. */
var admissionRound = null;
/* Client IDs waiting for that round. An uncontrolled wait page is still a
 * WindowClient, so the worker can stop heating the device after every joining
 * tab has gone away. A missing source ID disables cancellation for that caller
 * rather than risking a false abort on an unusual browser. */
var admissionWaiters = Object.create(null);
var admissionHasAnonymousWaiter = false;
/* pass_ttl_ms as last reported by the gate, so the retry backoff can be sized
 * against the pass it is protecting rather than against a constant. */
var lastTTL = 0;
/* Set by a "stop" message: the visitor asked to stop renewing. Pings from
 * pages that are already open cannot clear it — otherwise a driver on the very
 * page carrying the stop button would resurrect the schedule four seconds
 * later. Only a "start" from a freshly loaded page resumes renewal. */
var stopped = false;

self.addEventListener("install", function () {
  self.skipWaiting();
});

self.addEventListener("message", function (event) {
  var msg = event.data || {};

  /* RPC: the page asks us to run a full challenge round and report back. */
  if (msg.type === "ANTEROOM_RPC") {
    var port = event.ports && event.ports[0];
    if (!port) return;
    event.waitUntil(
      handleRPC(msg.operation, event.source && event.source.id)
        .then(function (result) {
          port.postMessage({ ok: true, result: result });
        })
        .catch(function (err) {
          port.postMessage({
            ok: false,
            error: String((err && err.message) || err),
          });
        }),
    );
    return;
  }

  /* A page loaded and wants renewal: always resumes, even after a stop. */
  if (msg.type === "start") {
    stopped = false;
  }

  /* Stand down. Unregistering from a page does not stop us — unregistration
   * only completes once every controlled client is gone — so a visitor asking
   * to stop renewing needs to be able to say so directly. Self-harming only:
   * the pass lapses and the next navigation is challenged.
   *
   * This flag is best-effort by nature: it lives in a worker global, and a
   * terminated worker starts again with it cleared. That is why the driver
   * stops pinging at the same time (renew.js). Without that half, the next
   * ping revives a fresh worker with renewal back on. */
  if (msg.type === "stop") {
    stopped = true;
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    return;
  }

  /* Liveness: a driver page is still open, so keep the pass fresh. */
  if (msg.type === "ping" || msg.type === "start") {
    if (stopped) return;
    lastPingAt = Date.now();
    if (timer === null) schedule(0);
  }
});

async function handleRPC(operation, clientID) {
  switch (operation) {
    case "solve":
      // Admission, driven by the page but fetched from here so a site worker
      // cannot intercept it. Counts as liveness: a page asking to be admitted
      // is a page that is open.
      stopped = false;
      lastPingAt = Date.now();
      if (clientID) admissionWaiters[clientID] = true;
      else admissionHasAnonymousWaiter = true;
      if (!admissionRound) {
        admissionRound = round(admissionStillWanted).then(function (out) {
          lastTTL = out.pass_ttl_ms || lastTTL;
          if (timer === null) schedule(nextDelay(out));
          return out;
        });
        admissionRound.then(clearAdmissionRound, clearAdmissionRound);
      }
      return admissionRound;
    default:
      throw new Error("unknown operation: " + operation);
  }
}

function clearAdmissionRound() {
  admissionRound = null;
  admissionWaiters = Object.create(null);
  admissionHasAnonymousWaiter = false;
}

async function admissionStillWanted() {
  if (admissionHasAnonymousWaiter) return true;
  var ids = Object.keys(admissionWaiters);
  if (ids.length === 0) return true;
  var live = await self.clients.matchAll({
    type: "window",
    includeUncontrolled: true,
  });
  for (var i = 0; i < live.length; i++) {
    if (admissionWaiters[live[i].id]) return true;
  }
  return false;
}

function schedule(ms) {
  if (timer !== null) clearTimeout(timer);
  timer = setTimeout(renew, ms);
}

function nextDelay(out) {
  /* Renew comfortably before expiry: a third of the TTL early, capped at 3s. */
  var headroom = Math.min(3000, (out.pass_ttl_ms || 10000) / 3);
  var base = Math.max(1000, out.exp_unix_ms - Date.now() - headroom);
  /* Independent early jitter avoids aligning a fleet of visitors on one
   * renewal instant after a shared outage or deployment. */
  var jitter = Math.random() * Math.min(1000, (out.pass_ttl_ms || 10000) / 10);
  return Math.max(400, base - jitter);
}

/* Keep retry backoff below the pass TTL so a transient failure need not cause
 * a visible re-challenge. */
function retryDelay() {
  var base = lastTTL ? Math.max(400, Math.min(3000, lastTTL / 3)) : 3000;
  return base + Math.random() * Math.min(500, base / 5);
}

/* A worker outlives the software that installed it. If the gate is gone —
 * endpoint missing, or answering with something that is not our JSON API — stop
 * and remove ourselves instead of polling a stranger's server forever. */
async function retireIfGateIsGone(res) {
  if (res.status === 404 || res.status === 410) {
    await self.registration.unregister();
    return true;
  }
  var ct = res.headers.get("Content-Type") || "";
  if (res.ok && ct.indexOf("application/json") === -1) {
    await self.registration.unregister();
    return true;
  }
  return false;
}

/* round runs one challenge → solve → answer cycle.
 *
 * The solve is bounded by the deadline the gate advertised, exactly as the page
 * bounds its own. Without it a device slow enough to pass the deadline keeps
 * hashing, submits work that can only be refused, and starts again — burning a
 * phone's battery on answers the gate will not take. Passing the deadline
 * through turns that into one abandoned round and a fresh challenge. */
async function round(stillWanted) {
  var probe = await fetch(CHALLENGE_URL, {
    credentials: "include",
    cache: "no-store",
  });
  if (await retireIfGateIsGone(probe)) throw new Error("gate is gone");
  if (!probe.ok) throw new Error("challenge " + probe.status);
  var ch = await probe.json();

  var deadline = ch.deadline_unix_ms || 0;
  var lastWantedCheck = 0;
  var nonce = await anteroomSolve(ch.challenge, ch.threshold, async function () {
    if (deadline && Date.now() > deadline - 500) {
      throw new Error("__anteroom_deadline__");
    }
    if (stillWanted && Date.now() - lastWantedCheck >= 500) {
      lastWantedCheck = Date.now();
      if (!(await stillWanted())) throw new Error("__anteroom_abandoned__");
    }
  }, ch);

  var ans = await fetch(ANSWER_URL, {
    method: "POST",
    credentials: "include",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge: ch.challenge, nonce: nonce }),
  });
  if (await retireIfGateIsGone(ans)) throw new Error("gate is gone");
  var out = await ans.json();
  if (!ans.ok || !out.ok) throw new Error(out.error || "answer rejected");
  if (stillWanted) await anteroomConfirmPass(CHALLENGE_URL);
  out.pass_ttl_ms = ch.pass_ttl_ms;
  return out;
}

async function renew() {
  timer = null;
  if (Date.now() - lastPingAt > DRIVER_STALE_MS) {
    return; // no driver pages: let the pass lapse
  }
  try {
    var out = await round();
    lastTTL = out.pass_ttl_ms || lastTTL;
    schedule(nextDelay(out));
  } catch (err) {
    schedule(retryDelay()); // transient failure; the gate re-admits if we lapse
  }
}
