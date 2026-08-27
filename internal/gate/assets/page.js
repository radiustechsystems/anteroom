/* Anteroom wait-page driver.
 *
 * Preferred path: register the /.anteroom/ worker and ask IT to run the
 * challenge round over a MessagePort. Fetches issued inside a service worker
 * cannot be intercepted by any service worker, which is the only reliable
 * defense against a site's own root-scoped worker answering our requests from
 * its offline cache. Scope does not protect us here — a root worker controlling
 * this page sees every fetch this page makes — so the work has to happen there.
 *
 * Fallback: fetch directly from the page. Strictly worse (interceptable) but
 * necessary where service workers are unavailable, including any insecure
 * context, where WebCrypto is missing too.
 */
(function () {
  "use strict";
  var cfg = window.__ANTEROOM__ || {};
  var statusEl = document.getElementById("anteroom-status");
  var liveEl = document.getElementById("anteroom-live");
  var lastSpoken = "";
  var say = function (msg, spoken) {
    if (statusEl) statusEl.textContent = msg;
    if (liveEl && spoken && spoken !== lastSpoken) {
      lastSpoken = spoken;
      liveEl.textContent = spoken;
    }
  };

  var haveDigest =
    (window.crypto && window.crypto.subtle) ||
    typeof anteroomSHA256 === "function";
  if (!haveDigest) {
    // WebCrypto needs a secure context. Without it and without the operator's
    // opt-in fallback, this page cannot work — say whose problem that is.
    var digestError = window.isSecureContext === false
        ? "This site's bot check needs HTTPS. Site operator: serve Anteroom behind TLS, or set allow_insecure_context in anteroom.toml for plain-HTTP deployments."
        : "This browser does not expose WebCrypto, so the automatic check cannot run.";
    say(digestError, digestError);
    return;
  }

  // ---- worker bridge -----------------------------------------------------

  var workerPromise = null;

  function getWorker() {
    if (workerPromise) return workerPromise;
    if (!("serviceWorker" in navigator) || !cfg.swURL) {
      return Promise.reject(new Error("no service worker support"));
    }
    workerPromise = navigator.serviceWorker
      // updateViaCache:"none" keeps a stale worker script from being served out
      // of the HTTP cache. The script fetch itself is protected from service
      // worker interception by the platform.
      .register(cfg.swURL, { updateViaCache: "none" })
      .then(function (reg) {
        if (reg.active) return reg;
        var sw = reg.installing || reg.waiting;
        if (!sw) throw new Error("worker has no installation");
        return new Promise(function (resolve, reject) {
          var timer = setTimeout(function () {
            reject(new Error("worker activation timed out"));
          }, 10000);
          sw.addEventListener("statechange", function () {
            if (sw.state === "activated") {
              clearTimeout(timer);
              resolve(reg);
            } else if (sw.state === "redundant") {
              clearTimeout(timer);
              reject(new Error("worker became redundant"));
            }
          });
        });
      });
    return workerPromise;
  }

  function rpc(operation) {
    return getWorker().then(function (reg) {
      // Address the registration's active worker. Deliberately NOT this page's
      // controlling worker: if the site has its own root-scoped worker, that is
      // what controls this page, and messaging it would be messaging a stranger.
      var target = reg.active;
      if (!target) throw new Error("worker not active");
      return new Promise(function (resolve, reject) {
        var channel = new MessageChannel();
        var timer = setTimeout(function () {
          var err = new Error("worker did not answer");
          err.fromWorker = true;
          reject(err);
        }, 30000);
        channel.port1.onmessage = function (e) {
          clearTimeout(timer);
          var data = e.data || {};
          if (data.ok) resolve(data.result);
          else {
            var err = new Error(data.error || "worker rpc failed");
            err.fromWorker = true;
            reject(err);
          }
        };
        target.postMessage(
          { type: "ANTEROOM_RPC", operation: operation },
          [channel.port2],
        );
      });
    });
  }

  function startPings(reg) {
    var ping = function () {
      var w = reg.active || reg.installing || reg.waiting;
      if (w) w.postMessage({ type: "ping" });
    };
    ping();
    setInterval(ping, 4000);
  }

  // ---- admission ---------------------------------------------------------

  var attempt = 0;
  var MAX_ATTEMPTS = 5;

  function done(started) {
    say(
      "Done in " + ((Date.now() - started) / 1000).toFixed(1) + "s — loading…",
      "Check complete. Loading the site.",
    );
    location.reload();
  }

  function solveInPage() {
    var started = Date.now();
    var deadline = 0;
    return anteroomFetchAndSolve(cfg.challengeURL, cfg.answerURL, function (n, ch) {
      if (!deadline && ch) deadline = ch.deadline_unix_ms || 0;
      if (deadline && Date.now() > deadline - 500) {
        throw new Error("__anteroom_deadline__");
      }
      say("Checking your browser… " + n.toLocaleString() + " attempts");
      return new Promise(function (r) {
        setTimeout(r, 0); // yield so the page stays responsive
      });
    }).then(function () {
      done(started);
    });
  }

  function run() {
    attempt++;
    var started = Date.now();
    say("Checking your browser…", "Checking your browser.");

    // Try the worker first; fall back to solving in the page.
    rpc("solve")
      .then(function () {
        getWorker().then(startPings, function () {});
        done(started);
      })
      .catch(function (err) {
        // Once a worker accepted the RPC it owns that round. Falling back after
        // its timeout/rejection starts a second concurrent solve and doubles
        // the work on exactly the slow devices least able to afford it.
        if (err && err.fromWorker) throw err;
        return solveInPage().then(function () {
          getWorker().then(startPings, function () {});
        });
      })
      .catch(function (err) {
        var msg = (err && err.message) || String(err);
        if (msg === "__anteroom_cookies__") {
          say(
            "The check succeeded, but this browser did not retain the required cookie. Enable first-party cookies for this site and reload.",
            "The check succeeded, but first-party cookies are disabled. Enable them for this site and reload.",
          );
          return;
        }
        if (msg === "__anteroom_deadline__") {
          // A fresh challenge discards all progress; windows do not accumulate.
          // Give probabilistic work a few independent chances, then stop rather
          // than hashing forever on a device whose speed and configured
          // difficulty do not fit inside the challenge lifetime.
          if (attempt >= MAX_ATTEMPTS) {
            say(
              "This device could not finish the check before its deadline after " +
                MAX_ATTEMPTS +
                " attempts. Please reload to try again, or contact the site owner.",
              "This device could not finish the check before its deadline. Please reload or contact the site owner.",
            );
            return;
          }
          say("Still checking your browser…", "The first check expired. Trying again.");
          setTimeout(run, 250);
          return;
        }
        if (msg === "__anteroom_intercepted__") {
          // A site worker answered our request from its cache and the worker
          // bridge was unavailable too. Retrying cannot help.
          say(
            "Another service worker on this site is intercepting requests, so " +
              "the check cannot complete. Site operator: exclude /.anteroom/* " +
              "from your service worker's fetch handler.",
            "The check cannot complete because another service worker is intercepting it.",
          );
          return;
        }
        if (attempt >= MAX_ATTEMPTS) {
          say(
            "We could not complete the automatic check on this device (" +
              msg +
              "). Please reload to try again, or contact the site owner.",
            "The automatic check could not complete. Please reload or contact the site owner.",
          );
          return;
        }
        say(
          "The automatic check failed (" + msg + "). Retrying…",
          "The automatic check failed. Retrying.",
        );
        setTimeout(run, 3000);
      });
  }

  run();
})();
