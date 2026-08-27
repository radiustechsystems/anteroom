/* Anteroom renewal driver, injected into proxied pages.
 *
 * Deliberately not the wait-page driver: this page is already admitted, so there
 * is nothing to solve on arrival and nothing to say to the visitor. All this does
 * is register the worker and tell it a page is still open. The worker owns the
 * schedule — it renews a third of a TTL before expiry and stops on its own once
 * the pings stop (DRIVER_STALE_MS in sw.js), so a closed tab lapses without
 * anyone having to clean up.
 *
 * No UI, no DOM reads, no eval: this must survive a strict CSP and a
 * require-trusted-types-for policy untouched.
 */
(function () {
  "use strict";

  /* Warn when renewal cannot start; the page otherwise works until its pass
   * expires, making the degraded state difficult to diagnose. */
  var say = function (why, detail) {
    if (window.console && console.warn) {
      console.warn("[anteroom] pass renewal is not running: " + why +
        ". This pass will lapse and you will be checked again.", detail || "");
    }
  };

  // Service workers need a secure context, exactly like WebCrypto. Where there
  // is none there is nothing to do: the visitor re-solves when the pass lapses,
  // which is the documented allow_insecure_context trade.
  if (!("serviceWorker" in navigator)) {
    say("this page is not a secure context, so there is no service worker to " +
      "renew in (see allow_insecure_context)");
    return;
  }

  var PING_MS = 4000;

  navigator.serviceWorker
    // The scope stays /.anteroom/ — the default for this script's location — so
    // this worker controls no page of the operator's and cannot become an
    // origin-wide interception surface.
    .register("/.anteroom/sw.js", { updateViaCache: "none" })
    .then(function (reg) {
      var stopped = false;
      var send = function (type) {
        if (stopped && type !== "stop") return;
        var w = reg.active || reg.installing || reg.waiting;
        if (w) w.postMessage({ type: type });
      };
      var ping = function () { send("ping"); };
      /* "start", not "ping", for the first message: a page that has just
       * loaded resumes renewal even if a previous page stood the worker down.
       * Later pings deliberately cannot, so a stop stays stopped. */
      send("start");
      var interval = setInterval(ping, PING_MS);

      /* The one control this script exposes. Telling the worker to stand down
       * is not enough on its own: a worker is terminated whenever the browser
       * feels like it, its variables go with it, and the very next ping would
       * wake a fresh one with renewal switched back on. So the driver has to
       * stop pinging as well — which is the half only this script can do. */
      window.__anteroomRenewal = {
        stop: function () {
          stopped = true;
          clearInterval(interval);
          send("stop");
        },
      };
      // Browsers throttle timers in background tabs, often below the worker's
      // staleness threshold, so a hidden tab is allowed to let its pass lapse —
      // that is the battery-friendly outcome and the correct one. Ping the
      // moment the visitor comes back rather than waiting for the next tick.
      document.addEventListener("visibilitychange", function () {
        if (!document.hidden) ping();
      });
      // A page restored from the back-forward cache resumes with old timer
      // state. Reassert liveness immediately instead of waiting up to PING_MS
      // (or for a throttled interval that the browser never resumes promptly).
      window.addEventListener("pageshow", function (event) {
        if (event.persisted) {
          send("start");
          ping();
        }
      });
    })
    .catch(function (err) {
      /* Registration may be refused by private mode, policy, or an insecure
       * context; the warning makes the resulting pass lapse visible. */
      say("the renewal worker could not be registered (private browsing, an " +
        "enterprise policy, or no HTTPS)", err);
    });
})();
