// Command hello-app is a small demonstration web service.
//
// It is deliberately varied rather than minimal: it serves HTML documents, a
// JSON API, static assets, a feed and crawler files, an inbound webhook, a
// server-sent event stream, a large download, a slow endpoint, pages carrying
// each flavor of Content-Security-Policy, and a page that registers its own
// root-scoped service worker. Anything placed in front of this app has to cope
// with all of it.
//
// Configuration is one environment variable, HELLO_LISTEN (default ":3000").
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	addr := os.Getenv("HELLO_LISTEN")
	if addr == "" {
		addr = ":3000"
	}

	mux := http.NewServeMux()

	// Ordinary HTML documents.
	mux.HandleFunc("/", index)
	mux.HandleFunc("/about", about)

	// A JSON API: not a browser navigation.
	mux.HandleFunc("/api/items", apiItems)

	// Static assets.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Crawler and feed files.
	mux.HandleFunc("/robots.txt", textFile("User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n"))
	mux.HandleFunc("/sitemap.xml", xmlFile(sitemap))
	mux.HandleFunc("/feed.xml", xmlFile(feed))

	// An inbound webhook: a cross-site POST carrying a body that matters.
	mux.HandleFunc("/webhooks/inbound", webhook)

	// A server-sent event stream.
	mux.HandleFunc("/events", events)

	// A large download.
	mux.HandleFunc("/download/big.bin", bigFile)

	// One page per Content-Security-Policy flavor.
	for name, policy := range cspCases {
		mux.HandleFunc("/csp/"+name, cspPage(name, policy))
	}

	// A page that registers a root-scoped service worker with a catch-all fetch
	// handler, the way a real progressive web app does.
	mux.HandleFunc("/sw-owner", swOwnerPage)
	// Named app-sw.js, not sw.js: the gate serves its own worker at
	// /.anteroom/sw.js, and two files both called "sw.js" are indistinguishable
	// in a browser's debugger exactly when you are trying to tell them apart.
	mux.HandleFunc("/app-sw.js", swOwnerScript)
	mux.HandleFunc("/sw-register.js", swRegisterScript)

	// A slow endpoint.
	mux.HandleFunc("/slow", slow)

	// Cookies and header reflection.
	mux.HandleFunc("/set-cookie", setCookie)
	mux.HandleFunc("/echo", echo)

	// A live view of the gate's renewal loop, and a switch to turn it off.
	// This page knowingly reaches into Anteroom's internals, which an ordinary
	// application has no business doing. It exists because renewal is invisible
	// by design, and a mechanism nobody can see is a mechanism nobody believes.
	mux.HandleFunc("/renewal", renewalPage)

	// Liveness.
	mux.HandleFunc("/healthz", textFile("ok\n"))

	log.Printf("hello-app listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// --- ordinary documents -----------------------------------------------------

const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:title" content="hello-app — %s">
<meta property="og:description" content="A small demonstration web service.">
<title>hello-app — %s</title>
</head>
<body>
<h1>%s</h1>
<p id="marker">%s</p>
<nav><a href="/">home</a> <a href="/about">about</a> <a href="/sw-owner">sw-owner</a></nav>
</body>
</html>
`

func page(w http.ResponseWriter, title, marker string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	path := "/" + title
	if title == "home" {
		path = "/"
	}
	fmt.Fprint(w, shellTop(title, path))
	fmt.Fprintf(w, "<h1>%s</h1>\n<p id=\"marker\">%s</p>\n", title, marker)
	fmt.Fprint(w, shellBottom)
}

func index(w http.ResponseWriter, r *http.Request) {
	// The catch-all pattern would otherwise answer every unrouted path with 200.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	page(w, "home", "hello from the app")
}

func about(w http.ResponseWriter, r *http.Request) { page(w, "about", "second document") }

// --- machine surfaces -------------------------------------------------------

func apiItems(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"items": []map[string]any{
			{"id": 1, "name": "first"},
			{"id": 2, "name": "second"},
		},
	})
}

func webhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// The body is echoed back, so a caller can confirm it survived the trip.
	w.Header().Set("Content-Type", "application/json")
	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"received": string(body), "bytes": len(body)})
}

func events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	for i := range 5 {
		fmt.Fprintf(w, "data: tick %d\n\n", i)
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(150 * time.Millisecond):
		}
	}
}

func bigFile(w http.ResponseWriter, r *http.Request) {
	const size = 8 << 20
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprint(size))
	// A deterministic body, so a caller can verify it without storing a copy.
	chunk := make([]byte, 4096)
	for i := range chunk {
		chunk[i] = byte(i % 251)
	}
	for written := 0; written < size; written += len(chunk) {
		w.Write(chunk)
	}
}

func slow(w http.ResponseWriter, r *http.Request) {
	select {
	case <-time.After(30 * time.Second):
		w.Write([]byte("slow but finished\n"))
	case <-r.Context().Done():
	}
}

// --- CSP matrix -------------------------------------------------------------

// cspCases is one page per Content-Security-Policy shape worth exercising. The
// value is the header verbatim; the empty string means no header at all.
var cspCases = map[string]string{
	"none":           "",
	"self":           "default-src 'self'; script-src 'self'",
	"unsafe-inline":  "script-src 'self' 'unsafe-inline'",
	"strict-dynamic": "script-src 'nonce-appnonce123' 'strict-dynamic'",
	"hash":           "script-src 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='",
	"none-directive": "script-src 'none'",
	"sandbox":        "sandbox",
	"host-allowlist": "script-src https://cdn.example.com",
	"report-only":    "",
	// The policy lives only in a <meta http-equiv> tag, not in a header.
	// "meta" allows 'self'; "meta-strict" is hash-only, so anything wanting to
	// add a script would have to rewrite a policy that is inside the document.
	"meta":        "",
	"meta-strict": "",
}

func cspPage(name, policy string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if policy != "" {
			w.Header().Set("Content-Security-Policy", policy)
		}
		if name == "report-only" {
			w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'self'; report-uri /csp-report")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if name == "meta" {
			fmt.Fprint(w, metaCSPPage)
			return
		}
		if name == "meta-strict" {
			fmt.Fprint(w, metaStrictCSPPage)
			return
		}
		fmt.Fprintf(w, pageTemplate, "csp/"+name, "csp/"+name, "csp/"+name, policy)
	}
}

// --- service worker coexistence ---------------------------------------------

func swOwnerPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, shellTop("service worker", "/sw-owner"))
	fmt.Fprint(w, `<h1>The site's own service worker</h1>
<p class="sub">This page registers a root-scoped worker with a catch-all fetch
handler, the way a real progressive web app does. Anteroom's renewal worker has
to coexist with it — and on Firefox, this is the configuration that used to wall
every visitor permanently.</p>
<p id="marker">this page registers its own root-scoped service worker</p>
<div id="sw-state">registering</div>
<script src="/sw-register.js"></script>
`)
	fmt.Fprint(w, shellBottom)
}

// swOwnerScript is a root-scoped worker with a catch-all fetch handler, served
// with Service-Worker-Allowed: / so it controls every document on the origin —
// which is what a real progressive web app's worker does.
func swOwnerScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Service-Worker-Allowed", "/")
	fmt.Fprint(w, `self.addEventListener("install", function (e) { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
// A catch-all handler: every fetch from a controlled page passes through here.
self.addEventListener("fetch", function (e) {
  e.respondWith(fetch(e.request));
});
`)
}

// --- header and cookie surfaces ---------------------------------------------

func setCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "app_session", Value: "abc123", Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "app_pref", Value: "dark", Path: "/"})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("cookies set\n"))
}

// echo reports exactly what the application received — the only trustworthy way
// to see what a proxy in front of it did or did not change.
func echo(w http.ResponseWriter, r *http.Request) {
	headers := map[string][]string{}
	names := make([]string, 0, len(r.Header))
	for k, v := range r.Header {
		headers[k] = v
		names = append(names, k)
	}
	sort.Strings(names)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"method":       r.Method,
		"path":         r.URL.Path,
		"raw_path":     r.URL.EscapedPath(),
		"query":        r.URL.RawQuery,
		"host":         r.Host,
		"remote_addr":  r.RemoteAddr,
		"proto":        r.Proto,
		"headers":      headers,
		"header_names": names,
		"cookie_raw":   strings.Join(r.Header.Values("Cookie"), " | "),
	})
}

// --- small static files -----------------------------------------------------

func textFile(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(body))
	}
}

func xmlFile(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write([]byte(body))
	}
}

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/about</loc></url>
</urlset>
`

const feed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>hello-app</title>
  <link>/</link>
  <description>A small demonstration web service.</description>
  <item><title>First post</title><link>/</link></item>
</channel></rss>
`

// metaCSPPage carries its policy in a meta tag and nowhere else.
const metaCSPPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
<title>hello-app — csp/meta</title>
</head>
<body>
<h1>csp/meta</h1>
<p id="marker">policy is in a meta tag only</p>
</body>
</html>
`

// metaStrictCSPPage carries a hash-only policy in a meta tag: satisfying it
// would require adding a hash to a policy that lives inside the document.
const metaStrictCSPPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="script-src 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='">
<title>hello-app — csp/meta-strict</title>
</head>
<body>
<h1>csp/meta-strict</h1>
<p id="marker">hash-only policy, in a meta tag</p>
</body>
</html>
`

func swRegisterScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	fmt.Fprint(w, `navigator.serviceWorker
  .register("/app-sw.js", { scope: "/" })
  .then(function (reg) {
    document.getElementById("sw-state").textContent = "registered:" + reg.scope;
  })
  .catch(function (err) {
    document.getElementById("sw-state").textContent = "failed:" + err;
  });
`)
}

// renewalPage shows whether the pass is alive, and lets a visitor stop the
// worker to watch it lapse and re-admission happen.
//
// What this page can honestly observe is narrow, and the narrowness is the
// lesson. The pass is HttpOnly, so script cannot read it or its expiry. The
// renewal fetches happen inside the service worker, so they never appear in the
// page's network panel. One signal is real: asking the gate for a challenge
// reports a kind, which is "renew" only while this visitor holds a live pass and
// "admit" once it has lapsed. That is a read and renews nothing.
//
// Deliberately NOT shown: a countdown. deadline_unix_ms belongs to the challenge
// just issued, not to the pass being held, so displaying it as an expiry
// produces a number that always looks healthy no matter what is happening.
func renewalPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, shellTop("renewal", "/renewal"))
	fmt.Fprint(w, renewalBody)
	fmt.Fprint(w, shellBottom)
}

const renewalBody = `<h1>Renewal, live</h1>
<p class="sub">The pass is short-lived and renewed in the background, which is why
you normally see nothing at all. Stop the worker and watch it lapse.</p>

<div class="grid">
  <span class="k">pass</span><span class="v" id="state">checking…</span>
  <span class="k">in this state for</span><span class="v" id="held">…</span>
  <span class="k">re-admissions</span><span class="v" id="count">0</span>
  <span class="k">renewal worker</span><span class="v" id="sw">…</span>
</div>
<div class="bar"><div class="fill" id="fill"></div></div>

<button id="stop">Stop renewing</button>
<button id="go" disabled>Reload now</button>

<div id="log"></div>
<script>
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var live = null, since = Date.now();

  // Re-admission is only ever observed across a reload: once renewal stops
  // there is no way back to a live pass except being challenged again, and
  // that navigation replaces this page. So the count and the "we were lapsed"
  // flag outlive the page, or the counter could never leave zero.
  var store = window.sessionStorage;
  var count = parseInt(store.getItem("anteroom-readmits") || "0", 10) || 0;
  var sawLapse = store.getItem("anteroom-lapsed") === "1";

  function log(msg, cls) {
    var d = document.createElement("div");
    d.textContent = new Date().toLocaleTimeString() + "  " + msg;
    if (cls) d.className = cls;
    $("log").insertBefore(d, $("log").firstChild);
  }

  function poll() {
    fetch("/.anteroom/challenge", { credentials: "include", cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (c) {
        var now = c.kind === "renew";
        if (live === null) {
          if (now && sawLapse) {
            // This page load is the far side of a re-admission: we recorded a
            // lapse, the visitor was challenged, and here we are with a pass.
            sawLapse = false;
            store.removeItem("anteroom-lapsed");
            count++;
            store.setItem("anteroom-readmits", String(count));
            $("count").textContent = count;
            log("re-admitted — a fresh pass was earned", "mark");
          }
          log(now ? "pass is live and being renewed" : "no pass — the next navigation is challenged");
        } else if (now !== live) {
          since = Date.now();
          if (now) {
            count++;
            $("count").textContent = count;
            log("re-admitted — a fresh pass was earned", "mark");
          } else {
            sawLapse = true;
            store.setItem("anteroom-lapsed", "1");
            log("pass lapsed — nothing is renewing it now", "mark");
          }
        }
        live = now;
        $("state").textContent = now ? "live" : "lapsed";
        $("state").className = "v " + (now ? "live" : "lapsed");
        $("fill").style.width = now ? "100%" : "0%";
        $("fill").className = "fill" + (now ? "" : " low");
        tick();
      })
      .catch(function () { $("state").textContent = "gate unreachable"; });
  }

  // The clock and the network are separate on purpose. The held counter wants
  // to move often enough to look alive; asking the gate does not, and every
  // poll mints a challenge that nobody is going to solve. Painting locally
  // keeps the demo smooth without making the demo itself the load.
  function tick() {
    $("held").textContent = ((Date.now() - since) / 1000).toFixed(1) + "s";
  }

  if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
    // Stop the injected driver first. The worker-side flag alone is not enough:
    // a terminated worker comes back with it cleared, and this page pings every
    // four seconds, so it would revive the renewal it just switched off.
    if (window.__anteroomRenewal) window.__anteroomRenewal.stop();
    navigator.serviceWorker.getRegistrations().then(function (rs) {
      var ours = rs.filter(function (r) { return r.scope.indexOf("/.anteroom/") !== -1; });
      $("sw").textContent = ours.length ? "registered" : "none";
    });
  } else {
    $("sw").textContent = "unavailable (needs HTTPS or localhost)";
  }

  $("stop").onclick = function () {
    $("stop").disabled = true;
    $("go").disabled = false;
    // Stop the injected driver first. The worker-side flag alone is not enough:
    // a terminated worker comes back with it cleared, and this page pings every
    // four seconds, so it would revive the renewal it just switched off.
    if (window.__anteroomRenewal) window.__anteroomRenewal.stop();
    navigator.serviceWorker.getRegistrations().then(function (rs) {
      Promise.all(
        rs.filter(function (r) { return r.scope.indexOf("/.anteroom/") !== -1; })
          .map(function (r) {
            // Stand it down before unregistering. This page is itself a driver:
            // the injected renewal script pings every 4s, and unregistration
            // does not complete while a controlled client is open, so without
            // the stop message the worker is renewing again seconds later.
            var w = r.active || r.waiting || r.installing;
            if (w) w.postMessage({ type: "stop" });
            return r.unregister();
          })
      ).then(function () {
        $("sw").textContent = "unregistered";
        log("renewal stopped — watch the pass lapse, then reload", "mark");
      });
    });
  };
  $("go").onclick = function () { location.reload(); };

  $("count").textContent = count;
  poll();
  setInterval(poll, 4000);
  setInterval(tick, 400);
})();
</script>
`

// shellTop renders the shared chrome for the demo's human-facing pages. The
// /csp/* pages deliberately do not use it — they exist to exercise policy, and
// an inline <style> would be blocked by half of the policies under test.
func shellTop(title, current string) string {
	mark := func(path string) string {
		if path == current {
			return " aria-current=\"page\""
		}
		return ""
	}
	return fmt.Sprintf(shellHTML, title,
		mark("/"), mark("/about"), mark("/renewal"), mark("/sw-owner"))
}

const shellHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta property="og:title" content="hello-app — %[1]s">
<meta property="og:description" content="A small demonstration web service.">
<title>hello-app — %[1]s</title>
<style>
 /* Light on dark, deliberately. This is the site being protected; Anteroom's
    wait page is light. When the gate interrupts a navigation the change is
    unmistakable from across a room, and when it hands you through, so is the
    return. */
 :root{--bg:#111417;--panel:#171b20;--line:#242a31;--ink:#e7ebef;--dim:#8e99a6;
       --accent:#5ad1a0;--warn:#e0a458}
 *{box-sizing:border-box}
 body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
      font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
      display:flex;align-items:flex-start;justify-content:center;padding:2.5rem 1rem}
 main{width:min(44rem,100%%)}
 nav{display:flex;gap:.25rem;flex-wrap:wrap;margin-bottom:2rem;
     border-bottom:1px solid var(--line);padding-bottom:.9rem}
 nav a{color:var(--dim);text-decoration:none;font-size:.88rem;padding:.3rem .7rem;
       border-radius:4px}
 nav a:hover{color:var(--ink);background:var(--panel)}
 nav a[aria-current]{color:var(--accent);background:var(--panel)}
 h1{font-size:1.45rem;margin:0 0 .4rem;letter-spacing:-.01em}
 .sub{color:var(--dim);margin:0 0 1.6rem}
 #marker{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent);
         background:var(--panel);border:1px solid var(--line);border-radius:4px;
         padding:.7rem .9rem;display:inline-block}
 a{color:var(--accent)}
 .grid{display:grid;grid-template-columns:max-content 1fr;gap:.45rem 1.25rem;
       align-items:baseline;font-variant-numeric:tabular-nums}
 .k{color:var(--dim);font-size:.85rem}
 .v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
 .v.live{color:var(--accent);font-weight:600}
 .v.lapsed{color:var(--warn);font-weight:600}
 .bar{height:8px;background:var(--panel);border:1px solid var(--line);border-radius:4px;
      overflow:hidden;margin:.9rem 0 1.3rem}
 .fill{height:100%%;width:100%%;background:var(--accent);transition:width .25s linear}
 .fill.low{background:var(--warn)}
 button{font:inherit;padding:.5rem 1rem;border:1px solid var(--line);background:var(--panel);
        color:var(--ink);border-radius:4px;cursor:pointer;margin-right:.5rem}
 button:hover:not(:disabled){border-color:var(--accent)}
 button:disabled{opacity:.35;cursor:default}
 #log,#sw-state{margin-top:1.4rem;font-family:ui-monospace,monospace;font-size:.8rem;
      background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:.6rem;
      color:var(--dim)}
 #log{max-height:10rem;overflow:auto}
 #log div{padding:.1rem 0;overflow-wrap:anywhere}
 .mark{color:var(--warn);font-weight:600}
</style>
</head>
<body><main>
<nav>
  <a href="/"%[2]s>home</a>
  <a href="/about"%[3]s>about</a>
  <a href="/renewal"%[4]s>renewal, live</a>
  <a href="/sw-owner"%[5]s>service worker</a>
  <a href="/api/items">api</a>
  <a href="/feed.xml">feed</a>
</nav>
`

const shellBottom = "\n</main></body></html>\n"
