# Operating Anteroom

Anteroom is a proxy that deliberately stops being transparent at a few points: it
serves an interstitial at the URL of real content, sets a cookie, and (optionally)
injects a script into HTML. Each of those has consequences. This document states
them plainly — what must be true of your deployment, and what stops working
until you configure around it.

## Deployment prerequisites

1. **HTTPS, or `localhost` — or opt into the fallback.** The solver uses
   WebCrypto, and service workers likewise require a secure context, so on plain
   HTTP over a network (`http://192.168.1.50:8080`, the common Docker case) both
   are unavailable and visitors would be walled permanently. Two options:
   - serve it behind TLS, and list your TLS terminator in `trusted_proxies`; or
   - set `allow_insecure_context = true`, which ships a JavaScript SHA-256 so the
     initial puzzle works. Service-worker renewal remains unavailable, so the
     visitor re-solves when the pass lapses.

   The fallback is a real trade, stated plainly: it is 10–50× slower per hash
   than WebCrypto, and that cost falls entirely on the honest visitor — an
   attacker's native implementation is unaffected, so the work asymmetry the gate
   depends on narrows. Reasonable on a LAN or in development; a downgrade on the
   public internet. The gate warns about it at startup.
2. **Set `hmac_keys` explicitly** — the same `kid` *and* key on every instance.
   The auto-generated key warns loudly at startup: passes die on restart and no
   other instance can verify them. Mixing `ANTEROOM_HMAC_KEY` (which registers as
   `kid = "env"`) with a file-configured key on other nodes has the same effect as
   using different keys.
3. **Your own service worker needs no special configuration.** The gate handles
   cross-browser fetch-metadata differences, but the underlying interaction is
   worth understanding.

   **What went wrong.** A worker with a catch-all `fetch` handler that re-issues
   requests (`e.respondWith(fetch(e.request))`) causes the browser to rewrite the
   navigation's fetch metadata. Anteroom read that metadata literally, concluded
   the request was machine traffic, and served the `403` refusal — which carries
   no solver, so the visitor could never earn a pass. Permanent, silent, and only
   on Firefox, so a developer testing in Chromium saw nothing wrong.

   `isBrowserNav` now corroborates the metadata against the `Accept` header and
   `User-Agent` rather than obeying it, so a re-issued navigation is recognised
   on both engines while an ordinary `fetch()` (which sends `Accept: */*`) still
   gets the refusal it should.

   **Still worth doing anyway**, because it is one line and it keeps your worker
   out of a path it has no reason to be in:

   ```js
   self.addEventListener("fetch", (e) => {
     if (e.request.mode === "navigate") return;   // let the browser do it
     e.respondWith(fetch(e.request));
   });
   ```

   **Why it matters.** When a worker re-issues a top-level navigation, the
   browser rewrites the request's fetch metadata. Measured across engines:

   | | `Sec-Fetch-Mode` | `Sec-Fetch-Dest` |
   |---|---|---|
   | ordinary navigation | `navigate` | `document` |
   | re-issued, Chromium | `navigate` | `empty` |
   | re-issued, Firefox | **`same-origin`** | `empty` |

   That difference is why the gate corroborates rather than obeys: `same-origin`
   on Firefox and `navigate` on Chromium describe the identical user action, and
   only one of them looks like a navigation.

   Everything below about scope is still true and still worth understanding. Service-worker *scope* selects
   which **documents** a worker controls, not which request URLs it sees: a
   root-scoped worker controlling the visitor's page intercepts every fetch that
   page makes, including ours, and moving our endpoints under `/.anteroom/` does
   nothing to prevent that. So Anteroom does not fetch from the page. It
   registers a narrow-scope worker at `/.anteroom/` and sends it an RPC over a
   `MessagePort`; the worker performs the network I/O, and **a fetch issued inside
   a service worker cannot be intercepted by any service worker** (its
   service-workers mode is "none", which is what stops `fetch(event.request)`
   from recursing). Your worker keeps its scope, ours does its work, and neither
   evicts the other.
   Two things still worth knowing: Anteroom's worker has **no `fetch` handler**
   and must never gain one; and if the worker bridge is unavailable the page falls
   back to fetching directly, where a catch-all `fetch` handler of yours *can*
   swallow the request — Anteroom detects that case and names it on the wait page
   rather than looping. Note this is purely client-side: `/.anteroom/*` is
   answered by the gate before the proxy, so no upstream route or SPA catch-all
   can ever shadow it.
4. **Bypass your own service worker's script path.** This is short and it is
   load-bearing, because getting it wrong is not recoverable by the visitor.

   A browser re-fetches a worker's script to check for updates. If that path is
   gated, a visitor without a pass gets `403` — and a failed update check does
   **not** drop the registration. Measured in both Chromium and Firefox: a
   registration survives a `403` on its script, and survives a `404` too. So a
   worker installed once keeps running, and you cannot ship it a fix to anyone
   whose pass has lapsed.

   ```toml
   [bypass]
   paths = ["/sw.js", "/service-worker.js"]   # whatever yours is called
   ```

   The script is a static asset that reveals nothing; bypassing it costs you
   nothing and keeps your own upgrade path open.

   Two consequences of the same measurement, worth knowing before you need them:

   - **Ordinary upgrades are automatic.** Change the script's *contents* and the
     browser byte-compares on the next update check and installs the new
     version. No visitor action, no cache-busting.
   - **Renaming or deleting a worker does not retire it.** The old registration
     persists indefinitely on a `404`. To actually remove one, keep serving the
     old path with a script whose only job is `self.registration.unregister()`.
     Anteroom's own worker does the equivalent from the inside — it unregisters
     itself once the gate's endpoints stop answering like the gate — which is
     why `/.anteroom/uninstall` is a convenience rather than the only way out.

   Anteroom's own worker and renewal script are served from `/.anteroom/`, which
   is answered before the gate ladder and is therefore never challenged. That is
   deliberate: a gate whose own solver was behind its own wall could never admit
   anyone.

5. **Do not cache HTML at an edge in front of the gate.** Gate-authored responses
   carry `no-store` and `Vary`, but a cache configured to "cache everything"
   overrides that and can pin the wait page at a content URL.
6. **Separate private virtual hosts, or set `public_hosts`.** Anteroom preserves
   the client's `Host` header for transparency. `public_hosts` is an optional
   exact authority allowlist checked before every bypass, challenge, payment, or
   proxy decision. Bind genuinely private vhosts to another listener as defense
   in depth.
7. **Take a CSP inventory before enabling `inject`.** See below.
8. **Give payment state an owned durable path.** `payments.state_file` must be on
   writable persistent storage. Multiple local processes may share the same
   supported filesystem; separate hosts need a real transactional backend that
   Anteroom does not yet ship.
9. **Match process and orchestrator drain budgets.** `shutdown_grace` defaults to
   five seconds and may be raised to one hour for uploads, downloads, SSE, or
   other long requests. Docker `stop_grace_period`, Kubernetes
   `terminationGracePeriodSeconds`, or the service manager's stop timeout must be
   longer; otherwise the orchestrator kills the process before Anteroom's own
   graceful deadline.
10. **Rate-limit before the gate.** Proof of work protects admission economics,
    not socket/request capacity. Put coarse per-client and tighter
    `/.anteroom/challenge`/`answer` limits in nginx, Caddy, HAProxy, a CDN, or the
    host firewall. [`nginx.md`](nginx.md#put-volumetric-limits-in-nginx) gives a
    minimal recipe. Keep this out of the Go gate: the outer proxy sees and can
    reject the traffic earlier.

### Serving on port 80 or 443

`listen` defaults to `:8080` because a default that cannot bind as an ordinary
user fails on first run: on Linux, ports below 1024 require root or the
`CAP_NET_BIND_SERVICE` capability. Anteroom does not terminate TLS, and the
solver needs a secure context, so the edge is someone else's job in most
deployments — but if you do want Anteroom on 80, pick one:

- **Grant the capability**, which is narrower than root:
  `sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/anteroom`, or
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit (keep
  `User=` set to an unprivileged account — this is the point of the capability).
  Note `setcap` is lost on every binary replacement, so re-apply it on upgrade.
- **Redirect in the kernel** and leave the process unprivileged:
  `iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080`.
- **Publish the port in Docker** — `-p 80:8080` — where the host side is bound by
  the daemon, not by Anteroom. Note that the rule this whole list works around
  does not apply *inside* a container at all: Docker sets
  `net.ipv4.ip_unprivileged_port_start=0`, so a non-root container can bind :80
  directly if you would rather. See [`docker.md`](docker.md).
- **Run as root.** Available, not recommended, and unnecessary given the above.

A bind failure on a privileged port says so explicitly rather than leaving you
with a bare "permission denied".

### The standard topology: TLS terminator → Anteroom → your app

This is the common deployment — nginx or Caddy terminates TLS and forwards to
Anteroom, which forwards to your application — and it has exactly one
configuration requirement, which is easy to miss and has two failure modes:

```toml
trusted_proxies = ["127.0.0.1/32"]   # or your nginx/Caddy address
```

For nginx specifically, [`nginx.md`](nginx.md) has the complete server block —
including the `proxy_pass` trailing slash, which silently rewrites the request
URI before the gate sees it.

Without it, Anteroom treats the *terminator* as the client. Consequences:

- The pass cookie loses its `Secure` flag, because `X-Forwarded-Proto: https`
  from an untrusted peer is (correctly) not believed. The pass then travels in
  cleartext on any downgrade.
- Your application sees the terminator's address instead of the visitor's, in
  logs and in any rate limiting, because Anteroom re-states `X-Forwarded-For`
  and `X-Real-IP` from the client it resolved — and it resolved the proxy.
- Bypass-by-CIDR matches against the proxy's address rather than the visitor's,
  so office/monitor allowlists silently stop working.

With it set, Anteroom reads the real visitor from `X-Forwarded-For`, strips any
inbound vendor client-IP headers (`X-Real-IP`, `CF-Connecting-IP`,
`True-Client-IP`, …) so a client cannot forge them, and re-states the resolved
address for your application. It also re-states `X-Forwarded-Proto` from the same
resolution, so an application behind a TLS terminator is told `https` and not the
scheme of the plaintext hop between the terminator and the gate. That one matters
more than it sounds: WordPress builds `http://` URLs from it, and Django's
`SECURE_PROXY_SSL_HEADER` and Rails' `force_ssl` see an insecure request and
redirect to HTTPS — which then loops. That stripping is why the value your app receives
is trustworthy — but it means Anteroom must be the only thing writing it, and
that it must know which peer to believe.

## Tuning the puzzle

`difficulty` is bits of work. Defaults are 14 for admission and 6 for renewal —
roughly a second on a laptop, a few seconds on an older phone, and milliseconds
for a renewal. Two constraints worth knowing:

- **`pass_ttl` is also the solve deadline.** A pass expires `pass_ttl` after its
  challenge was *issued*, so a solve handed to someone else is worth only the
  time left on it. That limits stale reuse; it does not stop a group that keeps
  passing fresh solves around, and nothing here tries to. If
  `difficulty` is high and `pass_ttl` is short, slow devices can never finish in
  time. The solver detects this and takes a fresh challenge, but the honest fix is
  a `pass_ttl` comfortably above your slowest visitor's solve time. The default is
  60 s for that reason.
- **A pass outlives the last tab by about 15 seconds.** The renewal worker stops
  when its driver pages stop pinging, and it waits for three missed pings before
  concluding they are gone. So the real bound on a closed browser is
  `15s + pass_ttl`, not `pass_ttl`. The window absorbs reloads and tab switches
  rather than charging admission again; it is not a leak, but it is the number to
  quote when someone asks how long a stolen pass keeps working.
- **`max_session` caps the renewal chain** (default 30 minutes). Renewals are far
  cheaper than admission, so without a cap one admission would buy unlimited
  time. At the cap the visitor solves admission once more; a live pass keeps
  working until it expires. It must be at least `pass_ttl`: a cap shorter than a
  single pass would elapse before the first renewal was even due, so the gate
  refuses that config at startup instead of quietly making renewal impossible.

## What Anteroom breaks, and how to fix it

Anything that is not a browser navigation gets a machine-readable refusal rather
than the wait page. That is correct for scrapers and wrong for several things you
probably run. Each of these needs a `bypass` rule.

Both the wait page and machine refusal use `403`: browsers still render the
interstitial, while clients, caches, and crawlers cannot mistake it for the
requested resource. Every such response is also marked `Cache-Control: no-store`
and `X-Anteroom-Action: challenge`. Temporary crawler-DNS failures instead use
`X-Anteroom-Action: crawler-verification-unavailable` with `503` and
`Retry-After`; clients can distinguish retryable verification failure from a
challenge without parsing the body.

| What breaks | Why | Fix |
|---|---|---|
| **Inbound webhooks** (Stripe, GitHub, Slack) | A POST is not a browser navigation, so it is refused; the sender sees an error and the body is gone | `bypass.paths = ["/webhooks/*"]`, plus `bypass.cidrs` where the sender publishes ranges |
| **OAuth / OIDC / SAML callbacks** | `response_mode=form_post` is a cross-site POST; `SameSite=Lax` withholds the pass, and the retry consumes the one-time code | bypass the callback path |
| **Form POSTs after a pass lapses** | The POST is refused and the reload loses the body | raise `pass_ttl`; bypass POST-heavy paths |
| **API clients, CLI tools, curl** | Refused at every endpoint | bypass `/api/*`, have the client solve the challenge (the refusal body explains how), or enable the experimental x402 admission door |
| **RSS/Atom readers** | `Accept: */*`, so refused | bypass your feed paths (the example config covers `/feed.xml` only) |
| **Link previews** (Slack, Discord, X, Facebook) | Browser-shaped unfurlers get the wait page HTML and do not run JS, so the preview reads "Pardon us for a moment" — and unfurl caches keep it for days | put Open Graph tags in your `header.html`, or bypass only dedicated preview paths/CIDRs you can authenticate |
| **Third-party iframe embeds, oEmbed** | `SameSite=Lax` and storage partitioning withhold the pass inside a frame; the wall reloads forever | bypass the embeddable paths |
| **Multi-subdomain fleets** | The pass cookie is host-only, so each hostname needs its own solve | accept it, or bypass shared asset hosts |
| **Private browsing without service workers** | Registration fails, so the pass is not renewed | raise `pass_ttl` |
| **URLs containing `..` as a real path segment** | Refused with 400 (see below) | none needed in practice; such URLs are not addressable through most upstreams either |

**CORS preflights are passed upstream.** A preflight is unauthenticated by
specification — the browser sends `OPTIONS`
without cookies — so it could never carry a pass, and challenging it walled
every cross-origin application behind the gate with an error naming CORS rather
than Anteroom. Requests that are unambiguously preflights (`OPTIONS`, with both
`Origin` and `Access-Control-Request-Method`) now go straight upstream so your
application can answer with its own policy. The request the preflight is asking
about is a separate request and is gated normally, so a cross-origin fetch still
needs a pass; a bare `OPTIONS` is content and is still challenged.

### Verified crawler bypass

`bypass.verified_crawlers` explicitly selects crawler identities allowed through
the gate: `googlebot`, `bingbot`, `yandexbot`, and `ccbot`. An operator-advertised
User-Agent product token is only a claim. Only tokens belonging to explicitly
configured providers trigger address verification, so ordinary traffic and
unconfigured crawlers stay on the normal challenge/payment ladder without DNS.

Googlebot, Bingbot, and CCBot use embedded snapshots of their operators'
published ranges as a fast path. Snapshot misses use the operator's documented
forward-confirmed reverse-DNS procedure. Yandex publishes no stable range list,
so it always uses forward-confirmed reverse DNS. Definitive positive and
negative results are cached for four hours in a shared, bounded 8,192-entry
cache; IPv6 negatives are coalesced by `/64` to resist address-rotation churn.
Temporary DNS failures return `503` with `Retry-After`; they are not cached.

Verified crawlers bypass proof of work and x402 on every route. An unverified
crawler claim receives the ordinary machine-readable `403`, never a payment
offer. Correct `trusted_proxies` configuration is essential because crawler
verification uses the same resolved client address as CIDR bypasses. If that
address cannot be resolved, the request follows the ordinary ladder rather than
being reported to the crawler as a permanent DNS outage.

Refresh the embedded snapshots with `scripts/update-crawler-ips.py`. The
scheduled workflow reports a semantic range change for human review rather
than committing generated data automatically.

Percent-encoding is *not* restricted: `/repos/owner%2Frepo`, `/file%20name.txt`,
and friends pass through untouched. Only paths whose decoded form is
non-canonical — dot-segments (`..`, `.`), doubled slashes, or a backslash — are
refused, and only because bypass patterns are matched against the decoded path
while the upstream resolves dot-segments itself. Without that check,
`/.well-known/../admin` would match a `/.well-known/*` bypass here and be served
as `/admin` there. Every hazardous use of `%2F` decodes into a dot-segment and is
caught by the same rule, so there is nothing to gain by rejecting encoding as
such.

Removing Anteroom: visit `/.anteroom/uninstall` to unregister the renewal worker,
or just delete the endpoint — the worker retires itself when it sees the gate is
gone.

## HTML injection and CSP

Injection is how renewal continues after the visitor leaves the wait page: an
admitted HTML document gets `<script src="/.anteroom/renew.js" defer>` right after
its opening `<head>`, and that script registers the worker and keeps it pinged.
It is off-by-default-safe (`inject = false` does nothing at all) and, when on,
conservative. The rules below are the contract, and they are enforced by the
tests in `internal/gate/inject_test.go` — including a byte-for-byte
non-interference test for every case where injection is declined.

**Inject only when all of these hold**; otherwise pass the response through
untouched:

- the request looks like a document navigation (`Sec-Fetch-Dest: document`, or a
  GET whose `Accept` contains `text/html`) and carries no `HX-Request`,
  `Turbo-Frame`, or `Turbo-Request-ID`; `X-Requested-With` excludes it only when
  its value is `XMLHttpRequest` because Android WebViews put application package
  names there;
- the status is exactly `200` (never 206, 304, 3xx, 4xx, 5xx — a 304 has no body
  and a 206 is a byte range);
- `Content-Type` is `text/html` with an ASCII-compatible charset; never
  `application/xhtml+xml`, `text/event-stream`, or `multipart/*`; abort on a
  UTF-16/32 BOM;
- the body actually starts like a document (`<!doctype html`, `<html`, `<head`);
- the response carries no `Content-Digest`, `Repr-Digest`, or `Signature` — never
  break a signature to make room;
- the body is under a size cap, buffering only up to the injection point.

**Mechanics:** request `Accept-Encoding: identity` only for requests that pass the
navigation test (so everything else keeps compression); if the response arrives
encoded anyway, skip. Inject a root-absolute external script
(`<script src="/.anteroom/renew.js" defer></script>`) right after the opening
`<head>` — root-absolute so a `<base href>` cannot retarget it. Then drop
`Content-Length`, weaken `ETag`, and add `Vary: Cookie`. Never inject on a
bypassed path.

**The CSP algorithm.** "Append a nonce" is the wrong default: it breaks sites
using `unsafe-inline`, and on a cacheable page it publishes one nonce to every
visitor. Instead:

1. Collect every policy — all `Content-Security-Policy` headers, comma-separated
   policies within each, and any `<meta http-equiv>` policy in the buffered head.
   Policies intersect; all must be satisfied.
2. The effective script directive per policy is `script-src-elem`, else
   `script-src`, else `default-src`. Absent means unrestricted.
3. **Refuse to inject** if any policy uses `'none'` for scripts, or has a
   `sandbox` directive without `allow-scripts` (no script can run) or without
   `allow-same-origin` (an opaque origin has no cookies and no service worker, so
   renewal is impossible anyway), or if a **restricting `<meta>` policy would have
   to be rewritten** to admit the script. That last one is narrower than it first
   sounds, and the distinction is load-bearing: a `<meta>` policy allowing
   `'self'` is satisfied by the external script exactly as it stands, so
   injection proceeds and nothing is modified. Only a `<meta>` policy that would
   need a nonce or hash added is fatal — a policy inside the document cannot be
   rewritten from the headers, and the head has already been sent by the time we
   would know.
4. If every restricting policy allows `'self'`: inject the external script and
   **change no header**. This is the common case and carries no risk.
5. Else if `'strict-dynamic'` is present: an external `src` is blocked, so use a
   fresh per-response nonce with an inline loader, and mark the response
   `no-store` — a nonce and a shared cache are incompatible.
6. Else if the policy has `'unsafe-inline'` with no nonce or hash: inject inline
   and **do not touch the policy**. Adding a nonce or hash would disable
   `unsafe-inline` under CSP3 and kill the operator's own inline scripts.
7. Else (hash-only, nonce-based, or a host allowlist without `'self'`): add a
   `'sha256-…'` hash of the exact inline script. Hashes are deterministic and
   therefore cache-safe, and coexist with existing nonces and hashes.
8. Never reuse the upstream's nonce or your own across responses, and apply the
   same modification to `Content-Security-Policy-Report-Only` — otherwise a
   correct injection floods the operator's report endpoint.
9. Keep the injected script free of DOM sinks (no `eval`, no `innerHTML`) so
   `require-trusted-types-for 'script'` is satisfied without a policy name.

Test matrix: no CSP, `unsafe-inline`, nonce + `strict-dynamic`, hash-only, two
headers, header plus meta, report-only alone, and `sandbox`. All of these are in
`TestPlanCSP`.

One honest limit: a `Content-Security-Policy-Report-Only` policy *stricter* than
the enforcing one may log the injected script. Report-only cannot block, so it
never changes the decision, and where a nonce or hash is added it is added to the
report-only policy too — but in the common case where the enforcing policy allows
`'self'` and nothing is modified, a stricter report-only policy will report us.

## Durable payment state and recovery

`payments.state_file` is a bbolt ledger mapping the semantic identity of a
chain-consumed authorization to its exact admission grant. A transaction reserves
an unseen identity before facilitator egress and commits scope, authority,
settlement evidence, and expiry before any cookie or upstream response. A retry
after restart, a lost response, or an upstream failure recovers that same grant
without calling the facilitator again. An expired grant remains spent.

The ledger is intentionally permanent: an EIP-3009 or Permit2 nonce remains
consumed on chain, so forgetting its record can let a facilitator-specific cached
success appear to be a fresh entitlement. Operate the file accordingly:

- put it on an owned, writable persistent volume with mode `0600`;
- monitor free space and startup/open errors; payment-enabled startup fails closed
  if the file cannot be opened;
- back it up with the config and keys, and do not restore an older snapshot over a
  live deployment—rollback forgets later consumed authorizations;
- expect growth with the number of distinct settled authorizations; bbolt reuses
  free pages but committed identities are not deleted;
- treat corruption as a payment outage, not a reason to delete the file; the free
  PoW path remains independent;
- share it only between local processes on a filesystem whose locking and
  durability semantics bbolt supports. A separate host or generic network mount
  is not a supported coordination mechanism.

This closes recovery after a known successful settlement. It cannot resolve a
`/settle` request whose response was lost before the grant was committed: x402
does not mandate an idempotent settle replay or a status lookup. The response
therefore says the result is ambiguous, names any available transaction, and
tells the payer not to sign a second authorization until they reconcile.

Payment presentation is an admission operation only. Present
`PAYMENT-SIGNATURE` on GET or HEAD, receive the pass cookie, then send the
original POST/PATCH/etc. with that cookie and without the payment header. This
keeps settlement retry separate from replaying an upstream mutation.

## Watching what the gate decides

`anteroom -v` logs one line per request naming the rung of the ladder that
answered it — `own-endpoint`, `bypass-path`, `bypass-ip`, `bypass-crawler`,
`crawler-verification-unavailable`, `crawler-unverified`, `pass-pow`, `pass-paid`,
`wait-page`, `refusal`, `non-canonical-path` — with the status, response size, and
duration:

```
level=DEBUG msg=hit method=GET path=/index.html decision=pass-pow status=200 bytes=142 dur=1.2ms ip=203.0.113.9 ua=Mozilla/5.0…
```

This is the fastest way to answer "why was this request walled?", which is
otherwise guesswork: the decision is the whole ladder's output in one word. It is
off by default because a proxy that logs every hit at INFO teaches operators to
ignore its logs. Note the line includes the client IP and user agent, so it is
request-level data — appropriate for debugging, not for leaving on in production
without deciding that is what you want.

## Monitoring

Set `admin_listen` to open an operator port alongside the gate:

```toml
admin_listen = "127.0.0.1:8090"
```

It serves three read-only endpoints, none of them proxied or gated:

- `/metrics` — Prometheus text exposition, the format Prometheus, Grafana
  Alloy, VictoriaMetrics, Datadog, and the OpenTelemetry collector all scrape.
- `/stats` — the same counters as one JSON object, for `curl` and scripts.
- `/activity` — the per-IP challenge-activity log for external ban tooling;
  answers 404 unless the `[activity]` section is configured (see below).
- `/healthz` — liveness.

The surface is **unauthenticated**; reachability is the entire access control.
Keep it on loopback or firewall it to your monitoring network — the counters
reveal traffic volumes and payment activity. The gate warns at startup when the
bind is wider than loopback.

Everything is a counter from process start. Rates, averages, and percentiles
are the scraper's job — `rate()`, `histogram_quantile()` — and restarts are
detected via `process_start_time_seconds`, so the gate keeps no windows, no
history, and — with one deliberate, opt-in exception, the `[activity]` log
described below — no per-visitor state. Nothing is ever pushed anywhere.

### The metrics

| Metric | What it counts |
|---|---|
| `anteroom_http_requests_total{decision=…}` | every request, labeled by the ladder rung that answered — the same vocabulary as `-v` above, including the `pay-*` outcomes |
| `anteroom_http_requests_in_flight` | requests being handled right now; long-lived streams (SSE, WebSockets) hold it up by design |
| `anteroom_challenges_issued_total{kind=…}` | challenges handed out: `admit` (full difficulty) vs `renew` (cheap background) |
| `anteroom_challenge_answers_total{outcome=…}` | answer submissions: `ok_admit`, `ok_renew`, `malformed`, `stale`, `bad_pow`, `window_elapsed`, `error` |
| `anteroom_challenge_solve_duration_seconds` | histogram of issue-to-successful-answer time, by kind |
| `anteroom_passes_minted_total{kind=…}` | passes minted: `pow` vs `paid` |
| `anteroom_upstream_errors_total` | proxy round trips that failed to reach the upstream (visitors saw 502) |
| `anteroom_crawler_dns_lookups_total{outcome=…}` | forward-confirmed crawler lookups split into `verified`, `unverified`, and temporary `indeterminate` results |
| `anteroom_crawler_dns_cache_hits_total`, `anteroom_crawler_dns_saturated_total`, `anteroom_crawler_dns_in_flight` | aggregate cache use, concurrency pressure, and current DNS work; no provider or address labels |
| `anteroom_challenge_bytes_total` | response body bytes the gate authored itself: wait pages, the solver, challenge and payment negotiation, refusals, error responses |
| `anteroom_upstream_bytes_total` | response body bytes proxied from the upstream — the real traffic |
| `anteroom_http_bytes_total` | all response body bytes served, always the sum of the two above; headers and post-upgrade (WebSocket) traffic are not counted |
| `go_memstats_*`, `go_goroutines`, `process_start_time_seconds` | process health: memory, goroutines, start time |
| `anteroom_build_info` | constant 1; the labels identify the running build (see below) |
| `anteroom_tracked_ips` | IPs currently in the activity log; only present when `[activity]` is configured. A count — the addresses themselves never appear in metrics |

### The activity log (`/activity`)

Configure the optional `[activity]` section and the admin server serves a
JSON list of every IP with recent *challenge* activity — walled requests
(wait page, refusal, or 402 on a paid route) and challenge answers, counted
per IP:

```json
{
  "window": "10m0s",
  "generated_at": "2026-08-25T12:00:00Z",
  "ips": [
    { "ip": "203.0.113.9", "first_seen": "2026-08-25T11:52:03Z",
      "last_seen": "2026-08-25T11:59:58Z", "failed": 412,
      "succeeded_admit": 0, "succeeded_renew": 0 }
  ]
}
```

`failed` counts walled requests plus refused answers (`malformed`, `stale`,
`bad_pow`, `window_elapsed` — never the gate's own `error`). Accepted answers
are split by challenge kind, because the two read oppositely:
`succeeded_admit` is the full-difficulty admission solve, and
`succeeded_renew` is the cheap background renewal a real browser's service
worker performs automatically (roughly once per `pass_ttl`) for as long as a
tab stays open. Counts are cumulative since `first_seen` — like the counters
above, the consumer diffs between polls. An IP quiet for `ttl` (`window` in
the response) falls off the list, so poll faster than that. Admitted
(pass-holding) and bypassed traffic never appear: this is a challenge log,
not visitor tracking, and omitting the section keeps the gate entirely free
of per-visitor state.

Reading an entry, four shapes cover most of what you will see:

| Shape | Reads as |
|---|---|
| high `succeeded_renew`, little else | a person with a tab open — renewals are keep-alive, not visits |
| `failed` ≈ `succeeded_admit`, both climbing | a **solve loop**: a client that earns a pass on every cycle but never presents a usable one (cookies not kept, User-Agent rotated between solve and fetch, or egress hopping /24 prefixes — the pass binds to all three), so it is walled again, re-solves, and never reaches the site |
| `failed` ≈ `succeeded_admit` + `succeeded_renew`, both high | a **renew mill**: a solve loop split across two clients at one egress. A solver component keeps one consistent identity, so its live pass earns the cheap renewal challenge over and over, while a fetcher presents a different User-Agent (or no cookie at all) and is walled on every content request. One failure per renewal, at machine cadence — far above the roughly one renewal per `pass_ttl` a real browser produces — with an occasional `succeeded_admit` when the solver re-pays admission at the `max_session` cap |
| `failed` climbing, both success counts 0 | a scraper that never attempts the challenge at all |

**The gate never judges or bans anyone.** The intended consumer is an
external, separately-privileged tool that polls `/activity` and applies its
own policy — say, "more than 10 failures and no success in my window". That
privilege separation is the design: anteroom needs no firewall rights, and
un-banning needs no anteroom involvement. A tool that rebuilds its iptables
DROP set (or its Cloudflare ban list, when the gate sits behind a CDN and
host-level drops would hit the CDN's addresses instead of the visitor's)
from each poll gets un-banning for free — a banned IP can no longer reach
the gate, goes quiet, and ages out of the list.

Things to know before wiring a banner to it:

- **One IP is not one person.** Carrier NAT can put a building behind one
  address (the same reason PoW passes bind to a /24, not an exact IP).
  Threshold accordingly, and prefer short external ban TTLs.
- A high `succeeded_renew` count is evidence of a real browser only at the
  honest rate: renewal runs inside a service worker with a live pass, roughly
  once per `pass_ttl` and with no failures, so long sessions accumulate
  renewals slowly. Renewals arriving much faster than that, each paired with
  a failure, are a renew mill (above), and don't treat raw success totals as
  legitimacy in general — `succeeded_admit` climbing alongside failures is
  the solve-loop shape.
- The log is in-memory and per-instance: a restart forgets it (re-offending
  re-lists within one window), and in a fleet each instance reports only the
  traffic it terminated — poll every instance.
- With `[activity]` on, the admin surface exposes visitor IP addresses —
  one more reason it belongs on loopback or a firewalled interface.

### Which build is running

`anteroom_build_info` is a constant 1 whose labels are the payload:

```
anteroom_build_info{version="v0.0.0-20260820210614-1afcda090040+dirty",
                    revision="1afcda0900409072bce33a17ff4e87a25936956d",
                    revision_time="2026-08-20T21:06:14Z",
                    modified="true",
                    goversion="go1.24.4"} 1
```

`revision` is the one to read. `version` is a Go pseudo-version, and it is
`(devel)` for anything not installed as `module@version` — which is most
deployments — so it rarely answers "which code is this?". `modified="true"`
means the working tree was dirty at build time, so the revision names the
commit the build started from and not the bytes that are running.

The toolchain fills these in automatically when it can see the repository. Two
cases where it cannot:

- **`version="(devel)"` with `revision="unknown"`** means the build saw no
  repository at all — built from a copied or unpacked tree, or with
  `-buildvcs=false`. Rebuild inside the checkout.
- **The container image** excludes `.git` from its build context on purpose, so
  pass the commit in and the linker records it:

  ```
  docker build \
    --build-arg VCS_REF=$(git rev-parse HEAD) \
    --build-arg VERSION=$(git describe --tags --always --dirty) \
    -t anteroom .
  ```

  `make image` does exactly this. Omitting either is not an error; the gate then
  reports `revision="unknown"` or `version="(devel)"`, which is true.

  A **published** image needs neither argument from you: the release workflow
  passes the git tag it published under, so `version` on a pulled image is a
  string you can check out. See [`releasing.md`](releasing.md).

  The `-X` paths the Dockerfile passes are built from `go list -m`, not written
  out. Worth knowing if you ever hand-roll the command: a `-X` path that does not
  resolve to a real package variable is **silently ignored** — the build
  succeeds, nothing warns, and the gate reports the toolchain's own guesses as
  though they were the answer.

Every label is always present, "unknown" where the value is missing — a label
set that varies between builds is a different series to a scraper, and anything
joining on `anteroom_build_info` would quietly stop matching.

The solve-time histogram measures challenge issue to answer received — it
includes network round trips and page-load time, not just hashing — and only
successful answers are observed. Its ceiling is the 60-second challenge window;
slower solves are rejected as stale and appear under
`anteroom_challenge_answers_total{outcome="stale"}` instead. Median solve time
against your real visitors is the number to watch when [tuning
difficulty](#tuning-the-puzzle):

```promql
histogram_quantile(0.5, rate(anteroom_challenge_solve_duration_seconds_bucket{kind="admit"}[10m]))
```

Payment outcomes need no second counter family; they are the `pay-*` decisions:

| Question | PromQL |
|---|---|
| settled and served | `rate(anteroom_http_requests_total{decision="pass-paid"}[5m])` |
| rejected by the facilitator | `…{decision="pay-rejected"}` |
| facilitator down / breaker open | `…{decision="pay-infra"}` — the breaker is per facilitator, so one facilitator down degrades only the rails it settles; other rails and the free path are unaffected |
| settled but pass not issued | `…{decision="pay-grant-failed"}` |
| replays and rate limiting | `…{decision=~"pay-replay\|pay-rate-limited"}` |

### Scraping

```yaml
scrape_configs:
  - job_name: anteroom
    static_configs:
      - targets: ["127.0.0.1:8090"]
```

A 15–60s interval is fine; each scrape costs one lock-free walk of a few dozen
atomics plus one `ReadMemStats`.

## Which Go builds this

`go.mod` requires **1.22**, and that is the oldest version the module works
under — not the oldest it compiles under, which is a different and more
dangerous number.

Compilation alone would allow 1.21. The binding constraint is `net/http`, which
gates method-and-wildcard `ServeMux` patterns (`"GET /metrics"`, `"GET /{$}"`)
on the module's `go` directive: below 1.22 those register as literal paths, the
admin server answers 404 to everything, and nothing fails to build. Measured —
`internal/admin`'s tests pass at `go 1.22` and fail at `go 1.21` with the same
compiler and the same code.

Below 1.21 the module does not compile at all: `log/slog` and the `min` builtin
both arrived there.

The directive is a floor, not a target, and setting it too high has a cost of
its own. With `go 1.27` in this file, Debian's own `go` downloaded a 1.27
toolchain before doing anything, which breaks offline and distro builds. At 1.22
Debian trixie's 1.24 builds the tree with `GOTOOLCHAIN=local` and no network.

Older distributions need a newer toolchain than their default: Ubuntu 22.04 LTS
ships 1.18 and Debian bookworm 1.19. Reaching either was measured and rejected.
Below 1.21 there is no `log/slog`, whose output is not private detail — the
acceptance suite greps the `-v` decision vocabulary and the metrics label set is
built on the same words — and below 1.20 there is no
`http.NewResponseController`, the one line that puts a read deadline on the
unauthenticated answer endpoint. Shipping a slowloris hole to widen distro
compatibility is the wrong trade for this program in particular. Those users can
install a newer Go from the archive, from snap, or from upstream; most never
compile the gate at all.

Release artifacts are built with a current toolchain (see the Dockerfile and the
CI workflow), because that is where standard-library security fixes actually
arrive. The floor says who may compile; it does not say what we ship.
