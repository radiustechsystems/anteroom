# nginx in front of Anteroom

nginx stays where it is: it keeps TLS, keeps its certificates, keeps being the
public entry point. What changes depends on **what nginx is currently talking
to**, and there are two answers, not one.

## Which shape is your site?

Look at what your `location /` block does.

| Your nginx does | Your stack | Gate goes |
|---|---|---|
| `proxy_pass http://127.0.0.1:PORT` | Node/Express/Next, gunicorn (Django/Flask), uvicorn (FastAPI), puma (Rails), any HTTP service | **behind** nginx — [family A](#family-a-nginx-reverse-proxies-an-http-app) |
| `fastcgi_pass …` | php-fpm: WordPress, Laravel, Drupal, Magento | **in front of** the origin — [family B](#family-b-nginx-is-the-origin) |
| `uwsgi_pass …` | older Django/uwsgi setups | family B |
| `root` + `try_files`, no pass at all | static sites, SPAs | family B |

The distinction is not stylistic. Anteroom is an HTTP reverse proxy. FastCGI and
uwsgi are **not HTTP** — nothing HTTP-shaped exists between nginx and php-fpm for
the gate to be inserted into. Point a browser at a php-fpm port and you get no
HTTP response at all, which is exactly what the gate would get.

So family B needs a different arrangement, and getting handed the family A recipe
for a WordPress site is a wasted afternoon.

---

# Family A: nginx reverse-proxies an HTTP app

```
before:  client ──► nginx ─────────────────────────► app
after:   client ──► nginx ──► anteroom ──► app
```

Only nginx's `proxy_pass` target changes — plus four settings that are easy to
miss, all of which fail quietly.

## The config

```nginx
upstream anteroom_gate {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl;
    server_name example.com;

    # ... your ssl_certificate lines, unchanged ...

    location / {
        # NO URI PART after the host. Not `http://anteroom_gate/`.
        # See "The trailing slash" below — this is the one that bites.
        proxy_pass http://anteroom_gate;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Must stay off: the gate serves an interstitial at the URL of real
        # content, and anything long-lived (SSE, websockets) dies behind a
        # buffer.
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
}

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

And in `anteroom.toml`, the one line the topology requires:

```toml
listen          = "127.0.0.1:8080"
upstream        = "127.0.0.1:3000"    # your app, where nginx used to point
trusted_proxies = ["127.0.0.1/32"]    # nginx's address
```

Bind the gate to loopback. Once nginx is in front, nothing else should be able to
reach it.

## The trailing slash

`proxy_pass http://anteroom_gate;` and `proxy_pass http://anteroom_gate/;` differ
by one character and are not the same directive. Without a URI part, nginx
forwards the request target **byte for byte**. With one — even a bare `/` — nginx
normalizes and percent-decodes the path first, then forwards the result.

Measured through this exact topology:

| Client sends | Gate receives, no URI part | Gate receives, with `/` |
|---|---|---|
| `/%65cho` | `/%65cho` | `/echo` |
| `/.well-known/../x` | `/.well-known/../x` → `400` | `/x` |

Two consequences, and the second is the one to care about.

**It breaks legitimate encoded URLs.** Anteroom deliberately does *not* restrict
percent-encoding — `/repos/owner%2Frepo` is an ordinary API URL and passes
through untouched (see the path-canonicalization note in
[`operating.md`](operating.md)). With a trailing slash, nginx decodes `%2F` into
a separator before the gate or your application ever sees it, and that URL now
addresses something else.

**It moves a security decision out of the gate.** Anteroom refuses non-canonical
paths with `400` rather than normalizing them, because bypass globs are matched
against the decoded path while your application resolves dot-segments itself —
so `/.well-known/../admin` matching a `/.well-known/*` bypass here and being
served as `/admin` there is a real bypass. With a trailing slash the gate never
sees the dot-segments, so that check never fires.

In fairness: nginx's own normalization happens to close that particular hole,
because the gate then matches its bypass list against the already-collapsed path.
The problem is not that this specific attack becomes possible; it is that the
gate is no longer inspecting what the client sent, so its guarantee — *what I
checked is what the upstream receives* — no longer holds, and you are relying on
two normalizers agreeing forever. Use the form without a URI part and the
question does not arise.

## `trusted_proxies` is not optional here

Omitting it has three consequences and no error message:

- **The pass cookie loses its `Secure` flag.** `X-Forwarded-Proto: https` from an
  untrusted peer is (correctly) not believed, so the gate concludes the
  connection is plaintext and drops `Secure`. The pass then travels in the clear
  on any downgrade.
- **Your application stops seeing real client IPs.** The gate re-states
  `X-Forwarded-For` and `X-Real-IP` from the client it resolved — and it resolved
  nginx.
- **`bypass.cidrs` silently stops working**, because it matches nginx's address
  rather than the visitor's.

With it set, the gate believes nginx's `X-Forwarded-For`, strips any inbound
`X-Real-IP` / `CF-Connecting-IP` / `True-Client-IP` so a client cannot forge
them, and re-states the resolved address. That stripping is why what your
application receives is trustworthy — and it is also why the gate must be the
only thing writing those headers.

## Do not buffer, do not cache

`proxy_buffering off` matters more with a gate in front than without one:

- The wait page is an **interstitial served at the URL of real content**. Any
  cache in front of the gate that ignores `no-store` can pin it there, and every
  visitor gets "Pardon us for a moment" as your homepage until it expires. The
  gate sets `Cache-Control: no-store` and `Vary` on everything it authors; an
  nginx `proxy_cache` configured to cache aggressively overrides that.
- Server-sent events and websockets die behind a buffer, and the symptom —
  "events all arrive at once when the connection closes" — is easy to
  misattribute to the application.

If you run `proxy_cache`, add `proxy_no_cache $upstream_http_cache_control;` or
exclude the gate's paths outright.

## Header budget: watch `proxy_buffer_size` as rails grow

With payments enabled, the machine-readable 402 carries the entire offer,
base64-encoded, in a `PAYMENT-REQUIRED` response header — deliberately, because
conformant clients exist that read only headers. That header is roughly 1KB
with one rail and grows ~0.6KB per additional rail, and nginx's default
`proxy_buffer_size` (4KB, and it must hold the **entire** response header
block) has no idea it's coming.

The failure when it overflows is quiet and lopsided: nginx refuses the
response ("upstream sent too big header" in its error log) and serves **502 —
but only to machine clients**. Browsers get the wait page, which carries no
offer header, so the site looks perfectly healthy while every paying agent
bounces. Measured in production the day a second rail was added.

The gate keeps the header lean (the extension's JSON Schema travels as a
`$ref` to `/.anteroom/x402-schema.json` rather than inline), so one or two
rails fit the default. At three or more rails, or if machine clients start
seeing 502s while browsers are fine, raise the buffers:

```nginx
proxy_buffer_size       16k;
proxy_buffers           8 16k;
proxy_busy_buffers_size 32k;
```

## Put volumetric limits in nginx

Proof of work prices a completed admission; it does not make TCP connections,
402s, challenge fetches, or invalid answer submissions free for the server.
Anteroom bounds facilitator egress and per-process bookkeeping, while nginx is
the smaller and better place to reject request floods before they occupy the Go
proxy. The following belongs in nginx's `http` context:

```nginx
# Empty keys are not accounted. Only the two work endpoints enter the second
# zone; every request enters the first.
map $uri $anteroom_work_client {
    default                        "";
    =/.anteroom/challenge         $binary_remote_addr;
    =/.anteroom/answer            $binary_remote_addr;
}

limit_req_zone $binary_remote_addr    zone=anteroom_client:10m rate=20r/s;
limit_req_zone $anteroom_work_client  zone=anteroom_work:10m   rate=2r/s;
limit_req_status 429;
```

Apply both zones in the outer `location /` that proxies to Anteroom:

```nginx
limit_req zone=anteroom_client burst=60 nodelay;
limit_req zone=anteroom_work   burst=4  nodelay;
```

These numbers are starting points, not a capacity claim. Raise the general zone
for APIs or asset-heavy pages; exclude authenticated webhook locations from it
when their sender has its own verification and retry contract. If a CDN or load
balancer is in front of nginx, configure nginx's real-IP module for only that
trusted peer first—otherwise every visitor shares the proxy's bucket, or a client
can forge the key. Keep connection limits, body-size limits, and network-layer
DDoS protection at the edge too; `limit_req` is not a SYN-flood defense.

---

# Family B: nginx is the origin

WordPress and friends. nginx speaks FastCGI to php-fpm, so there is no HTTP hop
to slot the gate into — the gate has to go in front of nginx instead.

It cannot go in front of *everything*, though: Anteroom does not terminate TLS,
and the solver needs a secure context. So the arrangement is **one nginx, two
server blocks, the gate in the middle**:

```
client ──► nginx :443  ──►  anteroom :8080  ──►  nginx :8081 ──► php-fpm
           (TLS, public)                        (origin, loopback)
```

One nginx process, one config file, one set of certificates. The outer block is
a plain reverse proxy; the inner block is your existing site config with the
`listen` changed.

```nginx
# OUTER: public. Your certificates stay here.
server {
    listen 443 ssl;
    server_name example.com;
    # ... ssl_certificate ... ;

    location / {
        proxy_pass http://127.0.0.1:8080;      # the gate
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}

# INNER: the origin. This is your existing server block, with `listen` changed
# from 443 to loopback:8081 and the TLS lines removed.
server {
    listen 127.0.0.1:8081;
    root /var/www/wordpress;
    index index.php;

    # The mirror of the gate's trusted_proxies. Without it every request looks
    # to PHP like it came from 127.0.0.1: $_SERVER['REMOTE_ADDR'] is the gate,
    # comment spam filters and geolocation see one visitor, and any
    # limit_req keyed on $binary_remote_addr collapses to a single bucket.
    set_real_ip_from 127.0.0.1;
    real_ip_header   X-Forwarded-For;
    real_ip_recursive on;

    location / { try_files $uri $uri/ /index.php?$args; }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.4-fpm.sock;
        # WordPress reads this to decide is_ssl(). The gate re-states
        # X-Forwarded-Proto from the visitor's real scheme, so this is correct
        # even though the hop into the origin is plaintext.
        fastcgi_param HTTPS $http_x_forwarded_proto if_not_empty;
    }
}
```

```toml
# anteroom.toml
listen          = "127.0.0.1:8080"
upstream        = "127.0.0.1:8081"   # the inner server block
trusted_proxies = ["127.0.0.1/32"]   # the outer server block
```

Three things to get right, all verified against a real nginx + php-fpm chain:

- **The inner block must listen on loopback**, or the gate can be walked around.
  Give it `server_name` care too: do not let it become the default server on a
  public interface.
- **Put any `fastcgi_cache` in the inner block**, never in the outer one. A cache
  in front of the gate can store the wait page — an interstitial served at the
  URL of real content — and pin it there for every visitor. A cache behind the
  gate only ever sees admitted traffic, which is what you wanted anyway.
- **Bypass your static paths.** In this shape *every* asset request passes the
  gate, and for WordPress that is the bulk of your traffic. `/wp-content/*` and
  `/wp-includes/*` in `bypass.paths` keeps images and stylesheets on the fast
  path. They are then ungated, which for static assets is usually the trade you
  want.

## Unix sockets

`upstream` accepts `unix:/run/app.sock` as well as `host:port`, so an app bound
to a socket — the default packaging for gunicorn, puma and uwsgi — does not have
to be moved onto a TCP port to be gated:

```toml
upstream = "unix:/run/gunicorn.sock"
```

Note what this does *not* do: a socket is still an HTTP server on a socket.
`php-fpm.sock` speaks FastCGI, so pointing `upstream` at it does not work and
family B above is still the answer for PHP.

---

## What your app already does that meets the gate

Verified against a real chain rather than reasoned about, because each of these
is something a framework does by default and nobody thinks to check.

**WebSockets pass through.** The `Upgrade` handshake reaches the app and the
`101 Switching Protocols` comes back, provided the request carries a pass. It
will: a same-origin WebSocket sends cookies, and the page that opened it was
admitted. Without a pass the handshake gets `403`, because a handshake is not a
browser navigation — so a WebSocket opened from a page on *another* origin, or by
a non-browser client, needs its path bypassed. An established connection is not
re-checked when the pass expires; it stays open.

**`X-Accel-Redirect` survives.** Django's `sendfile`, Rails, and any app that
authorizes a download and hands nginx the bytes keep working — the gate passes
the header through untouched, and the internal redirect is served by nginx
without re-entering the gate.

**Server-sent events stream.** The gate does not buffer them; make sure nginx
does not either (`proxy_buffering off`).

**Front controllers are fine.** `try_files $uri $uri/ /index.php?$args` and the
SPA equivalent work normally. Anteroom refuses non-canonical paths *before*
rewriting, so a permalink like `/2026/08/my-post/` passes and `/a/../b` does not.

**A refused POST loses its body.** This is the one that bites. The gate cannot
replay a POST after a challenge, so any endpoint receiving POSTs from something
that is not a logged-in browser — webhooks, form posts from partners, API
clients — needs a bypass or it will silently drop requests. `client_max_body_size`
still applies at nginx as before.

## Bypass rules an nginx-fronted site usually needs

Everything that is not a browser navigation gets a machine-readable `403` instead
of the wait page. That is right for scrapers and wrong for several things you
probably run. [`operating.md`](operating.md) has the full table; the ones that
come up on nearly every nginx deployment:

```toml
[bypass]
paths = [
  "/robots.txt", "/sitemap.xml", "/feed.xml",   # crawlers and readers
  "/.well-known/*",                             # ACME, and everything else there
  "/webhooks/*",                                # a POST is not a navigation
  "/sw.js",                                     # your service worker's script
]
```

That last one is easy to skip and expensive to skip. A browser re-fetches a
worker's script to check for updates; gate that path and a visitor without a
pass gets a `403`, and a failed update check does not drop the registration — so
the old worker keeps running and you cannot ship it a fix. See prerequisite 4 in
[`operating.md`](operating.md).

`/.well-known/*` deserves a specific note: if nginx renews certificates over
HTTP-01, the ACME challenge path must reach the responder. Bypassing it in the
gate is one way; handling `/.well-known/acme-challenge/` in its own nginx
`location` that never proxies to the gate is cleaner, because then the renewal
does not depend on the gate running at all.

## Verify it

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://example.com/
# 403 — correct. curl is not a browser navigation, so it gets the refusal.
# A 200 here means the gate is being bypassed and the site is ungated.

curl -s https://example.com/robots.txt        # 200: bypassed
curl -s https://example.com/.anteroom/healthz # ok
```

Then open the site in a browser: wait page, then your content, about a second.

Two checks worth doing once, because both fail silently:

```sh
# The app must not be reachable except through the chain.
curl -s -m 3 http://<your-host>:3000/ && echo "REACHABLE — fix this"

# Encoded paths must survive. Should print /%65cho, not /echo.
curl -s --path-as-is https://example.com/%65cho
```

Run the gate with `-v` while you are setting this up. It logs one line per
request naming the rung of the ladder that answered — `bypass-path`, `pass-pow`,
`wait-page`, `refusal`, `non-canonical-path` — which turns "why was this walled?"
into a single word.

## See also

- [`operating.md`](operating.md) — **read before going live**: the full table of
  what Anteroom breaks and the bypass rule for each, puzzle tuning, and the CSP
  algorithm for HTML injection.
- [`docker.md`](docker.md) — the container contract, and the same topology with
  Caddy in a sibling container.
- [`../examples/caddy-tls/`](../examples/caddy-tls/) — that Caddy topology as a
  working deployment. Worth a look even if you are staying on nginx: it lists
  which of the settings above Caddy does by default, and which one (rate
  limiting) it does not do at all.
