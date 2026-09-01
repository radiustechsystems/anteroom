# hello-app, behind Anteroom, behind Caddy

The production topology: a TLS terminator at the edge, the gate behind it, the
application behind that. Nothing but Caddy is reachable from outside.

```
client ──► caddy :443 ──► anteroom :8080 ──► app :3000
           (TLS, public)   (compose only)    (compose only)
```

Anteroom does not terminate TLS, and its solver needs a secure context —
WebCrypto and service workers are both unavailable over plain HTTP on anything
that is not loopback. So something in front has to hold the certificate, and
Caddy is the least work of the options: it obtains and renews one by itself, and
it already sends the forwarded headers the gate needs.

Where [`../anteroomized/`](../anteroomized/) shows the gate on its own at
`localhost`, this example is the shape you actually deploy.

## Run it locally

```sh
echo "ANTEROOM_HMAC_KEY=$(openssl rand -base64 32)" > .env
docker compose up -d --build
```

Then open **http://localhost:8080**: the wait page, then hello-app, about a
second later.

The first command creates a deployment-specific signing key. Keep `.env`
private, reuse that key across restarts and replicas, and do not commit it or
copy one from documentation.

No certificate is involved in that run, and none is needed — `SITE_ADDRESS`
defaults to `http://localhost`, and browsers treat loopback as a secure context
whatever the port. **Use `localhost`, not the machine's LAN address.**
`http://192.168.x.y:8080` is not a secure context, the puzzle cannot run at all,
and every visitor is walled permanently. That is trap 1 in
[`../../docs/docker.md`](../../docs/docker.md).

## Go live

Point DNS at the host, then:

```sh
cat >> .env <<'EOF'
SITE_ADDRESS=example.com
HTTP_PORT=80
HTTPS_PORT=443
EOF
docker compose up -d
```

That is the whole change. A bare domain in `SITE_ADDRESS` puts Caddy into
automatic HTTPS: it solves an ACME challenge, installs the certificate,
redirects `:80` to `:443`, serves HTTP/2 and HTTP/3, and renews on its own
schedule. There is no `tls` directive in the Caddyfile and no certbot.

Both port lines are load-bearing. ACME's HTTP-01 and TLS-ALPN challenges are
served on 80 and 443 only, by specification, so a public deployment published on
8080/8443 gets no certificate — the defaults exist so a local trial needs
neither a privileged port nor root.

Keep the `caddy_data` volume across deploys. It holds the certificates, their
private keys, and the ACME account key; losing it means re-issuing on every
restart, which runs into Let's Encrypt's rate limits soon enough to matter.

## What is in here

| File | What it decides |
| --- | --- |
| `compose.yaml` | the topology: only Caddy publishes a port; the gate and the app use `expose` |
| `Caddyfile` | the edge — TLS, compression, one `reverse_proxy` hop, and a list of the things Caddy does that nginx needs told |
| `anteroom.toml` | policy — `listen`, `trusted_proxies`, TTLs, difficulty, and the bypass list |
| `.env` | `ANTEROOM_HMAC_KEY`, and `SITE_ADDRESS` / ports when going live. Not committed; generate your own. |

The built-in wait page is used, because this example is about the topology;
[`../anteroomized/`](../anteroomized/) shows a custom `pages/` directory. Do
copy one thing from it before going public: Open Graph tags in `header.html`.
A link unfurler does not run JavaScript, so it sees the interstitial, and
"Pardon us for a moment" is what your shared links preview as for days.

## What Caddy already does, and the one thing it does not

Fronting the gate with nginx takes four `proxy_set_header` lines,
`proxy_http_version 1.1`, `proxy_buffering off`, and care with the `proxy_pass`
trailing slash — all of which fail quietly if you miss them
([`../../docs/nginx.md`](../../docs/nginx.md)). Caddy's `reverse_proxy` needs
none of it:

| The gate needs | Caddy | Why it matters here |
| --- | --- | --- |
| `X-Forwarded-For`, `-Proto`, `-Host` | set by default | this is what `trusted_proxies` reads; without the headers the gate cannot resolve a visitor |
| the visitor's `Host` forwarded | preserved by default | so the gate and your app see the public authority, and `public_hosts` (if set) lists that, not `anteroom:8080` |
| no response buffering | does not buffer; streams `text/event-stream` | the wait page is an interstitial, and SSE dies behind a buffer |
| no HTML cache in front | Caddy has no cache at all | prerequisite 5 satisfied by doing nothing |
| the request target unrewritten | no directive to get wrong — nginx's `proxy_pass` trailing slash has no Caddy equivalent | still worth the one check under [Verify it](#verify-it): a `rewrite`, `uri`, or `handle_path` directive of your own *does* rewrite it |
| ACME reaching the responder | Caddy answers it ahead of your routes | renewal does not depend on the gate running, or on a bypass |
| rate limiting | **not built in** | see below |

## `trusted_proxies` is the setting you must not omit

It is in `anteroom.toml`, it is commented at length there, and it is worth
restating because there is no error message: omit it and the gate treats Caddy
as the visitor. The pass cookie loses its `Secure` flag, your application sees
Caddy's address instead of the visitor's in every log line and rate limit, and
`bypass.cidrs` matches the wrong thing.

The value here is `172.16.0.0/12`, Docker's default range. That is broad on
purpose and safe for one specific reason: the gate has no host port, so nothing
outside the compose network can reach it to lie to it. Narrow it if you pin a
subnet:

```sh
docker network inspect caddy-tls_default -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

## Rate limiting

Proof of work prices a *completed* admission. It does not make TCP connections,
challenge fetches, or invalid answer submissions free, and the outer proxy is
the better place to reject a flood — prerequisite 10 in
[`../../docs/operating.md`](../../docs/operating.md).

Caddy has no `rate_limit` directive in the standard distribution, so unlike the
nginx recipe this is not a few lines of config. It needs a Caddy built with
[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit):

```dockerfile
# Dockerfile.caddy
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/mholt/caddy-ratelimit

FROM caddy:2
COPY --from=build /usr/bin/caddy /usr/bin/caddy
```

Point the `caddy` service at it (`build: {context: ., dockerfile: Dockerfile.caddy}`
instead of `image: caddy:2`), then in the Caddyfile:

```
{
	# The plugin is not in the standard directive order, so say where it goes.
	order rate_limit before reverse_proxy
}

{$SITE_ADDRESS:http://localhost} {
	rate_limit {
		# Every request. Generous — this is a flood limit, not a policy.
		zone client {
			key    {client_ip}
			events 1200
			window 1m
		}
		# The two work endpoints, which are the expensive ones to serve and the
		# only ones a solver needs.
		zone work {
			match {
				path /.anteroom/challenge /.anteroom/answer
			}
			key    {client_ip}
			events 120
			window 1m
		}
	}

	reverse_proxy anteroom:8080
}
```

These numbers are starting points, not a capacity claim: raise the general zone
for asset-heavy pages or an API, and exclude authenticated webhook paths whose
sender has its own retry contract. `{client_ip}` resolves through Caddy's own
`trusted_proxies` (see [Behind a CDN](#behind-a-cdn)); `{remote_host}` is the
raw peer if you would rather not depend on that. And keep connection limits and
network-layer DDoS protection at the edge — a request limiter is not a SYN-flood
defense.

If you would rather not maintain a custom Caddy build, this is a reasonable
thing to push out to a CDN or the host firewall instead.

## Behind a CDN

Add a CDN in front and there are two hops writing forwarded headers, so both
proxies need to know whom to believe. Caddy first:

```
{
	servers {
		trusted_proxies static <your CDN's published ranges>
	}
}
```

Without it, Caddy's `X-Forwarded-For` still carries what the CDN sent, so the
gate resolves the visitor correctly — but `{client_ip}` in the rate limiter
keys on the CDN's edge instead of the visitor, which collapses every visitor
into one bucket. Anteroom's own `trusted_proxies` stays as it is: it lists
Caddy, which is still the peer it talks to.

Two things change on the gate's side of a CDN. Host-level IP bans hit the CDN's
addresses rather than the visitor's, so any tool consuming `/activity` should
write to the CDN's ban list instead
([`../../docs/operating.md`](../../docs/operating.md)); and a CDN configured to
"cache everything" can pin the wait page at a content URL, which is
prerequisite 5 again and this time not free.

## Verify it

```sh
docker compose ps
# `caddy` has host ports; `anteroom` and `app` must have none.

curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8080/
# 403 — correct. curl is not a browser navigation, so it gets the refusal.
# A 200 here means the gate is being bypassed and the site is ungated.

curl -s http://localhost:8080/robots.txt          # 200: bypassed
curl -s http://localhost:8080/.anteroom/healthz   # ok
curl -s http://localhost:8080/.anteroom/instructions.md | head -20
# the contract for automated access, served to anything that is refused
```

Two checks worth doing once, because both fail silently:

```sh
# Does the gate see what the client sent? Anteroom refuses non-canonical paths
# with 400 rather than resolving them, and that check can only run on the
# original target.
curl -s -o /dev/null -w '%{http_code}\n' --path-as-is \
  'http://localhost:8080/.well-known/../x'
```

`400` means the dot-segments reached the gate, which is what you want: bypass
globs are matched against the decoded path while your application resolves
dot-segments itself, so `/.well-known/../admin` matching a `/.well-known/*`
bypass here and being served as `/admin` there is a real bypass, and the gate
closes it by refusing.

`403` means something in front collapsed the path to `/x` first. That specific
hole is then closed by the normalizer instead — but the gate is no longer
inspecting what the client sent, so its guarantee (*what I checked is what the
upstream receives*) rests on two normalizers agreeing forever. If you get `403`,
look for a `rewrite`, `uri`, or `handle_path` directive in the Caddyfile, or a
CDN normalizing ahead of it;
[`../../docs/nginx.md`](../../docs/nginx.md#the-trailing-slash) has the full
argument and the measurements.

Then, in a browser that has been through the wait page, open
**http://localhost:8080/echo**. hello-app reflects every header it received, so
that page shows exactly what the chain hands your application:
`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, and the `Host` the visitor
asked for.

Read the address there with the local trial in mind: it will be a `172.x`
address, and that is correct rather than broken. Publishing a port with Docker
NATs the connection, so Caddy's peer is the bridge gateway and that is what it
puts in `X-Forwarded-For` — trap 2 in
[`../../docs/docker.md`](../../docs/docker.md), and a property of port
publishing rather than of anything here. The check is worth repeating once on
the deployed instance, where a visitor arrives from the internet: your own
public address means the chain is resolving visitors, and Caddy's container
address means Anteroom is not believing Caddy — `trusted_proxies` is wrong or
unset.

Run the gate with `-v` while you are setting this up. Add it to the `anteroom`
service in `compose.yaml`:

```yaml
command: ["-config", "/etc/anteroom/anteroom.toml", "-v"]
```

It logs one line per request naming the rung of the ladder that answered —
`bypass-path`, `pass-pow`, `wait-page`, `refusal`, `non-canonical-path` — which
turns "why was this walled?" into a single word. Leave it off in production
unless you have decided you want request-level data, including client IPs, in
your logs.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Wait page loops forever, no errors | Reached over a LAN address or plain HTTP on a non-loopback host: no secure context. Use `localhost`, or set `SITE_ADDRESS` to a real domain. |
| No certificate, ACME errors in Caddy's log | `HTTP_PORT`/`HTTPS_PORT` are not 80/443, DNS does not point here yet, or the ports are not reachable from the internet. |
| Certificate re-issued on every restart | The `caddy_data` volume was removed. |
| Visitors re-solve after every deploy | No `ANTEROOM_HMAC_KEY` — check the gate's startup warning. |
| App logs show one client address for the world | `trusted_proxies` unset or wrong in `anteroom.toml`. |
| Pass cookie has no `Secure` flag | Same cause. `X-Forwarded-Proto: https` from an untrusted peer is not believed. |
| App reachable without a pass | Something published a host port. `docker compose ps`. |
| Webhooks stopped arriving | A POST is not a browser navigation. Bypass the path. |
| Link previews show the interstitial | Open Graph tags belong in your own `header.html`. |

## See also

- [`../../docs/operating.md`](../../docs/operating.md) — **read before going
  live**: the full table of what Anteroom breaks and the bypass rule for each,
  puzzle tuning, monitoring, and the CSP algorithm for HTML injection.
- [`../../docs/docker.md`](../../docs/docker.md) — the container contract and
  the two container-specific traps.
- [`../../docs/nginx.md`](../../docs/nginx.md) — the same topology with nginx,
  including the php-fpm case that has no HTTP hop to slot the gate into.
- [`../anteroomized/`](../anteroomized/) — the gate on its own, with a custom
  wait page. The acceptance suite's reference deployment.
