# Anteroom

A free, open-source, self-hosted reverse proxy that protects websites from bot
traffic using in-browser proof-of-work, with an optional x402 micropayment door
that lets automated visitors (e.g. AI agents) pay the site owner directly instead
of solving puzzles. No accounts, no telemetry, no fees, no middleman.

One binary, one config file. Its only direct dependencies are a TOML parser and
bbolt for durable payment grants.

**Status: the free gate works.** Proof-of-work challenges, passes, the wait page,
bypass lists, the background-renewal service worker, and CSP-aware script
injection into proxied pages are implemented and tested.

**The x402 pay door is implemented and experimental.** It is off unless
configured, and it should stay off outside a trial. Rail-selected payment
identity, durable restart recovery, and compiled route scopes are implemented.
The residual failure boundary is external: x402 does not require an idempotent
settle replay or status lookup when the facilitator's response is lost, and the
shipped bbolt ledger coordinates only processes on one supported filesystem. Do
not put it in front of anything whose revenue you would miss. Keep it disabled
unless you are prepared to reconcile ambiguous facilitator outcomes and operate
the payment ledger on supported persistent storage.

## How it works, in one paragraph

Every request hits one decision ladder: bypassed paths and CIDRs go straight
upstream; a valid pass cookie goes straight upstream; anything else is stopped. A
browser navigation is stopped with a wait page that solves a SHA-256 puzzle in
WebCrypto and reloads into the real content — about a second, no interaction.
Anything that is not a browser navigation is stopped with machine-readable
instructions for solving the same puzzle itself, so a well-behaved client is never
locked out. Passes are short-lived (60 s by default) and a narrow-scope service
worker renews them in the background at a much lower difficulty, up to
`max_session`, so there is no repeated interruption — the renewal script is added
to admitted HTML pages as they are proxied, so it keeps working once the visitor
has left the wait page. Free-path challenges and passes are self-authenticating,
signed with an HMAC key, so any instance can verify any other instance's without
shared request state. The payment path deliberately differs: it keeps a durable,
append-only grant ledger so a settled authorization cannot mint another pass
after a restart.

The goal is not to tell humans from bots. It is that high-volume automated access
is either cheap to tolerate, cheap to discourage, or paid for.

One explicit exception is enabled by default: source-verified `Claude-User`,
`ChatGPT-User`, and `Google-Agent` hosted fetchers pass through because they can
complete neither the browser proof nor x402. This also bypasses paid routes; it
authenticates vendor infrastructure, not a human or application user. Set
`triage.allow_hosted_fetchers = false` to give those requests a strict `403`.

## Running it

Every release attaches a static binary for Linux (x86-64, ARM64, ARMv7), macOS
(Intel and Apple silicon), Windows (x86-64), and FreeBSD (x86-64). Nothing to
install alongside it; the archive also holds the example config.

```sh
# from https://github.com/radiustechsystems/anteroom/releases/latest
tar xzf anteroom_v0.4.0_linux_amd64.tar.gz
cd anteroom_v0.4.0_linux_amd64
cp anteroom.example.toml anteroom.toml
```

The archives come with a `SHA256SUMS` signed by the release workflow;
[`docs/releasing.md`](docs/releasing.md) has the two commands that check it, and
they are worth running on something that sits in front of your site.

Or build it. Requires Go 1.22+ (see `go.mod`); release artifacts use the current
stable Go toolchain.

```sh
go build ./cmd/anteroom                  # produces ./anteroom
cp anteroom.example.toml anteroom.toml
```

Edit `anteroom.toml`. For a puzzle-only gate — which is the whole gate until you
want to take payments — delete **every** payments section: `[payments]` and both
of the `[[payments.rails]]` and `[[payments.rules]]` blocks under it. TOML array
tables are separate sections, so removing the first one does not remove the rest,
and a half-deleted `[payments]` fails to start rather than quietly ignoring the
remainder. Then set:

```toml
upstream = "127.0.0.1:3000"     # your real web server
```

With payments gone, `upstream` is the only key you must set; everything else has
a working default.

`listen` defaults to `127.0.0.1:8080` in the shipped example, which is right when
a TLS terminator sits in front — a gate reachable directly is a gate that can be
bypassed by asking the port behind it. Widen it to `:8080` only when something
must reach it across a network, such as a container. Either way it is
unprivileged on purpose: ports below 1024 need root or `CAP_NET_BIND_SERVICE` on
Linux. See "Serving on port 80 or 443" in
[`docs/operating.md`](docs/operating.md) if you want Anteroom itself at the edge.

Then:

```sh
./anteroom -config anteroom.toml       # -config defaults to ./anteroom.toml
```

Visit `http://localhost:8080` in a browser: you should get the wait page, then
your own site a second later. Startup warnings are worth reading: an
auto-generated HMAC key means passes die on restart and no second instance can
verify them, which is fine for a first run and wrong in production.

`ANTEROOM_LISTEN`, `ANTEROOM_UPSTREAM`, `ANTEROOM_PAGES`, and `ANTEROOM_HMAC_KEY`
override the file, for containers and secret managers.

Run with `-v` to log one line per request naming which rung of the ladder answered
it (`pass-pow`, `wait-page`, `refusal`, `bypass-path`, …) with the status, size,
and duration. It is the quickest way to see why something is being walled.

### Check it from the command line

```sh
curl -s localhost:8080/.anteroom/healthz          # liveness
curl -s localhost:8080/                           # the machine-readable refusal
curl -s localhost:8080/.anteroom/instructions.md  # how a client passes the gate
```

A non-browser client gets `403` with markdown telling it how to solve the puzzle
(`Accept: application/json` gets the same as JSON). That document is the contract
for automated access, and it is worth reading once: `GET /.anteroom/challenge`,
find a nonce whose `sha256(challenge + nonce)` sorts below the returned
threshold, `POST` it to `/.anteroom/answer`, and reuse the cookie you get back.

### In a container

```sh
docker run -d \
  -e ANTEROOM_UPSTREAM=host.docker.internal:3000 \
  -e ANTEROOM_HMAC_KEY="$(openssl rand -base64 32)" \
  -p 8080:8080 \
  ghcr.io/radiustechsystems/anteroom
```

The image is a static binary on a distroless base: no shell, no package manager,
non-root, about 9 MB. It ships a config holding every default and no `upstream`,
so the environment variable alone is enough to start.

Browse to `http://localhost:8080` — **loopback specifically**. A container
reached at `http://192.168.x.y:8080` has no secure context, so WebCrypto and
service workers are both unavailable and every visitor is walled permanently.
That trap, the `trusted_proxies` one that follows from Docker's NAT, and worked
Compose and Kubernetes topologies are in [`docs/docker.md`](docs/docker.md).
[`examples/anteroomized/`](examples/anteroomized/) is a working deployment used
by the acceptance suite.

That command takes `:latest`. In front of a real site, pin the digest or a minor
tag (`:0.4`) — [`docs/releasing.md`](docs/releasing.md) has the tag policy, what
a version number promises, and how to verify the signature and SBOM the image is
published with.

### Behind TLS

WebCrypto and service workers both require a secure context, so Anteroom needs
HTTPS or `localhost`. The standard topology is nginx/Caddy → Anteroom → your app,
and it has exactly one required setting:

```toml
trusted_proxies = ["127.0.0.1/32"]    # whoever terminates TLS in front of you
```

Omitting it costs the cookie's `Secure` flag and hides visitor IPs from your
application. [`examples/caddy-tls/`](examples/caddy-tls/) is that topology as a
working Compose deployment — Caddy gets the certificate by itself, so going live
is one line of `.env` — and [`docs/nginx.md`](docs/nginx.md) has the nginx
equivalent, including the php-fpm case where the gate goes in front of nginx
rather than behind it. For a deployment reached over plain HTTP on a LAN (the
common Docker-on-`192.168.x.y` case) there is an opt-in `allow_insecure_context = true`
that ships a JavaScript SHA-256 instead; it is 10–50× slower per hash and that
cost falls on the honest visitor, so it is a LAN convenience, not a public
posture.

### Before going live

Read [`docs/operating.md`](docs/operating.md). It lists the deployment
prerequisites and, more usefully, an honest table of **what Anteroom breaks** —
inbound webhooks, OAuth callbacks, API clients, RSS readers, link previews,
iframe embeds — with the bypass rule that fixes each. A gate that silently eats
your Stripe webhooks is worse than no gate.

Removing it later: visit `/.anteroom/uninstall` to unregister the renewal worker,
or just delete the endpoint — the worker retires itself once the gate is gone.

## Configuration

[`anteroom.example.toml`](anteroom.example.toml) is the entire configuration
surface, annotated. The dials most likely to matter:

| Key | Default | What it does |
|---|---|---|
| `upstream` | — | required; your real web server |
| `pass_ttl` | `60s` | pass lifetime, and also the solve deadline |
| `difficulty` | `14` | admission cost; +1 roughly doubles solve time |
| `renew_difficulty` | `6` | background renewal cost; cheap on purpose |
| `max_session` | `30m` | caps the renewal chain before re-admission |
| `pages` | unset | your own `header.html` / `footer.html`, re-read on change |
| `inject` | `true` | inject the renewal script into proxied HTML |
| `trusted_proxies` | `[]` | CIDRs whose `X-Forwarded-For` is believed |
| `[bypass]` | — | paths and CIDRs that are never challenged |
| `public_hosts` | unset | exact public authorities the listener will serve; set this on shared virtual-host listeners |
| `admin_listen` | unset | operator port serving Prometheus `/metrics`, JSON `/stats`, `/healthz`; unauthenticated, so keep it on loopback |
| `shutdown_grace` | `5s` | maximum graceful-drain interval after SIGTERM/SIGINT |
| `[payments]` | omitted | the optional pay door; `pay_to` is required to enable it |
| `payments.state_file` | beside config | durable single-use grant ledger; put it on an owned persistent volume |

Anteroom is non-custodial by invariant: `pay_to` is your public receiving address,
it is never generated for you, and the binary contains no key generation, no
transaction signing, and no chain RPC client.

## Documentation

- [`anteroom.example.toml`](anteroom.example.toml) — the annotated configuration
  contract.
- [`docs/operating.md`](docs/operating.md) — **read before going live**:
  prerequisites, puzzle tuning, what breaks and how to fix it, payment-state
  recovery, monitoring, and HTML injection.
- [`docs/nginx.md`](docs/nginx.md) — complete nginx topologies and the settings
  that fail quietly if omitted.
- [`docs/releasing.md`](docs/releasing.md) — what the image tags mean and which
  ones move, how a beta differs from a release, and how to check that what you
  pulled is what this repository built.
- [`docs/docker.md`](docs/docker.md) — the container contract, Compose and
  Kubernetes examples, and container-specific networking traps.

## Development

```sh
make check        # gofmt, vet, unit tests with the race detector
make acceptance   # the end-to-end suite (needs Docker; minutes, not seconds)
```

The tests include adversarial cases for tampered passes, skewed clocks, replayed
solves, malformed config, and path-canonicalization tricks.

The acceptance suite (`acceptance/`, behind the `e2e` build tag) runs the gate
as a container in front of a real application and asserts properties unit tests
cannot reach: the image has no shell and runs unprivileged, bypassed responses
remain byte-identical, event streams are not buffered, and the CSP ladder works
on the wire. Its solver follows the instructions served by the gate rather than
calling internal implementation code.

Layout: `cmd/anteroom` is the entrypoint; `internal/token` signs and verifies
passes; `internal/challenge` issues and verifies stateless puzzles; `internal/gate`
is the decision ladder, the proxy, and the served endpoints and assets;
`internal/bypass` and `internal/config` are what their names say.

## Related work

[Anubis](https://github.com/TecharoHQ/anubis) is a self-hosted web AI firewall
that applies configurable bot policy and browser challenges, including
proof-of-work, in front of an origin. Anteroom addresses the same broad traffic
problem with a deliberately small reverse-proxy decision ladder, machine-readable
instructions for its free challenge, and an optional x402 admission door.

[haproxy-protection](https://github.com/nayumiDEV/haproxy-protection) is an
HAProxy/Lua challenge-response system offering CAPTCHA and SHA-256 or Argon2
proof-of-work. It includes a browser-side background solver that watches its
proof cookie and starts a new check as expiry approaches. Anteroom also keeps an
open page admitted, but does so differently: a narrow-scope service worker
renews an HttpOnly pass at lower difficulty only while pages report liveness.

## License

MIT — see [`LICENSE`](LICENSE). The optional insecure-context SHA-256 fallback
includes MIT-licensed third-party code documented in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
