# Running Anteroom in a container

The image is a static binary on a distroless base: no shell, no package
manager, non-root, about 9 MB. It needs one required setting and has two traps
that are specific to containers. Both traps are silent — nothing crashes, and
the failure shows up as "the site is broken for everyone" or "my allowlist
stopped working" rather than as an error.

Read the two traps first. Everything else here is ordinary.

---

## Trap 1: a container on a LAN has no secure context

The solver uses WebCrypto and renewal uses a service worker. **Both require a
secure context**, which means HTTPS or `localhost` — and browsers treat loopback
as secure, but nothing else.

So this works:

```
http://localhost:8080          ✅ loopback is a secure context
https://example.com            ✅ TLS
```

and this **walls every visitor permanently**:

```
http://192.168.1.50:8080       ❌ no WebCrypto, no service worker
http://anteroom.internal:8080  ❌ same
```

The puzzle cannot run at all. Visitors see the wait page forever. This is the
single most common way a containerized deployment fails, because publishing a
port and browsing to the host's LAN address is the most natural thing to do.

There are exactly two fixes, and picking one is a posture decision:

**Put TLS in front.** The real fix. See [Behind a terminator](#behind-a-tls-terminator)
below.

**Or set `allow_insecure_context = true`.** This ships a JavaScript SHA-256 so
the puzzle works without WebCrypto. Be clear about what it costs: it is 10–50×
slower per hash, and **that cost falls entirely on the honest visitor** — an
attacker's native implementation is unaffected, so the work asymmetry the gate
depends on narrows by the same factor. Service workers are also unavailable, so
there is no background renewal; visitors re-solve when the pass lapses.
Reasonable on a LAN or in development; a downgrade on the public internet. The
gate warns about it at startup.

There is deliberately no `ANTEROOM_ALLOW_INSECURE_CONTEXT` environment override.
It is a security posture, so it is set in a file someone reviewed.

## Trap 2: the container network is a proxy in front of you

`trusted_proxies` decides whose `X-Forwarded-For` the gate believes. In a
container the peer address is almost never the visitor's, and the right setting
depends on what is in front:

| Topology | `trusted_proxies` | What the gate sees |
|---|---|---|
| Published port, nothing in front | `[]` | The Docker bridge gateway (`172.x.0.1`). Client IPs are **unavailable**. |
| Terminator in a sibling container | the compose network CIDR, e.g. `["172.16.0.0/12"]` | The real visitor, from `X-Forwarded-For` |
| Terminator on the host | the bridge gateway, e.g. `["172.17.0.1/32"]` | The real visitor |

The first row deserves emphasis because it surprises people: **when you publish
a port with Docker, the connection is NAT'd, so every request appears to come
from the bridge.** That is a property of port publishing, not of the gate.
Consequences:

- `bypass.cidrs` cannot work. An allowlist matches the bridge or nothing.
- Your application's logs and rate limiting see one address for the world.

If you need real client IPs, put a terminator in front and list it. If you set
`trusted_proxies` when nothing in front actually sets `X-Forwarded-For`, you
have done something worse than nothing: any client can then claim any address.

---

## Quick start

```sh
docker run -d \
  -e ANTEROOM_UPSTREAM=host.docker.internal:3000 \
  -e ANTEROOM_HMAC_KEY="$(openssl rand -base64 32)" \
  -p 8080:8080 \
  ghcr.io/radiustechsystems/anteroom
```

Then browse to `http://localhost:8080` — loopback, per trap 1.

The image ships a config at `/etc/anteroom/anteroom.toml` containing every
default and no `upstream`, which is why the environment variable alone is
enough to start. Mounting your own file over that path replaces it wholesale.

## Which tag

That command takes `:latest`, which is right for trying it and wrong in front of
a real site — with `pull_policy: always` or a Kubernetes `imagePullPolicy:
Always`, a restart can change the gate.

| Tag | Moves | Use |
|---|---|---|
| `@sha256:…` | never | production |
| `:0.4` | patch releases only | production, if you want fixes without review |
| `:latest` | every release | trying it out |
| `:beta` | every prerelease | testing the next release |
| `:edge` | on demand from main | unreviewed; expect nothing |

Every build also gets `:sha-<full commit>`, which is never reused.
[`releasing.md`](releasing.md) is the full policy: what a version number
promises, how to verify the signature and SBOM, and how to ask a running gate
which commit it is.

## The container contract

**Environment variables.** Only these four exist. Everything else is a config
file setting, deliberately — the surface an operator can change without review
is kept small.

| Variable | Effect |
|---|---|
| `ANTEROOM_UPSTREAM` | your application, e.g. `app:3000`. Required. |
| `ANTEROOM_LISTEN` | bind address; defaults to `:8080` |
| `ANTEROOM_PAGES` | directory holding `header.html` and `footer.html` |
| `ANTEROOM_HMAC_KEY` | the signing key; registers as `kid = "env"` |

**Ports.** The gate binds `:8080` as a non-root user. Publish it as `-p 80:8080`
and the daemon owns the privileged half — no capability, no root, nothing to
`setcap`. This is why the default is 8080 rather than 80.

Worth knowing, because it inverts the advice in
[`operating.md`](operating.md#serving-on-port-80-or-443): **inside a container,
a non-root process can bind port 80 directly.** Docker sets
`net.ipv4.ip_unprivileged_port_start=0`, so the privileged-port rule that makes
`setcap` and `AmbientCapabilities` necessary on a host does not apply here. Both
`-p 80:8080` and `ANTEROOM_LISTEN=:80` work; the former is preferred only
because it keeps the container's own configuration identical everywhere and
leaves the host mapping to the orchestrator.

**Volumes.** Mount the config read-only. If payments are enabled, set
`payments.state_file = "/var/lib/anteroom/payments.db"` and mount a persistent,
writable volume at `/var/lib/anteroom`; the image creates that mount point for
UID 65532. Without it, the default database resolves beside the read-only
`/etc/anteroom/anteroom.toml` and the gate correctly refuses to start. Mount a
`pages/` directory if you want your own wait page; both `header.html` and
`footer.html` must exist or the gate refuses to start, and edits are live on the
next challenge with no restart.

**Health.** The image has a `HEALTHCHECK` that runs the binary's own
`-healthcheck` flag, which probes `/.anteroom/healthz` over loopback and exits
0 or 1. There is no shell and no curl in the image, so this flag is the only way
a container can check itself; from outside, probe `/.anteroom/healthz` directly.

**Signals.** SIGTERM drains in-flight requests for `shutdown_grace` (default
five seconds, configurable from one second to one hour). Set Compose
`stop_grace_period` or Kubernetes `terminationGracePeriodSeconds` longer than
that value or the orchestrator will kill the process first.

**Hardening.** The image runs read-only with every capability dropped:

```yaml
read_only: true
cap_drop: [ALL]
security_opt: [no-new-privileges:true]
```

## The signing key

Passes and challenges are stateless signed artifacts. Their key is the only
secret in the deployment and the only shared material the free path needs.
Payment grants additionally require the durable state volume described above.

Leave it unset and one is generated per process. The gate warns loudly, and the
warning means what it says: **passes die on every restart, and no second replica
can verify them.** Every deploy, every crash, and every scale-up walls all your
visitors until they solve again.

```sh
openssl rand -base64 32
```

Supply it as `ANTEROOM_HMAC_KEY`, or as `[[hmac_keys]]` in a mounted config.
Never bake it into an image — an image is published, so a key in one is a
published key. The shipped default config deliberately contains no key.

One sharp edge: `ANTEROOM_HMAC_KEY` registers under `kid = "env"`. An instance
using the environment variable and an instance using a file-configured `kid`
**will not** validate each other's passes even if the key bytes are identical.
Pick one mechanism for the whole fleet.

## Compose: the sidecar

The working example is [`examples/anteroomized/`](../examples/anteroomized/),
which the acceptance suite uses as its reference deployment. Its shape is two
rules:

1. the gate is the only service that publishes a port;
2. the application uses `expose`, never `ports`.

```yaml
services:
  anteroom:
    image: ghcr.io/radiustechsystems/anteroom
    ports:
      - "80:8080"
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
      - ./pages:/etc/anteroom/pages:ro
      - anteroom_state:/var/lib/anteroom
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=${ANTEROOM_HMAC_KEY:?set it — see docs/docker.md}
    depends_on:
      app:
        condition: service_started
    read_only: true
    cap_drop: [ALL]

  app:
    build: .
    expose:
      - "3000"       # reachable on the compose network, never from the host

volumes:
  anteroom_state:
```

Verify rule 2 rather than trusting it:

```sh
docker compose ps        # `app` must show no host port mapping
```

An application still listening on its own published port has a gate standing
decoratively beside it, not in front of it.

`ANTEROOM_UPSTREAM` takes the **service name**, not `localhost` — in Compose the
app is a different host. (In a Kubernetes sidecar it is `127.0.0.1`, because
containers in a pod share a network namespace. This is the single most common
copy-paste error between the two.)

## Behind a TLS terminator

The production topology, and the fix for trap 1: Caddy or nginx terminates TLS,
forwards to Anteroom, which forwards to the app.

```yaml
services:
  caddy:
    image: caddy:2
    ports: ["80:80", "443:443"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on: [anteroom]

  anteroom:
    image: ghcr.io/radiustechsystems/anteroom
    expose: ["8080"]          # no host port: Caddy is the only way in
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
      - anteroom_state:/var/lib/anteroom
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=${ANTEROOM_HMAC_KEY:?}

  app:
    build: .
    expose: ["3000"]

volumes:
  caddy_data:
  anteroom_state:
```

```
# Caddyfile
example.com {
    reverse_proxy anteroom:8080
}
```

```toml
# anteroom.toml — the one line this topology requires
trusted_proxies = ["172.16.0.0/12"]   # the compose network
allow_insecure_context = false        # TLS is present; keep the fast path
```

Without `trusted_proxies`, three things break quietly: the pass cookie loses its
`Secure` flag (so it travels in cleartext on any downgrade), your application
sees Caddy's address instead of the visitor's, and CIDR bypass matches the wrong
thing. With it set, the gate believes Caddy's `X-Forwarded-For`, drops any
inbound `X-Real-IP` / `CF-Connecting-IP` / `True-Client-IP` so a client cannot
forge them, and re-states the resolved address for your application.

Narrow the CIDR to your actual compose subnet if you pin one. `172.16.0.0/12`
is the default Docker range and is fine when the gate has no host port — nothing
outside the network can reach it to lie to it.

## Kubernetes sidecar

```yaml
containers:
  - name: app
    image: myapp
    ports: [{containerPort: 3000}]
  - name: anteroom
    image: ghcr.io/radiustechsystems/anteroom
    ports: [{containerPort: 8080}]
    env:
      # 127.0.0.1, not a service name: containers in a pod share a network
      # namespace. This is the line that differs from Compose.
      - name: ANTEROOM_UPSTREAM
        value: "127.0.0.1:3000"
      - name: ANTEROOM_HMAC_KEY
        valueFrom:
          secretKeyRef: {name: anteroom, key: hmac-key}
    volumeMounts:
      - {name: anteroom-pages, mountPath: /etc/anteroom/pages}
      # Required only when payments are enabled; set payments.state_file to
      # /var/lib/anteroom/payments.db and make this claim writable by UID 65532.
      - {name: anteroom-state, mountPath: /var/lib/anteroom}
    livenessProbe:
      httpGet: {path: /.anteroom/healthz, port: 8080}
    securityContext:
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities: {drop: [ALL]}
volumes:
  - name: anteroom-pages
    configMap: {name: anteroom-pages}
  - name: anteroom-state
    persistentVolumeClaim: {claimName: anteroom-state}
```

Point the Service's `targetPort` at 8080, and make sure nothing else exposes
3000. Every replica needs the same key from the same Secret — passes are
stateless, so that alone makes them fleet-valid, but only if the key matches.
The local payment database is a single-gate topology: do not mount one bbolt
file over a network filesystem or run independent payment replicas, because
neither arrangement provides a fleet-wide settlement reservation. Use one
payment-enabled replica until a shared transactional store is configured.

Wait pages ship well as a ConfigMap: the kubelet syncs edits into the pod within
a minute and the gate re-reads them per challenge, so a copy change needs no
rollout.

## Building the image yourself

```sh
docker build -t anteroom:local .
docker buildx build --platform linux/amd64,linux/arm64 -t anteroom:local .
```

## Troubleshooting

Start with `-v`. It logs one line per request naming the rung of the ladder that
answered, which turns "why was this walled?" into a single word:

```yaml
command: ["-config", "/etc/anteroom/anteroom.toml", "-v"]
```

```
level=DEBUG msg=hit method=GET path=/ decision=wait-page status=200 dur=1.2ms
```

Decisions are `own-endpoint`, `bypass-path`, `bypass-ip`, `pass-pow`,
`pass-paid`, `wait-page`, `refusal`, `non-canonical-path`. Leave it off in
production unless you have decided you want request-level data in your logs —
the line includes the client IP and user agent.

| Symptom | Cause |
|---|---|
| Wait page loops forever, no errors | Trap 1: no secure context. See above. |
| Container exits immediately | No `upstream`. The error names the key. |
| Visitors re-solve after every deploy | No `ANTEROOM_HMAC_KEY`; check the startup warning. |
| Two replicas each wall the other's visitors | Different keys, or one on `ANTEROOM_HMAC_KEY` (`kid = "env"`) and one on a file `kid`. |
| Webhooks stopped arriving | A POST is not a browser navigation. Bypass the path — see [`operating.md`](operating.md). |
| `bypass.cidrs` matches nothing | Trap 2: NAT'd port publishing. Every request looks like the bridge. |
| App reachable without a pass | The app still publishes a host port. `docker compose ps`. |
| Link previews show the interstitial | Put Open Graph tags in your `header.html`. |
| `permission denied` binding a port | `listen` is below 1024. Publish `-p 80:8080` instead. |

## See also

- [`operating.md`](operating.md) — **read before going live**: what Anteroom
  breaks and the bypass rule that fixes each, puzzle tuning, and the CSP
  algorithm for HTML injection.
- [`../acceptance/README.md`](../acceptance/README.md) — the end-to-end suite,
  including the Tier 0 tests that assert the container contract.
- [`../examples/anteroomized/`](../examples/anteroomized/) — the working
  deployment this page describes.
