# hello-app, behind Anteroom

The reference deployment: `examples/hello-app` with a gate in front of it. The
acceptance suite tests this directory, so it is a working example rather than a
static illustration.

## Run it

```sh
echo "ANTEROOM_HMAC_KEY=$(openssl rand -base64 32)" > .env
docker compose up -d --build
```

The first command creates a deployment-specific signing key. Keep `.env`
private and reuse that key across restarts and replicas; do not commit it or
copy a key from documentation.

Then open **http://localhost:8080**.

Use `localhost`, not the machine's LAN address. WebCrypto and service workers
require a secure context; browsers treat loopback as secure and
`http://192.168.x.y` as not, so over a LAN address the puzzle cannot run and
every visitor is walled permanently. That is trap 1 in
[`../../docs/docker.md`](../../docs/docker.md), and the fix is either TLS in
front or `allow_insecure_context = true`.

Check that the gate is actually in the path:

```sh
docker compose ps          # `app` must show no host port
curl -s localhost:8080/    # 401 with instructions, not the app's HTML
```

## What is in here

| File | What it decides |
| --- | --- |
| `compose.yaml` | the topology: only the gate publishes a port; the app uses `expose` |
| `anteroom.toml` | policy — TTLs, difficulty, bypass list, and the two container traps |
| `pages/header.html` | your wait page, including the Open Graph tags that keep link previews working |
| `pages/footer.html` | closes it |
| `.env` | the signing key. Not committed; generate your own. |

Both page files must exist or the gate refuses to start, and both are re-read on
every challenge — edit them and reload, no restart and no rebuild.

## Things worth reading in `anteroom.toml`

Three settings carry comments longer than themselves, because each is a decision
that looks like a default:

- **`allow_insecure_context`** — false here, and only because you reach this at
  `localhost`. The comment explains when that stops being true.
- **`trusted_proxies`** — empty here, and correct, because nothing in front sets
  `X-Forwarded-For`. The cost is that Docker's NAT hides client IPs, which is
  why `bypass.cidrs` is unusable in this topology.
- **`bypass.paths`** — includes `/webhooks/*`. A POST is not a browser
  navigation, so without that line the app's webhook endpoint is refused and the
  body is gone.

## Removing it

Point your traffic back at the app and drop the gate. Visitors who still hold a
renewal service worker retire it themselves once the gate's endpoints stop
answering; `/.anteroom/uninstall` does it immediately.
