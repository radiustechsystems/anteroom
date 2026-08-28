# Acceptance suite

The end-to-end suite for the container image and deployed gate.

## Running it

```sh
make acceptance          # tiers 0-1, headless
make acceptance-browser  # tier 2, needs Playwright
```

Or directly:

```sh
go test -tags e2e -timeout 30m ./acceptance/...
go test -tags e2e -timeout 30m -run 'TestT1_45' -v ./acceptance   # one test
```

The `e2e` build tag keeps all of this out of `go test ./...`, so the ordinary
suite stays fast and needs no Docker.

## What it needs

- Docker, with your user in the `docker` group and the Compose plugin installed.
  Without it every test skips itself with a message saying so — check for skips
  before believing a green run.
- No network access beyond pulling base images once.

## How it is put together

`harness/` holds the shared machinery. `tier0_image_test.go` covers the image
and container contract; `tier1_gate_test.go` covers the gate as deployed. The
Playwright suite in `tier2_browser/` executes the solver and renewal flow in a
real browser.

Tier 1 shares one deployment, stood up in `TestMain` and torn down after the
whole package. Tests needing different configuration (short TTLs, two gate
instances) build their own project in a `t.TempDir()`.

Byte-identity assertions need to compare the gate's output against the
application's, so `fixtures/compose.probe.yaml` publishes the app directly. That
overlay deliberately breaks the deployment's central rule, so the test that
checks that rule — `TestT1_0_AppIsNotReachableFromTheHost` — runs against the
base compose file alone.

## The one rule worth preserving

**The solver in `harness/solver.go` is written from the instructions the gate
serves, not from the gate's source.** Read `/.anteroom/instructions.md`, then
read `Solve`. They must describe the same procedure.

That is what makes this suite worth running: it means a drift between what the
gate does and what the gate *says it does* fails a test here, rather than
silently breaking every automated client that ever reads those instructions.

If you change the challenge protocol, change the served document first, then
make the solver match it.

## When something fails

Every failure message includes the container logs. If it does not, that is worth
fixing — a compose-based failure with no logs is nearly undebuggable.

Add `-v` to the gate's command in the compose file under test and it will name
the rung of the ladder that answered each request, which is usually the whole
answer:

```
level=DEBUG msg=hit method=GET path=/ decision=wait-page status=403 dur=1.2ms
```

Stale projects from an interrupted run:

```sh
docker ps -a --filter 'name=artest-' -q | xargs -r docker rm -f
```
