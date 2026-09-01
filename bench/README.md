# The benchmark stack

Two gates in front of one app, and a k6 container that measures them from
inside the compose network. This is tooling for measuring Anteroom, not a
deployment to copy — for those, see [`../examples/`](../examples/).

```
                 ┌──► anteroom :8080 ──────────┐
                 │    (inject = true)          │
k6 ──────────────┼──► anteroom-noinject :8080 ─┼──► app :3000
 │               │    (inject = false)         │    (hello-app)
 │               └──► app :3000 (direct) ──────┘
 └──► anteroom :8090  /stats  (before and after)
```

Everything a run measures is described in
[`../docs/benchmarking.md`](../docs/benchmarking.md), including how to read the
table and what not to conclude from it. This file is about the stack.

## Run it

From the repository root:

```sh
make bench        # per-rung latency and throughput, ~5 minutes
make load         # the mixed-traffic load test with pass/fail thresholds, ~6 minutes
make load-smoke   # the ~1 minute functional slice CI runs on every pull request
PEAK=pass_json make peak   # step one rung's load up until it breaks; PEAK=direct first
make bench-down   # tear it down
```

The first run writes a signing key to `bench/.env` (as `make example-up`
does), builds `anteroom:local` and `hello-app:local`, waits for both gates'
healthchecks, then runs k6. Results land in `bench/results/`: a text table
(`<kind>-latest.txt`), the full k6 summary as JSON (`<kind>-latest.json` plus a
timestamped copy), and the table on stdout. Thresholds that fail make the
command fail.

The stack stays up between runs; `make bench` again is just the k6 step.

## What is in here

| File | What it decides |
| --- | --- |
| `compose.yaml` | the topology above; the fast healthcheck; the `k6` service behind a profile so `up` never starts it; results written as the invoking user |
| `anteroom.toml` | policy for the measured gate: the reference deployment's, with `admin_listen` on, `difficulty = 10`, and `/healthz` bypassed — each explained in the file |
| `anteroom.noinject.toml` | the same with `inject = false` and nothing else, so injection's cost is a subtraction |
| `k6/benchmark.js` | one scenario per rung of the ladder, back to back, at a fixed arrival rate |
| `k6/load.js` | four populations at once (bots, new visitors, pass holders, downloads), ramping, with thresholds |
| `k6/smoke.js` | `load.js`'s traffic at a trickle for 45 s, functional thresholds only |
| `k6/peak.js` | one rung, offered load stepped up until it breaks; a row per step, the knee and the peak marked |
| `peak-cpu.sh` | samples `docker stats` beside a peak run and reports each container's maximum, so "who ran out" has an answer |
| `k6/lib/pow.js` | the solver — written from `/.anteroom/instructions.md`, not from the Go source, like `acceptance/harness/solver.go` |
| `k6/lib/clients.js` | who the traffic pretends to be; the per-VU pass cache and the jar it lives in |
| `k6/lib/traffic.js` | the populations, as k6 exec functions shared by `load.js` and `smoke.js` |
| `k6/lib/stats.js` | `/stats` before and after, and the difference as k6 gauges with thresholds |
| `k6/lib/summary.js` | the report: a table per scenario, the solver's cost, what the gate counted, the thresholds |
| `results/` | output; gitignored except the placeholder |
| `local/` | gitignored; your policy variants (`BENCH_CONFIG=./local/d14.toml make load`) |
| `.env` | `ANTEROOM_HMAC_KEY`; written on first run, never committed |

## Knobs

All are environment variables read by `compose.yaml`; set them on the `make`
command line.

| Variable | Default | Effect |
| --- | --- | --- |
| `BENCH_RATE` | `200` | requests/s per benchmark scenario (`challenge_answer` runs at a tenth) |
| `BENCH_DURATION` | `20s` | length of each benchmark scenario |
| `LOAD_SCALE` | `1` | multiplies every rate in `load.js`; 1 fits a 4-vCPU CI runner |
| `BENCH_CONFIG` | `./anteroom.toml` | the measured gate's policy; relative to `bench/` |
| `K6_IMAGE` | pinned in `compose.yaml` | try another k6 |
| `PEAK` | `refusal` | the rung `make peak` climbs: `direct`, `bypass`, `refusal`, `refusal_json`, `wait_page`, `answer`, `pass_json`, `pass_html` |
| `PEAK_START`, `PEAK_STEP`, `PEAK_MAX` | `500`, `500`, `15000` | the staircase, in req/s |
| `PEAK_RAMP_S`, `PEAK_HOLD_S` | `5`, `25` | seconds per step: ramp, then the hold the report describes |
| `PEAK_P99_MS` | `50` | where the knee is drawn |
| `PEAK_VUS`, `PEAK_MAX_DROPPED` | `1000`, `500` | k6's VU ceiling; dropped iterations that end the climb |
| `BENCH_GATE_CPUS` | `0` (unlimited) | cap the measured gate's cores so it saturates before k6 and the peak is per core |
| `GATE_PORT` | `18080` | host port for the measured gate, for a k6 binary on the host |
| `ADMIN_PORT` | `18090` | host port (loopback only) for `/stats` and `/metrics` |

## Verify it

```sh
docker compose -f bench/compose.yaml ps       # two gates healthy, app up, no k6 (it is a profile)
curl -s 127.0.0.1:18090/stats | head -c 400   # the gate's counters, cumulative since start
curl -si 127.0.0.1:18080/api/items | head -3  # 403: you are not a browser and hold no pass
```

`docker compose ps` should show host ports for `anteroom` only — the app and
the second gate are reachable from k6 and from nothing else.

## When it goes wrong

| Symptom | Cause |
| --- | --- |
| `permission denied` writing `/results` | `BENCH_UID`/`BENCH_GID` were not set; run through `make`, which sets them from `id -u`/`id -g` |
| `not a directory` from the gate at startup | `bench/anteroom.toml` is missing, so compose created a directory at the mount point. `.gitignore` ignores every `anteroom.toml` unless excepted — check the exception is still there |
| `dropped_iterations` above zero | k6 could not keep the requested rate. The numbers are bounded by the generator, not the gate: lower `BENCH_RATE` or `LOAD_SCALE`, or stop running other things |
| `window_elapsed` answers growing | solves are finishing after the challenge deadline (`pass_ttl` from issue). The generator is CPU-starved; see above |
| `bad_pow` above zero | the solver and the served instructions disagree. This is the drift detector — read `/.anteroom/instructions.md`, then `k6/lib/pow.js` |
| `upstream_errors` above zero | the gate could not reach `app`; look at `docker compose -f bench/compose.yaml logs app` |
| every pass holder gets 403 | passes are bound to the User-Agent that earned them and to the client's /24. One UA per run (`clients.js`), and a distributed k6 will not share passes across nodes |
| `make peak` on a `pass_*` rung knees at a few thousand req/s with the gate at several cores and the app idle | upstream connection churn: the proxy's transport keeps two idle connections per host. Confirm with the socket-table one-liner in `docs/benchmarking.md`, "Finding the peak" |
| `make peak` stops with `dropped_iterations` while p99 is still low and k6's CPU is high | the generator was the limit, not the gate. Lower `PEAK_STEP`, raise `PEAK_VUS`, or for the refusal rung accept that one k6 cannot outrun it |
| thresholds fail on latency, nothing else | on a laptop, usually something else was running; on CI, a noisy neighbour. Rerun before believing it; `bench.yaml` keeps artifacts so a real trend is visible |
