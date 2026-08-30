# Benchmarking Anteroom

What the gate costs per request, how to measure it on your own hardware, and
what not to conclude from the numbers. The harness is k6 in a container,
driven by `make`, in [`bench/`](../bench/); Go micro-benchmarks cover the
pieces k6 cannot isolate.

Every figure in this document, and every figure the harness prints, is a
starting point on one machine — not a capacity claim. The gate, the
application and the load generator share a CPU during a run; Docker Desktop
adds a VM hop on macOS; a CI runner has neighbours. Compare runs on one machine
against each other, and treat the shape of the table (which rung costs what,
relative to the others) as the portable result.

## Quick start

```sh
make bench        # each rung of the ladder on its own, ~5 minutes
make load         # bots, new visitors, pass holders and downloads at once, ~6 minutes
make bench-go     # Go micro-benchmarks, no Docker
make bench-down   # tear the stack down
```

`make bench` and `make load` build the images, start two gates and the
application, and run k6 from a fourth container on the same network. The
report is printed and written to `bench/results/` as text and as the full k6
summary JSON. Thresholds fail the command.

## What is being measured

Anteroom answers every request from one rung of a ladder
([README, "How it works"](../README.md#how-it-works-in-one-paragraph);
[operating.md, "Watching what the gate decides"](operating.md#watching-what-the-gate-decides)),
and the rung's name is the `decision` label on `anteroom_http_requests_total`.
`bench/k6/benchmark.js` sends one kind of request per scenario so that each
row of its table is one rung against an otherwise idle gate:

| Scenario | Request | Rung (`decision`) | What the row isolates |
| --- | --- | --- | --- |
| `direct_small` | `GET /robots.txt` at the app, no gate | — | the floor: network and application alone |
| `bypass_small` | `GET /robots.txt` through the gate | `bypass-path` | **the proxy hop**: `bypass_small − direct_small` |
| `refusal` | `GET /api/items`, not a browser, no pass | `refusal` | the cheapest gated answer: a 403 with the markdown instructions |
| `refusal_json` | same with `Accept: application/json` | `refusal` | the JSON refusal body |
| `wait_page` | `GET /` shaped like a browser navigation, no pass | `wait-page` | issuing a challenge and rendering the interstitial, served as 403 (which re-reads `pages/` from disk) |
| `challenge_answer` | `GET /.anteroom/challenge`, solve, `POST /.anteroom/answer` | `own-endpoint` | **verifying a solve**: look at the `answer` row of the by-class table |
| `pass_json` | `GET /api/items` with a pass | `pass-pow` | **verifying a pass cookie** and proxying: `pass_json − bypass_small` |
| `pass_html_inject` | `GET /` with a pass, `inject = true` | `pass-pow` | proxying HTML through the streaming rewriter |
| `pass_html_noinject` | the same page from the second gate, `inject = false` | `pass-pow` | **the rewriter**: `pass_html_inject − pass_html_noinject` |
| `download` | `GET /download/big.bin` (8 MiB) with a pass, 4 streams | `pass-pow` | bytes through the proxy, as MiB/s |
| `download_direct` | the same from the app | — | the network's own ceiling for the download row |

Each scenario runs at a constant arrival rate (`BENCH_RATE`, default 200/s,
for `BENCH_DURATION`, default 20 s; `challenge_answer` at a tenth of the rate).
That measures latency at a fixed offered load, which is what sizing a
deployment needs and what stays comparable between runs — not throughput at
saturation, which measures whichever of the three containers ran out of CPU
first. `dropped_iterations` must be zero: if k6 could not keep the rate, the
row describes the generator, and the report says so.

Below the table the report prints:

- **by request class**: `challenge` and `answer` broken out, because a solve
  is two requests and only the second one does the gate's work;
- **solver**: how many hashes each admission cost the generator, and its wall
  time. `anteroom_solve_hashes` is what `difficulty` prices;
- **gate**: what the gate itself counted over the run, read from `/stats` on
  the admin listener before and after. The request total should match k6's;
  `bad_pow`, `malformed` and `upstream_errors` must be zero. This is the same
  data as `/metrics`, and the same vocabulary as `anteroom -v`.

### The load test

`bench/k6/load.js` runs four populations at once for about five minutes,
ramping — a minute up, two level, one higher, thirty seconds down:

| Population | What it does | Rungs |
| --- | --- | --- |
| `bots` | never earns a pass; mostly refused, sometimes on a bypassed path | `refusal`, `bypass-path` |
| `browsers` | new visitors: wait page, solve, admitted with the renewal script injected, two more pages | `wait-page`, `own-endpoint`, `pass-pow` |
| `passholders` | returning visitors with a live pass: HTML, JSON and a static file, re-solving only near expiry | `pass-pow` |
| `downloads` | two pass holders pulling the 8 MiB file back to back | `pass-pow` |

Its thresholds are the regression gate: p95 latency per population and per
request class, a failure rate under 1 %, no `upstream_errors`, no `bad_pow`, no
`malformed`, fewer than ten `window_elapsed`, and under 500 dropped iterations.
They are loose — a p95 of 150 ms for a 403 from a process that does one HMAC
is two orders of magnitude above what the rung costs idle — because they are
meant to catch a change that makes a rung several times slower, on a shared
runner, without crying wolf. Once a machine has a history, tighten them.

`LOAD_SCALE` multiplies every rate. `1` is sized for a 4-vCPU CI runner with
all three containers on it; a laptop takes 2–3 before the generator saturates,
and when it does `dropped_iterations` rises before the gate's latency does.

### The smoke test

`bench/k6/smoke.js` is the load test's traffic at a trickle for 45 seconds,
with functional thresholds only: passes were minted, each population got the
answer the ladder promises it, no upstream errors, no `bad_pow`. CI runs it on
every pull request (`ci.yaml`, `k6-smoke`). It has no latency thresholds
because `ci.yaml` is what the release workflow calls to decide a tag is
publishable, and a runner's speed is not a property of the code.

## Running at production difficulty

The stack runs at `difficulty = 10` (about a thousand hashes per admission)
rather than the default 14 (about sixteen thousand), so the load generator
solving puzzles in JavaScript is not the thing being measured. The gate's cost
per answer — one SHA-256 and one HMAC — is the same at any difficulty; only
the client's changes.

To measure with production settings anyway:

```sh
cp bench/anteroom.toml bench/local/d14.toml      # bench/local is gitignored
$EDITOR bench/local/d14.toml                     # difficulty = 14
BENCH_CONFIG=./local/d14.toml make load
```

Expect `anteroom_solve_hashes` per solve to rise sixteenfold, the k6 container
to become CPU-bound, and `dropped_iterations` to climb in the `browsers`
population first. Lower `LOAD_SCALE`, or accept that the run measures the
solver. k6's `k6/crypto` SHA-256 runs in Go, so it is a fair stand-in for a
browser's WebCrypto; the `allow_insecure_context` JavaScript fallback is
10–50× slower per hash and is not modelled here.

## A k6 binary on the host

The compose stack publishes the measured gate on `localhost:18080` and its
admin listener on `127.0.0.1:18090`. With k6 installed:

```sh
make bench-up
k6 run -e BASE_URL=http://localhost:18080 -e ADMIN_URL=http://127.0.0.1:18090 \
       -e RESULTS_DIR=./bench/results bench/k6/benchmark.js
```

`NOINJECT_URL` and `APP_URL` are unset here, so the second gate and the
direct-to-app rows are skipped (those services publish no host port). Numbers
from this mode include the host port-forward — and on macOS, Docker Desktop's
VM — so compare them only with each other, never with compose-mode numbers.

Against any deployment, set only `BASE_URL`: the scripts skip `/stats` when
`ADMIN_URL` is empty. Remember that passes bind to the client's /24 and
User-Agent, so k6 must run from one place with one UA per run.

## The Go micro-benchmarks

`make bench-go` runs `go test -bench` across the repository. They measure the
same rungs with the network taken out — the handler called directly, the
upstream an in-process test server — and the primitives under them:

| Package | Benchmarks | What they bound |
| --- | --- | --- |
| `internal/gate` | `ServeHTTP/{bypass,refusal,refusal_json,wait_page,challenge,pass_json,pass_html_inject}`, `ServeHTTP_NoInject/pass_html`, `Answer`, `parallel/*` | one request per rung, allocations included; the `parallel` variants show what shared state costs under contention |
| `internal/challenge` | `Issue`, `Verify`, `Threshold`, `CheckPoW/{accept,reject}`, `Solve/difficulty=8,10,12` | the puzzle: one HMAC to issue or verify, one SHA-256 to check; and how solve time doubles per bit |
| `internal/token` | `Mint`, `Verify`, `Verify_RotatedKey` | the pass cookie: the per-request floor for an admitted visitor |
| `internal/bypass` | `Path/*`, `IP/*`, `ClientIP/*` | the matcher every request runs through before any cryptography |

Use `-count=6` and [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat)
to compare two commits; a single run's ns/op is not a comparison.

## Reading the numbers

Some things the table will show, and what they mean:

- **The refusal is the cheapest gated answer, and the wait page is not far
  behind.** Both are the gate writing a body itself; neither touches the
  upstream. This is the property that matters under a scrape: the more of the
  traffic the gate refuses, the less of it the application sees.
- **`pass_json` costs a little more than `bypass_small`.** The difference is
  one cookie verification (base64, HMAC, JSON) — the per-request price of
  admission.
- **`pass_html_inject` costs more than `pass_html_noinject`.** The rewriter
  scans the response for `<head>` and forces `Accept-Encoding: identity`
  upstream so it can. On a large HTML page the identity encoding, not the
  scan, is the larger cost — and it is a cost to the upstream's bandwidth,
  which `anteroom_upstream_bytes_total` shows.
- **The download rows are bounded by the network** before they are bounded by
  the gate; `download` and `download_direct` should be close. At 200 req/s
  nothing here touches the proxy's real ceiling — the upstream connection
  churn that "Finding the peak" below measures.
- **`anteroom_solve_ms` is not gate latency.** It includes the hashing, which
  is the visitor's cost by design.

## Finding the peak

`benchmark.js` measures at a load the gate handles easily. `peak.js` asks the
other question — how much of one kind of request can it take — by stepping the
offered load up until something breaks:

```sh
PEAK=direct    make peak    # the app alone: the ceiling no proxied rung can exceed
PEAK=pass_json make peak    # admitted traffic through the gate
PEAK=refusal   make peak    # a scrape flood
```

One rung per run (`direct`, `bypass`, `refusal`, `refusal_json`, `wait_page`,
`answer`, `pass_json`, `pass_html`). The load climbs a staircase — `PEAK_START`
to `PEAK_MAX` req/s in `PEAK_STEP` increments, each step `PEAK_RAMP_S` seconds
of ramp and `PEAK_HOLD_S` of hold (defaults 500 → 15 000 by 500, 5 s + 25 s) —
using an open-model executor: requests fire at the target rate whether or not
earlier ones have returned, which is the only way to overload a server rather
than wait politely for it. A second, one-VU scenario samples `/stats` every two
seconds for the gate's own view. The report is one row per step. This is
`PEAK=pass_json` on the laptop from the sample run above, 1 000 → 12 000 by
1 000 with short 8 s holds:

```
step  target/s     k6/s   gate/s  short     p50     p95     p99     max   fail inflight gorout
----------------------------------------------------------------------------------------------
   0      1000   1000.0   1000.4  0.00%   0.22   0.33   0.76   6.00  0.00%        1    513
   1      2000   1999.8   1917.4  0.01%   0.25   0.49   1.02   6.52  0.00%        3    519
   2      3000   3000.1   2980.3  0.00%   0.22   0.48   1.81   14.0  0.00%        4    521
   3      4000   4000.0   3919.1  0.00%   0.20   0.44   1.61   9.04  0.00%        1    513
   4      5000   4998.9   4981.0  0.02%   0.25   36.0   90.8  203.6  0.00%        4    521  ◂
peak: 4000 req/s (step 3) — delivered in full, no failures, p99 1.61ms
knee: step 4 at 5000 req/s — first p99 over 50ms
stopped: during step 5 of 11 (6000 req/s) — dropped_iterations: count<500
gate-side signals during the climb (fine past the peak, a problem before it):
  anteroom_stats_upstream_errors: value==0
```

Two lines matter. The **knee** is the first step whose p99 crosses
`PEAK_P99_MS` (default 50 ms). The **peak** is the last step that was delivered
in full (shortfall under 2 %), with no failures, below the knee. Quote the peak
with its p99. And read the shape: the median never moved — 0.2 ms at every
step — while the p95 went from half a millisecond to 36 at step 4. That is not
a server running out of CPU, which raises every percentile together; it is a
fraction of requests hitting something expensive.

### What stops the climb

The run ends when requests fail, or when k6 **drops iterations** — it had no
free VU when the next request was due. Under saturation that is exactly what
the gate's rising latency looks like from the generator, so it is the natural
end of a climb. It is also what a CPU-starved k6 looks like. The summary cannot
tell the two apart; the CPU log can. `make peak` samples `docker stats` beside
the run and prints each container's maximum afterwards. For the run above:

```
cpu: peak per container over the run (docker stats, % of one core; 200% is two cores)
  arbench-anteroom-1                 493.5%   mem 83.78MiB / 31.29GiB
  arbench-app-1                       42.9%   mem 21.11MiB / 31.29GiB
  arbench-k6-run-35d4311bf4bd        150.1%   mem 490MiB / 31.29GiB
```

The app is at less than half a core and k6 at one and a half, so neither was
the limit. The gate is at five cores to proxy 5 000 small JSON responses per
second — far more than the request handling costs (`make bench-go` puts a
proxied request at about 50 µs of handler time) — so the cores are going
somewhere else. They are going to the kernel. The proxy uses Go's
`http.DefaultTransport`, which keeps **two** idle connections per upstream
host; every request past the second opens a TCP connection to the app and
closes it afterwards. Sampling the gate's own socket table during the climb
shows it:

```sh
docker run --rm --network container:arbench-anteroom-1 alpine \
  awk 'NR>1{c[$4]++} END{print "established", c["01"], "time_wait", c["06"]}' /proc/net/tcp
# at step 4:  established 613  time_wait 26685
```

Twenty-seven thousand sockets in `TIME_WAIT`, six hundred connections open at
once, and — the gate-side signal in the report — the first 502s, as connection
attempts start failing. That was the ceiling `pass_json` found, and it was a
property of the proxy, not the hardware.

### What fixing it looked like

The fix is `upstreamTransport` in `internal/gate/gate.go`: the proxy's
transport keeps up to 512 idle connections to the upstream instead of two, so
the pool grows to the concurrency the traffic actually has and every request
after that reuses a connection. `TestUpstreamConnectionsAreReused` pins the
property. The same climb, same machine, after the change:

```
step  target/s     k6/s   gate/s  short     p50     p95     p99     max   fail inflight gorout
----------------------------------------------------------------------------------------------
   4      5000   4999.8   4980.4  0.00%   0.24   0.73   2.71   12.2  0.00%        2    632
   6      7000   6999.8   6980.6  0.00%   0.19   0.43   1.68   10.0  0.00%        2    630
   8      9000   8999.9   8981.5  0.00%   0.20   0.73   3.01   17.9  0.00%        3    692
   9     10000   9953.1   9887.8  0.47%   0.22   7.79   46.4  160.5  0.00%        2   1576
  10     11000   1181.6      0.0 89.26%   0.30   22.4   46.8   89.4  0.00%        0      0  ◂
peak: 10000 req/s (step 9) — delivered in full, no failures, p99 46.4ms

cpu: peak per container over the run
  arbench-anteroom-1                 151.5%
  arbench-app-1                       63.1%
  arbench-k6-run-edb47b4eb6a2        192.0%
# socket table at step 9:  established 1056  time_wait 115
```

The step that used to be the knee (5 000) now has a p99 of 2.7 ms; the peak
moved from 4 000 to 10 000 req/s; the gate is at a core and a half instead of
five; `TIME_WAIT` went from twenty-seven thousand to a hundred. And the run
still ended the way a climb does — but look at who was busy: k6 at two cores
with its VUs exhausted (the goroutine count says a thousand requests were in
flight at once), the gate at 1.5. Past 10 000 req/s this laptop, with all three
containers on it, is the limit. The proxied ceiling is now "more than one
machine can measure cleanly", which is where a harness like this hands over to
dedicated hardware.

### Making the result mean something

- **Run `PEAK=direct` first.** The gate's proxied peak cannot be measured above
  the app's own; hello-app's `/robots.txt` is cheap, but it is still a Go HTTP
  server on the same machine. If `direct` knees where the gate does, the app
  was the limit. On the laptop above it did not: `direct` delivered 15 000
  req/s at p99 1.9 ms with the app at 85 % of one core and no knee in sight,
  so at 5 000 the app had three times the headroom the gate ran out of.
- **Cap the gate's cores.** `BENCH_GATE_CPUS=2 PEAK=refusal make peak` limits
  the gate to two cores so it saturates before k6 does, and the result is
  quotable as *req/s per core*.
- **The refusal rung will outrun one k6.** A refusal is about two microseconds
  of handler work; k6 on a laptop generates a few tens of thousands of requests
  per second before it is the bottleneck. Expect `dropped` with k6 pegged and
  the gate not. For that rung the honest ceiling is the `parallel/refusal` Go
  benchmark (CPU-bound, no network), or k6 on separate hardware.
- **Lower `difficulty` for the `answer` rung** (`bench/local/`, `BENCH_CONFIG`)
  to 4 or so: verification costs the gate the same at any difficulty, and k6
  stops spending its CPU on hashing.
- **Hold longer than the example.** 8 s holds were chosen for a quick
  illustration; the 25 s default gives stable percentiles. Widen `PEAK_STEP`
  first, then narrow it around the knee.
- `PEAK_VUS` (default 1000) bounds k6's memory; 500 are preallocated because
  k6 drops iterations while it initialises VUs on demand, which would read as
  saturation. VUs needed ≈ rate × latency; a thousand covers 15 000 req/s at
  60 ms, well past any knee worth reporting.
- The three containers share a machine, so numbers are the machine's; compare
  runs on one machine, and read the shape.

`make peak` exits 0 when the climb ends by tripping a stop condition — that is
how it is meant to end. The gate-side signals (502s, bad answers, failed
checks) are listed separately: past the peak they are how it broke, which is
the finding; before the peak they mean the measurement is not clean.

## A sample run

One laptop (Apple silicon, Docker Desktop, everything on one machine), the
stack as committed, `BENCH_RATE=200`, k6 v1.8. Latencies in milliseconds as k6
saw them over the compose bridge. Read the shape, not the digits.

```
scenario             rung              reqs   req/s     p50     p90     p95     p99     max   fail       recv
-------------------------------------------------------------------------------------------------------------
direct_small         none              4001   200.1   0.12   0.17   0.19   0.26   2.02  0.00%  633.0 KiB
bypass_small         bypass-path       4001   200.1   0.28   0.38   0.42   0.56   3.88  0.00%  633.0 KiB
refusal              refusal           4001   200.1   0.14   0.21   0.23   0.32   2.91  0.00%    5.7 MiB
refusal_json         refusal           4001   200.1   0.16   0.23   0.26   0.45   4.71  0.00%    2.9 MiB
wait_page            wait-page         4001   200.1   0.16   0.23   0.25   0.34   2.48  0.00%   12.6 MiB
challenge_answer     own-endpoint       802    40.1   0.19   0.27   0.30   0.52   6.02  0.00%  451.9 KiB
pass_json            pass-pow          4101   205.1   0.32   0.43   0.48   0.67   2.94  0.00%  716.7 KiB
pass_html_inject     pass-pow          4101   205.1   0.35   0.53   0.64   2.01   30.5  0.00%   13.1 MiB
pass_html_noinject   pass-pow          4101   205.1   0.29   0.44   0.51   0.85   10.5  0.00%   12.9 MiB
download             pass-pow         10277   513.9   7.33   10.8   12.2   15.3   41.9  0.00%   80.2 GiB
download_direct      none             12259   613.0   6.19   8.79   9.94   12.8   25.0  0.00%   95.8 GiB
by request class (ms):
  challenge        555 reqs   p50   0.20  p95   0.31  p99   0.42
  answer           555 reqs   p50   0.15  p95   0.27  p99   1.85
gate: answers ok_admit=501 ok_renew=4 bad_pow=0 malformed=0 stale=0 window_elapsed=0 error=0
```

What that run says, in the terms above: the proxy hop is about 0.16 ms at the
median (`bypass_small − direct_small`); a refusal costs the gate less than the
proxy hop does, and so does the wait page; verifying a pass cookie adds about
0.04 ms (`pass_json − bypass_small`); the rewriter adds about 0.06 ms at the
median and shows in the tail (`pass_html_inject − pass_html_noinject`, p99
2.0 vs 0.85); verifying a solve is a 0.15 ms request. The download rows are the
bridge's bandwidth, with the proxy taking about 15 % of it. The four
`ok_renew` are pass holders whose passes neared `pass_ttl` mid-scenario and
took the cheap renewal challenge instead of admission — the harness reproduces
that path without meaning to, which is the right kind of accident.

Those are sub-millisecond figures from a process that is not doing much per
request, on a machine with nothing else to do. Behind a TLS terminator and
across a real network, every row moves up by the same network cost and the
differences between rows stay about where they are. That is the portable
result.

## In CI

Two workflows:

- **`ci.yaml`, job `k6-smoke`** — the smoke test, on every push and pull
  request. Functional thresholds only; it is part of what a release requires.
- **`bench.yaml`** — the load test, Monday mornings and on demand
  (`gh workflow run bench.yaml -f script=load`, or `-f script=benchmark`). The
  report goes to the job's step summary; the k6 JSON is kept as an artifact
  for 90 days, so a regression can be traced to the week it landed. Not part
  of `ci.yaml`, deliberately: a load test on a shared runner is a trend
  signal, not a release gate.
