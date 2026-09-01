package gate

import (
	"github.com/radiustechsystems/anteroom/internal/metrics"
)

// solveBuckets spans the observable solve range: renewals (difficulty 6) land
// in the millisecond buckets, admissions at the default difficulty 14 around
// 0.5-5s, and nothing past 60s exists to measure — the challenge window
// rejects it as stale first.
var solveBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// gateMetrics is the gate's registry and the handles its request path bumps.
// Everything here is counters over events the gate already distinguishes;
// nothing in this registry observes, stores, or labels anything per-visitor.
// The opt-in [activity] log is the one deliberate per-visitor surface, and it
// lives outside the metrics namespace on purpose: served only at the admin
// /activity endpoint, so the scrape surface stays IP-free.
type gateMetrics struct {
	registry *metrics.Registry
	// requests by ladder decision; the operational overview.
	requests *metrics.CounterVec
	// inFlight includes long-lived streams (SSE, WebSockets), so a steady
	// nonzero value under streaming workloads is correct, not a leak.
	inFlight  *metrics.Gauge
	issued    *metrics.CounterVec   // challenges handed out, by kind
	answers   *metrics.CounterVec   // answer submissions, by outcome
	solveTime *metrics.HistogramVec // issue-to-successful-answer, by kind
	minted    *metrics.CounterVec   // passes minted, by kind
	// paidValue counts each fresh settlement's value exactly once; grant
	// recovery re-mints a pass for money already counted and never adds here.
	paidValue   *metrics.Counter
	upstreamErr *metrics.Counter
	// Throughput, split by who authored the response body: the upstream (real
	// traffic) or the gate itself (challenge machinery, broadly construed).
	// bytesTotal is always the sum of the other two.
	challengeBytes *metrics.Counter
	upstreamBytes  *metrics.Counter
	bytesTotal     *metrics.Counter
}

func newGateMetrics() *gateMetrics {
	r := metrics.NewRegistry()
	return &gateMetrics{
		registry: r,
		requests: r.CounterVec("anteroom_http_requests_total",
			"Requests handled, by the ladder rung that answered (the same vocabulary as `anteroom -v` and the docs).",
			"decision", decisionLabels()...),
		inFlight: r.Gauge("anteroom_http_requests_in_flight",
			"Requests currently being handled, including long-lived streams."),
		issued: r.CounterVec("anteroom_challenges_issued_total",
			"Challenges handed out, by kind (admit = full difficulty, renew = cheap background renewal).",
			"kind", "admit", "renew"),
		answers: r.CounterVec("anteroom_challenge_answers_total",
			"Answer submissions, by outcome.",
			"outcome", "ok_admit", "ok_renew", "malformed", "stale", "bad_pow", "window_elapsed", "error"),
		solveTime: r.HistogramVec("anteroom_challenge_solve_duration_seconds",
			"Time from challenge issue to a successful answer. Includes network and page-load time, not just hashing; bounded by the 60s challenge window.",
			solveBuckets, "kind", "admit", "renew"),
		minted: r.CounterVec("anteroom_passes_minted_total",
			"Passes minted, by kind (pow = solved puzzle, paid = x402 settlement or durable recovery).",
			"kind", "pow", "paid"),
		paidValue: r.Counter("anteroom_payment_value_microdollars_total",
			"Settled x402 payment value, in millionths of the display currency (a $0.01 settlement adds 10000)."),
		upstreamErr: r.Counter("anteroom_upstream_errors_total",
			"Proxy round trips that failed to reach the upstream (served to the visitor as 502)."),
		challengeBytes: r.Counter("anteroom_challenge_bytes_total",
			"Response body bytes the gate authored itself: wait pages, the solver, challenge and payment negotiation, refusals, and error responses."),
		upstreamBytes: r.Counter("anteroom_upstream_bytes_total",
			"Response body bytes proxied from the upstream — the real traffic, served to admitted, bypassed, and preflight requests."),
		bytesTotal: r.Counter("anteroom_http_bytes_total",
			"Response body bytes served on the gate's listener, altogether; always the sum of the challenge and upstream byte counters. Headers and post-upgrade (WebSocket) traffic are not counted."),
	}
}

// countBytes attributes one finished request's response body to the side of
// the split that produced it, and to the grand total.
func (m *gateMetrics) countBytes(d decision, n uint64) {
	m.bytesTotal.Add(n)
	if d.upstream() {
		m.upstreamBytes.Add(n)
	} else {
		m.challengeBytes.Add(n)
	}
}

// Metrics exposes the gate's registry for the admin server. Read-only
// exposition; the counters themselves stay private to the gate.
func (g *Gate) Metrics() *metrics.Registry { return g.met.registry }
