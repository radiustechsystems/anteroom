package gate

import (
	"net/http"

	"github.com/radiustechsystems/anteroom/internal/activity"
)

// Activity exposes the challenge-activity log for the admin server, mirroring
// Metrics(). Nil when the [activity] section is unconfigured; the admin
// endpoint answers 404 for a nil log.
func (g *Gate) Activity() *activity.Log { return g.activity }

// recordDecision is the ladder-side activity hook, one call per request from
// ServeHTTP. Challenge-answer outcomes never reach it — they hide behind the
// "own-endpoint" decision and are recorded by noteAnswer instead.
func (g *Gate) recordDecision(d decision, r *gateRequest) {
	if g.activity == nil || !d.walled() {
		return
	}
	// An unresolvable client is skipped, not bucketed under a sentinel key
	// (contrast the payment limiter's fail-closed "unresolved-client"): the
	// limiter withholds a grant, but this log's consumer is a firewall, and a
	// sentinel entry is nothing it can act on. On a TCP listener the branch is
	// theoretical anyway — every real request has a parseable peer.
	if r.clientIP.IsValid() {
		g.activity.RecordFailure(r.clientIP.String())
	}
}

// noteAnswer records each challenge outcome in metrics and, when enabled, the
// activity log.
//
// "error" is deliberately in neither set — it is the gate failing to mint,
// not the client failing to solve, and a server fault must never edge an IP
// toward someone's ban threshold.
func (g *Gate) noteAnswer(outcome string, r *http.Request) {
	g.met.answers.With(outcome).Inc()
	if g.activity == nil {
		return
	}
	var record func(string)
	switch outcome {
	case "malformed", "stale", "bad_pow", "window_elapsed":
		record = g.activity.RecordFailure
	// Successes stay split by challenge kind: admissions and renewals mean
	// opposite things about the client (see activity.Entry), and collapsing
	// them is what made solve loops indistinguishable from idle browsers.
	case "ok_admit":
		record = g.activity.RecordAdmit
	case "ok_renew":
		record = g.activity.RecordRenew
	default:
		return
	}
	ip, err := g.match.ClientIP(r)
	if err != nil {
		return
	}
	record(ip.String())
}
