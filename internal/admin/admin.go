// Package admin serves metrics, health, and activity on the operator listener.
// Nothing here is proxied, gated, or reachable from the gate's port.
//
// There is no authentication; reachability is the access control, so the
// listener is disabled by default and should be bound to loopback.
package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/radiustechsystems/anteroom/internal/activity"
	"github.com/radiustechsystems/anteroom/internal/metrics"
)

// New builds the admin handler over the gate's registry and, when the
// [activity] section is configured, its challenge-activity log (nil otherwise).
func New(reg *metrics.Registry, act *activity.Log) http.Handler {
	metrics.RegisterRuntime(reg)
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler())
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		reg.WriteJSON(w)
	})
	mux.HandleFunc("GET /activity", func(w http.ResponseWriter, r *http.Request) {
		// 404-with-hint, not 200-with-empty: a polling tool pointed at a gate
		// whose operator forgot the section must fail loudly, and "disabled"
		// must never be confusable with "enabled but currently empty".
		if act == nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "activity log is not enabled; add an [activity] section to anteroom.toml", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		writeActivity(w, act)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})
	return mux
}

// activityResponse is the /activity JSON shape. Counts are cumulative since
// first_seen; the polling tool diffs between polls, the same contract the
// counters have with a scraper.
type activityResponse struct {
	// Window is the configured ttl: how long a quiet IP stays listed, and
	// therefore the ceiling on a sensible poll interval.
	Window      string          `json:"window"`
	GeneratedAt string          `json:"generated_at"`
	IPs         []activityEntry `json:"ips"`
}

type activityEntry struct {
	IP        string `json:"ip"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Failed    uint64 `json:"failed"`
	// Successes split by challenge kind, because they read oppositely:
	// renewals are the cheap background puzzle real browsers solve while a
	// tab sits open, admissions alongside failures and no site traffic are a
	// solve loop. See activity.Entry.
	SucceededAdmit uint64 `json:"succeeded_admit"`
	SucceededRenew uint64 `json:"succeeded_renew"`
}

func writeActivity(w http.ResponseWriter, act *activity.Log) {
	snap := act.Snapshot()
	resp := activityResponse{
		Window:      act.TTL().String(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		// Initialized non-nil so an empty log marshals as [], never null — a
		// consumer iterating the field must not need a null branch.
		IPs: make([]activityEntry, 0, len(snap)),
	}
	for _, e := range snap {
		resp.IPs = append(resp.IPs, activityEntry{
			IP:             e.IP,
			FirstSeen:      e.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:       e.LastSeen.UTC().Format(time.RFC3339),
			Failed:         e.Failed,
			SucceededAdmit: e.SucceededAdmit,
			SucceededRenew: e.SucceededRenew,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(resp)
}

const indexHTML = `<!doctype html>
<title>anteroom admin</title>
<h1>anteroom admin</h1>
<ul>
<li><a href="/metrics">/metrics</a> — Prometheus text exposition (point your scraper here)</li>
<li><a href="/stats">/stats</a> — the same counters as JSON</li>
<li><a href="/activity">/activity</a> — per-IP challenge activity for external ban tooling (404 unless <code>[activity]</code> is configured)</li>
<li><a href="/healthz">/healthz</a> — liveness</li>
</ul>
<p>Counters reset when the process restarts; scrapers detect that via
<code>process_start_time_seconds</code>. This surface is unauthenticated —
and with <code>[activity]</code> configured it includes visitor IP addresses —
keep it on loopback or a private interface.</p>
`
