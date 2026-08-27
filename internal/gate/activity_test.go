package gate

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/activity"
	"github.com/radiustechsystems/anteroom/internal/challenge"
)

const activityCfg = "[activity]\nttl = \"10m\"\n"

// findEntry returns the log entry for ip, failing the test if absent.
func findEntry(t *testing.T, g *Gate, ip string) activity.Entry {
	t.Helper()
	for _, e := range g.Activity().Snapshot() {
		if e.IP == ip {
			return e
		}
	}
	t.Fatalf("no activity entry for %s; have %v", ip, g.Activity().Snapshot())
	return activity.Entry{}
}

// TestWalledRequestsRecorded pins the ladder-side hook: each walled decision
// is one failure against the client's IP, and like every observability
// surface it must record with logging off.
func TestWalledRequestsRecorded(t *testing.T) {
	t.Run("wait page", func(t *testing.T) {
		g, _ := newTestGate(t, activityCfg)
		do(g, browserReq("/page"))
		if e := findEntry(t, g, "192.0.2.10"); e.Failed != 1 || e.SucceededAdmit != 0 || e.SucceededRenew != 0 {
			t.Errorf("failed=%d admit=%d renew=%d want 1/0/0", e.Failed, e.SucceededAdmit, e.SucceededRenew)
		}
	})
	t.Run("refusal", func(t *testing.T) {
		g, _ := newTestGate(t, activityCfg)
		do(g, agentReq("/page"))
		do(g, agentReq("/page"))
		if e := findEntry(t, g, "192.0.2.10"); e.Failed != 2 {
			t.Errorf("failed=%d want 2", e.Failed)
		}
	})
	t.Run("payment required", func(t *testing.T) {
		g, _ := payGate(t, "[[payments.rules]]\nname = \"site\"\npaths = [\"/*\"]\nprice = \"$0.01\"\npaid_ttl = \"1h\"\n\n"+activityCfg, nil)
		do(g, agentReq("/page")) // no PAYMENT-SIGNATURE: the machine-readable 402
		if e := findEntry(t, g, "192.0.2.10"); e.Failed != 1 {
			t.Errorf("failed=%d want 1", e.Failed)
		}
	})
}

// TestAnswerOutcomesRecorded pins the answer-side hook via the real challenge
// API. httptest.NewRequest's default peer is 192.0.2.1.
func TestAnswerOutcomesRecorded(t *testing.T) {
	t.Run("malformed body is a failure", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		r := httptest.NewRequest("POST", pathAnswer, strings.NewReader("not json"))
		do(g, r)
		if e := findEntry(t, g, "192.0.2.1"); e.Failed != 1 || e.SucceededAdmit != 0 || e.SucceededRenew != 0 {
			t.Errorf("failed=%d admit=%d renew=%d want 1/0/0", e.Failed, e.SucceededAdmit, e.SucceededRenew)
		}
	})
	t.Run("stale answer is a failure", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		base := time.Now()
		g.now = func() time.Time { return base }
		c, nonce := issueAndSolve(t, g)
		g.now = func() time.Time { return base.Add(24 * time.Hour) }
		postAnswer(g, c, nonce)
		if e := findEntry(t, g, "192.0.2.1"); e.Failed != 1 {
			t.Errorf("failed=%d want 1", e.Failed)
		}
	})
	t.Run("bad pow is a failure", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
		var ch challengeResponse
		if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
			t.Fatal(err)
		}
		th, err := hexTo32(ch.Threshold)
		if err != nil {
			t.Fatal(err)
		}
		// A nonce PROVEN to fail, exactly as in TestAnswerOutcomesCounted.
		bad := ""
		for n := 0; n < 1_000_000; n++ {
			if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) != nil {
				bad = strconv.Itoa(n)
				break
			}
		}
		postAnswer(g, ch.Challenge, bad)
		if e := findEntry(t, g, "192.0.2.1"); e.Failed != 1 {
			t.Errorf("failed=%d want 1", e.Failed)
		}
	})
	t.Run("admission solve counts as admit", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		solveAndGetCookie(t, g, nil)
		if e := findEntry(t, g, "192.0.2.1"); e.SucceededAdmit != 1 || e.SucceededRenew != 0 || e.Failed != 0 {
			t.Errorf("failed=%d admit=%d renew=%d want 0/1/0", e.Failed, e.SucceededAdmit, e.SucceededRenew)
		}
	})
	t.Run("renewal solve counts as renew", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		pass := solveAndGetCookie(t, g, nil)
		// A second round holding the live pass is issued the cheap renew
		// profile and lands as ok_renew — the idle-open-tab signature the
		// split exists to expose.
		solveAndGetCookie(t, g, pass)
		if e := findEntry(t, g, "192.0.2.1"); e.SucceededAdmit != 1 || e.SucceededRenew != 1 || e.Failed != 0 {
			t.Errorf("failed=%d admit=%d renew=%d want 0/1/1", e.Failed, e.SucceededAdmit, e.SucceededRenew)
		}
	})
}

// TestAdmittedAndBypassedNeverRecorded pins the boundary that makes the log a
// challenge log rather than visitor tracking: traffic the ladder admits —
// by pass or by bypass — leaves it untouched.
func TestAdmittedAndBypassedNeverRecorded(t *testing.T) {
	t.Run("pass-holding request", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg+activityCfg)
		pass := solveAndGetCookie(t, g, nil) // records the one success
		do(g, docReq("/page", pass))
		snap := g.Activity().Snapshot()
		if len(snap) != 1 || snap[0].Failed != 0 || snap[0].SucceededAdmit != 1 || snap[0].SucceededRenew != 0 {
			t.Errorf("admitted request changed the log: %v", snap)
		}
	})
	t.Run("bypass CIDR", func(t *testing.T) {
		g, _ := newTestGate(t, "[bypass]\ncidrs = [\"192.0.2.10/32\"]\n"+activityCfg)
		do(g, agentReq("/anything"))
		if snap := g.Activity().Snapshot(); len(snap) != 0 {
			t.Errorf("bypassed request was recorded: %v", snap)
		}
	})
}

// TestActivityDisabled: without the [activity] section the gate carries no
// log, records nothing, and exposes no tracked_ips family — the default
// deployment stays completely free of per-visitor state.
func TestActivityDisabled(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	if g.Activity() != nil {
		t.Fatal("Activity() should be nil without [activity]")
	}
	do(g, browserReq("/page"))
	do(g, agentReq("/page"))
	solveAndGetCookie(t, g, nil)
	if g.Activity().Snapshot() != nil {
		t.Error("nil log grew entries")
	}
	if out := scrape(g); strings.Contains(out, "anteroom_tracked_ips") {
		t.Errorf("anteroom_tracked_ips exposed with the feature off:\n%s", out)
	}
}

func TestTrackedIPsGauge(t *testing.T) {
	g, _ := newTestGate(t, activityCfg)
	do(g, browserReq("/page"))
	wantSample(t, g, "anteroom_tracked_ips 1")
}
