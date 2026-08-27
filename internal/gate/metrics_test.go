package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/challenge"
	"github.com/radiustechsystems/anteroom/internal/payment"
)

// scrape renders the gate's metrics the way the admin server would.
func scrape(g *Gate) string {
	var sb strings.Builder
	g.Metrics().WritePrometheus(&sb)
	return sb.String()
}

// wantSample asserts one exact exposition line is present.
func wantSample(t *testing.T, g *Gate, line string) {
	t.Helper()
	if out := scrape(g); !strings.Contains(out, line+"\n") {
		t.Errorf("metrics lack %q:\n%s", line, out)
	}
}

// TestRequestsCountedByDecision pins the request counter to the ladder
// vocabulary — and, unlike the -v log, it must count with logging off, because
// a scraper is exactly the consumer that runs when nobody is watching.
func TestRequestsCountedByDecision(t *testing.T) {
	tests := []struct {
		name     string
		cfg      string
		request  func() *http.Request
		decision string
	}{
		{
			name:     "walled browser",
			request:  func() *http.Request { return browserReq("/page") },
			decision: "wait-page",
		},
		{
			name:     "refused agent",
			request:  func() *http.Request { return agentReq("/page") },
			decision: "refusal",
		},
		{
			name:     "own endpoint",
			request:  func() *http.Request { return httptest.NewRequest("GET", HealthPath, nil) },
			decision: "own-endpoint",
		},
		{
			name: "non-canonical path",
			request: func() *http.Request {
				r := agentReq("/a")
				r.URL.Path = "/.well-known/../admin"
				return r
			},
			decision: "non-canonical-path",
		},
		{
			name:     "bypassed path",
			cfg:      "[bypass]\npaths = [\"/robots.txt\"]\n",
			request:  func() *http.Request { return agentReq("/robots.txt") },
			decision: "bypass-path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := newTestGate(t, tt.cfg)
			do(g, tt.request())
			wantSample(t, g, `anteroom_http_requests_total{decision="`+tt.decision+`"} 1`)
		})
	}
}

func TestAdmittedRequestCounted(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	pass := solveAndGetCookie(t, g, nil)
	do(g, docReq("/page", pass))
	wantSample(t, g, `anteroom_http_requests_total{decision="pass-pow"} 1`)
}

// TestPayDecisionsCounted proves decisions returned through servePayment reach
// the same counter — the ladder has one counting point, not two.
func TestPayDecisionsCounted(t *testing.T) {
	g, _ := payGate(t, "[[payments.rules]]\nname = \"site\"\npaths = [\"/*\"]\nprice = \"$0.01\"\npaid_ttl = \"1h\"\n", nil)

	do(g, agentReq("/page")) // no signature: the machine-readable 402
	wantSample(t, g, `anteroom_http_requests_total{decision="payment-required"} 1`)

	acc := offered(g, t, "/page")
	r := agentReq("/page")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	if w := do(g, r); w.Code != http.StatusOK {
		t.Fatalf("payment did not serve: status %d body %s", w.Code, w.Body)
	}
	wantSample(t, g, `anteroom_http_requests_total{decision="pass-paid"} 1`)
	wantSample(t, g, `anteroom_passes_minted_total{kind="paid"} 1`)
}

// TestPaidValueCountedOncePerSettlement pins the value counter to money
// actually moving: a $0.01 settlement on a 6-decimal rail adds 10000
// micro-dollars, and a retry that recovers the durable grant — another pass,
// no second settlement — adds nothing.
func TestPaidValueCountedOncePerSettlement(t *testing.T) {
	g, _ := payGate(t, `[[payments.rules]]
name = "site"
paths = ["/*"]
price = "$0.01"
paid_ttl = "1h"
`, nil)

	acc := offered(g, t, "/page")
	hdr := present(t, acc, nil)
	first := agentReq("/page")
	first.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, first); w.Code != http.StatusOK {
		t.Fatalf("payment did not serve: status %d body %s", w.Code, w.Body)
	}
	wantSample(t, g, `anteroom_payment_value_microdollars_total 10000`)

	retry := agentReq("/page")
	retry.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, retry); w.Code != http.StatusOK {
		t.Fatalf("recovery retry did not serve: status %d body %s", w.Code, w.Body)
	}
	wantSample(t, g, `anteroom_passes_minted_total{kind="paid"} 2`)
	wantSample(t, g, `anteroom_payment_value_microdollars_total 10000`)
}

// issueAndSolve fetches a challenge and grinds out a valid nonce, leaving the
// answer unsent so the test controls the clock between issue and answer.
func issueAndSolve(t *testing.T, g *Gate) (challengeStr, nonce string) {
	t.Helper()
	cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	var ch challengeResponse
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		t.Fatalf("challenge JSON: %v", err)
	}
	th, err := hexTo32(ch.Threshold)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			return ch.Challenge, strconv.Itoa(n)
		}
	}
	t.Fatal("no PoW solution found")
	return "", ""
}

func postAnswer(g *Gate, challengeStr, nonce string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(answerRequest{Challenge: challengeStr, Nonce: nonce})
	r := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return do(g, r)
}

// TestSolveTimeObserved pins the histogram to the issue-to-answer interval the
// challenge itself carries: issue at base, answer two seconds later, and the
// observation must land in the le="2.5" bucket and not the le="1" one.
func TestSolveTimeObserved(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	// Truncated because the challenge carries its issue time at second
	// granularity: a fractional base would inflate the measured solve time by
	// the lost fraction and land it in the next bucket up.
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }
	c, nonce := issueAndSolve(t, g)

	g.now = func() time.Time { return base.Add(2 * time.Second) }
	if w := postAnswer(g, c, nonce); w.Code != 200 {
		t.Fatalf("answer: status %d body %s", w.Code, w.Body)
	}

	wantSample(t, g, `anteroom_challenges_issued_total{kind="admit"} 1`)
	wantSample(t, g, `anteroom_challenge_answers_total{outcome="ok_admit"} 1`)
	wantSample(t, g, `anteroom_passes_minted_total{kind="pow"} 1`)
	wantSample(t, g, `anteroom_challenge_solve_duration_seconds_bucket{kind="admit",le="1"} 0`)
	wantSample(t, g, `anteroom_challenge_solve_duration_seconds_bucket{kind="admit",le="2.5"} 1`)
	wantSample(t, g, `anteroom_challenge_solve_duration_seconds_count{kind="admit"} 1`)
}

func TestAnswerOutcomesCounted(t *testing.T) {
	t.Run("malformed body", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg)
		r := httptest.NewRequest("POST", pathAnswer, strings.NewReader("not json"))
		do(g, r)
		wantSample(t, g, `anteroom_challenge_answers_total{outcome="malformed"} 1`)
	})
	t.Run("stale challenge", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg)
		base := time.Now()
		g.now = func() time.Time { return base }
		c, nonce := issueAndSolve(t, g)
		// Far enough past issuance to be stale under any configured window.
		// challenge.Window is unexported now, and was the wrong number here
		// anyway: this gate's issuer measures freshness from pass_ttl.
		g.now = func() time.Time { return base.Add(24 * time.Hour) }
		postAnswer(g, c, nonce)
		wantSample(t, g, `anteroom_challenge_answers_total{outcome="stale"} 1`)
	})
	t.Run("bad pow", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg)
		cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
		var ch challengeResponse
		if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
			t.Fatal(err)
		}
		th, err := hexTo32(ch.Threshold)
		if err != nil {
			t.Fatal(err)
		}
		// A nonce PROVEN to fail, not assumed: at test difficulty a guessed one
		// passes often enough to flake.
		bad := ""
		for n := 0; n < 1_000_000; n++ {
			if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) != nil {
				bad = strconv.Itoa(n)
				break
			}
		}
		postAnswer(g, ch.Challenge, bad)
		wantSample(t, g, `anteroom_challenge_answers_total{outcome="bad_pow"} 1`)
	})
	t.Run("pass window elapsed", func(t *testing.T) {
		g, _ := newTestGate(t, fastCfg) // pass_ttl = 10s
		base := time.Now().Truncate(time.Second)
		g.now = func() time.Time { return base }
		c, nonce := issueAndSolve(t, g)
		// The issuer's freshness window IS pass_ttl, so the zero-remaining
		// branch is only reachable at exactly the boundary: one second later
		// the same answer is refused as stale instead.
		g.now = func() time.Time { return base.Add(10 * time.Second) }
		postAnswer(g, c, nonce)
		wantSample(t, g, `anteroom_challenge_answers_total{outcome="window_elapsed"} 1`)
	})
}

// TestThroughputCounted pins the byte counters to the two sides of the split:
// a wait page is challenge bytes, a bypassed fetch is upstream bytes, and the
// total is always their sum. Like every counter, they must count with logging
// off — a scraper is exactly the consumer that runs when nobody is watching.
func TestThroughputCounted(t *testing.T) {
	g, _ := newTestGate(t, "[bypass]\npaths = [\"/robots.txt\"]\n")

	walled := do(g, browserReq("/page"))
	challengeBytes := walled.Body.Len()
	if challengeBytes == 0 {
		t.Fatal("wait page served no bytes; the test would prove nothing")
	}
	wantSample(t, g, fmt.Sprintf("anteroom_challenge_bytes_total %d", challengeBytes))
	wantSample(t, g, "anteroom_upstream_bytes_total 0")
	wantSample(t, g, fmt.Sprintf("anteroom_http_bytes_total %d", challengeBytes))

	open := do(g, agentReq("/robots.txt"))
	upstreamBytes := open.Body.Len()
	if upstreamBytes == 0 {
		t.Fatal("bypassed request served no bytes; the test would prove nothing")
	}
	wantSample(t, g, fmt.Sprintf("anteroom_challenge_bytes_total %d", challengeBytes))
	wantSample(t, g, fmt.Sprintf("anteroom_upstream_bytes_total %d", upstreamBytes))
	wantSample(t, g, fmt.Sprintf("anteroom_http_bytes_total %d", challengeBytes+upstreamBytes))
}

// TestAdmittedThroughputIsUpstream proves a PoW admission's response counts as
// real traffic, not challenge activity — the solve that earned the pass was
// challenge bytes, the page it unlocks is not.
func TestAdmittedThroughputIsUpstream(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	pass := solveAndGetCookie(t, g, nil)
	w := do(g, docReq("/page", pass))
	wantSample(t, g, fmt.Sprintf("anteroom_upstream_bytes_total %d", w.Body.Len()))
}

func TestUpstreamErrorsCounted(t *testing.T) {
	g, up := newTestGate(t, "[bypass]\npaths = [\"/open\"]\n")
	up.Close() // the gate now fronts a dead upstream
	if w := do(g, agentReq("/open")); w.Code != http.StatusBadGateway {
		t.Fatalf("dead upstream served status %d", w.Code)
	}
	wantSample(t, g, "anteroom_upstream_errors_total 1")
}

func TestInFlightReturnsToZero(t *testing.T) {
	g, _ := newTestGate(t, "")
	do(g, browserReq("/a"))
	do(g, agentReq("/b"))
	wantSample(t, g, "anteroom_http_requests_in_flight 0")
}
