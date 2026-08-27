package gate

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/payment"
)

// What a visitor experiences when the facilitator is slow, flaky, or gone.
//
// The question these answer is not "does the gate cope" in the abstract but
// "does a person or an agent get a result they can act on". A payment path that
// technically fails closed while emitting a 503, or a browser that waits ten
// seconds for a puzzle it did not need a facilitator for, is a correct gate and
// a broken site.

// faultyFacilitator serves whatever the test tells it to, and counts calls.
type faultyFacilitator struct {
	handler atomic.Value // func(endpoint string, w http.ResponseWriter, r *http.Request)
	calls   atomic.Int64
}

func (f *faultyFacilitator) set(h func(string, http.ResponseWriter, *http.Request)) {
	f.handler.Store(h)
}

func (f *faultyFacilitator) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ep := r.URL.Path
		f.calls.Add(1)
		if h, ok := f.handler.Load().(func(string, http.ResponseWriter, *http.Request)); ok && h != nil {
			h(ep, w, r)
			return
		}
		if strings.HasSuffix(ep, "/verify") {
			json.NewEncoder(w).Encode(payment.VerifyResponse{IsValid: true, Payer: "0xpayer"})
			return
		}
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// resilientGate wires a gate to a faulty facilitator.
func resilientGate(t *testing.T, f *faultyFacilitator) *Gate {
	t.Helper()
	fac := f.start(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	body := "upstream = \"" + up.URL + "\"\ndifficulty = 6\n\n" +
		"[payments]\npay_to = \"0x000000000000000000000000000000000000dEaD\"\n" +
		"facilitator = \"" + fac.URL + "\"\nmax_timeout_seconds = 300\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:72344\"\nasset = \"0xasset\"\ndecimals = 6\n" +
		"asset_name = \"T\"\nasset_version = \"1\"\nasset_transfer_method = \"permit2\"\n\n" +
		oneRule

	path := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// hangUntilCancelled stands in for a facilitator that accepts the connection and
// never answers — the worst case, because it consumes the full budget.
func hangUntilCancelled(_ string, w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(3 * time.Second):
	}
}

// TestFreePathIsUnaffectedByAFacilitatorOutage is invariant 2, and the single
// most important resilience property: a person who was never going to pay must
// not wait on, or be refused by, a payment dependency.
func TestFreePathIsUnaffectedByAFacilitatorOutage(t *testing.T) {
	f := &faultyFacilitator{}
	f.set(hangUntilCancelled)
	g := resilientGate(t, f)

	before := f.calls.Load()
	start := time.Now()

	// A browser arriving cold gets the wait page.
	w := do(g, browserReq("/"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "anteroom-status") {
		t.Fatalf("browser did not get the wait page: status %d", w.Code)
	}
	// And can solve it, and be admitted, with the facilitator hung throughout.
	cookie := solveAndGetCookie(t, g, nil)
	r := browserReq("/")
	r.AddCookie(cookie)
	if w := do(g, r); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("solved visitor not admitted during a facilitator outage: %d", w.Code)
	}

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the free path took %s with the facilitator hung; it must not wait on one", elapsed)
	}
	if f.calls.Load() != before {
		t.Errorf("the free path made %d facilitator calls; it must make none",
			f.calls.Load()-before)
	}
}

// TestAnExistingPaidPassSurvivesAnOutage. Someone who already paid holds a
// signed cookie the gate validates locally, so an outage cannot revoke access
// they have already bought.
func TestAnExistingPaidPassSurvivesAnOutage(t *testing.T) {
	f := &faultyFacilitator{}
	g := resilientGate(t, f)

	acc := offered(g, t, "/")
	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	w := do(g, r)
	if w.Code != http.StatusOK {
		t.Fatalf("initial payment failed: %d", w.Code)
	}
	var pass *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no paid pass")
	}

	// Now the facilitator dies.
	f.set(hangUntilCancelled)
	before := f.calls.Load()

	r2 := agentReq("/")
	r2.AddCookie(pass)
	start := time.Now()
	w2 := do(g, r2)

	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "UPSTREAM:") {
		t.Errorf("a paid visitor was refused during an outage: %d", w2.Code)
	}
	if time.Since(start) > time.Second {
		t.Error("a held paid pass waited on the facilitator")
	}
	if f.calls.Load() != before {
		t.Error("validating a held pass called the facilitator")
	}
}

// TestPaymentPathNever503s. A 503 claims the site is down, which is false — the
// free door works. An agent that sees 503 backs off or gives up; an agent that
// sees 402 with requirements can act.
func TestPaymentPathNever503s(t *testing.T) {
	faults := map[string]func(string, http.ResponseWriter, *http.Request){
		"hang": hangUntilCancelled,
		"500": func(_ string, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"429": func(_ string, w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		},
		"garbage": func(_ string, w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "definitely not json")
		},
		"redirect": func(_ string, w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example/verify", http.StatusPermanentRedirect)
		},
		"settle success without tx": func(ep string, w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(ep, "/verify") {
				json.NewEncoder(w).Encode(payment.VerifyResponse{IsValid: true})
				return
			}
			json.NewEncoder(w).Encode(payment.SettleResponse{Success: true})
		},
		"reject": func(ep string, w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(payment.VerifyResponse{
				IsValid: false, InvalidReason: "insufficient_funds"})
		},
	}

	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			f := &faultyFacilitator{}
			g := resilientGate(t, f)
			acc := offered(g, t, "/")
			f.set(fault)

			r := agentReq("/")
			r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
			w := do(g, r)

			if w.Code == http.StatusServiceUnavailable {
				t.Fatal("the payment path emitted 503; the free door still works, so that is a lie")
			}
			if w.Code != http.StatusPaymentRequired {
				t.Errorf("status %d, want 402", w.Code)
			}
			// Every 402 must carry the offer, or a client cannot retry.
			if w.Header().Get(payment.HeaderRequired) == "" {
				t.Error("no PAYMENT-REQUIRED header — a bare 402 is a bug")
			}
			// And it must say something actionable, which is a property of the
			// content and not of its length. A hundred bytes of anything
			// satisfied the old check, including a hundred bytes of apology.
			// What a client refused by a broken facilitator actually needs is
			// the free door, which is the whole point of there being two ways in.
			body := w.Body.String()
			for _, want := range []string{pathChallenge, pathAnswer} {
				if !strings.Contains(body, want) {
					t.Errorf("the 402 body never mentions %s, so a client refused by "+
						"a broken facilitator is not told the free door exists: %s", want, body)
				}
			}
		})
	}
}

// TestRetryAfterIsHonestAboutTheBreaker.
//
// twoFacResilientGate wires rail A (eip155:72344) to facA via the global key
// and rail B (eip155:8453) to facB per-rail — the resilience twin of
// payGateTwoFacilitators, taking raw URLs so a test can hand it a faulty
// facilitator.
func twoFacResilientGate(t *testing.T, facAURL, facBURL string) *Gate {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	body := "upstream = \"" + up.URL + "\"\ndifficulty = 6\n\n" +
		"[payments]\npay_to = \"0x000000000000000000000000000000000000dEaD\"\n" +
		"facilitator = \"" + facAURL + "\"\nmax_timeout_seconds = 300\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:72344\"\nasset = \"0xasset\"\ndecimals = 6\n" +
		"asset_name = \"T\"\nasset_version = \"1\"\nasset_transfer_method = \"permit2\"\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:8453\"\nasset = \"0xusdc\"\ndecimals = 6\n" +
		"asset_name = \"USD Coin\"\nasset_version = \"2\"\nasset_transfer_method = \"eip3009\"\n" +
		"facilitator = \"" + facBURL + "\"\n\n" +
		oneRule

	path := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// TestBreakerIsolationBetweenFacilitators is what the per-rail split buys at
// failure time: one facilitator plainly down must degrade only its own rails.
// Before the split, a Base outage opened the one breaker and took Radius
// payments down with it.
func TestBreakerIsolationBetweenFacilitators(t *testing.T) {
	facA := &faultyFacilitator{}
	facA.set(func(_ string, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	facB := newFacFake(t, "eip155:8453")
	g := twoFacResilientGate(t, facA.start(t).URL, facB.srv.URL)

	// Trip A's breaker: transport-class failures on distinct payments.
	accA := offeredNet(g, t, "/", "eip155:72344")
	for i := range 4 {
		r := agentReq("/")
		r.Header.Set(payment.HeaderSignature, presentSigned(t, accA, "0xsigA"+strconv.Itoa(i)))
		do(g, r)
	}
	aCallsWhenOpen := facA.calls.Load()

	// (a) Rail B still settles, through its own breaker.
	accB := offeredNet(g, t, "/", "eip155:8453")
	rb := agentReq("/")
	rb.Header.Set(payment.HeaderSignature, presentSigned(t, accB, "0xsigB"))
	if w := do(g, rb); !strings.Contains(w.Body.String(), "UPSTREAM:/") {
		t.Fatalf("rail B walled while only facA is down: %d %s", w.Code, w.Body.String())
	}
	if facB.settleN.Load() != 1 {
		t.Errorf("facB settle = %d, want 1", facB.settleN.Load())
	}

	// (b) A further rail-A presentation is refused from the open breaker with
	// zero new egress to facA.
	ra := agentReq("/")
	ra.Header.Set(payment.HeaderSignature, presentSigned(t, accA, "0xsigA-late"))
	w := do(g, ra)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("open-breaker answer = %d, want 402", w.Code)
	}
	if got := facA.calls.Load(); got != aCallsWhenOpen {
		t.Errorf("facA was called %d more time(s) while its breaker was open", got-aCallsWhenOpen)
	}

	// (c) The free path never noticed any of it.
	bw := do(g, browserReq("/"))
	if bw.Code != http.StatusOK || !strings.Contains(bw.Body.String(), "anteroom-status") {
		t.Fatalf("free path degraded during a facilitator outage: %d", bw.Code)
	}
	if got := facA.calls.Load(); got != aCallsWhenOpen {
		t.Errorf("free path produced facilitator egress: %d extra calls", got-aCallsWhenOpen)
	}
}

// TestStartupMakesNoFacilitatorCalls ensures constructing a payment-enabled
// gate does not turn process startup into facilitator-controlled egress.
func TestStartupMakesNoFacilitatorCalls(t *testing.T) {
	facA := newFacFake(t, "eip155:72344")
	facB := newFacFake(t, "eip155:8453")
	_ = twoFacResilientGate(t, facA.srv.URL, facB.srv.URL)

	if got := facA.calls.Load(); got != 0 {
		t.Errorf("facilitator A received %d startup calls", got)
	}
	if got := facB.calls.Load(); got != 0 {
		t.Errorf("facilitator B received %d startup calls", got)
	}
}

// When the breaker is open the gate knows exactly how long it will refuse to
// try, so telling a client to come back sooner than that guarantees a wasted
// round trip — and every wasted retry from every client lands at once when the
// cooldown ends.
func TestRetryAfterIsHonestAboutTheBreaker(t *testing.T) {
	f := &faultyFacilitator{}
	f.set(func(_ string, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	g := resilientGate(t, f)
	acc := offered(g, t, "/")

	// Trip the breaker: three transport-class failures.
	var last *httptest.ResponseRecorder
	for i := range 4 {
		r := agentReq("/")
		// A distinct PAYMENT each time, so dedup does not refuse them first —
		// which means a distinct signature. Salting an unsigned envelope field
		// would produce one payment in four wrappers, and the gate identifies a
		// payment by its authorization.
		a := map[string]any{}
		for k, v := range acc {
			a[k] = v
		}
		r.Header.Set(payment.HeaderSignature, presentSigned(t, a, "0xsig"+strconv.Itoa(i)))
		last = do(g, r)
	}

	ra := last.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("no Retry-After while the breaker is open")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After %q is not a number of seconds", ra)
	}
	// Read against the cooldown the gate actually built the breaker with, not a
	// number typed beside it. The old bound was 20s against a 30s cooldown, which
	// accepted exactly the answer this test exists to reject: a gate promising
	// the door reopens ten seconds before it does. One second of slack covers the
	// time the test itself spent tripping the breaker.
	if want := int(breakerCooldown.Seconds()) - 1; secs < want {
		t.Errorf("Retry-After is %ds while the breaker holds egress shut for %s; "+
			"clients will retry into a closed door and pile up when it opens",
			secs, breakerCooldown)
	}
}

// TestSlowFacilitatorDoesNotHoldTheRequestOpenForever. A client that gives up
// before the gate does gets nothing useful, so the gate must answer inside a
// budget an agent would plausibly wait out.
func TestSlowFacilitatorAnswersWithinBudget(t *testing.T) {
	f := &faultyFacilitator{}
	f.set(hangUntilCancelled)
	g := resilientGate(t, f)
	acc := offered(g, t, "/")

	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	start := time.Now()
	w := do(g, r)
	elapsed := time.Since(start)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402", w.Code)
	}
	// verify budget is 2s and it is the first call, so this should be ~2s.
	if elapsed > 5*time.Second {
		t.Errorf("took %s to answer with the facilitator hung", elapsed)
	}
}

// TestConcurrentPaymentsDuringAnOutageAreBounded.
//
// Every in-flight presentation holds a goroutine and a connection for the whole
// paid-path budget. Under facilitator slowness those pile up, and the per-client
// rate limit does not help against many clients.
//
// What this asserts is the end-to-end consequence: with the facilitator hung,
// forty concurrent clients each get an answer, and the gate does not open one
// facilitator call per client. The exact ceiling is asserted in the package that
// sets it (payment.TestEgressCapBoundsConcurrentFacilitatorCalls), where the
// shed presentations are visible as verdicts rather than only as an absence.
// Naming the cap from here meant exporting it, which said "another package owns
// this bound" about a number that is this verifier's own.
func TestConcurrentPaymentsDuringAnOutageAreBounded(t *testing.T) {
	f := &faultyFacilitator{}
	var inFlight, peak atomic.Int64
	f.set(func(_ string, w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inFlight.Add(-1)
		hangUntilCancelled("", w, r)
	})
	g := resilientGate(t, f)
	acc := offered(g, t, "/")

	const clients = 40
	codes := make([]int, clients)
	done := make(chan struct{}, clients)
	for i := range clients {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			r := agentReq("/")
			r.RemoteAddr = "192.0.2." + strconv.Itoa(i%250) + ":1234" // distinct clients
			a := map[string]any{}
			for k, v := range acc {
				a[k] = v
			}
			// Distinct signatures, so these are forty payments from forty
			// clients rather than one payment presented forty times — otherwise
			// dedup answers thirty-nine of them and the egress cap is never
			// exercised at all.
			r.Header.Set(payment.HeaderSignature, presentSigned(t, a, "0xsig"+strconv.Itoa(i)))
			codes[i] = do(g, r).Code
		}(i)
	}
	for range clients {
		<-done
	}

	t.Logf("peak concurrent facilitator calls: %d (from %d clients)", peak.Load(), clients)
	for i, code := range codes {
		if code != http.StatusPaymentRequired {
			t.Errorf("client %d got status %d, want 402: a presentation the gate sheds "+
				"must still be answered, and the free path must be unaffected", i, code)
		}
	}
	// Egress did not scale with clients. This is the weak half of the bound on
	// purpose — the ceiling itself is asserted in package payment — but it is
	// the half that is about the GATE: forty presentations must not become forty
	// held facilitator calls.
	if peak.Load() >= clients {
		t.Errorf("%d concurrent facilitator calls from %d clients: the gate queued "+
			"rather than shedding, so a slow facilitator is unbounded in-flight work",
			peak.Load(), clients)
	}
	// And the other side, or a verifier that serialised every call would pass:
	// the cap has to be a ceiling, not the throughput.
	if peak.Load() < 2 {
		t.Errorf("peak concurrency %d from %d clients: nothing ran in parallel, "+
			"so this test is not measuring a cap", peak.Load(), clients)
	}
}
