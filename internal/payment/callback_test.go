package payment

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// facilitator is a scriptable stand-in. Every failure mode in
// The verifier's timing policy is injectable here.
type facilitator struct {
	verify  func(w http.ResponseWriter, r *http.Request)
	settle  func(w http.ResponseWriter, r *http.Request)
	verifyN atomic.Int32
	settleN atomic.Int32
}

func (f *facilitator) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		f.verifyN.Add(1)
		if f.verify != nil {
			f.verify(w, r)
			return
		}
		json.NewEncoder(w).Encode(VerifyResponse{IsValid: true, Payer: "0xpayer"})
	})
	mux.HandleFunc("/settle", func(w http.ResponseWriter, r *http.Request) {
		f.settleN.Add(1)
		if f.settle != nil {
			f.settle(w, r)
			return
		}
		json.NewEncoder(w).Encode(SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx",
			Network: "eip155:72344", Amount: "10000"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newVerifier builds a verifier with test-sized budgets.
func newVerifier(t *testing.T, base string, b *Breaker) *CallbackVerifier {
	t.Helper()
	v := NewCallbackVerifier(base, nil, quiet(), b)
	v.shrinkBudgets(200*time.Millisecond, 400*time.Millisecond, time.Second)
	return v
}

// newVerifierWithHeaders is newVerifier for the auth path.
func newVerifierWithHeaders(t *testing.T, base string, h http.Header) *CallbackVerifier {
	t.Helper()
	v := NewCallbackVerifier(base, h, quiet(), nil)
	v.shrinkBudgets(200*time.Millisecond, 400*time.Millisecond, time.Second)
	return v
}

func verifyWith(t *testing.T, f *facilitator) Result {
	t.Helper()
	srv := f.start(t)
	p, _ := payload(t, "eip155:72344", "exact")
	return newVerifier(t, srv.URL, nil).Verify(context.Background(), p, reqs())
}

// hang blocks until the client gives up, with a hard backstop: a handler that
// waits only on the request context can outlive the test if the disconnect is
// not observed, and httptest.Server.Close then blocks forever.
func hang(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

// TestHappyPathServes is the only outcome that serves anything.
func TestHappyPathServes(t *testing.T) {
	res := verifyWith(t, &facilitator{})
	if res.Verdict != Valid {
		t.Fatalf("verdict %v, want Valid (%v)", res.Verdict, res.Err)
	}
	if res.Tx != "0xtx" || res.Payer != "0xpayer" {
		t.Errorf("result = %+v", res)
	}
}

// TestSettleTimeoutDoesNotServe — ambiguity serves nothing.
func TestSettleTimeoutDoesNotServe(t *testing.T) {
	f := &facilitator{settle: hang}
	res := verifyWith(t, f)
	if res.Verdict != Ambiguous {
		t.Fatalf("verdict %v, want Ambiguous", res.Verdict)
	}
	if !strings.Contains(res.Reason, "may have been charged") {
		t.Errorf("reason does not warn the payer they may have been charged: %q", res.Reason)
	}
}

// TestSettleSuccessWithoutTxHashIsAmbiguous — a settlement claim with no
// evidence must never mint a pass that embeds a transaction.
func TestSettleSuccessWithoutTxHashIsAmbiguous(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SettleResponse{Success: true, Payer: "0xpayer"})
	}}
	res := verifyWith(t, f)
	if res.Verdict != Ambiguous {
		t.Fatalf("verdict %v, want Ambiguous — success without a tx hash is not evidence", res.Verdict)
	}
}

// TestSettlementOnAnotherNetworkIsNotSuccess. A settlement on a chain the gate
// did not price is not the payment the gate asked for, whatever `success` says.
// Ambiguous rather than invalid: something may have moved on that other chain,
// so the operator needs a loud signal and the payer must not simply be told to
// sign again.
func TestSettlementOnAnotherNetworkIsNotSuccess(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:8453"})
	}}
	if res := verifyWith(t, f); res.Verdict != Ambiguous {
		t.Fatalf("verdict %v, want Ambiguous — settled on eip155:8453, priced on eip155:72344",
			res.Verdict)
	}
}

// TestAnOmittedAmountIsNotInvented. Amount is optional in x402 v2, so an absent
// value remains absent rather than being replaced with the requested amount.
func TestAnOmittedAmountIsNotInvented(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	}}
	res := verifyWith(t, f)
	if res.Verdict != Valid {
		t.Fatalf("verdict %v, want Valid", res.Verdict)
	}
	if res.Amount != "" {
		t.Fatalf("amount = %q, want absent", res.Amount)
	}
}

func TestContradictorySettlementEvidenceIsNotSuccess(t *testing.T) {
	for _, tc := range []struct {
		name   string
		settle SettleResponse
	}{
		{"missing network", SettleResponse{Success: true, Payer: "0xpayer", Transaction: "0xtx"}},
		{"wrong amount", SettleResponse{Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344", Amount: "9999"}},
		{"wrong payer", SettleResponse{Success: true, Payer: "0xother", Transaction: "0xtx", Network: "eip155:72344", Amount: "10000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(tc.settle)
			}}
			if got := verifyWith(t, f); got.Verdict != Ambiguous {
				t.Fatalf("verdict = %v, want Ambiguous", got.Verdict)
			}
		})
	}
}

// TestSettlementPendingIsNotARejection. `settlement_pending` is the one
// success:false the specification marks non-terminal: the transfer was
// broadcast and only its confirmation is unknown, which is why the transaction
// and network are required to come with it. Classifying it as Invalid discards
// that evidence and tells the payer to sign again for a transfer that may
// already be confirming.
func TestSettlementPendingIsNotARejection(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SettleResponse{
			Success: false, ErrorReason: ErrorSettlementPending,
			Transaction: "0xpending", Network: "eip155:72344", Payer: "0xpayer"})
	}}
	res := verifyWith(t, f)
	if res.Verdict != Pending {
		t.Fatalf("verdict %v, want Pending", res.Verdict)
	}
	if res.Tx != "0xpending" || res.Network != "eip155:72344" {
		t.Errorf("tx=%q network=%q — the payer cannot reconcile without both", res.Tx, res.Network)
	}
	if res.RetryAfter <= 0 {
		t.Error("no retry advice on a non-terminal outcome")
	}
}

// A facilitator that says pending without saying what it broadcast leaves
// nothing to reconcile against. That is the ambiguous case, not a licence to
// invent a transaction.
func TestSettlementPendingWithoutATransactionIsAmbiguous(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SettleResponse{
			Success: false, ErrorReason: ErrorSettlementPending, Network: "eip155:72344"})
	}}
	if res := verifyWith(t, f); res.Verdict != Ambiguous {
		t.Fatalf("verdict %v, want Ambiguous", res.Verdict)
	}
}

// TestDefinitiveRejectionIsInvalidNotIndeterminate. The distinction decides
// whether the client is told to sign a fresh payment or to retry the same one.
func TestDefinitiveRejectionIsInvalidNotIndeterminate(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *facilitator
	}{
		{"verify says invalid", &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(VerifyResponse{IsValid: false, InvalidReason: "insufficient_funds"})
		}}},
		{"settle says failed", &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(SettleResponse{Success: false, ErrorReason: "transfer_reverted"})
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := verifyWith(t, tc.f)
			if res.Verdict != Invalid {
				t.Fatalf("verdict %v, want Invalid", res.Verdict)
			}
			if res.Reason == "" {
				t.Error("the facilitator's reason was not relayed")
			}
		})
	}
}

// TestVerifyFailurePreSettleIsIndeterminate. Nothing left the gate for
// settlement, so the payer's exposure is zero and the payment stays retryable.
func TestVerifyFailurePreSettleIsIndeterminate(t *testing.T) {
	f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}}
	srv := f.start(t)
	p, _ := payload(t, "eip155:72344", "exact")
	res := newVerifier(t, srv.URL, nil).Verify(context.Background(), p, reqs())

	if res.Verdict != Indeterminate {
		t.Fatalf("verdict %v, want Indeterminate", res.Verdict)
	}
	if f.settleN.Load() != 0 {
		t.Error("settle was called after verify failed")
	}
	if !strings.Contains(res.Reason, "not charged") {
		t.Errorf("reason should reassure the payer they were not charged: %q", res.Reason)
	}
}

// TestSettleIsNeverRetried. A retry after the bytes left is a second settlement
// request for the same authorization.
func TestSettleIsNeverRetried(t *testing.T) {
	f := &facilitator{settle: func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}}
	srv := f.start(t)
	p, _ := payload(t, "eip155:72344", "exact")
	res := newVerifier(t, srv.URL, nil).Verify(context.Background(), p, reqs())

	if res.Verdict != Ambiguous {
		t.Errorf("verdict %v, want Ambiguous", res.Verdict)
	}
	if n := f.settleN.Load(); n != 1 {
		t.Errorf("settle called %d times, want exactly 1", n)
	}
}

func TestNonceUsedVerifyRejectionDoesNotSettle(t *testing.T) {
	f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(VerifyResponse{
			IsValid: false, InvalidReason: "nonce already used"})
	}}
	res := verifyWith(t, f)

	if f.settleN.Load() != 0 {
		t.Fatalf("settle called %d times after verify rejected", f.settleN.Load())
	}
	if res.Verdict != Invalid {
		t.Errorf("verdict %v, want Invalid", res.Verdict)
	}
}

// TestRedirectIsInfraErrorNotFollowed. A 3xx on a POST re-targets the trust
// anchor and may drop the body.
func TestRedirectIsInfraErrorNotFollowed(t *testing.T) {
	var landed atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landed.Store(true)
		json.NewEncoder(w).Encode(VerifyResponse{IsValid: true})
	}))
	defer elsewhere.Close()

	f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/verify", http.StatusPermanentRedirect)
	}}
	res := verifyWith(t, f)

	if landed.Load() {
		t.Error("the client followed a redirect from the facilitator")
	}
	if res.Verdict != Indeterminate {
		t.Errorf("verdict %v, want Indeterminate", res.Verdict)
	}
}

// TestBreakerOpensAndSkipsEgress, and — the part that matters against an
// attacker — TestDefinitiveRejectDoesNotTripBreaker.
func TestBreaker(t *testing.T) {
	t.Run("transport failures open it and then skip egress", func(t *testing.T) {
		f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}}
		srv := f.start(t)
		b := NewBreaker(3, 30*time.Second, 30*time.Second)
		v := newVerifier(t, srv.URL, b)
		p, _ := payload(t, "eip155:72344", "exact")

		for range 3 {
			v.Verify(context.Background(), p, reqs())
		}
		if !b.Open() {
			t.Fatal("breaker did not open after three transport failures")
		}
		before := f.verifyN.Load()
		res := v.Verify(context.Background(), p, reqs())
		if f.verifyN.Load() != before {
			t.Error("egress happened while the breaker was open")
		}
		if res.Verdict != Indeterminate {
			t.Errorf("verdict %v, want Indeterminate while open", res.Verdict)
		}
	})

	t.Run("client-caused rejections never open it", func(t *testing.T) {
		f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(VerifyResponse{IsValid: false, InvalidReason: "bad_signature"})
		}}
		srv := f.start(t)
		b := NewBreaker(3, 30*time.Second, 30*time.Second)
		v := newVerifier(t, srv.URL, b)
		p, _ := payload(t, "eip155:72344", "exact")

		for range 10 {
			v.Verify(context.Background(), p, reqs())
		}
		if b.Open() {
			t.Error("garbage presentations opened the breaker — an attacker could " +
				"disable the pay door for everyone by presenting invalid payments")
		}
	})
}

// TestAuthHeadersReachEveryFacilitatorCall: hosted facilitators commonly need
// one API credential on both protocol calls. The protocol headers must survive
// alongside it.
func TestAuthHeadersReachEveryFacilitatorCall(t *testing.T) {
	var got sync.Map // endpoint -> Authorization value
	record := func(name string, r *http.Request) {
		got.Store(name+"/auth", r.Header.Get("Authorization"))
		got.Store(name+"/accept", r.Header.Get("Accept"))
		got.Store(name+"/ctype", r.Header.Get("Content-Type"))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		record("verify", r)
		json.NewEncoder(w).Encode(VerifyResponse{IsValid: true, Payer: "0xpayer"})
	})
	mux.HandleFunc("/settle", func(w http.ResponseWriter, r *http.Request) {
		record("settle", r)
		json.NewEncoder(w).Encode(SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v := newVerifierWithHeaders(t, srv.URL, http.Header{"Authorization": {"Bearer sekrit"}})
	pl, _ := payload(t, "eip155:72344", "exact")
	v.Verify(context.Background(), pl, reqs())

	for _, ep := range []string{"verify", "settle"} {
		if a, _ := got.Load(ep + "/auth"); a != "Bearer sekrit" {
			t.Errorf("%s: Authorization = %v, want the configured header", ep, a)
		}
		if a, _ := got.Load(ep + "/accept"); a != "application/json" {
			t.Errorf("%s: Accept = %v — the protocol headers must survive auth headers", ep, a)
		}
		if c, _ := got.Load(ep + "/ctype"); c != "application/json" {
			t.Errorf("%s: Content-Type = %v", ep, c)
		}
	}
}

// A verifier built with no headers must not invent any.
func TestNoAuthHeadersByDefault(t *testing.T) {
	var auth atomic.Value
	f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(VerifyResponse{IsValid: true, Payer: "0xpayer"})
	}}
	verifyWith(t, f)
	if got, _ := auth.Load().(string); got != "" {
		t.Errorf("Authorization = %q on a header-less verifier", got)
	}
}

// TestEgressCapBoundsConcurrentFacilitatorCalls verifies that excess
// presentations are shed immediately rather than queued behind a slow caller.
func TestEgressCapBoundsConcurrentFacilitatorCalls(t *testing.T) {
	var inFlight, peak atomic.Int64
	release := make(chan struct{})
	f := &facilitator{verify: func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inFlight.Add(-1)
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(10 * time.Second): // backstop; see hang
		}
		json.NewEncoder(w).Encode(VerifyResponse{IsValid: false, InvalidReason: "no"})
	}}
	srv := f.start(t)
	v := NewCallbackVerifier(srv.URL, nil, quiet(), nil)
	// Budgets longer than the test holds the facilitator for, so a held call
	// cannot free its slot by timing out and blur what is being measured.
	v.shrinkBudgets(4*time.Second, 4*time.Second, 8*time.Second)

	const callers = 2 * maxInFlight
	p, _ := payload(t, "eip155:72344", "exact")
	results := make(chan Result, callers)
	for range callers {
		go func() { results <- v.Verify(context.Background(), p, reqs()) }()
	}

	// Every presentation past the cap answers while the first maxInFlight are
	// still held. Queueing instead is the failure: it converts one slow
	// dependency into a pile of held goroutines and connections.
	shed := 0
	deadline := time.After(3 * time.Second)
	for shed < callers-maxInFlight {
		select {
		case res := <-results:
			if res.Verdict != Indeterminate {
				t.Errorf("a shed presentation reported %v, want Indeterminate", res.Verdict)
			}
			shed++
		case <-deadline:
			close(release)
			t.Fatalf("only %d of %d excess presentations were shed while %d were held; "+
				"the rest queued", shed, callers-maxInFlight, inFlight.Load())
		}
	}
	close(release)
	for range maxInFlight {
		<-results
	}

	if got := peak.Load(); got > maxInFlight {
		t.Errorf("%d concurrent facilitator calls, cap is %d; a slow facilitator "+
			"becomes unbounded in-flight work", got, maxInFlight)
	}
	// And the other side, or a verifier that serialised every call would pass.
	if peak.Load() < 2 {
		t.Errorf("peak concurrency %d: nothing ran in parallel, so this is not measuring a cap",
			peak.Load())
	}
}
