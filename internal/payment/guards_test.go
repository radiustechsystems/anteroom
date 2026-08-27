package payment

import (
	"testing"
	"time"
)

// TestLimiterBurstThenRefuse. The limiter exists so a bogus PAYMENT-SIGNATURE
// cannot buy a facilitator round trip per request.
func TestLimiterBurstThenRefuse(t *testing.T) {
	now := time.Now()
	l := NewLimiter(6, 3)
	l.now = func() time.Time { return now }

	for i := range 3 {
		if !l.Allow("ip") {
			t.Fatalf("burst request %d refused", i+1)
		}
	}
	if l.Allow("ip") {
		t.Error("the limiter allowed more than the burst")
	}
	// A different client is unaffected.
	if !l.Allow("other") {
		t.Error("one client's burst exhausted another's budget")
	}
	// Tokens refill.
	now = now.Add(30 * time.Second)
	if !l.Allow("ip") {
		t.Error("tokens did not refill")
	}
}

// TestBreakerOnlyCountsTransportFailures is the property that keeps an attacker
// from disabling the pay door for everyone: only Fail() opens the breaker, and
// the caller only calls it for transport-class errors, never for a facilitator
// that answered "this payment is invalid".
func TestBreakerLifecycle(t *testing.T) {
	now := time.Now()
	b := NewBreaker(3, 30*time.Second, 30*time.Second)
	b.now = func() time.Time { return now }

	if b.Open() {
		t.Fatal("a fresh breaker is open")
	}
	if opened := b.Fail(); opened {
		t.Error("opened on the first failure")
	}
	b.Fail()
	if !b.Fail() {
		t.Error("did not open at the threshold")
	}
	if !b.Open() {
		t.Fatal("Open() disagrees with Fail()")
	}

	// It closes on its own after the cooldown…
	now = now.Add(31 * time.Second)
	if b.Open() {
		t.Error("still open past the cooldown")
	}
	// …and a working round trip closes it immediately.
	b.Fail()
	b.Fail()
	b.Succeed()
	if b.Fail() {
		t.Error("Succeed() did not clear the failure count")
	}
}

// TestBreakerFailuresAgeOut — three failures spread over an hour are not an
// outage, and must not open the breaker.
func TestBreakerFailuresAgeOut(t *testing.T) {
	now := time.Now()
	b := NewBreaker(3, 30*time.Second, 30*time.Second)
	b.now = func() time.Time { return now }

	for range 5 {
		if opened := b.Fail(); opened {
			t.Fatal("occasional failures spread over time opened the breaker")
		}
		now = now.Add(20 * time.Second)
	}
}
