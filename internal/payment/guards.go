package payment

import (
	"sync"
	"time"
)

// Everything in this file runs before any byte leaves the gate. That ordering
// is the point: a garbage "I totally paid" header must not purchase a
// facilitator round trip, and a facilitator having a bad day must not turn every
// request into a ten-second wait.

// ---------------------------------------------------------------------------
// Presentation rate limiting
// ---------------------------------------------------------------------------

// Limiter is a per-client token bucket over payment presentations, applied
// before any egress. It targets the RPC-waste denial of service: without it,
// an attacker replaying a bogus PAYMENT-SIGNATURE buys a facilitator round trip
// per request at no cost to themselves.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter allows burst presentations immediately and perMinute sustained.
func NewLimiter(perMinute, burst int) *Limiter {
	if perMinute <= 0 {
		perMinute = 6
	}
	if burst <= 0 {
		burst = perMinute
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		now:     time.Now,
	}
}

// Allow reports whether this client may present a payment now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// Bound the map: an attacker rotating source addresses must not be able
		// to grow it without limit. Eviction is crude on purpose — the buckets
		// are advisory, and a rebuilt bucket only ever grants the burst again,
		// which the facilitator-side limits also bound.
		if len(l.buckets) > 8192 {
			l.buckets = make(map[string]*bucket)
		}
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------------------------------------------------------------------------
// Circuit breaker
// ---------------------------------------------------------------------------

// Breaker stops the gate from queueing behind a facilitator that is plainly
// down. It counts transport-class failures only: a facilitator that answers
// "this payment is invalid" is working correctly, and letting client-caused
// rejections open the breaker would let an attacker disable the pay door for
// everyone by presenting garbage.
//
// There is deliberately no background health pinger. A gate that polls its
// facilitator on a timer is phone-home-shaped traffic, and the next real
// presentation half-opens the breaker anyway.
type Breaker struct {
	mu        sync.Mutex
	failures  []time.Time
	openUntil time.Time
	threshold int
	window    time.Duration
	cooldown  time.Duration
	now       func() time.Time
}

// NewBreaker opens after threshold transport failures inside window, and stays
// open for cooldown.
func NewBreaker(threshold int, window, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 3
	}
	if window <= 0 {
		window = 30 * time.Second
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{threshold: threshold, window: window, cooldown: cooldown, now: time.Now}
}

// Open reports whether egress should be skipped entirely.
func (b *Breaker) Open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.now().Before(b.openUntil)
}

// RetryAfter reports how long the breaker will keep skipping egress. Zero when
// it is closed.
func (b *Breaker) RetryAfter() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := b.openUntil.Sub(b.now()); d > 0 {
		return d
	}
	return 0
}

// Fail records a transport-class failure, opening the breaker at the threshold.
// It reports whether this failure is the one that opened it, so the caller can
// log that transition once rather than on every subsequent request.
func (b *Breaker) Fail() (opened bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if now.Before(b.openUntil) {
		return false
	}
	cut := now.Add(-b.window)
	kept := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	b.failures = append(kept, now)
	if len(b.failures) >= b.threshold {
		b.openUntil = now.Add(b.cooldown)
		b.failures = nil
		return true
	}
	return false
}

// Succeed closes the breaker: a working round trip is the only evidence that
// matters, and it is why no separate half-open state is needed.
func (b *Breaker) Succeed() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = nil
	b.openUntil = time.Time{}
}
