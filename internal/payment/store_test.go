package payment

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func testGrantStore(t *testing.T) (*GrantStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payments.db")
	s, err := NewGrantStore(path)
	if err != nil {
		t.Fatalf("NewGrantStore: %v", err)
	}
	return s, path
}

func completeGrant(now time.Time) Grant {
	return Grant{
		Scope:       "scope-v1",
		Audience:    "example.com",
		Payer:       "0xpayer",
		Transaction: "0xtx",
		Amount:      "10000",
		Network:     "eip155:1",
		ExpiresAt:   now.Add(time.Hour).Unix(),
	}
}

func TestGrantStoreCommitAndRecoverAcrossInstances(t *testing.T) {
	s, path := testGrantStore(t)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	state, lease, _, err := s.Begin("payment-1")
	if err != nil || state != BeginNew || lease == "" {
		t.Fatalf("Begin = (%v, %q, %v), want new lease", state, lease, err)
	}
	if state, _, _, err := s.Begin("payment-1"); err != nil || state != BeginInFlight {
		t.Fatalf("concurrent Begin = (%v, %v), want in-flight", state, err)
	}

	want := completeGrant(now)
	got, created, err := s.Commit("payment-1", lease, want)
	if err != nil || !created || got != want {
		t.Fatalf("Commit = (%+v, %v, %v), want created %+v", got, created, err, want)
	}

	// A new Gate process opens the same file and recovers the exact semantic
	// grant without contacting the facilitator.
	restarted, err := NewGrantStore(path)
	if err != nil {
		t.Fatalf("restart NewGrantStore: %v", err)
	}
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	state, lease, got, err = restarted.Begin("payment-1")
	if err != nil || state != BeginRecoverable || lease != "" || got != want {
		t.Fatalf("restart Begin = (%v, %q, %+v, %v), want recoverable", state, lease, got, err)
	}

	restarted.now = func() time.Time { return now.Add(2 * time.Hour) }
	if state, _, _, err := restarted.Begin("payment-1"); err != nil || state != BeginSpent {
		t.Fatalf("expired grant Begin = (%v, %v), want spent", state, err)
	}

	// The chain nonce is permanently spent. Time never makes it a new payment.
	restarted.now = func() time.Time { return now.Add(26 * time.Hour) }
	if state, _, _, err := restarted.Begin("payment-1"); err != nil || state != BeginSpent {
		t.Fatalf("old grant Begin = (%v, %v), want spent", state, err)
	}
}

func TestGrantStoreReleaseUsesLeaseOwnership(t *testing.T) {
	s, _ := testGrantStore(t)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	_, first, _, _ := s.Begin("payment-1")
	now = now.Add(paymentLease + time.Second)
	state, second, _, err := s.Begin("payment-1")
	if err != nil || state != BeginNew || second == first {
		t.Fatalf("replacement Begin = (%v, %q, %v)", state, second, err)
	}
	if err := s.Release("payment-1", first); err != nil {
		t.Fatalf("late Release: %v", err)
	}
	if state, _, _, err := s.Begin("payment-1"); err != nil || state != BeginInFlight {
		t.Fatalf("old lease removed new reservation: state=%v err=%v", state, err)
	}
	if err := s.Release("payment-1", second); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if state, _, _, err := s.Begin("payment-1"); err != nil || state != BeginNew {
		t.Fatalf("released Begin = (%v, %v), want new", state, err)
	}
}

func TestGrantStoreSerializesIndependentProcesses(t *testing.T) {
	one, path := testGrantStore(t)
	two, err := NewGrantStore(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	one.now = func() time.Time { return now }
	two.now = func() time.Time { return now }

	stores := []*GrantStore{one, two}
	states := make(chan BeginResult, len(stores))
	errs := make(chan error, len(stores))
	var wg sync.WaitGroup
	for _, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			state, _, _, err := s.Begin("payment-1")
			states <- state
			errs <- err
		}()
	}
	wg.Wait()
	close(states)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	counts := map[BeginResult]int{}
	for state := range states {
		counts[state]++
	}
	if counts[BeginNew] != 1 || counts[BeginInFlight] != 1 {
		t.Fatalf("states = %#v, want one new and one in-flight", counts)
	}
}

func TestGrantStoreCorruptionFailsClosed(t *testing.T) {
	s, path := testGrantStore(t)
	if err := s.update(func(b *bolt.Bucket) error {
		return b.Put([]byte("payment-1"), []byte("not-json"))
	}); err != nil {
		t.Fatalf("seed corrupt record: %v", err)
	}
	if _, _, _, err := s.Begin("payment-1"); err == nil {
		t.Fatal("Begin accepted corrupt record")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file disappeared: %v", err)
	}
}
