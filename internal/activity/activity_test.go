package activity

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// testLog returns a Log on a controllable clock starting at base.
func testLog(ttl time.Duration, cap int) (*Log, *time.Time) {
	l := New(ttl, cap)
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	at := &base
	l.now = func() time.Time { return *at }
	return l, at
}

func one(t *testing.T, l *Log, ip string) Entry {
	t.Helper()
	for _, e := range l.Snapshot() {
		if e.IP == ip {
			return e
		}
	}
	t.Fatalf("no entry for %s", ip)
	return Entry{}
}

func TestRecordSemantics(t *testing.T) {
	l, at := testLog(time.Minute, 100)
	start := *at
	l.RecordFailure("203.0.113.9")
	e := one(t, l, "203.0.113.9")
	if !e.FirstSeen.Equal(start) || !e.LastSeen.Equal(start) {
		t.Errorf("first record: first=%v last=%v want both %v", e.FirstSeen, e.LastSeen, start)
	}
	if e.Failed != 1 || e.SucceededAdmit != 0 || e.SucceededRenew != 0 {
		t.Errorf("first record: failed=%d admit=%d renew=%d", e.Failed, e.SucceededAdmit, e.SucceededRenew)
	}

	*at = start.Add(10 * time.Second)
	l.RecordFailure("203.0.113.9")
	l.RecordAdmit("203.0.113.9")
	l.RecordRenew("203.0.113.9")
	l.RecordRenew("203.0.113.9")
	e = one(t, l, "203.0.113.9")
	if !e.FirstSeen.Equal(start) {
		t.Errorf("FirstSeen moved to %v", e.FirstSeen)
	}
	if !e.LastSeen.Equal(start.Add(10 * time.Second)) {
		t.Errorf("LastSeen not advanced: %v", e.LastSeen)
	}
	// The three counters are independent: an admit must never inflate the
	// renew count or vice versa — the split exists to tell those apart.
	if e.Failed != 2 || e.SucceededAdmit != 1 || e.SucceededRenew != 2 {
		t.Errorf("counts: failed=%d admit=%d renew=%d want 2/1/2", e.Failed, e.SucceededAdmit, e.SucceededRenew)
	}
}

// TestExpiry pins the contract that the TTL runs from the LAST activity: an
// entry refreshed at ttl-ε survives, and quiet past the ttl means gone — from
// Snapshot and from memory.
func TestExpiry(t *testing.T) {
	l, at := testLog(time.Minute, 100)
	start := *at
	l.RecordFailure("203.0.113.9")

	*at = start.Add(time.Minute - time.Second)
	l.RecordFailure("203.0.113.9") // refresh just inside the window

	*at = start.Add(2*time.Minute - 2*time.Second)
	if got := len(l.Snapshot()); got != 1 {
		t.Fatalf("refreshed entry expired early: %d entries", got)
	}

	*at = start.Add(3 * time.Minute)
	if got := l.Snapshot(); len(got) != 0 {
		t.Fatalf("quiet entry not expired: %v", got)
	}
	if l.Len() != 0 {
		t.Fatalf("expired entry still in memory: Len=%d", l.Len())
	}
}

// TestCapEviction fills the log, then inserts one more: expired entries are
// pruned first, and only if none were expired does the single quietest
// survivor go — never the whole map.
func TestCapEviction(t *testing.T) {
	t.Run("no expired: quietest evicted", func(t *testing.T) {
		l, at := testLog(time.Hour, 4)
		start := *at
		for i := 0; i < 4; i++ {
			*at = start.Add(time.Duration(i) * time.Second)
			l.RecordFailure(fmt.Sprintf("192.0.2.%d", i))
		}
		*at = start.Add(10 * time.Second)
		l.RecordFailure("198.51.100.1")
		if l.Len() != 4 {
			t.Fatalf("Len=%d want 4 (cap)", l.Len())
		}
		for _, e := range l.Snapshot() {
			if e.IP == "192.0.2.0" {
				t.Fatalf("oldest entry survived eviction")
			}
		}
		one(t, l, "198.51.100.1")
		one(t, l, "192.0.2.3")
	})
	t.Run("expired pruned first, survivors kept", func(t *testing.T) {
		l, at := testLog(time.Minute, 4)
		start := *at
		l.RecordFailure("192.0.2.0") // will be expired at insert time
		l.RecordFailure("192.0.2.1")
		*at = start.Add(59 * time.Second)
		l.RecordFailure("192.0.2.2")
		l.RecordFailure("192.0.2.3")
		*at = start.Add(90 * time.Second) // .0 and .1 now past the ttl
		l.RecordFailure("198.51.100.1")
		got := l.Snapshot()
		if len(got) != 3 {
			t.Fatalf("got %d entries want 3 (two expired, none evicted): %v", len(got), got)
		}
		one(t, l, "192.0.2.2")
		one(t, l, "192.0.2.3")
		one(t, l, "198.51.100.1")
	})
}

func TestSnapshotOrderAndCopy(t *testing.T) {
	l, at := testLog(time.Hour, 100)
	start := *at
	l.RecordFailure("10.0.0.2")
	l.RecordFailure("10.0.0.1") // same instant: IP ascending breaks the tie
	*at = start.Add(time.Second)
	l.RecordFailure("10.0.0.3") // most recent: leads

	got := l.Snapshot()
	if got[0].IP != "10.0.0.3" || got[1].IP != "10.0.0.1" || got[2].IP != "10.0.0.2" {
		t.Fatalf("order: %v %v %v", got[0].IP, got[1].IP, got[2].IP)
	}

	got[0].Failed = 999
	if e := one(t, l, "10.0.0.3"); e.Failed != 1 {
		t.Fatalf("snapshot is not a copy: log now reads failed=%d", e.Failed)
	}
}

func TestNilLogIsInert(t *testing.T) {
	var l *Log
	l.RecordFailure("192.0.2.1")
	l.RecordAdmit("192.0.2.1")
	l.RecordRenew("192.0.2.1")
	if l.Snapshot() != nil {
		t.Error("nil Snapshot not nil")
	}
	if l.Len() != 0 {
		t.Error("nil Len not 0")
	}
	if l.TTL() != 0 {
		t.Error("nil TTL not 0")
	}
}

func TestDefaultsClamped(t *testing.T) {
	l := New(0, 0)
	if l.ttl != 10*time.Minute || l.cap != 8192 {
		t.Fatalf("defaults: ttl=%v cap=%d", l.ttl, l.cap)
	}
}

// TestConcurrent is a -race smoke: recorders and snapshotters interleaving.
func TestConcurrent(t *testing.T) {
	l := New(time.Minute, 64)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				l.RecordFailure(fmt.Sprintf("192.0.2.%d", j%100))
				if j%20 == 0 {
					l.Snapshot()
					l.Len()
				}
			}
		}(i)
	}
	wg.Wait()
}
