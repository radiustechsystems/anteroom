// Package activity is the gate's opt-in, in-memory record of per-IP challenge
// activity: who was walled, who failed a challenge answer, who solved one. It
// exists for one consumer — an EXTERNAL privileged tool (an iptables
// auto-banner, a Cloudflare API script) polling the admin endpoint — and it
// deliberately judges nothing: entries are raw counts, the "this is an
// offender" decision belongs to the poller, and so do ban and unban. A banned
// IP stops reaching the gate, goes quiet, and falls out of the log after the
// TTL, so a tool that rebuilds its drop table from each poll gets un-banning
// for free without anteroom ever knowing a ban existed.
//
// This is the one deliberate exception to the gate's no-per-visitor-state
// stance: opt-in via the [activity] config section, memory-only, never
// persisted, never pushed anywhere, and kept out of the metrics registry so
// the scrape surface stays IP-free.
package activity

import (
	"sort"
	"sync"
	"time"
)

// Log is a bounded, lazily-pruned map of per-IP challenge activity. A nil
// *Log is valid and inert: every method no-ops or returns zero, which is how
// the gate runs with the feature off without a branch at any call site.
type Log struct {
	mu      sync.Mutex
	entries map[string]*entry
	ttl     time.Duration    // quiet time before an entry is dropped
	cap     int              // hard bound on tracked IPs
	now     func() time.Time // injectable clock, for tests
}

type entry struct {
	firstSeen, lastSeen time.Time
	failed              uint64
	admits, renews      uint64
}

// Entry is one IP's snapshot. Counts are cumulative since FirstSeen — the
// consumer diffs between polls, the same contract the metrics endpoint has
// with its scraper.
//
// Successes are split by challenge kind because the two mean opposite things
// about the client: renewals are the cheap background puzzle a real browser
// solves automatically while a tab sits open, so a high SucceededRenew is
// evidence of a person; admissions are the full-difficulty solve, and a high
// SucceededAdmit alongside failures and no site traffic is the signature of a
// solve loop — a bot that earns passes it never manages to present.
type Entry struct {
	IP                  string
	FirstSeen, LastSeen time.Time
	Failed              uint64
	SucceededAdmit      uint64
	SucceededRenew      uint64
}

// New builds a Log. Non-positive arguments take the documented defaults
// (ttl 10m, maxIPs 8192) rather than erroring, matching payment.NewLimiter.
func New(ttl time.Duration, maxIPs int) *Log {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxIPs <= 0 {
		maxIPs = 8192
	}
	return &Log{
		entries: make(map[string]*entry),
		ttl:     ttl,
		cap:     maxIPs,
		now:     time.Now,
	}
}

// RecordFailure counts one walled request or refused challenge answer.
func (l *Log) RecordFailure(ip string) { l.record(ip, func(e *entry) { e.failed++ }) }

// RecordAdmit counts one accepted full-difficulty admission answer.
func (l *Log) RecordAdmit(ip string) { l.record(ip, func(e *entry) { e.admits++ }) }

// RecordRenew counts one accepted cheap background-renewal answer.
func (l *Log) RecordRenew(ip string) { l.record(ip, func(e *entry) { e.renews++ }) }

func (l *Log) record(ip string, bump func(*entry)) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[ip]
	if !ok {
		if len(l.entries) >= l.cap {
			l.makeRoom(now)
		}
		e = &entry{firstSeen: now}
		l.entries[ip] = e
	}
	e.lastSeen = now
	bump(e)
}

// makeRoom frees at least one slot: one pass deletes every expired entry and,
// should none be expired, evicts the single quietest survivor. Deliberately
// NOT the payment.Limiter wipe — that map is advisory, this one has a
// consumer, and blanking it mid-attack would hand the auto-banner an empty
// poll at exactly the moment it matters. The O(n) walk runs only on insert
// while full, paid by the address-spraying traffic that caused it.
// Called with l.mu held.
func (l *Log) makeRoom(now time.Time) {
	oldest := ""
	var oldestAt time.Time
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > l.ttl {
			delete(l.entries, ip)
			continue
		}
		if oldest == "" || e.lastSeen.Before(oldestAt) {
			oldest, oldestAt = ip, e.lastSeen
		}
	}
	if len(l.entries) >= l.cap && oldest != "" {
		delete(l.entries, oldest)
	}
}

// Snapshot prunes expired entries and returns a copy of the rest, most recent
// activity first (ties broken by IP) so the output is deterministic and the
// interesting rows lead.
func (l *Log) Snapshot() []Entry {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	out := make([]Entry, 0, len(l.entries))
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > l.ttl {
			delete(l.entries, ip)
			continue
		}
		out = append(out, Entry{
			IP: ip, FirstSeen: e.firstSeen, LastSeen: e.lastSeen,
			Failed: e.failed, SucceededAdmit: e.admits, SucceededRenew: e.renews,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Len prunes expired entries and reports how many IPs are tracked. It backs
// the anteroom_tracked_ips gauge — a count, deliberately IP-free, so the
// metrics surface stays clean of per-visitor data.
func (l *Log) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for ip, e := range l.entries {
		if now.Sub(e.lastSeen) > l.ttl {
			delete(l.entries, ip)
		}
	}
	return len(l.entries)
}

// TTL reports the configured quiet period, for the endpoint's window field —
// the consumer's contract for how stale a listed entry can be, and therefore
// how often to poll.
func (l *Log) TTL() time.Duration {
	if l == nil {
		return 0
	}
	return l.ttl
}
