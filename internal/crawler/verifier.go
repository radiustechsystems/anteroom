// Package crawler authenticates explicitly configured search crawlers.
package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/radiustechsystems/anteroom/internal/metrics"
	"github.com/radiustechsystems/anteroom/internal/useragent"
)

// 8,192 compact entries occupy roughly 1 MiB in Go 1.22's map layout. A map
// growth can transiently use more while the runtime moves old buckets.
const maxCacheEntries = 8192
const dnsCacheTTL = 4 * time.Hour

// AvailableNames is the human-readable list used in configuration errors.
const AvailableNames = "googlebot, bingbot, yandexbot, ccbot"

// Supported reports whether name is an exact supported configuration value.
func Supported(name string) bool {
	_, ok := findProvider(name)
	return ok
}

// Verdict is the result of authenticating a claimed crawler address.
type Verdict uint8

const (
	Unverified Verdict = iota
	Verified
	Indeterminate
)

type resolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type provider struct {
	id          uint8
	name        string
	uaProducts  []string
	prefixes    []netip.Prefix
	ptrSuffixes []string
	rangeJSON   []byte
	rangeSource string
	// Common Crawl documents that its IPv6 crawler addresses do not yet
	// have reverse DNS. Its embedded ranges remain authoritative for IPv6.
	dnsIPv4Only bool
}

var providers = []provider{googlebot, bingbot, yandexbot, commonCrawl}

func findProvider(name string) (provider, bool) {
	for i, p := range providers {
		if p.name == name {
			p.id = uint8(i + 1)
			return p, true
		}
	}
	return provider{}, false
}

func (p provider) claims(userAgent string) bool {
	for _, token := range p.uaProducts {
		if useragent.ContainsProduct(userAgent, token) {
			return true
		}
	}
	return false
}

type cacheKey struct {
	addr     netip.Addr
	provider uint8
	negative bool
}

type cacheEntry struct {
	expires int64
	verdict Verdict
}

// Set verifies any of the crawler providers selected by configuration. All
// providers share the DNS concurrency limit and bounded cache, so enabling
// more providers cannot multiply resource use.
type Set struct {
	providers []provider
	resolver  resolver
	timeout   time.Duration
	limit     chan struct{}
	now       func() time.Time

	mu    sync.Mutex
	cache map[cacheKey]cacheEntry

	dnsOutcomes  *metrics.CounterVec
	dnsCacheHits *metrics.Counter
	dnsSaturated *metrics.Counter
	dnsInFlight  atomic.Int64
}

// RegisterMetrics adds aggregate DNS health to both /metrics and /stats. It
// has no provider or address labels, keeping the surface bounded and private.
func (s *Set) RegisterMetrics(reg *metrics.Registry) {
	s.dnsOutcomes = reg.CounterVec("anteroom_crawler_dns_lookups_total",
		"Forward-confirmed reverse-DNS lookups, by outcome.",
		"outcome", "verified", "unverified", "indeterminate")
	s.dnsCacheHits = reg.Counter("anteroom_crawler_dns_cache_hits_total",
		"Crawler verifications answered from the DNS-result cache.")
	s.dnsSaturated = reg.Counter("anteroom_crawler_dns_saturated_total",
		"Crawler verifications deferred because the DNS concurrency limit was full.")
	reg.GaugeFunc("anteroom_crawler_dns_in_flight",
		"Crawler forward-confirmed reverse-DNS lookups currently in progress.",
		func() float64 { return float64(s.dnsInFlight.Load()) })
}

// New builds a verifier for the exact configured provider names.
func New(names []string) (*Set, error) {
	providers := make([]provider, 0, len(names))
	for _, name := range names {
		p, ok := findProvider(name)
		if !ok {
			return nil, fmt.Errorf("crawler: unsupported provider %q", name)
		}
		if p.rangeJSON != nil {
			var err error
			p.prefixes, err = parsePrefixes(p.rangeJSON, p.rangeSource)
			if err != nil {
				return nil, err
			}
		}
		providers = append(providers, p)
	}
	return &Set{
		providers: providers,
		resolver:  net.DefaultResolver,
		timeout:   2 * time.Second,
		limit:     make(chan struct{}, 16),
		now:       time.Now,
		cache:     make(map[cacheKey]cacheEntry),
	}, nil
}

// Claim returns the stable name claimed by a configured crawler User-Agent. It
// is cheap and unauthoritative: the name selects verification and presentation;
// only Verify can grant access. Unconfigured providers stay on the ordinary
// challenge/payment ladder.
func (s *Set) Claim(userAgent string) string {
	if s == nil {
		return ""
	}
	for _, p := range s.providers {
		if p.claims(userAgent) {
			return p.name
		}
	}
	return ""
}

// Verify authenticates a claimed provider that this Set was configured to
// allow. Embedded published ranges are the fast path; a miss uses that
// provider's documented forward-confirmed reverse DNS method.
func (s *Set) Verify(ctx context.Context, claim string, addr netip.Addr) Verdict {
	for _, p := range s.providers {
		if p.name == claim {
			return s.verifyProvider(ctx, p, addr.Unmap())
		}
	}
	return Unverified
}

func (s *Set) verifyProvider(ctx context.Context, p provider, addr netip.Addr) Verdict {
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return Verified
		}
	}
	if p.dnsIPv4Only && !addr.Is4() {
		return Unverified
	}

	now := s.now()
	s.mu.Lock()
	for _, key := range cacheLookupKeys(p, addr) {
		if cached, ok := s.cache[key]; ok && now.UnixNano() < cached.expires {
			s.mu.Unlock()
			if s.dnsCacheHits != nil {
				s.dnsCacheHits.Inc()
			}
			return cached.verdict
		}
	}
	s.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	select {
	case s.limit <- struct{}{}:
	default:
		if s.dnsSaturated != nil {
			s.dnsSaturated.Inc()
		}
		select {
		case s.limit <- struct{}{}:
		case <-lookupCtx.Done():
			return Indeterminate
		}
	}
	s.dnsInFlight.Add(1)
	defer func() {
		s.dnsInFlight.Add(-1)
		<-s.limit
	}()
	verdict := s.verifyDNS(lookupCtx, p, addr)
	if s.dnsOutcomes != nil {
		outcome := "indeterminate"
		if verdict == Verified {
			outcome = "verified"
		} else if verdict == Unverified {
			outcome = "unverified"
		}
		s.dnsOutcomes.With(outcome).Inc()
	}

	if verdict != Indeterminate {
		key := cacheStoreKey(p, addr, verdict)
		s.mu.Lock()
		if len(s.cache) >= maxCacheEntries {
			// The cache is defensive, not authoritative. Arbitrary eviction is
			// enough to bound memory without an LRU dependency.
			for old := range s.cache {
				delete(s.cache, old)
				break
			}
		}
		s.cache[key] = cacheEntry{verdict: verdict, expires: now.Add(dnsCacheTTL).UnixNano()}
		s.mu.Unlock()
	}
	return verdict
}

func cacheLookupKeys(p provider, addr netip.Addr) [2]cacheKey {
	return [2]cacheKey{
		{provider: p.id, addr: addr},
		cacheStoreKey(p, addr, Unverified),
	}
}

func cacheStoreKey(p provider, addr netip.Addr, verdict Verdict) cacheKey {
	key := cacheKey{provider: p.id, addr: addr, negative: verdict == Unverified}
	// An attacker can rotate cheaply through an IPv6 /64. Coalescing negative
	// answers at that boundary prevents one PTR lookup and cache entry per
	// address while retaining exact-address positive verification. The tradeoff
	// is that one negative can temporarily shadow a legitimate neighbour in the
	// same /64; crawler operators normally control that whole prefix.
	if key.negative && addr.Is6() {
		key.addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return key
}

func (s *Set) verifyDNS(ctx context.Context, p provider, addr netip.Addr) Verdict {
	names, err := s.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		return dnsErrorVerdict(err)
	}
	indeterminate := false
	for _, rawName := range names {
		name := strings.TrimSuffix(strings.ToLower(rawName), ".")
		if !hasDomainSuffix(name, p.ptrSuffixes) {
			continue
		}
		addrs, err := s.resolver.LookupIPAddr(ctx, name)
		if err != nil {
			if dnsErrorVerdict(err) == Indeterminate {
				indeterminate = true
			}
			continue
		}
		for _, resolved := range addrs {
			got, ok := netip.AddrFromSlice(resolved.IP)
			if ok && got.Unmap() == addr {
				return Verified
			}
		}
	}
	if indeterminate {
		return Indeterminate
	}
	return Unverified
}

func hasDomainSuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func dnsErrorVerdict(err error) Verdict {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return Unverified
	}
	return Indeterminate
}

func parsePrefixes(raw []byte, source string) ([]netip.Prefix, error) {
	var document struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("crawler: parsing %s: %w", source, err)
	}
	if len(document.Prefixes) == 0 {
		return nil, fmt.Errorf("crawler: %s contains no prefixes", source)
	}
	prefixes := make([]netip.Prefix, 0, len(document.Prefixes))
	for _, item := range document.Prefixes {
		if (item.IPv4 == "") == (item.IPv6 == "") {
			return nil, fmt.Errorf("crawler: %s prefix entry must contain exactly one address family", source)
		}
		rawPrefix := item.IPv4
		if rawPrefix == "" {
			rawPrefix = item.IPv6
		}
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err != nil {
			return nil, fmt.Errorf("crawler: bad prefix %q from %s: %w", rawPrefix, source, err)
		}
		if (item.IPv4 != "") != prefix.Addr().Is4() {
			return nil, fmt.Errorf("crawler: prefix %q from %s is under the wrong address family", rawPrefix, source)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
