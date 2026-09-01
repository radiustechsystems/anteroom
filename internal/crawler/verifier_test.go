package crawler

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/metrics"
)

type fakeResolver struct {
	names        []string
	addresses    []net.IPAddr
	reverseErr   error
	forwardErr   error
	blockReverse bool
	reverseCalls int
	forwardCalls int
	forwardNames []string
}

func (r *fakeResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	r.reverseCalls++
	if r.blockReverse {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.names, r.reverseErr
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	r.forwardCalls++
	r.forwardNames = append(r.forwardNames, name)
	return r.addresses, r.forwardErr
}

func testSet(t *testing.T, name string, r resolver) *Set {
	t.Helper()
	s, err := New([]string{name})
	if err != nil {
		t.Fatal(err)
	}
	s.resolver = r
	s.timeout = 100 * time.Millisecond
	return s
}

func TestCrawlerClaimsAreNarrow(t *testing.T) {
	tests := []struct {
		name string
		yes  []string
		no   []string
	}{
		{
			name: "googlebot",
			yes: []string{
				"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				"Googlebot-Image/1.0", "Googlebot-Video/1.0",
				"Mozilla/5.0 (compatible; Google-InspectionTool/1.0)",
			},
			no: []string{"Storebot-Google/1.0", "GoogleOther", "Google-CloudVertexBot", "NotGooglebot/2.1", "gOoGlEbOt/2.1"},
		},
		{name: "bingbot", yes: []string{"Mozilla/5.0 (compatible; bingbot/2.0)"}, no: []string{"BingPreview/1.0", "adidxbot/2.0", "BiNgBoT/2.0"}},
		{name: "yandexbot", yes: []string{"YandexBot/3.0", "YandexImages/3.0", "YandexWebmaster/2.0"}, no: []string{"YandexDirect/3.0", "YandexMetrika/4.0"}},
		{name: "ccbot", yes: []string{"CCBot/2.0"}, no: []string{"CCBot-fake", "CommonCrawl/1.0", "cCbOt/2.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := testSet(t, tt.name, &fakeResolver{})
			for _, ua := range tt.yes {
				if got := s.Claim(ua); got != tt.name {
					t.Errorf("did not recognize %q", ua)
				}
			}
			for _, ua := range tt.no {
				if got := s.Claim(ua); got == tt.name {
					t.Errorf("treated %q as %s", ua, tt.name)
				}
			}
		})
	}
}

func TestUnconfiguredCrawlerDoesNotProduceAClaim(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Claim("Mozilla/5.0 (compatible; Googlebot/2.1)"); got != "" {
		t.Fatalf("unconfigured verifier claimed %q", got)
	}
}

func TestEmbeddedRangesNeedNoDNS(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr string
	}{
		{name: "googlebot", addr: "66.249.66.1"},
		{name: "bingbot", addr: "157.55.39.1"},
		{name: "ccbot", addr: "18.97.14.84"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeResolver{reverseErr: errors.New("DNS must not be called")}
			s := testSet(t, tt.name, r)
			got := s.Verify(context.Background(), tt.name, netip.MustParseAddr(tt.addr))
			if got != Verified {
				t.Fatalf("Verify = %v; want verified", got)
			}
			if r.reverseCalls != 0 {
				t.Fatalf("embedded match made %d reverse lookups", r.reverseCalls)
			}
		})
	}
}

func TestForwardConfirmedReverseDNS(t *testing.T) {
	const address = "203.0.113.9"
	for _, tt := range []struct {
		name string
		host string
	}{
		{name: "googlebot", host: "crawl-203-0-113-9.googlebot.com."},
		{name: "googlebot", host: "crawl-203-0-113-9.google.com."},
		{name: "bingbot", host: "msnbot-203-0-113-9.search.msn.com."},
		{name: "yandexbot", host: "crawler-203-0-113-9.yandex.ru."},
		{name: "ccbot", host: "203-0-113-9.crawl.commoncrawl.org."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeResolver{
				names:     []string{tt.host},
				addresses: []net.IPAddr{{IP: net.ParseIP(address)}},
			}
			s := testSet(t, tt.name, r)
			got := s.Verify(context.Background(), tt.name, netip.MustParseAddr(address))
			if got != Verified {
				t.Fatalf("Verify = %v; want verified", got)
			}
			wantName := strings.TrimSuffix(strings.ToLower(tt.host), ".")
			if len(r.forwardNames) != 1 || r.forwardNames[0] != wantName {
				t.Fatalf("forward lookup names = %q, want [%q]", r.forwardNames, wantName)
			}
		})
	}
}

func TestForwardConfirmedReverseDNSRejectsSpoofsAndFailures(t *testing.T) {
	const address = "203.0.113.9"
	for _, tt := range []struct {
		name     string
		resolver *fakeResolver
		want     Verdict
	}{
		{
			name:     "suffix spoof",
			resolver: &fakeResolver{names: []string{"crawl.googlebot.com.attacker.example."}},
			want:     Unverified,
		},
		{
			name:     "unanchored suffix spoof",
			resolver: &fakeResolver{names: []string{"evilgooglebot.com."}},
			want:     Unverified,
		},
		{
			name: "forward mismatch",
			resolver: &fakeResolver{
				names:     []string{"crawl-203-0-113-9.googlebot.com."},
				addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
			},
			want: Unverified,
		},
		{
			name:     "temporary DNS failure",
			resolver: &fakeResolver{reverseErr: &net.DNSError{Err: "temporary", IsTemporary: true}},
			want:     Indeterminate,
		},
		{
			name: "temporary forward failure",
			resolver: &fakeResolver{
				names:      []string{"crawl-203-0-113-9.googlebot.com."},
				forwardErr: &net.DNSError{Err: "temporary", IsTemporary: true},
			},
			want: Indeterminate,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := testSet(t, "googlebot", tt.resolver)
			got := s.Verify(context.Background(), "googlebot", netip.MustParseAddr(address))
			if got != tt.want {
				t.Fatalf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSTimeoutBoundsResolverWork(t *testing.T) {
	s := testSet(t, "googlebot", &fakeResolver{blockReverse: true})
	s.timeout = time.Millisecond
	if got := s.Verify(context.Background(), "googlebot", netip.MustParseAddr("203.0.113.9")); got != Indeterminate {
		t.Fatalf("verdict = %v, want indeterminate", got)
	}
}

func TestDNSResultIsCached(t *testing.T) {
	r := &fakeResolver{
		names:     []string{"crawl-203-0-113-9.googlebot.com."},
		addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}},
	}
	s := testSet(t, "googlebot", r)
	addr := netip.MustParseAddr("203.0.113.9")
	if got := s.Verify(context.Background(), "googlebot", addr); got != Verified {
		t.Fatal("first lookup was not verified")
	}
	if got := s.Verify(context.Background(), "googlebot", addr); got != Verified {
		t.Fatal("cached lookup did not stay verified")
	}
	if r.reverseCalls != 1 || r.forwardCalls != 1 {
		t.Fatalf("DNS calls = reverse %d, forward %d; want one each", r.reverseCalls, r.forwardCalls)
	}
}

func TestNegativeDNSResultIsCached(t *testing.T) {
	r := &fakeResolver{names: []string{"spoof.attacker.example."}}
	s := testSet(t, "googlebot", r)
	addr := netip.MustParseAddr("203.0.113.9")
	for range 2 {
		if got := s.Verify(context.Background(), "googlebot", addr); got != Unverified {
			t.Fatalf("verdict = %v, want unverified", got)
		}
	}
	if r.reverseCalls != 1 {
		t.Fatalf("reverse calls = %d, want one", r.reverseCalls)
	}
}

func TestNegativeIPv6CacheIsCoalescedBy64(t *testing.T) {
	r := &fakeResolver{names: []string{"spoof.attacker.example."}}
	s := testSet(t, "googlebot", r)
	for _, raw := range []string{"2001:db8:1:2::1", "2001:db8:1:2::ffff"} {
		if got := s.Verify(context.Background(), "googlebot", netip.MustParseAddr(raw)); got != Unverified {
			t.Fatalf("verdict for %s = %v, want unverified", raw, got)
		}
	}
	if r.reverseCalls != 1 {
		t.Fatalf("reverse calls = %d, want one for one IPv6 /64", r.reverseCalls)
	}
}

func TestDNSCacheRemainsBounded(t *testing.T) {
	s := testSet(t, "googlebot", &fakeResolver{names: []string{"spoof.attacker.example."}})
	for i := 0; i < maxCacheEntries; i++ {
		addr := netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)})
		s.cache[cacheKey{provider: 1, addr: addr}] = cacheEntry{expires: time.Now().Add(time.Hour).UnixNano(), verdict: Verified}
	}
	if got := s.Verify(context.Background(), "googlebot", netip.MustParseAddr("203.0.113.9")); got != Unverified {
		t.Fatalf("verdict = %v, want unverified", got)
	}
	if got := len(s.cache); got != maxCacheEntries {
		t.Fatalf("cache entries = %d, want %d", got, maxCacheEntries)
	}
}

func TestDNSMetricsDescribeLookupAndCache(t *testing.T) {
	r := &fakeResolver{
		names:     []string{"crawl-203-0-113-9.googlebot.com."},
		addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}},
	}
	s := testSet(t, "googlebot", r)
	reg := metrics.NewRegistry()
	s.RegisterMetrics(reg)
	addr := netip.MustParseAddr("203.0.113.9")
	s.Verify(context.Background(), "googlebot", addr)
	s.Verify(context.Background(), "googlebot", addr)
	var out strings.Builder
	reg.WritePrometheus(&out)
	for _, sample := range []string{
		`anteroom_crawler_dns_lookups_total{outcome="verified"} 1`,
		`anteroom_crawler_dns_cache_hits_total 1`,
		`anteroom_crawler_dns_in_flight 0`,
	} {
		if !strings.Contains(out.String(), sample) {
			t.Errorf("missing %q:\n%s", sample, out.String())
		}
	}
}

func TestCommonCrawlUnknownIPv6DoesNotUseUnsupportedReverseDNS(t *testing.T) {
	r := &fakeResolver{reverseErr: errors.New("DNS must not be called")}
	s := testSet(t, "ccbot", r)
	got := s.Verify(context.Background(), "ccbot", netip.MustParseAddr("2001:db8::1"))
	if got != Unverified || r.reverseCalls != 0 {
		t.Fatalf("verdict = %v, reverse calls = %d", got, r.reverseCalls)
	}
}
