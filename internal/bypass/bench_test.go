package bypass

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

// The bypass matcher runs on every request before any cryptography does, so
// its cost is paid by every rung. Paths are a linear scan of globs; IPs a
// linear scan of prefixes; ClientIP parses RemoteAddr and, behind a trusted
// proxy, walks X-Forwarded-For from the right.

var benchPaths = []string{"/robots.txt", "/sitemap.xml", "/feed.xml", "/.well-known/*", "/webhooks/*", "/healthz"}

func BenchmarkPath(b *testing.B) {
	m := matcher(b, benchPaths, nil, nil)
	for _, tc := range []struct{ name, path string }{
		{"hit_exact", "/robots.txt"},
		{"hit_glob", "/.well-known/acme-challenge/token"},
		{"miss", "/api/items/12345"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				m.Path(tc.path)
			}
		})
	}
}

func BenchmarkIP(b *testing.B) {
	m := matcher(b, nil, []string{"10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"}, nil)
	hit := netip.MustParseAddr("192.168.4.4")
	miss := netip.MustParseAddr("203.0.113.9")
	b.Run("hit", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			m.IP(hit)
		}
	})
	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			m.IP(miss)
		}
	})
}

func BenchmarkClientIP(b *testing.B) {
	direct := matcher(b, nil, nil, nil)
	proxied := matcher(b, nil, nil, []string{"10.0.0.0/8"})

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:44321"
	b.Run("direct", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := direct.ClientIP(r); err != nil {
				b.Fatal(err)
			}
		}
	})

	fr := httptest.NewRequest("GET", "/", nil)
	fr.RemoteAddr = "10.1.2.3:44321"
	fr.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.2")
	b.Run("behind_trusted_proxy", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := proxied.ClientIP(fr); err != nil {
				b.Fatal(err)
			}
		}
	})
}
