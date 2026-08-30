package bypass

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func matcher(t testing.TB, paths, cidrs, trusted []string) *Matcher {
	t.Helper()
	m, err := New(paths, cidrs, trusted)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestNewRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		paths, cidrs, trusted []string
	}{
		{"two stars", []string{"/a*b*"}, nil, nil},
		{"no leading slash", []string{"robots.txt"}, nil, nil},
		{"bad cidr", nil, []string{"999.1.2.3/8"}, nil},
		{"bad trusted", nil, nil, []string{"not-an-ip"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.paths, tc.cidrs, tc.trusted); err == nil {
				t.Fatal("New accepted bad input")
			}
		})
	}
}

func TestPath(t *testing.T) {
	m := matcher(t, []string{"/robots.txt", "/.well-known/*", "/feed*.xml"}, nil, nil)
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/robots.txt", true},
		{"/robots.txt2", false},
		{"/ROBOTS.TXT", false},                    // case-sensitive, like URLs
		{"/.well-known/acme-challenge/xyz", true}, // * crosses /
		{"/.well-known/", true},
		{"/.well-known", false},
		{"/feed.xml", true},
		{"/feed-atom.xml", true},
		{"/feed.xml.bak", false},
		{"/", false},
	} {
		if got := m.Path(tc.path); got != tc.want {
			t.Errorf("Path(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestIP(t *testing.T) {
	m := matcher(t, nil, []string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7"}, nil)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"203.0.113.55", true},
		{"203.0.114.1", false},
		{"2001:db8::1", true},
		{"2001:db9::1", false},
		{"198.51.100.7", true}, // bare address as /32
		{"198.51.100.8", false},
		{"::ffff:203.0.113.9", true}, // v4-mapped v6 unmaps
	} {
		if got := m.IP(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("IP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trusted []string
		remote  string
		xff     []string
		want    string
	}{
		{"no trusted proxies: peer wins, XFF ignored",
			nil, "192.0.2.9:1234", []string{"203.0.113.1"}, "192.0.2.9"},
		{"untrusted peer: XFF ignored even when configured",
			[]string{"10.0.0.0/8"}, "192.0.2.9:1234", []string{"203.0.113.1"}, "192.0.2.9"},
		{"trusted peer: rightmost untrusted hop wins",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", []string{"203.0.113.50, 10.2.2.2"}, "203.0.113.50"},
		{"spoofed left-hand entries do not matter",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", []string{"6.6.6.6, 203.0.113.50"}, "203.0.113.50"},
		{"multiple XFF headers are joined in order",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", []string{"6.6.6.6", "203.0.113.50, 10.9.9.9"}, "203.0.113.50"},
		{"all hops trusted: peer wins",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", []string{"10.5.5.5"}, "10.1.1.1"},
		{"garbage XFF from trusted proxy: fall back to peer",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", []string{"not-an-ip"}, "10.1.1.1"},
		{"no XFF at all from trusted peer: peer",
			[]string{"10.0.0.0/8"}, "10.1.1.1:80", nil, "10.1.1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := matcher(t, nil, nil, tc.trusted)
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			got, err := m.ClientIP(r)
			if err != nil {
				t.Fatalf("ClientIP: %v", err)
			}
			if got != netip.MustParseAddr(tc.want) {
				t.Errorf("ClientIP = %s, want %s", got, tc.want)
			}
		})
	}

	t.Run("unparseable RemoteAddr errors", func(t *testing.T) {
		m := matcher(t, nil, nil, nil)
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "@@@"
		if _, err := m.ClientIP(r); err == nil {
			t.Fatal("ClientIP accepted garbage RemoteAddr")
		}
	})
}
