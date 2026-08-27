// Package bypass decides which traffic is never challenged: exempted paths,
// always-allowed CIDR ranges, and (with them) the client-IP question itself —
// who the peer really is when trusted proxies sit in front of the gate.
package bypass

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Matcher answers "does this request bypass the gate?".
type Matcher struct {
	paths   []string
	cidrs   []netip.Prefix
	trusted []netip.Prefix
}

// New compiles the bypass lists. Patterns use a single-`*` glob where `*`
// matches any run of characters, including `/` — "/.well-known/*" therefore
// covers nested paths. Invalid CIDRs fail loudly at load, not at match time.
func New(paths []string, cidrs, trustedProxies []string) (*Matcher, error) {
	m := &Matcher{paths: paths}
	for _, pat := range paths {
		if strings.Count(pat, "*") > 1 {
			return nil, fmt.Errorf("bypass: path pattern %q has more than one *", pat)
		}
		if !strings.HasPrefix(pat, "/") {
			return nil, fmt.Errorf("bypass: path pattern %q must start with /", pat)
		}
	}
	var err error
	if m.cidrs, err = parsePrefixes(cidrs); err != nil {
		return nil, fmt.Errorf("bypass: cidrs: %w", err)
	}
	if m.trusted, err = parsePrefixes(trustedProxies); err != nil {
		return nil, fmt.Errorf("bypass: trusted_proxies: %w", err)
	}
	return m, nil
}

func parsePrefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Accept bare addresses as /32 (v4) or /128 (v6) — operators list
			// single machines more often than ranges.
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("%q is neither a CIDR nor an address", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Path reports whether reqPath matches any exempted pattern.
func (m *Matcher) Path(reqPath string) bool {
	for _, pat := range m.paths {
		if matchGlob(pat, reqPath) {
			return true
		}
	}
	return false
}

// matchGlob matches pat against s where a single `*` matches any run of
// characters (including `/`). No `*` means exact match.
func matchGlob(pat, s string) bool {
	pre, post, ok := strings.Cut(pat, "*")
	if !ok {
		return pat == s
	}
	return len(s) >= len(pre)+len(post) && strings.HasPrefix(s, pre) && strings.HasSuffix(s, post)
}

// IP reports whether addr is inside an always-allowed range.
func (m *Matcher) IP(addr netip.Addr) bool {
	return contains(m.cidrs, addr)
}

func contains(ps []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// TrustedPeer reports whether the request's socket peer is a configured
// trusted proxy — i.e. whether its X-Forwarded-* headers may be believed.
func (m *Matcher) TrustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return contains(m.trusted, a)
}

// ClientIP resolves the request's client address. The socket peer is the
// client — unless the peer is a trusted proxy, in which case the rightmost
// X-Forwarded-For hop not belonging to a trusted proxy is the client (the
// rightmost value is the only one a trusted proxy actually observed; anything
// left of it is attacker-controllable).
func (m *Matcher) ClientIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // no port (some tests / unix sockets)
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("bypass: unparseable RemoteAddr %q", r.RemoteAddr)
	}
	peer = peer.Unmap()
	if !contains(m.trusted, peer) {
		return peer, nil
	}
	// Walk X-Forwarded-For right to left past trusted hops.
	hops := splitXFF(r.Header.Values("X-Forwarded-For"))
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			// Garbage in XFF from a trusted proxy: stop believing the header.
			return peer, nil
		}
		a = a.Unmap()
		if !contains(m.trusted, a) {
			return a, nil
		}
	}
	// Every hop was a trusted proxy — the nearest one is the best answer.
	return peer, nil
}

func splitXFF(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
