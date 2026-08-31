// Package hosted authenticates user-triggered fetchers operated by AI vendors.
// It identifies a claim from the User-Agent, then verifies the source address
// against that vendor's published ranges. It does not decide whether the
// request is admitted; that policy belongs to the gate.
package hosted

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/radiustechsystems/anteroom/internal/useragent"
)

// Provider is a stable hosted-fetcher identity claimed in a User-Agent.
type Provider string

const (
	None        Provider = ""
	Claude      Provider = "claude"
	ChatGPT     Provider = "chatgpt"
	GoogleAgent Provider = "google-agent"
)

type definition struct {
	provider Provider
	token    string
	sources  []rangeSource
}

type rangeSource struct {
	raw []byte
	url string
}

var definitions = [...]definition{
	{
		provider: Claude,
		token:    "Claude-User/",
		sources: []rangeSource{
			{raw: claudeBotsJSON, url: claudeBotsURL},
			{raw: claudeOutboundJSON, url: claudeOutboundURL},
		},
	},
	{
		provider: ChatGPT,
		token:    "ChatGPT-User/",
		sources:  []rangeSource{{raw: chatGPTUserJSON, url: chatGPTUserURL}},
	},
	{
		provider: GoogleAgent,
		token:    "Google-Agent;",
		sources:  []rangeSource{{raw: googleAgentJSON, url: googleAgentURL}},
	},
}

// Set is the immutable collection of published hosted-fetcher ranges.
type Set struct {
	prefixes map[Provider][]netip.Prefix
}

// New parses every embedded range snapshot. A malformed generated file is a
// startup error rather than an identity check that silently stops working.
func New() (*Set, error) {
	s := &Set{prefixes: make(map[Provider][]netip.Prefix, len(definitions))}
	for _, d := range definitions {
		for _, source := range d.sources {
			prefixes, err := parsePrefixes(source.raw, source.url)
			if err != nil {
				return nil, err
			}
			s.prefixes[d.provider] = append(s.prefixes[d.provider], prefixes...)
		}
	}
	return s, nil
}

// Claim identifies a known hosted-fetcher User-Agent. It is deliberately
// unauthoritative: a claim changes presentation, never access, until Verify
// authenticates its source address.
func Claim(userAgent string) Provider {
	for _, d := range definitions {
		// Claude Code is a command-line agent that can follow Anteroom's x402
		// instructions. Never let a future UA variant containing Claude-User/
		// move it onto the hosted fetcher's strict non-x402 path.
		if d.provider == Claude && strings.Contains(userAgent, "claude-code/") {
			continue
		}
		if useragent.ContainsProduct(userAgent, d.token) {
			return d.provider
		}
	}
	return None
}

func (p Provider) String() string {
	return string(p)
}

// Verify reports whether addr belongs to the published ranges for claim.
func (s *Set) Verify(claim Provider, addr netip.Addr) bool {
	if s == nil || claim == None || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.prefixes[claim] {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePrefixes(raw []byte, source string) ([]netip.Prefix, error) {
	var document struct {
		Prefixes []struct {
			IPv4 string `json:"ipv4Prefix"`
			IPv6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("hosted: parsing %s: %w", source, err)
	}
	if len(document.Prefixes) == 0 {
		return nil, fmt.Errorf("hosted: %s contains no prefixes", source)
	}
	prefixes := make([]netip.Prefix, 0, len(document.Prefixes))
	for _, item := range document.Prefixes {
		if (item.IPv4 == "") == (item.IPv6 == "") {
			return nil, fmt.Errorf("hosted: %s prefix entry must contain exactly one address family", source)
		}
		rawPrefix := item.IPv4
		if rawPrefix == "" {
			rawPrefix = item.IPv6
		}
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err != nil {
			return nil, fmt.Errorf("hosted: bad prefix %q from %s: %w", rawPrefix, source, err)
		}
		if (item.IPv4 != "") != prefix.Addr().Is4() {
			return nil, fmt.Errorf("hosted: prefix %q from %s is under the wrong address family", rawPrefix, source)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
