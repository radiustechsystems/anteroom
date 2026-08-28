package hosted

import (
	"net/netip"
	"testing"
)

func TestClaim(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ua   string
		want Provider
	}{
		{"Claude web", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claude-user@anthropic.com)", Claude},
		{"ChatGPT web", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", ChatGPT},
		{"Google user-triggered agent", "Mozilla/5.0 (compatible; Google-Agent; +https://developers.google.com/crawling/docs/crawlers-fetchers/google-agent)", GoogleAgent},
		{"Claude Code", "Claude-User (claude-code/2.1.250; +https://support.anthropic.com/)", None},
		{"future Claude Code form", "Claude-User/1.0 (claude-code/2.2.0; +https://support.anthropic.com/)", None},
		{"embedded Claude token", "NotClaude-User/1.0", None},
		{"embedded ChatGPT token", "NotChatGPT-User/1.0", None},
		{"embedded Google token", "NotGoogle-Agent;", None},
		{"wrong-case Claude", "Mozilla/5.0 (compatible; claude-user/1.0)", None},
		{"wrong-case ChatGPT", "Mozilla/5.0 (compatible; Chatgpt-User/1.0)", None},
		{"wrong-case Google", "Mozilla/5.0 (compatible; google-agent)", None},
		{"Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", None},
		{"ordinary browser", "Mozilla/5.0 Chrome/152.0", None},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Claim(tc.ua); got != tc.want {
				t.Fatalf("Claim(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

func TestPublishedRangesAuthenticateTheirProvider(t *testing.T) {
	t.Parallel()
	set, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range definitions {
		provider := definition.provider
		t.Run(provider.String(), func(t *testing.T) {
			t.Parallel()
			if len(set.prefixes[provider]) == 0 {
				t.Fatal("embedded manifest has no ranges")
			}
			ip := set.prefixes[provider][0].Addr()
			if !set.Verify(provider, ip) {
				t.Fatalf("%s did not verify for %s", ip, provider)
			}
			if ip.Is4() && !set.Verify(provider, netip.AddrFrom16(ip.As16())) {
				t.Fatalf("IPv4-mapped %s did not verify for %s", ip, provider)
			}
			for other := range set.prefixes {
				if other != provider && set.Verify(other, ip) {
					t.Fatalf("%s for %s also verified as %s", ip, provider, other)
				}
			}
		})
	}
	if set.Verify(Claude, netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("TEST-NET address verified as Claude")
	}
}

func TestClaudeUsesBotAndStableOutboundRanges(t *testing.T) {
	t.Parallel()
	set, err := New()
	if err != nil {
		t.Fatal(err)
	}
	botRanges, err := parsePrefixes(claudeBotsJSON, claudeBotsURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{botRanges[0].Addr().String(), "160.79.104.1", "160.79.111.254"} {
		if !set.Verify(Claude, netip.MustParseAddr(ip)) {
			t.Errorf("published Claude address %s did not verify", ip)
		}
	}
	if set.Verify(Claude, netip.MustParseAddr("160.79.112.1")) {
		t.Error("address adjacent to Claude's stable outbound range verified")
	}
}
