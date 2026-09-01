package gate

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/radiustechsystems/anteroom/internal/crawler"
	"github.com/radiustechsystems/anteroom/internal/hosted"
)

type crawlerVerifier interface {
	Claim(string) string
	Verify(context.Context, string, netip.Addr) crawler.Verdict
}

type hostedVerifier interface {
	Verify(hosted.Provider, netip.Addr) bool
}

// serveClaimedIdentity handles requests that claim a machine identity whose
// protocol is known not to be x402. A claim chooses verification and response
// shape; only an authenticated source can bypass the gate.
func (g *Gate) serveClaimedIdentity(w http.ResponseWriter, r *gateRequest) (decision, bool) {
	if !r.clientIP.IsValid() && (r.facts.crawlerClaim != "" || r.facts.hostedClaim != hosted.None) {
		// Verification cannot run without a resolved peer. Fall back to the
		// ordinary ladder rather than telling a real provider the site is
		// temporarily unavailable forever because of local proxy config.
		g.warnIdentityIP(r.Request)
		return 0, false
	}

	if claim := r.facts.crawlerClaim; claim != "" {
		switch g.crawlers.Verify(r.Context(), claim, r.clientIP) {
		case crawler.Verified:
			r.Header.Set("X-Anteroom-Status", "bypass-crawler-"+claim)
			g.forward(w, r.Request)
			return decisionBypassCrawler, true
		case crawler.Indeterminate:
			serveCrawlerVerificationUnavailable(w)
			return decisionCrawlerVerificationUnavailable, true
		default:
			g.serveStrictRefusal(w, r.Request)
			return decisionCrawlerUnverified, true
		}
	}

	if claim := r.facts.hostedClaim; claim != hosted.None {
		verified := g.hosted.Verify(claim, r.clientIP)
		if verified && g.cfg.Triage.AllowHostedFetchers {
			r.Header.Set("X-Anteroom-Status", "bypass-hosted-"+claim.String())
			g.forward(w, r.Request)
			return decisionBypassHosted, true
		}
		g.serveStrictRefusal(w, r.Request)
		if verified {
			return decisionHostedRefusal, true
		}
		return decisionHostedUnverified, true
	}

	return 0, false
}
