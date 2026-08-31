package gate

import (
	"context"
	"net/http"
	"net/netip"

	"github.com/radiustechsystems/anteroom/internal/crawler"
)

type crawlerVerifier interface {
	Claim(string) string
	Verify(context.Context, string, netip.Addr) crawler.Verdict
}

// serveClaimedIdentity handles requests that claim a machine identity whose
// protocol is known not to be x402. A claim chooses verification and response
// shape; only an authenticated source can bypass the gate.
func (g *Gate) serveClaimedIdentity(w http.ResponseWriter, r *gateRequest) (decision, bool) {
	claim := r.facts.crawlerClaim
	if claim == "" {
		return 0, false
	}
	if !r.clientIP.IsValid() {
		// Verification cannot run without a resolved peer. Fall back to the
		// ordinary ladder rather than telling a real crawler the site is
		// temporarily unavailable forever because of local proxy config.
		g.warnIdentityIP(r.Request)
		return 0, false
	}
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
