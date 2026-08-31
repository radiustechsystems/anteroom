package gate

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// requestFacts is the immutable, header-derived view of a request. Parsing it
// once keeps admission, response presentation, and HTML injection from growing
// subtly different definitions of the same client.
type requestFacts struct {
	userAgent    string
	navigation   bool
	preflight    bool
	crawlerClaim string
}

// gateRequest adds facts that need Gate state to resolve. Embedding the ordinary
// request keeps internal handler signatures small without hiding net/http.
type gateRequest struct {
	*http.Request
	facts requestFacts

	clientIP netip.Addr
	audience string
	route    *paidRoute
}

func (g *Gate) inspect(r *http.Request) *gateRequest {
	ip, err := g.match.ClientIP(r)
	if err != nil {
		ip = netip.Addr{}
	}
	q := &gateRequest{
		Request:  r,
		facts:    inspectRequest(r, g.crawlers.Claim(r.Header.Get("User-Agent"))),
		clientIP: ip,
		audience: requestAudience(r),
	}
	if g.paymentsEnabled() {
		if route, ok := g.matchRoute(r.URL.Path); ok {
			q.route = route
		}
	}
	return q
}

func inspectRequest(r *http.Request, crawlerClaim string) requestFacts {
	accept := parseAccept(r.Header.Get("Accept"))
	facts := requestFacts{
		userAgent:    r.Header.Get("User-Agent"),
		preflight:    isCORSPreflight(r),
		crawlerClaim: crawlerClaim,
	}
	facts.navigation = classifyNavigation(r, facts, accept, isFragmentRequest(r))
	return facts
}

// classifyNavigation decides who gets the wait page and who gets the
// machine-readable refusal. Both mistakes are expensive: HTML gives a program
// a solver it cannot run, while a refusal gives a person no way through. Fetch
// metadata is therefore obeyed where decisive and corroborated where browsers
// are known to rewrite it.
//
// Measured clients that must not become navigations include Claude Code
// (`Accept: text/markdown, text/html, */*`) and agent fetchers that rank
// markdown above HTML. A bare "Accept contains text/html" test misclassifies
// both. A q=0 offer is explicitly unacceptable and does not count.
func classifyNavigation(r *http.Request, facts requestFacts, accept acceptPreferences, fragment bool) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if facts.crawlerClaim != "" || fragment || accept.prefersMarkdown() {
		return false
	}
	// A subresource is never a navigation. "empty" remains eligible because a
	// site's service worker can re-issue a top-level navigation with an empty
	// destination; an ordinary XHR has the same value, so Accept and UA must
	// separate them below.
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "", "document", "empty":
	default:
		return false
	}
	switch r.Header.Get("Sec-Fetch-Mode") {
	case "navigate":
		return true
	case "", "same-origin":
		// Missing metadata covers older browsers. "same-origin" is also the
		// Firefox service-worker lockout case: fetch(event.request) rewrites a
		// real top-level navigation from mode=navigate to same-origin. Requiring
		// both acceptable HTML and a Mozilla UA admits that person without
		// turning the ordinary `fetch()` shape (`Accept: */*`) into a page load.
		return accept.offersHTML() && strings.Contains(facts.userAgent, "Mozilla")
	default:
		// cors, no-cors, websocket: programmatic by construction.
		return false
	}
}

func isFragmentRequest(r *http.Request) bool {
	if r.Header.Get("HX-Request") != "" || r.Header.Get("Turbo-Frame") != "" || r.Header.Get("Turbo-Request-ID") != "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Requested-With")), "XMLHttpRequest")
}

type mediaPreference struct {
	q       float64
	order   int
	offered bool
}

type acceptPreferences struct {
	html     mediaPreference
	markdown mediaPreference
}

func parseAccept(value string) acceptPreferences {
	var a acceptPreferences
	for i, part := range strings.Split(value, ",") {
		media, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		media = strings.ToLower(strings.TrimSpace(media))
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			key, raw, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
				q = parsed
			}
		}
		var dst *mediaPreference
		switch media {
		case "text/html":
			dst = &a.html
		case "text/markdown":
			dst = &a.markdown
		default:
			continue
		}
		if !dst.offered || q > dst.q {
			*dst = mediaPreference{q: q, order: i, offered: true}
		}
	}
	return a
}

func (a acceptPreferences) offersHTML() bool {
	return a.html.offered && a.html.q > 0
}

func (a acceptPreferences) prefersMarkdown() bool {
	if !a.markdown.offered || a.markdown.q <= 0 {
		return false
	}
	if !a.html.offered || a.html.q <= 0 {
		return true
	}
	if a.markdown.q != a.html.q {
		return a.markdown.q > a.html.q
	}
	return a.markdown.order < a.html.order
}

// isBrowserNav is the configuration-free test/injection view. Production uses
// Gate.inspect, which also supplies any claim from configured crawler providers.
func isBrowserNav(r *http.Request) bool { return inspectRequest(r, "").navigation }

func prefersMarkdown(value string) bool { return parseAccept(value).prefersMarkdown() }

func looksLikeBrowserHTML(r *http.Request, value string) bool {
	return parseAccept(value).offersHTML() && strings.Contains(r.Header.Get("User-Agent"), "Mozilla")
}
