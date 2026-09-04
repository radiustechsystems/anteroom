// Package gate is Anteroom's request path: the decision ladder, the reverse
// proxy, the wait page, and the gate's own endpoints under /.anteroom/.
//
//	own endpoints → bypass → valid pass → challenge/refusal
//
// Everything the gate serves itself is marked no-store; everything a pass
// unlocks flows to the upstream byte-for-byte.
package gate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radiustechsystems/anteroom/internal/activity"
	"github.com/radiustechsystems/anteroom/internal/bypass"
	"github.com/radiustechsystems/anteroom/internal/challenge"
	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/crawler"
	"github.com/radiustechsystems/anteroom/internal/hosted"
	"github.com/radiustechsystems/anteroom/internal/metrics"
	"github.com/radiustechsystems/anteroom/internal/payment"
	"github.com/radiustechsystems/anteroom/internal/token"
)

// cookieName carries the pass. One cookie, HttpOnly; the renewal machinery
// never needs to read it — expiry travels in answer responses.
const cookieName = "anteroom_pass"

// prefix is the gate's own URL namespace. It is never proxied, which is what
// keeps the service worker and challenge API reachable without a pass.
const prefix = "/.anteroom/"

// Gate is the http.Handler in front of the upstream.
type Gate struct {
	cfg         *config.Config
	lg          *slog.Logger
	upstream    http.Handler
	keyring     *token.Keyring
	issuer      *challenge.Issuer
	admit       challenge.Profile
	renew       challenge.Profile
	match       *bypass.Matcher
	publicHosts map[string]struct{}
	routes      []paidRoute
	pages       *pageSource
	now         func() time.Time
	met         *gateMetrics
	crawlers    crawlerVerifier
	hosted      hostedVerifier

	// The challenge-activity log for external ban tooling. Nil when the
	// [activity] section is unconfigured — every Record call no-ops on nil,
	// so the free path pays nothing when it is off.
	activity *activity.Log

	// skipReported remembers which injection-skip reasons have already been
	// warned about, so each is stated once per process rather than once per
	// request. See noteInjectionSkipped.
	skipReported sync.Map

	// The wait page's solver, assembled once at construction because its
	// contents depend on allow_insecure_context, and served from its own URL
	// rather than inlined. solverURL carries a content hash so the bundle can
	// be cached forever and still change the moment the binary does.
	solverJS  []byte
	solverURL string

	// The pay door. All nil when payments are unconfigured, and nothing on the
	// free path ever reads them: proof-of-work admission makes no external call,
	// which is why a facilitator outage is never a site outage.
	// verifiers maps a rail's CAIP-2 network — unique per rail, enforced by
	// config — to the verifier for that rail's facilitator. Rails sharing a
	// facilitator identity (URL + headers) share a verifier and therefore a
	// breaker; distinct facilitators fail independently. The durable grant store
	// and client limiter deliberately stay gate-wide: one authorization has one
	// claim no matter which facilitator settles its rail.
	verifiers map[string]payment.Verifier
	grants    *payment.GrantStore
	payLimit  *payment.Limiter

	identityIPWarning sync.Once
}

// New builds a Gate from validated config.
func New(cfg *config.Config, lg *slog.Logger) (*Gate, error) {
	if lg == nil {
		lg = slog.Default()
	}
	rawKeys, err := cfg.Keys()
	if err != nil {
		return nil, err
	}
	tks := make([]token.Key, len(rawKeys))
	chs := make([]challenge.Key, len(rawKeys))
	for i, k := range rawKeys {
		tks[i] = token.Key{Kid: k.Kid, Key: k.Key}
		chs[i] = challenge.Key{Kid: k.Kid, Key: k.Key}
	}
	keyring, err := token.NewKeyring(tks)
	if err != nil {
		return nil, err
	}
	issuer, err := challenge.NewIssuer(chs)
	if err != nil {
		return nil, err
	}
	at, err := challenge.Threshold(cfg.Difficulty)
	if err != nil {
		return nil, err
	}
	rt, err := challenge.Threshold(cfg.RenewDifficulty)
	if err != nil {
		return nil, err
	}
	admit := challenge.Profile{Kind: challenge.KindAdmit, TTL: cfg.PassTTL.D(), Threshold: at}
	renew := challenge.Profile{Kind: challenge.KindRenew, TTL: cfg.PassTTL.D(), Threshold: rt}
	match, err := bypass.New(cfg.Bypass.Paths, cfg.Bypass.CIDRs, cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	routes, err := compilePaidRoutes(cfg.Payments)
	if err != nil {
		return nil, err
	}
	publicHosts := make(map[string]struct{}, len(cfg.PublicHosts))
	for _, authority := range cfg.PublicHosts {
		publicHosts[normalizeAuthority(authority)] = struct{}{}
	}
	u, err := cfg.UpstreamURL()
	if err != nil {
		return nil, err
	}
	met := newGateMetrics()
	crawlers, err := crawler.New(cfg.Bypass.VerifiedCrawlers)
	if err != nil {
		return nil, err
	}
	crawlers.RegisterMetrics(met.registry)
	hostedFetchers, err := hosted.New()
	if err != nil {
		return nil, err
	}
	g := &Gate{
		cfg:         cfg,
		lg:          lg,
		upstream:    newProxy(u, cfg.UpstreamSocket(), match, lg, met.upstreamErr),
		keyring:     keyring,
		issuer:      issuer,
		admit:       admit,
		renew:       renew,
		match:       match,
		publicHosts: publicHosts,
		routes:      routes,
		pages:       newPageSource(cfg.Pages),
		now:         time.Now,
		met:         met,
		crawlers:    crawlers,
		hosted:      hostedFetchers,
	}
	g.solverJS, g.solverURL = buildSolver(cfg.AllowInsecureContext)
	if cfg.Payments != nil {
		// One verifier (and so one breaker) per distinct facilitator
		// identity. Same URL with different headers is two identities —
		// different credentials mean independent failure domains.
		groups := make(map[string]*payment.CallbackVerifier)
		bases := make([]string, 0, 2)
		g.verifiers = make(map[string]payment.Verifier, len(cfg.Payments.Rails))
		for _, rl := range cfg.Payments.Rails {
			key := facilitatorIdentity(rl.Facilitator, rl.FacilitatorHeader)
			if groups[key] == nil {
				br := payment.NewBreaker(breakerThreshold, breakerWindow, breakerCooldown)
				groups[key] = payment.NewCallbackVerifier(rl.Facilitator, rl.FacilitatorHeader, lg, br)
				bases = append(bases, rl.Facilitator)
			}
			g.verifiers[rl.Network] = groups[key]
		}
		g.grants, err = payment.NewGrantStore(cfg.Payments.StateFile)
		if err != nil {
			return nil, err
		}
		g.payLimit = payment.NewLimiter(6, 6)
		lg.Info("payment rails configured", "facilitators", bases, "rails", len(cfg.Payments.Rails))
		lg.Info("payment grants use durable state", "path", cfg.Payments.StateFile)
	}

	if cfg.Activity != nil {
		g.activity = activity.New(cfg.Activity.TTL.D(), cfg.Activity.MaxIPs)
		// The gauge is a bare count and carries no addresses — the metrics
		// surface stays per-visitor free; the IPs themselves live only on the
		// admin /activity endpoint. Registered here rather than in
		// newGateMetrics so the family is absent entirely when the log is off.
		met.registry.GaugeFunc("anteroom_tracked_ips",
			"IPs currently in the challenge-activity log ([activity] section). Count only; the addresses are served at the admin /activity endpoint.",
			func() float64 { return float64(g.activity.Len()) })
		lg.Info("challenge-activity log enabled",
			"ttl", cfg.Activity.TTL.D().String(), "max_ips", cfg.Activity.MaxIPs)
	}

	if cfg.KeyAutoGenerated {
		lg.Warn("hmac key auto-generated for this process only",
			"consequence", "passes will not survive a restart and no other instance can verify them",
			"fix", "set [[hmac_keys]] in anteroom.toml (openssl rand -base64 32), same key(s) on every instance")
	}
	if cfg.AllowInsecureContext {
		lg.Warn("allow_insecure_context is on: shipping the JavaScript SHA-256 fallback",
			"consequence", "visitors without WebCrypto hash 10-50x slower than an attacker's native code, and service-worker renewal is unavailable so they re-solve after the pass lapses",
			"appropriate_for", "LAN and development deployments reached over plain HTTP",
			"fix", "serve Anteroom behind TLS and turn this off")
	}
	if !cfg.Inject {
		lg.Warn("inject is off: nothing renews a pass after the wait page",
			"consequence", "every visitor is re-challenged on the first navigation after pass_ttl ("+cfg.PassTTL.D().String()+") elapses, for as long as they browse",
			"appropriate_for", "sites that cannot accept a byte of rewriting, or that drive renewal themselves",
			"fix", "leave inject = true, or raise pass_ttl to match how long a visit lasts")
	}
	return g, nil
}

// facilitatorIdentity keys verifier sharing: rails whose facilitator URL and
// headers are identical share one verifier and breaker. NUL joins because it
// cannot appear in a validated URL or header, so distinct configs cannot
// collide by concatenation.
func facilitatorIdentity(base string, h http.Header) string {
	var b strings.Builder
	b.WriteString(strings.TrimSuffix(base, "/"))
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, v := range h[k] {
			b.WriteString("\x00")
			b.WriteString(k)
			b.WriteString("\x00")
			b.WriteString(v)
		}
	}
	return b.String()
}

// clientIPHeaders are vendor client-IP conventions that Go's SetXForwarded does
// not manage. An upstream configured the nginx way trusts X-Real-IP, so a
// client-supplied copy would let an attacker pick their own address for the
// upstream's allowlists, logs, and rate limits. All are dropped; the gate then
// re-states the one answer it actually computed.
var clientIPHeaders = []string{
	"X-Real-IP",
	"CF-Connecting-IP",
	"True-Client-IP",
	"X-Client-IP",
	"Fastly-Client-IP",
	"X-Cluster-Client-IP",
	"X-Original-Forwarded-For",
}

// newProxy builds the reverse proxy: Host preserved, X-Forwarded-* set to the
// resolved client, immediate flush so SSE/streaming pass through untouched.
// newProxy builds the reverse proxy. socket, when non-empty, is a unix socket
// path to dial instead of a TCP address.
func newProxy(u *url.URL, socket string, m *bypass.Matcher, lg *slog.Logger, upstreamErr *metrics.Counter) http.Handler {
	p := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			r.SetXForwarded() // also strips inbound Forwarded/X-Forwarded-*
			for _, h := range clientIPHeaders {
				r.Out.Header.Del(h)
			}
			// SetXForwarded reports the socket peer, which behind a trusted
			// proxy is the proxy itself — tell the upstream who the visitor
			// actually is, using the same resolution the gate's own policy used.
			if ip, err := m.ClientIP(r.In); err == nil {
				r.Out.Header.Set("X-Forwarded-For", ip.String())
				r.Out.Header.Set("X-Real-IP", ip.String())
			}
			// Likewise for the scheme. SetXForwarded derives
			// X-Forwarded-Proto from OUR inbound connection, which behind a TLS
			// terminator is the plaintext hop from the terminator to us — so it
			// would tell the upstream "http" about a request the visitor made
			// over HTTPS, overwriting the terminator's correct header. That is
			// the classic proxy bug: WordPress then builds http:// URLs,
			// Django and Rails see an insecure request and redirect to https,
			// and the redirect loops. We already resolved this question for the
			// cookie's Secure flag; the upstream gets the same answer.
			if requestIsTLS(m, r.In) {
				r.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Out.Header.Set("X-Forwarded-Proto", "http")
			}
			// Transparent proxy semantics: the upstream sees the visitor's
			// Host, not ours.
			r.Out.Host = r.In.Host
		},
		ModifyResponse: func(r *http.Response) error {
			// This response marker belongs to the gate. An upstream copy would
			// make ordinary application content look like an interdiction.
			r.Header.Del(actionHeader)
			return nil
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			upstreamErr.Inc()
			lg.ErrorContext(r.Context(), "upstream unreachable", "err", err, "path", r.URL.Path)
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
		},
	}
	p.Transport = upstreamTransport(socket)
	return p
}

// upstreamIdleConns is how many idle keep-alive connections the proxy holds
// open to the upstream. It exists because Go's DefaultTransport keeps two: with
// a single upstream host, that means every request beyond the second in flight
// opens a TCP connection and closes it afterwards. Under a few thousand
// requests per second that is tens of thousands of TIME_WAIT sockets, several
// cores of kernel time, and eventually failed connects served as 502 — the
// first ceiling a load test finds, and one that has nothing to do with the
// gate's own work.
//
// The pool grows to the peak concurrency actually seen and no further; an idle
// connection costs the upstream one open socket and a few kilobytes. 512 is
// far above the concurrency a single gate sees before it saturates on CPU, and
// far below where an application server's connection limit becomes the
// operator's concern.
const upstreamIdleConns = 512

// upstreamTransport is the proxy's connection pool. socket, when non-empty, is
// a unix socket path to dial instead of the URL's TCP address; everything else
// — the request line, headers, and streaming behaviour — is identical on both
// paths, so nothing downstream needs to know which one it is.
func upstreamTransport(socket string) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 0 // no total cap: there is one host, and the per-host cap is the limit
	t.MaxIdleConnsPerHost = upstreamIdleConns
	if socket != "" {
		t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}
	}
	return t
}

// ServeHTTP walks the ladder. Every request runs through the recorder so the
// throughput counters can attribute its response bytes to the rung that
// answered; the recorder forwards Flush and exposes Unwrap, so streaming and
// hijacking behave exactly as with a bare ResponseWriter. With debug logging on
// (`anteroom -v`) it also reports one line per request: which rung answered,
// and what the visitor got.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.met.inFlight.Inc()
	defer g.met.inFlight.Dec()
	verbose := g.lg.Enabled(r.Context(), slog.LevelDebug)
	var start time.Time
	if verbose {
		start = g.now()
	}
	rec := &recorder{ResponseWriter: w, status: http.StatusOK}
	request := g.inspect(r)
	d := g.serve(rec, request)
	g.met.requests.With(d.String()).Inc()
	g.met.countBytes(d, uint64(rec.n))
	g.recordDecision(d, request)
	if !verbose {
		return
	}
	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"decision", d.String(),
		"status", rec.status,
		"bytes", rec.n,
		"dur", g.now().Sub(start).Round(time.Microsecond).String(),
	}
	if request.clientIP.IsValid() {
		attrs = append(attrs, "ip", request.clientIP.String())
	}
	if ua := request.facts.userAgent; ua != "" {
		attrs = append(attrs, "ua", ua)
	}
	g.lg.DebugContext(request.Context(), "hit", attrs...)
}

// serve is the ladder proper. It returns the name of the rung that answered, for
// logging; the name is also the vocabulary the docs use to describe the ladder.
func (g *Gate) serve(w http.ResponseWriter, q *gateRequest) decision {
	r := q.Request
	// Strip headers the gate itself authors: an inbound copy is a forgery
	// attempt, and the upstream must only ever see ours.
	r.Header.Del("X-Anteroom-Status")
	r.Header.Del(actionHeader)
	// Also gate-authored, and both are response headers: an inbound copy is a
	// forgery attempt. PAYMENT-REQUIRED matters as much as PAYMENT-RESPONSE —
	// an upstream that logs or echoes one would be quoting an offer with a
	// payTo the client chose.
	r.Header.Del(payment.HeaderResponse)
	r.Header.Del(payment.HeaderRequired)

	// 0. Refuse un-normalized paths outright. A pattern like "/.well-known/*"
	// must not admit "/.well-known/../admin" — and since upstreams normalize
	// dot-segments, matching on the raw path would be an auth bypass. Rejecting
	// (rather than silently rewriting) keeps one canonical form on the wire and
	// avoids proxying a path the operator never audited. Backslashes count as
	// separators too: a Windows/IIS upstream resolves "/pub/\..\admin", so a
	// glob that matched it here would be the same bypass.
	if p := r.URL.Path; p != cleanPath(p) || strings.Contains(p, `\`) {
		noStore(w)
		http.Error(w, "bad request: non-canonical path", http.StatusBadRequest)
		return decisionNonCanonicalPath
	}

	// An authority allowlist is a deployment boundary, so it precedes every
	// admission and bypass decision. Otherwise wildcard DNS or a forwarded Host
	// can reach an unintended upstream vhost after earning an ordinary pass.
	// Health is content-free and remains reachable to a local orchestrator whose
	// probe authority is necessarily the container's loopback address.
	if r.URL.Path != HealthPath && len(g.publicHosts) > 0 {
		if _, ok := g.publicHosts[q.audience]; !ok {
			noStore(w)
			http.Error(w, "misdirected request: authority is not served here", http.StatusMisdirectedRequest)
			return decisionUnknownAuthority
		}
	}

	// 1. The gate's own endpoints — never proxied, never gated.
	if strings.HasPrefix(r.URL.Path, prefix) {
		g.serveOwn(w, r)
		return decisionOwnEndpoint
	}

	// 2. Bypass: exempted paths and always-allowed ranges. Never injected into —
	// a bypass exists because something needs the bytes untouched.
	if g.match.Path(r.URL.Path) {
		g.forward(w, r)
		return decisionBypassPath
	}
	if q.clientIP.IsValid() && g.match.IP(q.clientIP) {
		g.forward(w, r)
		return decisionBypassIP
	}

	// 2b. A CORS preflight goes upstream. Not a concession — a preflight is
	// unauthenticated by specification: the browser sends it without cookies,
	// so it can never carry a pass and challenging it can never do anything but
	// fail. The visible result is that every cross-origin application behind
	// the gate breaks, permanently, with a browser error that names CORS rather
	// than Anteroom.
	//
	// What travels is a policy question and a policy answer. The browser
	// discards the body, and the request the preflight is asking about is still
	// on the ladder like anything else — a cross-origin fetch without a pass is
	// still walled. What this gives up is that an unauthenticated client can
	// make the upstream answer OPTIONS, which is a cheap handler and no content.
	if q.facts.preflight {
		g.forward(w, r)
		return decisionCORSPreflight
	}

	// 3. Authenticate claimed machine identities before passes and payment.
	// Their protocols cannot complete x402, so spoofed claims fail closed.
	if d, handled := g.serveClaimedIdentity(w, q); handled {
		return d
	}

	// 4. A valid pass whose scope covers this path.
	if p, ok := g.validPass(r); ok && g.scopeCovers(p, r.URL.Path) {
		r.Header.Set("X-Anteroom-Status", "pass-"+string(p.Kind))
		g.stripPassCookie(r)
		if p.Kind == token.KindPaid {
			// Everything a paid pass opens is paid content, not just the one
			// request that carried the payment. The seal has to be here as well
			// as on the presentation, or the second request for the same report
			// keeps the upstream's `public, max-age=3600` and a shared cache
			// hands it to people who never paid. No settlement happened on this
			// request, so there is no receipt to re-state — and an upstream copy
			// of one is deleted rather than forwarded.
			g.forward(&paidWriter{ResponseWriter: w}, r)
			return decisionPassPaid
		}
		g.servePoWUpstream(w, q)
		return decisionPassPoW
	}

	// 4. No pass. A presented payment is tried first, then the client class
	// decides: browsers get the wait page, everything else the machine-readable
	// refusal — which carries the payment offer when the pay door is open.
	//
	// A payment may arrive with no preceding 402, because clients cache
	// requirements per route and pre-attach payment to the first request. That
	// is an ordinary presentation, not a protocol error and not a replay:
	// requirements are re-derived from the matched rule, never from anything
	// the gate remembers issuing.
	if g.paymentsEnabled() {
		if route := q.route; route != nil {
			if values := r.Header.Values(payment.HeaderSignature); len(values) > 0 {
				if len(values) != 1 {
					g.servePaymentRequired(w, r, &route.rule,
						"exactly one PAYMENT-SIGNATURE header is required", 0)
					return decisionPayMalformed
				}
				return g.servePayment(w, r, route, values[0])
			}
			if !q.facts.navigation {
				g.servePaymentRequired(w, r, &route.rule, "PAYMENT-SIGNATURE header is required", 0)
				return decisionPaymentRequired
			}
		}
	}
	if q.facts.navigation {
		g.serveWaitPage(w, r)
		return decisionWaitPage
	}
	g.serveRefusal(w, r)
	return decisionRefusal
}

func (g *Gate) warnIdentityIP(r *http.Request) {
	g.identityIPWarning.Do(func() {
		g.lg.WarnContext(r.Context(), "machine identity verification skipped: client IP unavailable",
			"remote_addr", r.RemoteAddr)
	})
}

// serveUpstream proxies an admitted request, injecting the renewal script into
// HTML documents when the operator left `inject` on.
//
// Identity encoding is requested only for requests that could carry an injection,
// so everything else — assets, API calls, downloads — keeps its compression.
func (g *Gate) servePoWUpstream(w http.ResponseWriter, r *gateRequest) {
	if !g.cfg.Inject {
		g.forward(w, r.Request)
		return
	}
	if !injectableRequest(r.Request, r.facts.navigation) {
		// Browser navigations should always be injectable; report any disagreement
		// because it admits the page without equipping it for renewal.
		if r.Method == http.MethodGet && r.facts.navigation {
			g.noteInjectionSkipped(r.Request, "request-shape-not-injectable")
		}
		g.forward(w, r.Request)
		return
	}
	r.Header.Set("Accept-Encoding", "identity")
	iw := newInjector(w, func(reason string) { g.noteInjectionSkipped(r.Request, reason) })
	g.forward(iw, r.Request)
	iw.finish()
}

// forward is the only path to the reverse proxy. Gate credentials are removed
// for paid, PoW, bypass, and CORS admissions alike.
func (g *Gate) forward(w http.ResponseWriter, r *http.Request) {
	g.stripPassCookie(r)
	r.Header.Del(payment.HeaderSignature)
	r.Header.Del(payment.HeaderRequired)
	r.Header.Del(payment.HeaderResponse)
	g.upstream.ServeHTTP(w, r)
}

// noteInjectionSkipped logs every skipped injection at debug level and warns
// once per reason, avoiding per-request warning noise from persistent policies.
func (g *Gate) noteInjectionSkipped(r *http.Request, reason string) {
	g.lg.DebugContext(r.Context(), "renewal script not injected", "reason", reason, "path", r.URL.Path)
	if _, seen := g.skipReported.LoadOrStore(reason, struct{}{}); seen {
		return
	}
	g.lg.WarnContext(r.Context(), "renewal script not injected — visitors reading these pages will lapse and be re-challenged",
		"reason", reason,
		"example_path", r.URL.Path,
		"consequence", "the pass is not renewed from this response, so the visitor is walled again when it expires",
		"fix", "docs/operating.md, \"Guidance for HTML injection and CSP\"",
		"note", "reported once per reason; run with -v for one line per request")
}

// recorder captures the status and size of a response, for the throughput
// counters and the verbose log. It forwards Flush and exposes Unwrap so
// http.ResponseController can still reach the real writer for hijacking and
// deadlines — a recorder that swallowed those would break WebSockets and
// server-sent events. Bytes moved on a connection after a hijack bypass it,
// which is why the byte counters exclude post-upgrade traffic.
type recorder struct {
	http.ResponseWriter
	status int
	n      int
	wrote  bool
}

func (rec *recorder) WriteHeader(status int) {
	// Informational responses precede, rather than replace, the final response.
	// Forward them without letting an Early Hints status become the status in
	// the per-request log line.
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		rec.ResponseWriter.WriteHeader(status)
		return
	}
	if !rec.wrote {
		rec.status, rec.wrote = status, true
	}
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recorder) Write(b []byte) (int, error) {
	rec.wrote = true
	n, err := rec.ResponseWriter.Write(b)
	rec.n += n
	return n, err
}

func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *recorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// passPrefixBits are how much of the client's address a PoW pass is bound
// to: /24 for IPv4, /48 for IPv6. Coarser than the exact address on purpose —
// a phone hopping between towers or a household behind carrier NAT stays
// inside its prefix, while a copied pass does not work across a fleet spread
// across networks. It does not prevent an active relay from redeeming fresh work
// on the eventual consumer's prefix.
const (
	passPrefixBits4 = 24
	passPrefixBits6 = 48
)

// uaHash is the short User-Agent digest carried in a PoW pass (token.Pass.UAH).
// Nine bytes of SHA-256 — collisions buy an attacker nothing (the pass still
// binds to their own UA), so the only requirement is that honest UAs don't
// collide by accident, and 72 bits is far past that.
func uaHash(ua string) string {
	sum := sha256.Sum256([]byte("anteroom-ua-v0." + ua))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

// clientPrefix is the network prefix a PoW pass minted for this request is
// bound to, in canonical form ("203.0.113.0/24"). Empty on a resolution
// failure — the mint then produces an unbound pass and the check refuses it,
// so an unresolvable client is re-challenged rather than quietly unbound.
func (g *Gate) clientPrefix(r *http.Request) string {
	ip, err := g.match.ClientIP(r)
	if err != nil {
		return ""
	}
	bits := passPrefixBits4
	if ip.Is6() {
		bits = passPrefixBits6
	}
	pfx, err := ip.Prefix(bits)
	if err != nil {
		return ""
	}
	return pfx.String()
}

// validPass extracts and verifies the pass cookie. Invalid or absent is one
// answer: no pass.
func (g *Gate) validPass(r *http.Request) (token.Pass, bool) {
	return g.validPassAt(r, g.now())
}

// validPassAt is validPass as of a specific instant. Answer handling needs to
// ask "was this pass live when the challenge was issued", not "is it live now".
func (g *Gate) validPassAt(r *http.Request, at time.Time) (token.Pass, bool) {
	var fallback token.Pass
	var found bool
	for _, c := range r.Cookies() {
		if c.Name != cookieName || c.Value == "" {
			continue
		}
		p, err := g.keyring.Verify(c.Value, at)
		if err != nil || p.Aud != requestAudience(r) {
			continue
		}
		if p.Kind == token.KindPoW &&
			(p.IPP != g.clientPrefix(r) || p.UAH != uaHash(r.Header.Get("User-Agent"))) {
			continue
		}
		// Repeated same-name cookies are legal and browsers order them by path,
		// so an invalid or narrow cookie must not shadow a usable one. Prefer a
		// wildcard PoW pass, then a paid pass covering this request.
		if p.Kind == token.KindPoW || g.scopeCovers(p, r.URL.Path) {
			return p, true
		}
		if !found {
			fallback, found = p, true
		}
	}
	return fallback, found
}

// mayRenew reports whether this request is entitled to the cheap renewal
// threshold, and the root admission time to carry forward if so.
//
// Two rules, both load-bearing:
//   - Only a live wildcard PoW pass qualifies. A paid pass must never be
//     renewable, or one payment under the narrowest, cheapest rule would mint an
//     unscoped PoW pass and sustain whole-site access forever at renewal cost.
//   - The renewal chain is capped at max_session from the ROOT admission.
//     Otherwise a single admission solve buys unlimited time at 1/256 the cost,
//     and the difficulty dial bounds nothing.
//
// `at` is the instant the entitlement is judged against, and it must be the
// moment the challenge was ISSUED, not the moment the answer arrived. Judging
// twice against two different instants is a race with a nasty shape: a pass
// that lapses between the two makes the gate hand out a cheap renewal puzzle
// and then grade the honest answer against the expensive admission threshold,
// so the client is told "solution does not meet the required threshold" for
// solving exactly what it was given. The worker treats that as an error and
// backs off, and at short TTLs the backoff outlives the pass.
//
// Judging at issuance grants nothing extra: the minted pass expires at
// issuedAt+pass_ttl either way, and an answer arriving after that is refused on
// the remaining-lifetime check below.
func (g *Gate) mayRenew(r *http.Request, at time.Time) (rootAt time.Time, ok bool) {
	p, valid := g.validPassAt(r, at)
	if !valid || p.Kind != token.KindPoW || p.Scope != token.ScopeAll {
		return time.Time{}, false
	}
	root := p.RootAt()
	if at.Sub(root) >= g.cfg.MaxSession.D() {
		return time.Time{}, false // session too old: pay admission again
	}
	return root, true
}

// isCORSPreflight reports whether this is a browser asking permission rather
// than asking for content. All three conditions are required: OPTIONS alone is
// also a legitimate way to ask what a resource supports, and that answer is
// content the gate does have a say over.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, field := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(field), "upgrade") {
			return true
		}
	}
	return false
}

// scopeCovers reports whether a pass unlocks reqPath.
//
// PoW passes gate bots rather than value, so one solve covers the site. A paid
// pass unlocks only what was bought, and what was bought is decided the way the
// price was: by the first rule matching this path now. Asking instead whether
// the purchased rule's own matcher covers the path is the escalation that
// pricing order exists to prevent — with an expensive "/reports/*" above a
// cheap "/*", a cent spent at "/" mints the cheap scope and the cheap matcher
// then admits "/reports/q1", which nobody paid for.
//
// The wildcard is structural rather than a name: a paid pass never gets it,
// whatever a rule happens to be called.
func (g *Gate) scopeCovers(p token.Pass, reqPath string) bool {
	if p.Kind != token.KindPaid {
		return p.Scope == token.ScopeAll
	}
	route, ok := g.matchRoute(reqPath)
	return ok && route.scope == p.Scope
}

type paidRoute struct {
	rule    config.Rule
	matcher *bypass.Matcher
	scope   string
}

func compilePaidRoutes(payments *config.Payments) ([]paidRoute, error) {
	if payments == nil {
		return nil, nil
	}
	routes := make([]paidRoute, 0, len(payments.Rules))
	for _, rule := range payments.Rules {
		matcher, err := bypass.New(rule.Paths, nil, nil)
		if err != nil {
			return nil, err
		}
		paths := append([]string(nil), rule.Paths...)
		sort.Strings(paths)
		encoded, _ := json.Marshal(paths)
		digest := sha256.Sum256(append([]byte("anteroom-paid-scope-v1\x00"), encoded...))
		routes = append(routes, paidRoute{
			rule: rule, matcher: matcher,
			scope: base64.RawURLEncoding.EncodeToString(digest[:]),
		})
	}
	return routes, nil
}

// setPassCookie mints p and sets it as the pass cookie, expiring at exp.
// rootAt is the admission this pass descends from (zero for a fresh admission).
//
// The caller owns everything that says what the pass IS — kind, scope, and for
// a paid pass the settlement that bought it. Iat is stamped here so that no
// caller can mint a pass dated other than now.
// passCookieGrace keeps the pass cookie in the jar past its own expiry, long
// enough for an in-flight renewal round to post the answer it is already
// solving. See setPassCookie for why this is safe.
const passCookieGrace = 30 * time.Second

func (g *Gate) setPassCookie(w http.ResponseWriter, r *http.Request, p token.Pass, exp, rootAt time.Time) error {
	now := g.now()
	p.Aud = requestAudience(r)
	p.Iat = now.Unix()
	p.Exp = exp.Unix()
	// Bind PoW passes to the solving client's network; see token.Pass.IPP.
	// Paid passes stay unbound — what they grant was bought, not solved, and
	// a paying agent may legitimately present from changing addresses.
	if p.Kind == token.KindPoW {
		p.IPP = g.clientPrefix(r)
		p.UAH = uaHash(r.Header.Get("User-Agent"))
	}
	if !rootAt.IsZero() {
		p.Rt = rootAt.Unix()
	}
	s, err := g.keyring.Mint(p)
	if err != nil {
		return err
	}
	// MaxAge rounds up and then adds grace, because the browser dropping the
	// cookie at Exp is not the same event as the pass expiring at Exp.
	//
	// A renewal round fetches a challenge while the pass is live and posts the
	// answer a moment later. Without grace, a round that straddles Exp posts
	// COOKIELESS: the gate then sees no pass, grades an honest renewal solution
	// against the admission threshold, and answers "solution does not meet the
	// required threshold" — the client told it did bad work for doing exactly
	// the work it was handed. Deterministic when a terminated worker is revived
	// near expiry, since sw.js schedules its round immediately regardless of how
	// close Exp is.
	//
	// The grace grants nothing: Exp inside the signed pass is what walls
	// admission, mayRenew judges entitlement as of the moment the CHALLENGE was
	// issued (which must still predate Exp), and the pass a renewal mints
	// expires at issuedAt+pass_ttl either way. All the extra seconds buy is that
	// the answer can still carry the evidence of which tier it was issued at.
	maxAge := int((exp.Sub(now)+time.Second-time.Nanosecond)/time.Second) + int(passCookieGrace/time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   g.requestIsTLS(r),
		MaxAge:   maxAge,
	})
	return nil
}

func requestAudience(r *http.Request) string {
	return normalizeAuthority(r.Host)
}

func normalizeAuthority(value string) string {
	authority := strings.ToLower(strings.TrimSpace(value))
	host, port, err := net.SplitHostPort(authority)
	if err == nil {
		return strings.TrimSuffix(host, ".") + ":" + port
	}
	return strings.TrimSuffix(authority, ".")
}

// cleanPath is path.Clean with the trailing slash preserved — "/a/" and "/a"
// are different resources to most upstreams, but "/a/../b" and "//a" are not
// canonical forms we will proxy.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// stripPassCookie removes the pass from the request forwarded upstream: it is a
// bearer credential for the gate, and the upstream has no use for it.
//
// This is byte-level surgery on the raw header rather than a Cookies()/AddCookie
// round trip on purpose: re-serializing would silently drop cookies Go considers
// invalid, sanitize bytes out of values, collapse multiple Cookie headers, and
// reorder pairs — and only on gated requests, which is a miserable bug to chase.
func (g *Gate) stripPassCookie(r *http.Request) {
	vals := r.Header.Values("Cookie")
	if len(vals) == 0 {
		return
	}
	out := make([]string, 0, len(vals))
	changed := false
	for _, v := range vals {
		kept := make([]string, 0, 8)
		for _, pair := range strings.Split(v, ";") {
			name, _, _ := strings.Cut(strings.TrimLeft(pair, " \t"), "=")
			if name == cookieName {
				changed = true
				continue
			}
			kept = append(kept, strings.TrimLeft(pair, " \t"))
		}
		if len(kept) > 0 {
			out = append(out, strings.Join(kept, "; "))
		}
	}
	if !changed {
		return
	}
	r.Header.Del("Cookie")
	for _, v := range out {
		r.Header.Add("Cookie", v)
	}
}

// requestIsTLS decides the cookie's Secure flag. Direct TLS is authoritative;
// X-Forwarded-Proto is believed only from a trusted proxy, because an
// attacker-injected header on a plaintext deployment would make the browser
// drop the cookie (a solve loop), and ignoring it behind a real TLS proxy would
// send the pass in cleartext.
func (g *Gate) requestIsTLS(r *http.Request) bool {
	return requestIsTLS(g.match, r)
}

// requestIsTLS is the gate's one answer to "did the visitor arrive over TLS?".
// Both callers matter and they must not disagree: the pass cookie's Secure flag
// depends on it, and so does what the upstream is told in X-Forwarded-Proto.
func requestIsTLS(m *bypass.Matcher, r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !m.TrustedPeer(r) {
		return false
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
