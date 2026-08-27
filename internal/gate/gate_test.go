package gate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/challenge"
	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/payment"
	"github.com/radiustechsystems/anteroom/internal/token"
)

// newTestGate spins up an upstream that echoes a marker, and a gate in front
// of it built from a config file body.
func newTestGate(t *testing.T, cfgBody string) (*Gate, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		io.WriteString(w, "UPSTREAM:"+r.URL.Path+":host="+r.Host)
	}))
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + cfgBody
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return g, up
}

// get performs a request against the gate handler directly.
func do(g *Gate, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}

func browserReq(path string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.RemoteAddr = "192.0.2.10:44321"
	return r
}

func agentReq(path string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Accept", "*/*")
	r.Header.Set("User-Agent", "curl/8.0")
	r.RemoteAddr = "192.0.2.10:44321"
	return r
}

// solveAndGetCookie drives the real challenge API at test difficulty and
// returns the pass cookie.
// shape mutators are applied to both the challenge and answer requests — the
// pass binds to the solving client's User-Agent, so a test presenting the
// cookie under a particular UA must earn it under that UA too.
func solveAndGetCookie(t *testing.T, g *Gate, withCookie *http.Cookie, shape ...func(*http.Request)) *http.Cookie {
	t.Helper()
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	if withCookie != nil {
		cr.AddCookie(withCookie)
	}
	for _, f := range shape {
		f(cr)
	}
	cw := do(g, cr)
	if cw.Code != 200 {
		t.Fatalf("challenge: status %d", cw.Code)
	}
	var ch challengeResponse
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		t.Fatalf("challenge JSON: %v", err)
	}
	th, err := hexTo32(ch.Threshold)
	if err != nil {
		t.Fatalf("threshold: %v", err)
	}
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		t.Fatal("no PoW solution found")
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	if withCookie != nil {
		ar.AddCookie(withCookie)
	}
	for _, f := range shape {
		f(ar)
	}
	aw := do(g, ar)
	if aw.Code != 200 {
		t.Fatalf("answer: status %d body %s", aw.Code, aw.Body)
	}
	res := httptest.NewRecorder()
	res.Header().Set("Set-Cookie", aw.Header().Get("Set-Cookie"))
	cookies := (&http.Response{Header: res.Header()}).Cookies()
	for _, c := range cookies {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("answer did not set the pass cookie")
	return nil
}

func hexTo32(s string) ([32]byte, error) {
	var out [32]byte
	for i := 0; i < 32; i++ {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return out, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// Low difficulty keeps solve loops instant in tests; a short pass_ttl keeps
// expiry assertions readable.
const fastCfg = "difficulty = 8\nrenew_difficulty = 4\npass_ttl = \"10s\"\n"

func TestLadder(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[bypass]
paths = ["/robots.txt", "/.well-known/*"]
cidrs = ["203.0.113.0/24"]
`)
	t.Run("healthz", func(t *testing.T) {
		w := do(g, httptest.NewRequest("GET", HealthPath, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "ok") {
			t.Fatalf("healthz: %d %q", w.Code, w.Body)
		}
	})
	t.Run("bypass path goes upstream", func(t *testing.T) {
		w := do(g, agentReq("/robots.txt"))
		if !strings.Contains(w.Body.String(), "UPSTREAM:/robots.txt") {
			t.Fatalf("bypass path did not proxy: %d %q", w.Code, w.Body)
		}
	})
	t.Run("bypass glob crosses slashes", func(t *testing.T) {
		w := do(g, agentReq("/.well-known/acme-challenge/tok"))
		if !strings.Contains(w.Body.String(), "UPSTREAM:") {
			t.Fatalf("glob bypass failed: %d", w.Code)
		}
	})
	t.Run("bypass CIDR goes upstream", func(t *testing.T) {
		r := agentReq("/anything")
		r.RemoteAddr = "203.0.113.9:999"
		w := do(g, r)
		if !strings.Contains(w.Body.String(), "UPSTREAM:/anything") {
			t.Fatalf("CIDR bypass failed: %d %q", w.Code, w.Body)
		}
	})
	t.Run("browser without pass gets wait page", func(t *testing.T) {
		w := do(g, browserReq("/article"))
		if w.Code != 200 {
			t.Fatalf("wait page status = %d", w.Code)
		}
		b := w.Body.String()
		if !strings.Contains(b, "anteroom-status") {
			t.Fatal("wait page lacks its status element")
		}
		if !strings.Contains(b, `id="anteroom-live"`) ||
			!strings.Contains(b, `aria-live="polite"`) {
			t.Fatal("wait page lacks a quiet assistive status channel")
		}
		if !strings.Contains(solverOf(t, g, b), "anteroomSolve") {
			t.Fatal("wait page lacks solver")
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
			t.Fatalf("wait page cacheable: %q", cc)
		}
		if w.Header().Get("X-Robots-Tag") != "noindex" {
			t.Fatal("wait page indexable")
		}
	})
	t.Run("agent without pass gets 401 markdown", func(t *testing.T) {
		w := do(g, agentReq("/article"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("refusal status = %d", w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
			t.Fatalf("refusal content-type = %q", ct)
		}
		if !strings.Contains(w.Body.String(), pathChallenge) {
			t.Fatal("refusal does not point at the challenge API")
		}
	})
	t.Run("agent asking for JSON gets JSON", func(t *testing.T) {
		r := agentReq("/article")
		r.Header.Set("Accept", "application/json")
		w := do(g, r)
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		if out["free_challenge"] == nil {
			t.Fatal("JSON refusal lacks challenge pointer")
		}
	})
	t.Run("solve then access", func(t *testing.T) {
		c := solveAndGetCookie(t, g, nil)
		r := browserReq("/article")
		r.AddCookie(c)
		w := do(g, r)
		if !strings.Contains(w.Body.String(), "UPSTREAM:/article") {
			t.Fatalf("valid pass did not proxy: %d %q", w.Code, w.Body)
		}
	})
	t.Run("tampered cookie walls", func(t *testing.T) {
		c := solveAndGetCookie(t, g, nil)
		c.Value += "x"
		r := browserReq("/article")
		r.AddCookie(c)
		w := do(g, r)
		if strings.Contains(w.Body.String(), "UPSTREAM:") {
			t.Fatal("tampered pass reached upstream")
		}
	})
	t.Run("host preserved to upstream", func(t *testing.T) {
		c := solveAndGetCookie(t, g, nil, func(r *http.Request) { r.Host = "site.example" })
		r := browserReq("/h")
		r.Host = "site.example"
		r.AddCookie(c)
		w := do(g, r)
		if !strings.Contains(w.Body.String(), "host=site.example") {
			t.Fatalf("Host not preserved: %q", w.Body)
		}
	})
}

func TestExpiryWalls(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	c := solveAndGetCookie(t, g, nil)
	// Move the gate's clock past the pass TTL.
	g.now = func() time.Time { return time.Now().Add(11 * time.Second) }
	r := browserReq("/x")
	r.AddCookie(c)
	w := do(g, r)
	if strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("expired pass reached upstream")
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "anteroom-status") {
		t.Fatalf("expired browser should re-see the wait page, got %d", w.Code)
	}
}

func TestRenewalRequiresValidPass(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)

	// Without a cookie the challenge advertises admission.
	w := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	var ch challengeResponse
	json.Unmarshal(w.Body.Bytes(), &ch)
	if ch.Kind != "admit" {
		t.Fatalf("kind = %q, want admit", ch.Kind)
	}

	// With a valid cookie it advertises the cheap renewal.
	c := solveAndGetCookie(t, g, nil)
	r := httptest.NewRequest("GET", pathChallenge, nil)
	r.AddCookie(c)
	w = do(g, r)
	json.Unmarshal(w.Body.Bytes(), &ch)
	if ch.Kind != "renew" {
		t.Fatalf("kind = %q, want renew", ch.Kind)
	}
	// Against the renewal threshold, not merely "not the admission one". Any
	// other value satisfied that — a HARDER threshold, or a garbage string —
	// which would make renewal more expensive than admission while the test
	// stayed green.
	renewThreshold := hex.EncodeToString(g.renew.Threshold[:])
	admitThreshold := hex.EncodeToString(g.admit.Threshold[:])
	if ch.Threshold != renewThreshold {
		t.Fatalf("threshold = %q, want the renewal threshold %q (admission is %q)",
			ch.Threshold, renewThreshold, admitThreshold)
	}

	// SECURITY: a renewal-difficulty solution WITHOUT a valid pass must be
	// rejected — otherwise every bot would use the cheap path.
	nonce := ""
	rt := g.renew.Threshold
	at := g.admit.Threshold
	for n := 0; n < 1_000_000; n++ {
		s := strconv.Itoa(n)
		// Meets renew threshold but NOT admission (the gap is where the attack lives).
		if challenge.CheckPoW(ch.Challenge, s, rt) == nil && challenge.CheckPoW(ch.Challenge, s, at) != nil {
			nonce = s
			break
		}
	}
	if nonce == "" {
		t.Skip("no gap nonce found (statistically ~never)")
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	aw := do(g, ar) // no cookie!
	if aw.Code == 200 {
		t.Fatal("cheap renewal accepted without a valid pass")
	}
	// The same solution WITH the valid pass renews fine.
	ar2 := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar2.Header.Set("Content-Type", "application/json")
	ar2.AddCookie(c)
	aw2 := do(g, ar2)
	if aw2.Code != 200 {
		t.Fatalf("renewal with valid pass rejected: %d %s", aw2.Code, aw2.Body)
	}
	var out answerResponse
	json.Unmarshal(aw2.Body.Bytes(), &out)
	if out.Kind != "renew" {
		t.Fatalf("kind = %q, want renew", out.Kind)
	}
}

func TestAnswerRejects(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", pathAnswer, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return do(g, r)
	}
	if w := post(`not json`); w.Code != http.StatusBadRequest {
		t.Errorf("garbage body: %d", w.Code)
	}
	if w := post(`{"challenge":"AAAA","nonce":"1"}`); w.Code != http.StatusBadRequest {
		t.Errorf("forged challenge: %d", w.Code)
	}
	// A real challenge with a wrong nonce fails the threshold.
	cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	var ch challengeResponse
	json.Unmarshal(cw.Body.Bytes(), &ch)
	at := g.admit.Threshold
	bad := "0"
	for challenge.CheckPoW(ch.Challenge, bad, at) == nil { // ensure it's actually wrong
		bad += "0"
	}
	if w := post(`{"challenge":"` + ch.Challenge + `","nonce":"` + bad + `"}`); w.Code != http.StatusForbidden {
		t.Errorf("wrong nonce: %d", w.Code)
	}
	if w := do(g, httptest.NewRequest("GET", pathAnswer, nil)); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET answer: %d", w.Code)
	}
	// A stale challenge names the fix. The window in force is the one this gate
	// was built with — pass_ttl — not challenge's package default; reading the
	// default here made the assertion true by the accident that it is longer.
	g.now = func() time.Time { return time.Now().Add(g.cfg.PassTTL.D() + time.Minute) }
	w := post(`{"challenge":"` + ch.Challenge + `","nonce":"1"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "fresh") {
		t.Errorf("stale challenge: %d %q", w.Code, w.Body)
	}
}

func TestScopeCoverage(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[payments]
pay_to      = "0x000000000000000000000000000000000000dEaD"
facilitator = "https://f.example"

[[payments.rails]]
network       = "eip155:72344"
asset         = "0xtoken"
asset_name    = "Token"
asset_version = "1"

[[payments.rules]]
name  = "reports"
paths = ["/reports/*"]
price = "$1"
paid_ttl = "1h"
`)
	// Mint a paid-style pass scoped to the reports rule directly; this test is
	// about scope semantics rather than settlement.
	now := g.now()
	reportsScope := g.routes[0].scope
	mint := func(scope string) *http.Cookie {
		s, err := g.keyring.Mint(tokenPass(scope, now))
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: cookieName, Value: s}
	}
	mintPoW := func(scope string) *http.Cookie {
		p := tokenPass(scope, now)
		p.Kind = token.KindPoW
		p.IPP = "192.0.2.0/24" // browserReq's peer, or the binding walls it
		p.UAH = uaHash("")     // test requests send no User-Agent
		s, err := g.keyring.Mint(p)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: cookieName, Value: s}
	}
	r := browserReq("/reports/q3.pdf")
	r.AddCookie(mint(reportsScope))
	if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/reports/q3.pdf") {
		t.Fatalf("in-scope paid pass walled: %d", w.Code)
	}
	r = browserReq("/search")
	r.AddCookie(mint(reportsScope))
	if w := do(g, r); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("reports-scoped pass unlocked /search")
	}
	r = browserReq("/search")
	r.AddCookie(mintPoW("*"))
	if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/search") {
		t.Fatal("wildcard PoW pass walled")
	}
	// The wildcard belongs to proof of work and is rejected at the token codec,
	// before gate policy can accidentally interpret it as site-wide paid access.
	if _, err := g.keyring.Mint(tokenPass("*", now)); err == nil {
		t.Fatal("mint accepted a wildcard paid pass")
	}
	r = browserReq("/x")
	r.AddCookie(mint("nonexistent-rule"))
	if w := do(g, r); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("unknown scope unlocked content")
	}
}

func TestOKBodyAgents(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[triage]
ok_body_agents = ["claude-user"]
`)
	r := agentReq("/x")
	r.Header.Set("User-Agent", "Claude-User (claude-code/2.0)")
	w := do(g, r)
	if w.Code != 200 {
		t.Fatalf("2xx-only agent got %d; it would see nothing", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Pass required") {
		t.Fatal("200 body is not the instruction markdown")
	}
	// Regular agents still get the honest 401.
	if w := do(g, agentReq("/x")); w.Code != http.StatusUnauthorized {
		t.Fatalf("curl got %d, want 401", w.Code)
	}

	// The downgrade is withheld from a client that shows protocol competence:
	// such a client keys off the status, and a 200 would read as "served" so it
	// would never pay or solve. A matching UA is necessary, not sufficient.
	t.Run("not downgraded when already presenting a payment", func(t *testing.T) {
		r := agentReq("/x")
		r.Header.Set("User-Agent", "Claude-User (claude-code/2.1)")
		r.Header.Set("PAYMENT-SIGNATURE", "eyJ4NDAyVmVyc2lvbiI6Mn0=")
		if w := do(g, r); w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 for a payment-capable client", w.Code)
		}
	})
	t.Run("not downgraded when asking for JSON", func(t *testing.T) {
		r := agentReq("/x")
		r.Header.Set("User-Agent", "Claude-User (claude-code/2.1)")
		r.Header.Set("Accept", "application/json")
		if w := do(g, r); w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 for a JSON client", w.Code)
		}
	})
}

// TestWWWAuthenticateSchemeIsNotPayment: at least one popular agent skill treats
// `WWW-Authenticate: Payment …` as the marker for a different payment protocol,
// so using that token would route agents into the wrong rail.
func TestWWWAuthenticateSchemeIsNotPayment(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	a := do(g, agentReq("/x")).Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(a, "Anteroom ") {
		t.Fatalf("WWW-Authenticate = %q, want the Anteroom scheme token", a)
	}
	if strings.HasPrefix(strings.ToLower(a), "payment") {
		t.Error("the Payment scheme token belongs to another protocol")
	}
}

func TestOperatorPagesAreLive(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "header.html"), []byte("<html><body><h1>ACME Corp</h1><div id=anteroom-status></div>"), 0o600)
	os.WriteFile(filepath.Join(dir, "footer.html"), []byte("</body></html>"), 0o600)
	g, _ := newTestGate(t, fastCfg+"pages = \""+dir+"\"\n")

	w := do(g, browserReq("/x"))
	if !strings.Contains(w.Body.String(), "ACME Corp") {
		t.Fatal("operator header not used")
	}
	// Edit the file; the very next challenge must reflect it. No restart.
	os.WriteFile(filepath.Join(dir, "header.html"), []byte("<html><body><h1>ACME v2</h1>"), 0o600)
	w = do(g, browserReq("/x"))
	if !strings.Contains(w.Body.String(), "ACME v2") {
		t.Fatal("operator edit not live")
	}
}

func TestServiceWorkerServed(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, httptest.NewRequest("GET", pathSW, nil))
	if w.Code != 200 {
		t.Fatalf("sw.js: %d", w.Code)
	}
	b := w.Body.String()
	// The served worker is core + shell: solver present, ping gating present.
	if !strings.Contains(b, "anteroomSolve") || !strings.Contains(b, "DRIVER_STALE_MS") {
		t.Fatal("sw.js not assembled from core + shell")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("sw.js content-type: %q", ct)
	}
	// The worker's solve must be bounded by the deadline the gate advertises,
	// like the page's. Unbounded, a device slow enough to pass the deadline
	// keeps hashing, submits work that can only be refused, and starts over —
	// a phone burning battery on answers the gate will not take. A string check
	// is a proxy; the real evidence is a browser driving a renewal.
	if !strings.Contains(b, "deadline_unix_ms") {
		t.Error("the worker's solve ignores the advertised deadline")
	}
	if !strings.Contains(b, "admissionRound") {
		t.Error("concurrent tabs do not share one worker admission round")
	}
	if !strings.Contains(b, "admissionStillWanted") ||
		!strings.Contains(b, "includeUncontrolled: true") {
		t.Error("worker does not abandon admission work after every waiting tab closes")
	}
	if !strings.Contains(b, "anteroomConfirmPass") ||
		!strings.Contains(b, "__anteroom_cookies__") {
		t.Error("worker does not detect a browser that discarded the admission cookie")
	}
	if !strings.Contains(b, "Math.random()") {
		t.Error("renewal schedule has no jitter")
	}
}

func TestUpstreamErrorIs502(t *testing.T) {
	g, up := newTestGate(t, fastCfg)
	up.Close() // kill the upstream
	c := solveAndGetCookie(t, g, nil)
	r := browserReq("/x")
	r.AddCookie(c)
	w := do(g, r)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("dead upstream: %d, want 502", w.Code)
	}
}

// TestRealAgentFetchToolsGetInstructions pins the behavior of fetch tools whose
// headers were measured, not guessed. Both send text/markdown ahead of (or above)
// text/html with no Sec-Fetch-Mode, and both would be misclassified as browsers
// by a bare "Accept contains text/html" test — which is exactly the bug this
// guards. A misclassified agent gets a spinner and no instructions.
func TestRealAgentFetchToolsGetInstructions(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	for _, tc := range []struct {
		name, accept, ua string
		wantStatus       int
	}{
		{
			// Claude Code's fetch: equal quality, markdown listed first. Its UA
			// is in the default ok_body_agents list because it discards non-2xx
			// bodies entirely, so 200 is the only status it can learn from.
			name: "claude code fetch", accept: "text/markdown, text/html, */*",
			ua:         "Claude-User (claude-code/2.1.220; +https://support.anthropic.com/)",
			wantStatus: http.StatusOK,
		},
		{
			// Cloudflare's agent fetch: explicit q-values, HTML down-weighted.
			name:   "cloudflare agent fetch",
			accept: "text/markdown, text/plain;q=0.9, application/json;q=0.8, text/html;q=0.5, */*;q=0.1",
			ua:     "Mozilla/5.0 (compatible; CloudflareAgent)",
			// Not in ok_body_agents, so an honest 401 — it reads bodies.
			wantStatus: http.StatusUnauthorized,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/article", nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("User-Agent", tc.ua)
			r.RemoteAddr = "192.0.2.10:1234"
			w := do(g, r)
			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
				t.Fatalf("content-type = %q — this client was handed the HTML wait page", ct)
			}
			if !strings.Contains(w.Body.String(), pathChallenge) {
				t.Error("body does not explain how to get in")
			}
		})
	}
}

func TestPrefersMarkdown(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   bool
	}{
		{"text/markdown, text/html, */*", true},    // equal q, markdown first
		{"text/html, text/markdown", false},        // equal q, html first
		{"text/markdown;q=0.9, text/html", false},  // html outranks
		{"text/html;q=0.5, text/markdown", true},   // markdown outranks
		{"text/markdown", true},                    // html not offered
		{"text/html,application/xhtml+xml", false}, // ordinary browser
		{"*/*", false}, // neither named
		{"", false},
	} {
		if got := prefersMarkdown(tc.accept); got != tc.want {
			t.Errorf("prefersMarkdown(%q) = %v, want %v", tc.accept, got, tc.want)
		}
	}
}

// TestWaitPageInstructionsAreVisibleText: agentic fetch tools convert HTML
// readability-style, dropping <head>, <noscript>, and comments — measured. So the
// pointer must also exist as visible body text or it reaches no model at all.
func TestWaitPageInstructionsAreVisibleText(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	body := do(g, browserReq("/x")).Body.String()
	// Strip the parts a readability converter discards, then check what is left.
	visible := body
	for _, cut := range []struct{ from, to string }{
		{"<noscript>", "</noscript>"},
		{"<script>", "</script>"},
		{"<style>", "</style>"},
		{"<head>", "</head>"},
		// <link> too, and this is the one that mattered: serveWaitPage writes
		// the alternate link AFTER pages.header(), so it lands inside <body> and
		// survived the strip above. It was satisfying this assertion on its own,
		// which meant the visible <p class="anteroom-agent-note"> — the only
		// thing this test exists to protect — could be deleted with the test
		// still passing. Verified by deleting it.
		{"<link", ">"},
	} {
		for {
			i := strings.Index(visible, cut.from)
			if i < 0 {
				break
			}
			j := strings.Index(visible[i:], cut.to)
			if j < 0 {
				break
			}
			visible = visible[:i] + visible[i+j+len(cut.to):]
		}
	}
	if !strings.Contains(visible, pathInstructions) {
		t.Error("the instructions URL survives only in markup a fetch tool discards")
	}
}

func TestGateEndpointsNeverProxied(t *testing.T) {
	// Even if the upstream serves /.anteroom/*, the gate answers first — this
	// is what keeps sw.js and the challenge API trustworthy.
	g, _ := newTestGate(t, fastCfg)
	w := do(g, agentReq(prefix+"unknown"))
	if strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("gate namespace leaked to upstream")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown gate path: %d, want 404", w.Code)
	}
}

func TestXForwardedForSetForUpstream(t *testing.T) {
	var seenXFF string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer up.Close()
	cfgPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg), 0o600)
	cfg, _ := config.Load(cfgPath)
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := solveAndGetCookie(t, g, nil)
	r := browserReq("/x")
	r.AddCookie(c)
	do(g, r)
	if !strings.Contains(seenXFF, "192.0.2.10") {
		t.Fatalf("upstream saw XFF %q", seenXFF)
	}
}

// TestNonCanonicalPathsRejected covers the auth bypass that dot-segments would
// otherwise open: "/.well-known/*" must never admit "/.well-known/../admin",
// because upstreams normalize the traversal and would serve the private path.
func TestNonCanonicalPathsRejected(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[bypass]
paths = ["/robots.txt", "/.well-known/*"]
`)
	for _, target := range []string{
		"/.well-known/../secret",
		"/.well-known/%2e%2e/secret",
		"/.well-known/./../secret",
		"//.well-known/x",
		"/robots.txt/../secret",
		"/a//b",
	} {
		t.Run(target, func(t *testing.T) {
			r := agentReq(target)
			w := do(g, r)
			if strings.Contains(w.Body.String(), "UPSTREAM:") {
				t.Fatalf("non-canonical path reached upstream: %d %q", w.Code, w.Body)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
		})
	}
	// Canonical paths — including a legitimate trailing slash — still work.
	for _, target := range []string{"/robots.txt", "/.well-known/acme/tok", "/dir/"} {
		r := agentReq(target)
		if w := do(g, r); w.Code == http.StatusBadRequest {
			t.Fatalf("canonical path %q rejected", target)
		}
	}
}

// TestPercentEncodingIsNotTheEnemy pins down the scope of the canonicalization
// check: it exists because bypass globs are matched against the DECODED path
// while the upstream resolves dot-segments itself, so only that mismatch is
// dangerous. Encoding as such is fine, and rejecting it would break ordinary API
// URLs (e.g. GitHub-style "/repos/owner%2Frepo") for no security gain — every
// hazardous use of %2F decodes into a dot-segment and is caught as traversal.
func TestPercentEncodingIsNotTheEnemy(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	for _, tc := range []struct {
		target     string
		wantReject bool
		why        string
	}{
		{"/repos/owner%2Frepo", false, "encoded slash inside a segment is a normal API URL"},
		{"/file%20name.txt", false, "encoded space"},
		{"/a%2Bb", false, "encoded plus"},
		{"/robots%2Etxt", false, "encoded dot decodes to an equivalent path"},
		{"/search?q=a%2Fb", false, "encoding in the query is none of our business"},
		{"/deep/%2E%2E/secret", true, "encoded traversal"},
		{"/deep/../secret", true, "raw traversal"},
		{"/a%2F%2E%2E%2Fb", true, "encoded slash used to build a traversal"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			w := do(g, agentReq(tc.target))
			rejected := w.Code == http.StatusBadRequest
			if rejected != tc.wantReject {
				t.Fatalf("%q rejected=%v, want %v (%s)", tc.target, rejected, tc.wantReject, tc.why)
			}
		})
	}
}

// TestPaidPassCannotRenewIntoWildcard covers the escalation where a narrowly
// scoped paid pass is presented to /answer with a cheap renewal solution: the
// gate must not mint an unscoped PoW pass, or one payment under the cheapest
// rule would sustain whole-site access forever at renewal cost.
func TestPaidPassCannotRenewIntoWildcard(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[payments]
pay_to      = "0x000000000000000000000000000000000000dEaD"
facilitator = "https://f.example"

[[payments.rails]]
network       = "eip155:72344"
asset         = "0xtoken"
asset_name    = "Token"
asset_version = "1"

[[payments.rules]]
name  = "reports"
paths = ["/reports/*"]
price = "$0.01"
paid_ttl = "1h"
`)
	paid, err := g.keyring.Mint(tokenPass("reports", g.now()))
	if err != nil {
		t.Fatal(err)
	}
	paidCookie := &http.Cookie{Name: cookieName, Value: paid}

	// The challenge endpoint must not offer the renewal tier to a paid pass.
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	cr.AddCookie(paidCookie)
	cw := do(g, cr)
	var ch challengeResponse
	json.Unmarshal(cw.Body.Bytes(), &ch)
	if ch.Kind != "admit" {
		t.Fatalf("paid pass was offered kind %q, want admit", ch.Kind)
	}

	// And a renewal-difficulty solution must be rejected even when presented
	// together with the valid paid pass.
	rt := g.renew.Threshold
	at := g.admit.Threshold
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		s := strconv.Itoa(n)
		if challenge.CheckPoW(ch.Challenge, s, rt) == nil && challenge.CheckPoW(ch.Challenge, s, at) != nil {
			nonce = s
			break
		}
	}
	if nonce == "" {
		t.Skip("no gap nonce found")
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	ar.AddCookie(paidCookie)
	if aw := do(g, ar); aw.Code == 200 {
		t.Fatal("paid pass bought a cheap renewal into a wildcard PoW pass")
	}
}

// TestCORSPreflightIsNotChallenged.
//
// A preflight is unauthenticated by specification — the browser sends it
// without cookies — so it can never present a pass, and challenging it is a
// wall that no amount of solving gets past. The effect is that every
// cross-origin application behind the gate is broken permanently, and the error
// the developer sees names CORS rather than Anteroom.
//
// The request the preflight asks about is a separate request and stays on the
// ladder, which is what keeps this from being a hole: the check below pairs the
// two.
func TestCORSPreflightIsNotChallenged(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)

	preflight := func(method string) *http.Request {
		r := httptest.NewRequest("OPTIONS", "/api/items", nil)
		r.Header.Set("Origin", "https://app.example")
		r.Header.Set("Access-Control-Request-Method", method)
		r.RemoteAddr = "192.0.2.10:44321"
		return r
	}
	if w := do(g, preflight("POST")); !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Errorf("a CORS preflight was walled (status %d) — the real request can never follow", w.Code)
	}

	// The actual cross-origin request is not a preflight and is still gated.
	real := httptest.NewRequest("POST", "/api/items", nil)
	real.Header.Set("Origin", "https://app.example")
	real.RemoteAddr = "192.0.2.10:44321"
	if w := do(g, real); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Error("the cross-origin request itself went upstream without a pass")
	}

	// Nor is a bare OPTIONS: "what does this resource support" is content, and
	// only the preflight shape earns the exemption.
	bare := httptest.NewRequest("OPTIONS", "/api/items", nil)
	bare.RemoteAddr = "192.0.2.10:44321"
	if w := do(g, bare); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Error("a bare OPTIONS was treated as a preflight")
	}
	noACRM := httptest.NewRequest("OPTIONS", "/api/items", nil)
	noACRM.Header.Set("Origin", "https://app.example")
	noACRM.RemoteAddr = "192.0.2.10:44321"
	if w := do(g, noACRM); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Error("an OPTIONS with only an Origin was treated as a preflight")
	}
}

// TestAdvertisedDeadlineIsTheDeadlineEnforced verifies that deadline_unix_ms
// matches the challenge freshness window for every configured pass TTL.
func TestAdvertisedDeadlineIsTheDeadlineEnforced(t *testing.T) {
	for _, ttl := range []string{"30s", "60s", "120s"} {
		t.Run(ttl, func(t *testing.T) {
			g, _ := newTestGate(t, "difficulty = 8\nrenew_difficulty = 4\npass_ttl = \""+ttl+
				"\"\nmax_session = \"30m\"\n")
			base := time.Now().Truncate(time.Second)
			g.now = func() time.Time { return base }

			cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
			var ch challengeResponse
			if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
				t.Fatalf("challenge JSON: %v", err)
			}
			th, err := hexTo32(ch.Threshold)
			if err != nil {
				t.Fatal(err)
			}
			nonce := ""
			for n := range 1_000_000 {
				if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
					nonce = strconv.Itoa(n)
					break
				}
			}
			if nonce == "" {
				t.Fatal("no PoW solution found")
			}
			body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
			answerAt := func(at time.Time) int {
				g.now = func() time.Time { return at }
				r := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				return do(g, r).Code
			}

			deadline := time.UnixMilli(ch.DeadlineMs)
			if got, want := deadline.Sub(base).Round(time.Second), g.cfg.PassTTL.D(); got != want {
				t.Fatalf("advertised deadline is +%s, want +%s", got, want)
			}
			// Just inside the number the gate published: honest work, accepted.
			if code := answerAt(deadline.Add(-time.Second)); code != 200 {
				t.Errorf("a solve one second inside the advertised deadline: status %d, want 200", code)
			}
			// Past it: refused, which is what makes the number worth trusting.
			if code := answerAt(deadline.Add(time.Second)); code == 200 {
				t.Error("a solve past the advertised deadline was accepted")
			}
		})
	}
}

// A challenge carries a whole-second timestamp, so its advertised deadline
// must be derived from that timestamp even when the current clock has a
// sub-second component.
func TestAdvertisedDeadlineSurvivesASubSecondClock(t *testing.T) {
	g, _ := newTestGate(t, fastCfg) // pass_ttl = 10s
	base := time.Now().Truncate(time.Second).Add(900 * time.Millisecond)
	g.now = func() time.Time { return base }

	cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	var ch challengeResponse
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		t.Fatalf("challenge JSON: %v", err)
	}
	th, err := hexTo32(ch.Threshold)
	if err != nil {
		t.Fatal(err)
	}
	nonce := ""
	for n := range 1_000_000 {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		t.Fatal("no PoW solution found")
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})

	// One millisecond inside the number the gate published.
	deadline := time.UnixMilli(ch.DeadlineMs)
	g.now = func() time.Time { return deadline.Add(-time.Millisecond) }
	r := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if w := do(g, r); w.Code != http.StatusOK {
		t.Errorf("a solve submitted 1ms inside the advertised deadline: status %d %q, want 200",
			w.Code, w.Body)
	}
}

// TestAnswerHonorsTheSignedChallengeProfileAcrossConfigChange models a rolling
// restart: one instance advertises a profile, then another instance with the
// shared key but different difficulty/TTL receives the answer. The verifier
// must honor the signed promise for its short lifetime rather than silently
// grading under the answer node's current policy.
func TestAnswerHonorsTheSignedChallengeProfileAcrossConfigChange(t *testing.T) {
	g, _ := newTestGate(t, fastCfg) // difficulty 8, pass_ttl 10s
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }

	var ch challengeResponse
	json.Unmarshal(do(g, httptest.NewRequest("GET", pathChallenge, nil)).Body.Bytes(), &ch)
	threshold, err := hexTo32(ch.Threshold)
	if err != nil {
		t.Fatal(err)
	}
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), threshold) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		t.Fatal("no solution found")
	}

	// Simulate the answering instance having a much harder, shorter current
	// profile. Neither value may rewrite the already-issued promise.
	hard, _ := challenge.Threshold(255)
	g.admit = challenge.Profile{Kind: challenge.KindAdmit, TTL: time.Second, Threshold: hard}
	g.now = func() time.Time { return base.Add(5 * time.Second) }
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	r := httptest.NewRequest(http.MethodPost, pathAnswer, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := do(g, r)
	if w.Code != http.StatusOK {
		t.Fatalf("answer under changed config = %d %s", w.Code, w.Body.String())
	}
	var out answerResponse
	json.Unmarshal(w.Body.Bytes(), &out)
	if got, want := out.ExpUnixMs, base.Add(10*time.Second).UnixMilli(); got != want {
		t.Fatalf("expiry = %d, want signed-profile expiry %d", got, want)
	}
}

// TestPassExpiryDerivesFromChallenge covers solve-sharing: redeeming a
// (challenge, nonce) pair later must yield only the remaining lifetime, and
// nothing once pass_ttl has elapsed since the challenge was issued.
func TestPassExpiryDerivesFromChallenge(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	// Whole seconds: the challenge carries a unix-second timestamp, so a
	// derived expiry is second-granular by construction.
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }

	cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	var ch challengeResponse
	json.Unmarshal(cw.Body.Bytes(), &ch)
	at := g.admit.Threshold
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), at) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})

	// Redeem immediately: full pass, expiring ~pass_ttl after issue.
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	aw := do(g, ar)
	var out answerResponse
	json.Unmarshal(aw.Body.Bytes(), &out)
	if !out.OK {
		t.Fatalf("first redemption failed: %s", aw.Body)
	}
	wantExp := base.Add(g.cfg.PassTTL.D()).UnixMilli()
	if out.ExpUnixMs != wantExp {
		t.Errorf("exp = %d, want %d (derived from challenge issue time)", out.ExpUnixMs, wantExp)
	}

	// Replay the same solve after the pass TTL has elapsed: refused, because
	// the pass it would mint is already dead. Both refusals available here say
	// the same thing at the same instant — the challenge freshness window is
	// pass_ttl, so a solve that can only buy a dead pass is also a stale
	// challenge — and what matters is that it buys nothing and says where to
	// get a fresh one.
	g.now = func() time.Time { return base.Add(11 * time.Second) }
	ar2 := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar2.Header.Set("Content-Type", "application/json")
	aw2 := do(g, ar2)
	if aw2.Code == 200 {
		t.Fatal("a shared solve still bought a pass after pass_ttl elapsed")
	}
	if !strings.Contains(aw2.Body.String(), pathChallenge) {
		t.Errorf("the refusal does not point at a fresh challenge: %s", aw2.Body)
	}
}

func TestGateAuthoredHeaderNotSpoofable(t *testing.T) {
	// A recording upstream, because the shared one writes only its path and Host
	// and so could never contain the forgery this test looks for: the old
	// `strings.Contains(body, "spoofed")` check could not fire under any
	// implementation, correct or broken. What matters is what the UPSTREAM saw,
	// and only an upstream can report that.
	var saw string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("X-Anteroom-Status")
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + fastCfg + "[bypass]\npaths = [\"/robots.txt\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	r := agentReq("/robots.txt")
	r.Header.Set("X-Anteroom-Status", "pass-paid")
	w := do(g, r)
	if !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("the bypassed path never reached the upstream, so nothing was tested")
	}
	if saw == "pass-paid" {
		t.Fatal("a client's forged X-Anteroom-Status reached the upstream, which " +
			"would read it as the gate's own verdict that this request was paid for")
	}
	// And the gate's own request object, so a future rewrite that re-adds the
	// header on the outbound clone cannot pass by deleting it only here.
	if r.Header.Get("X-Anteroom-Status") == "pass-paid" {
		t.Fatal("inbound X-Anteroom-Status survived on the request")
	}
}

func TestPassCookieNotForwardedUpstream(t *testing.T) {
	var seenCookie string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenCookie = r.Header.Get("Cookie")
	}))
	defer up.Close()
	cfgPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg), 0o600)
	cfg, _ := config.Load(cfgPath)
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := solveAndGetCookie(t, g, nil)
	r := browserReq("/x")
	r.AddCookie(c)
	r.AddCookie(&http.Cookie{Name: "app_session", Value: "keep-me"})
	do(g, r)
	if strings.Contains(seenCookie, cookieName) {
		t.Errorf("pass cookie forwarded upstream: %q", seenCookie)
	}
	if !strings.Contains(seenCookie, "app_session=keep-me") {
		t.Errorf("unrelated cookies must survive: %q", seenCookie)
	}
}

func TestEveryForwardStripsGateCredentials(t *testing.T) {
	type seen struct{ cookie, signature string }
	var requests []seen
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, seen{
			cookie: r.Header.Get("Cookie"), signature: r.Header.Get(payment.HeaderSignature),
		})
	}))
	t.Cleanup(up.Close)
	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + fastCfg +
		"[bypass]\npaths = [\"/public\"]\ncidrs = [\"192.0.2.0/24\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	pathBypass := agentReq("/public")
	ipBypass := agentReq("/private")
	ipBypass.RemoteAddr = "192.0.2.8:1234"
	preflight := httptest.NewRequest(http.MethodOptions, "/private", nil)
	preflight.RemoteAddr = "198.51.100.8:1234"
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	for _, r := range []*http.Request{pathBypass, ipBypass, preflight} {
		r.Header.Set("Cookie", cookieName+"=secret; app_session=keep")
		r.Header.Set(payment.HeaderSignature, "signed-payment")
		do(g, r)
	}
	if len(requests) != 3 {
		t.Fatalf("upstream saw %d requests, want 3", len(requests))
	}
	for i, got := range requests {
		if got.signature != "" || strings.Contains(got.cookie, cookieName) {
			t.Errorf("request %d leaked gate credentials: %+v", i, got)
		}
		if !strings.Contains(got.cookie, "app_session=keep") {
			t.Errorf("request %d lost application cookies: %+v", i, got)
		}
	}
}

func TestCookieSecureFlagRequiresTrust(t *testing.T) {
	// X-Forwarded-Proto from an untrusted peer must not set Secure (the browser
	// would drop the cookie on a plaintext deployment → endless solve loop).
	g, _ := newTestGate(t, fastCfg)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.5:1111"
	r.Header.Set("X-Forwarded-Proto", "https")
	if err := g.setPassCookie(w, r, token.Pass{Kind: token.KindPoW, Scope: "*"}, g.now().Add(time.Minute), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Header().Get("Set-Cookie"), "Secure") {
		t.Error("Secure set from an untrusted X-Forwarded-Proto")
	}

	// From a trusted proxy it IS honored (else the pass travels in cleartext).
	g2, _ := newTestGate(t, fastCfg+`trusted_proxies = ["10.0.0.0/8"]`+"\n")
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.1.2.3:1111"
	r2.Header.Set("X-Forwarded-Proto", "https")
	if err := g2.setPassCookie(w2, r2, token.Pass{Kind: token.KindPoW, Scope: "*"}, g2.now().Add(time.Minute), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w2.Header().Get("Set-Cookie"), "Secure") {
		t.Error("Secure not set behind a trusted TLS proxy")
	}
}

// TestServiceWorkerStaysInItsOwnScope: only one worker can own a scope, so
// claiming "/" would evict an operator's own PWA/offline worker (and be evicted
// by it). Renewal needs no page control — pages postMessage the registration —
// so the worker must never ask for root scope, and must never gain a fetch
// handler (which would make it a full-origin interception surface).
func TestServiceWorkerStaysInItsOwnScope(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, httptest.NewRequest("GET", pathSW, nil))
	if got := w.Header().Get("Service-Worker-Allowed"); got != "" {
		t.Errorf("Service-Worker-Allowed = %q; the worker must not claim a wider scope", got)
	}
	body := w.Body.String()
	if strings.Contains(body, "self.clients.claim") {
		t.Error("worker claims clients; it should control no page")
	}
	if strings.Contains(body, `addEventListener("fetch"`) || strings.Contains(body, "addEventListener('fetch'") {
		t.Error("worker has a fetch handler; that is a full-origin interception surface")
	}
	if !strings.Contains(body, "unregister") {
		t.Error("worker has no self-retirement path; it would outlive the gate")
	}
	// The page script must register at the default scope, not "/".
	wp := do(g, browserReq("/x")).Body.String()
	if strings.Contains(wp, `{ scope: "/" }`) || strings.Contains(wp, `{scope:"/"}`) {
		t.Error("page registers the worker at root scope")
	}
}

// TestWaitPageAdvertisesInstructions: agent detection is a heuristic, so an
// automated client will sometimes be handed the HTML wait page. It has no JS and
// would see nothing useful, so the page must point at the machine-readable
// instructions in ways different clients actually notice.
func TestWaitPageAdvertisesInstructions(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, browserReq("/article"))
	body := w.Body.String()

	if link := w.Header().Get("Link"); !strings.Contains(link, pathInstructions) ||
		!strings.Contains(link, "text/markdown") {
		t.Errorf("Link header missing the markdown alternate: %q", link)
	}
	// Inside the tag, not merely somewhere on the page. The page names
	// pathInstructions five times, so "contains rel=alternate AND contains the
	// path" was two unrelated facts: delete the pointer from either element and
	// the other four occurrences kept the assertion green.
	if link := between(body, `<link rel="alternate"`, ">"); !strings.Contains(link, pathInstructions) {
		t.Errorf("the <link rel=alternate> does not point at the instructions: <link rel=\"alternate\"%s>", link)
	}
	if ns := between(body, "<noscript>", "</noscript>"); !strings.Contains(ns, pathInstructions) {
		t.Errorf("the <noscript> block carries no pointer for text extractors: %q", ns)
	}
}

func TestInstructionsEndpoint(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, httptest.NewRequest("GET", pathInstructions, nil))
	if w.Code != 200 {
		t.Fatalf("instructions: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "markdown") {
		t.Errorf("content-type = %q", ct)
	}
	body := w.Body.String()
	// It must be self-sufficient: everything needed to solve, without the
	// reader having seen a refusal first.
	for _, want := range []string{pathChallenge, pathAnswer, cookieName, "threshold", "nonce", "deadline_unix_ms"} {
		if !strings.Contains(body, want) {
			t.Errorf("instructions omit %q", want)
		}
	}
	// The standalone document is the same text a refusal carries, so an agent
	// pointed at either learns the same thing.
	ref := do(g, agentReq("/x")).Body.String()
	if ref != body {
		t.Error("refusal body and standalone instructions have diverged")
	}
	if w.Header().Get("X-Robots-Tag") != "noindex" {
		t.Error("instructions should not be indexed")
	}
}

// TestWorkerDoesTheNetworkIO pins the architecture that defends against a site's
// own root-scoped service worker. Scope selects which DOCUMENTS a worker
// controls, not which URLs it sees — so a root worker intercepts every fetch our
// wait page makes, wherever the endpoint lives. A fetch issued INSIDE a service
// worker has service-workers mode "none" and cannot be intercepted, so the page
// must delegate the round to our worker over a MessagePort rather than fetching.
func TestWorkerDoesTheNetworkIO(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	worker := do(g, httptest.NewRequest("GET", pathSW, nil)).Body.String()
	page := solverOf(t, g, do(g, browserReq("/x")).Body.String())

	// The worker owns the fetches and answers RPC over a port.
	for _, want := range []string{"ANTEROOM_RPC", "event.ports", "fetch(CHALLENGE_URL", "fetch(ANSWER_URL"} {
		if !strings.Contains(worker, want) {
			t.Errorf("worker missing %q", want)
		}
	}
	// The page asks the worker first, and addresses registration.active — never
	// navigator.serviceWorker.controller, which is the SITE's worker if it has one.
	if !strings.Contains(page, `rpc("solve")`) {
		t.Error("page does not delegate the solve to the worker")
	}
	if !strings.Contains(page, "MAX_ATTEMPTS") ||
		!strings.Contains(page, "A fresh challenge discards all progress") {
		t.Error("page does not bound deadline refreshes on slow devices")
	}
	if strings.Contains(page, "serviceWorker.controller") {
		t.Error("page addresses the controller, which may be the site's own worker")
	}
	if !strings.Contains(page, "updateViaCache") {
		t.Error("registration does not bypass the HTTP cache for the worker script")
	}
	// Still no fetch handler, and still no wider scope.
	if strings.Contains(worker, `addEventListener("fetch"`) {
		t.Error("worker gained a fetch handler: origin-wide interception surface")
	}
	if got := do(g, httptest.NewRequest("GET", pathSW, nil)).Header().Get("Service-Worker-Allowed"); got != "" {
		t.Errorf("worker claims scope %q", got)
	}
}

func TestInsecureContextFallback(t *testing.T) {
	// Off by default: the implementation is absent (the solver still *checks*
	// for it, which is how the page reports the misconfiguration honestly).
	off, _ := newTestGate(t, fastCfg)
	if body := solverOf(t, off, do(off, browserReq("/x")).Body.String()); strings.Contains(body, "function anteroomSHA256") {
		t.Error("SHA-256 fallback shipped without opt-in")
	}
	// On: the fallback is inlined so a plain-HTTP deployment can still solve.
	on, _ := newTestGate(t, fastCfg+"allow_insecure_context = true\n")
	body := solverOf(t, on, do(on, browserReq("/x")).Body.String())
	if !strings.Contains(body, "function anteroomSHA256") {
		t.Error("SHA-256 fallback not shipped despite opt-in")
	}
	// The solver must prefer WebCrypto whenever it exists, in both modes.
	if !strings.Contains(body, "crypto.subtle") {
		t.Error("fallback mode dropped the WebCrypto path")
	}
}

// solverOf fetches the cacheable solver bundle referenced by a wait page.
func solverOf(t *testing.T, g *Gate, page string) string {
	t.Helper()
	m := regexp.MustCompile(`<script src="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("wait page does not reference a solver script")
	}
	w := do(g, httptest.NewRequest("GET", m[1], nil))
	if w.Code != 200 {
		t.Fatalf("solver %s: status %d", m[1], w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("solver not immutably cacheable: %q — it is refetched on every challenge", cc)
	}
	return w.Body.String()
}

func TestUninstallEndpoint(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, httptest.NewRequest("GET", pathUninstall, nil))
	if w.Code != 200 {
		t.Fatalf("uninstall: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unregister") {
		t.Error("uninstall page does not unregister anything")
	}
}

// TestSessionChainIsCapped: renewals are 256x cheaper than admission, so an
// uncapped chain would let one solve sustain access forever and the difficulty
// dial would bound nothing.
func TestSessionChainIsCapped(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+"max_session = \"1m\"\n")
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }

	c := solveAndGetCookie(t, g, nil)
	// Inside the session window the pass may renew.
	r := httptest.NewRequest("GET", pathChallenge, nil)
	r.AddCookie(c)
	var ch challengeResponse
	json.Unmarshal(do(g, r).Body.Bytes(), &ch)
	if ch.Kind != "renew" {
		t.Fatalf("kind = %q, want renew inside the session window", ch.Kind)
	}

	// Build a still-valid pass whose ROOT admission is older than max_session:
	// it must fall back to admission even though the pass itself is live.
	old, err := g.keyring.Mint(token.Pass{
		Kind:  token.KindPoW,
		Scope: "*",
		Aud:   "example.com",
		IPP:   "192.0.2.0/24", // covers httptest's 192.0.2.1 and browserReq's .10
		UAH:   uaHash(""),     // test requests send no User-Agent
		Iat:   base.Unix(),
		Exp:   base.Add(10 * time.Second).Unix(),
		Rt:    base.Add(-2 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	r2 := httptest.NewRequest("GET", pathChallenge, nil)
	r2.AddCookie(&http.Cookie{Name: cookieName, Value: old})
	json.Unmarshal(do(g, r2).Body.Bytes(), &ch)
	if ch.Kind != "admit" {
		t.Fatalf("kind = %q, want admit once max_session has elapsed", ch.Kind)
	}
	// And the pass still works for access — capping renewal must not wall a
	// visitor mid-pass.
	rr := browserReq("/x")
	rr.AddCookie(&http.Cookie{Name: cookieName, Value: old})
	if w := do(g, rr); !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Error("a live pass past max_session should still grant access until it expires")
	}
}

// The other half of TestSessionChainIsCapped, and the half that is the actual
// defence.
//
// That test asks /challenge what it ADVERTISES past max_session and stops there.
// Nothing made an attacker fetch a challenge first: the endpoint is the polite
// interface, and a client that ignores kind:"admit" and simply submits a
// renewal-difficulty solution is the whole attack — renewals are 256x cheaper,
// so if /answer grades leniently the cap bounds nothing and one solve sustains
// access forever.
//
// Both rungs read mayRenew today, so this passes; what it stops is a future
// split where the advertisement is capped and the grading is not, which would
// leave TestSessionChainIsCapped green.
func TestSessionCapIsEnforcedAtTheAnswerEndpointToo(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+"max_session = \"1m\"\n")
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }

	// A live pass whose ROOT admission is older than max_session.
	old, err := g.keyring.Mint(token.Pass{
		Kind:  token.KindPoW,
		Scope: "*",
		Aud:   "example.com",
		IPP:   "192.0.2.0/24", // covers httptest's 192.0.2.1 and browserReq's .10
		UAH:   uaHash(""),     // test requests send no User-Agent
		Iat:   base.Unix(),
		Exp:   base.Add(10 * time.Second).Unix(),
		Rt:    base.Add(-2 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// A second pass is inside the session window and can honestly obtain a signed
	// renewal profile. Re-presenting that cheap proof with the old pass must not
	// bypass the answer-time session-cap check.
	fresh, err := g.keyring.Mint(token.Pass{
		Kind: token.KindPoW, Scope: "*", Aud: "example.com",
		IPP: "192.0.2.0/24", UAH: uaHash(""),
		Iat: base.Unix(), Exp: base.Add(10 * time.Second).Unix(),
		Rt: base.Add(-10 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var ch challengeResponse
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	cr.AddCookie(&http.Cookie{Name: cookieName, Value: fresh})
	json.Unmarshal(do(g, cr).Body.Bytes(), &ch)
	if ch.Kind != "renew" {
		t.Fatalf("fixture challenge kind = %q, want renew", ch.Kind)
	}

	// A nonce in the gap: good enough to renew, not good enough to be admitted.
	rt := g.renew.Threshold
	at := g.admit.Threshold
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		s := strconv.Itoa(n)
		if challenge.CheckPoW(ch.Challenge, s, rt) == nil && challenge.CheckPoW(ch.Challenge, s, at) != nil {
			nonce = s
			break
		}
	}
	if nonce == "" {
		t.Fatal("no gap nonce in a million tries — fastCfg's thresholds are too close " +
			"for this test to mean anything; widen them rather than skipping")
	}

	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	r := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: cookieName, Value: old})
	w := do(g, r)
	if w.Code == http.StatusOK {
		t.Fatal("a renewal-difficulty solve was accepted past max_session: one admission " +
			"solve now buys unlimited time at 1/256 the cost, and the difficulty dial bounds nothing")
	}
	// And the same pass inside the window IS renewable, or this test would pass
	// for a gate that had simply stopped renewing anything.
	r2 := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	r2.Header.Set("Content-Type", "application/json")
	r2.AddCookie(&http.Cookie{Name: cookieName, Value: fresh})
	if w2 := do(g, r2); w2.Code != http.StatusOK {
		t.Fatalf("the same cheap solve was refused INSIDE the session window (%d: %s); "+
			"the refusal above proves nothing about max_session", w2.Code, w2.Body)
	}
}

func TestRenewalCarriesRootForward(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	base := time.Now().Truncate(time.Second)
	g.now = func() time.Time { return base }
	c := solveAndGetCookie(t, g, nil)
	// A renewal must preserve the original admission time, not reset it —
	// otherwise the cap never triggers.
	c2 := solveAndGetCookie(t, g, c)
	p, err := g.keyring.Verify(c2.Value, base)
	if err != nil {
		t.Fatal(err)
	}
	if p.Rt == 0 {
		t.Fatal("renewed pass carries no root admission time; the cap cannot apply")
	}
	if !p.RootAt().Equal(base) {
		t.Errorf("root = %v, want the original admission %v", p.RootAt(), base)
	}
}

func TestGateResponsesVary(t *testing.T) {
	// These bodies sit at content URLs and depend on the request; an
	// intermediary that ignores no-store must at least not share them.
	g, _ := newTestGate(t, fastCfg)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"wait page": do(g, browserReq("/x")),
		"refusal":   do(g, agentReq("/x")),
	} {
		v := w.Header().Get("Vary")
		for _, want := range []string{"Cookie", "Accept", "User-Agent"} {
			if !strings.Contains(v, want) {
				t.Errorf("%s: Vary = %q, missing %s", name, v, want)
			}
		}
	}
}

func TestPublicHostsPrecedeEveryAdmissionPath(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+"public_hosts = [\"example.com\"]\n[bypass]\npaths = [\"/public\"]\n")

	for _, path := range []string{"/public", pathChallenge, pathInstructions} {
		r := agentReq(path)
		r.Host = "attacker.example"
		w := do(g, r)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("unknown authority %s = %d, want 421", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "UPSTREAM:") {
			t.Errorf("unknown authority %s reached upstream", path)
		}
	}

	allowed := agentReq("/public")
	allowed.Host = "EXAMPLE.COM."
	if w := do(g, allowed); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("normalized allowed authority = %d %q", w.Code, w.Body.String())
	}

	health := agentReq(HealthPath)
	health.Host = "127.0.0.1:8080"
	if w := do(g, health); w.Code != http.StatusOK {
		t.Fatalf("local health probe under allowlist = %d", w.Code)
	}
}

func TestRefusalCarriesWWWAuthenticate(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	w := do(g, agentReq("/x"))
	if a := w.Header().Get("WWW-Authenticate"); !strings.Contains(a, "Anteroom") {
		t.Errorf("401 without a challenge header: %q", a)
	}
}

func TestVendorClientIPHeadersStripped(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))
	defer up.Close()
	cfgPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg+`trusted_proxies = ["10.0.0.0/8"]`+"\n"), 0o600)
	cfg, _ := config.Load(cfgPath)
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Hand-mint rather than solve: the solve would bind the pass to the
	// solving peer, and this request presents as 203.0.113.7 via the trusted
	// proxy. Header hygiene is what's under test, not the binding.
	now := g.now()
	pass, err := g.keyring.Mint(token.Pass{
		Kind: token.KindPoW, Scope: token.ScopeAll, Aud: "example.com",
		IPP: "203.0.113.0/24", UAH: uaHash(""),
		Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Cookie{Name: cookieName, Value: pass}
	r := browserReq("/x")
	r.RemoteAddr = "10.1.1.1:5555" // trusted proxy
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("CF-Connecting-IP", "6.6.6.6")
	r.Header.Set("True-Client-IP", "6.6.6.6")
	r.AddCookie(c)
	do(g, r)

	if got := seen.Get("CF-Connecting-IP"); got != "" {
		t.Errorf("CF-Connecting-IP reached upstream: %q", got)
	}
	if got := seen.Get("True-Client-IP"); got != "" {
		t.Errorf("True-Client-IP reached upstream: %q", got)
	}
	// The upstream must learn the real visitor, not the proxy.
	if got := seen.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Errorf("XFF = %q, want the resolved client 203.0.113.7", got)
	}
	if got := seen.Get("X-Real-IP"); got != "203.0.113.7" {
		t.Errorf("X-Real-IP = %q, want the resolved client", got)
	}
}

// TestPassBoundToClientNetwork is the counter to the redistribution attack:
// a pass is a bearer capability, so without binding, one
// solve fans out to a whole fleet. With binding, a pass presented from outside
// the /24 (or /48) it was earned on is no pass at all — for access AND for the
// cheap renewal threshold.
func TestPassBoundToClientNetwork(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	c := solveAndGetCookie(t, g, nil) // solved from httptest's 192.0.2.1

	// Same /24, different host: still admitted (carrier NAT, mobile drift).
	r := browserReq("/x")
	r.RemoteAddr = "192.0.2.99:1000"
	r.AddCookie(c)
	if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/x") {
		t.Fatalf("pass refused within its own /24: %d", w.Code)
	}

	// Same network, different User-Agent: walled. This is the two-persona
	// scraper shape — a headless solver earning passes that a differently
	// dressed consumer on the same node spends.
	r = browserReq("/x")
	r.RemoteAddr = "192.0.2.99:1000"
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	r.AddCookie(c)
	if w := do(g, r); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("a pass solved under one User-Agent was spent under another")
	}

	// Outside the /24: walled, exactly as if no pass were presented.
	r = browserReq("/x")
	r.RemoteAddr = "198.51.100.7:1000"
	r.AddCookie(c)
	if w := do(g, r); strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("a shared pass worked from a foreign network")
	}

	// And the foreign network does not get the cheap renewal threshold either:
	// the pass it presents is invalid there, so /challenge quotes admission.
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	cr.RemoteAddr = "198.51.100.7:1000"
	cr.AddCookie(c)
	var ch challengeResponse
	json.Unmarshal(do(g, cr).Body.Bytes(), &ch)
	if ch.Kind != "admit" {
		t.Fatalf("kind = %q, want admit: a foreign network renewed on a shared pass", ch.Kind)
	}

	// The token codec will not mint an unbound PoW variant.
	now := g.now()
	if _, err := g.keyring.Mint(token.Pass{
		Kind: token.KindPoW, Scope: token.ScopeAll, Aud: "example.com",
		Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}); err == nil {
		t.Fatal("mint accepted a prefix-less PoW pass")
	}
}

func TestUsablePassIsNotShadowedByDuplicateCookies(t *testing.T) {
	g, _ := newTestGate(t, fastCfg+`
[payments]
pay_to = "0x000000000000000000000000000000000000dEaD"
facilitator = "https://f.example"

[[payments.rails]]
network = "eip155:72344"
asset = "0xtoken"
asset_name = "Token"
asset_version = "1"

[[payments.rules]]
name = "reports"
paths = ["/reports/*"]
price = "$0.01"
paid_ttl = "1h"
`)
	pow := solveAndGetCookie(t, g, nil)
	now := g.now()
	narrow, err := g.keyring.Mint(tokenPass(g.routes[0].scope, now))
	if err != nil {
		t.Fatal(err)
	}
	expiredPass := tokenPass(g.routes[0].scope, now.Add(-2*time.Hour))
	expired, err := g.keyring.Mint(expiredPass)
	if err != nil {
		t.Fatal(err)
	}

	for name, values := range map[string][]string{
		"invalid first":     {"garbage", pow.Value},
		"expired first":     {expired, pow.Value},
		"narrow paid first": {narrow, pow.Value},
		"invalid last":      {pow.Value, "garbage"},
	} {
		t.Run(name, func(t *testing.T) {
			r := browserReq("/search")
			for _, value := range values {
				r.AddCookie(&http.Cookie{Name: cookieName, Value: value})
			}
			if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/search") {
				t.Fatalf("usable pass was shadowed: status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestCookieStrippingPreservesOddValues(t *testing.T) {
	var seen string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
	}))
	defer up.Close()
	cfgPath := filepath.Join(t.TempDir(), "c.toml")
	os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg), 0o600)
	cfg, _ := config.Load(cfgPath)
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := solveAndGetCookie(t, g, nil)
	r := browserReq("/x")
	// A raw header with a value Go's cookie serializer would mangle or drop.
	r.Header.Set("Cookie", "weird={\"a\":1}; "+cookieName+"="+c.Value+"; plain=ok")
	do(g, r)
	if strings.Contains(seen, cookieName) {
		t.Errorf("pass forwarded: %q", seen)
	}
	if !strings.Contains(seen, `weird={"a":1}`) {
		t.Errorf("odd cookie value mangled: %q", seen)
	}
	if !strings.Contains(seen, "plain=ok") {
		t.Errorf("trailing cookie lost: %q", seen)
	}
}

// tokenPass builds a paid-style pass payload for scope tests.

func TestOwnEndpointMethodGuards(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	for _, p := range []string{HealthPath, pathSW, pathChallenge} {
		if w := do(g, httptest.NewRequest("POST", p, nil)); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", p, w.Code)
		}
	}
}

func TestOversizePagesFallBackToDefault(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, maxPageBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	os.WriteFile(filepath.Join(dir, "header.html"), big, 0o600)
	os.WriteFile(filepath.Join(dir, "footer.html"), []byte("</body></html>"), 0o600)
	g, _ := newTestGate(t, fastCfg+"pages = \""+dir+"\"\n")
	w := do(g, browserReq("/x"))
	if strings.Contains(w.Body.String(), "xxxxxxxxxx") {
		t.Fatal("oversize operator page was served")
	}
	if !strings.Contains(w.Body.String(), "Pardon us") {
		t.Fatal("did not fall back to the embedded default")
	}
}

// tokenPass builds a paid-style pass payload for scope tests.
func tokenPass(scope string, now time.Time) token.Pass {
	return token.Pass{
		Kind:  token.KindPaid,
		Scope: scope,
		Aud:   "example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
	}
}

// X-Forwarded-Proto must preserve a trusted terminator's visitor-facing scheme
// rather than describe the gate's plaintext connection from that terminator.
func TestForwardedProtoReflectsTheVisitorsScheme(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		inbound string
		want    string
	}{
		{
			name:    "trusted terminator reporting https",
			cfg:     "trusted_proxies = [\"192.0.2.10/32\"]\n",
			inbound: "https",
			want:    "https",
		},
		{
			name:    "trusted terminator reporting http",
			cfg:     "trusted_proxies = [\"192.0.2.10/32\"]\n",
			inbound: "http",
			want:    "http",
		},
		{
			// An untrusted peer claiming https must not be believed: otherwise
			// any client could persuade the upstream it was on TLS.
			name:    "untrusted peer claiming https",
			cfg:     "",
			inbound: "https",
			want:    "http",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Get("X-Forwarded-Proto")
			}))
			defer up.Close()

			cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
			body := "upstream = \"" + up.URL + "\"\n" + tt.cfg
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatalf("gate.New: %v", err)
			}

			cookie := solveAndGetCookie(t, g, nil)
			r := browserReq("/")
			r.Header.Set("X-Forwarded-Proto", tt.inbound)
			r.AddCookie(cookie)
			do(g, r)

			if got != tt.want {
				t.Errorf("upstream saw X-Forwarded-Proto %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUnixSocketUpstream proves the gate can front an application bound to a
// unix socket rather than a TCP port, which is how gunicorn, puma, uwsgi and
// php-fpm are usually packaged. Without it the only way to gate such an app is
// to move it onto a port — a change to someone else's service to accommodate
// ours.
func TestUnixSocketUpstream(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "app.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on a unix socket here: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "UPSTREAM:"+r.URL.Path+":host="+r.Host)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(cfgPath, []byte("upstream = \"unix:"+sock+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	cookie := solveAndGetCookie(t, g, nil)
	r := browserReq("/hello")
	r.AddCookie(cookie)
	w := do(g, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "UPSTREAM:/hello") {
		t.Errorf("body = %q, want the socket-served upstream response", w.Body.String())
	}
}

// TestIsBrowserNav pins who gets the wait page and who gets the refusal.
//
// The table is the contract. The rows that matter most are the two
// service-worker rows: a site's own root-scoped worker re-issuing a top-level
// navigation has its fetch metadata rewritten by the browser, differently per
// engine, and believing that metadata walls the visitor permanently — the
// refusal carries no solver, so no pass can ever be earned. Measured values:
//
//	ordinary navigation   mode=navigate     dest=document
//	re-issued, Chromium   mode=navigate     dest=empty
//	re-issued, Firefox    mode=same-origin  dest=empty
func TestIsBrowserNav(t *testing.T) {
	const (
		browserUA  = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
		htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	)

	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{
			name:   "ordinary browser navigation",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: true,
		},
		{
			name:   "navigation re-issued by a service worker, chromium shape",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: true,
		},
		{
			// The lockout. Before the corroboration this returned false and the
			// visitor received a refusal they could never act on.
			name:   "navigation re-issued by a service worker, firefox shape",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: true,
		},
		{
			// The cost of the fix, bounded: a same-origin fetch() sends
			// Accept: */* by default, so it stays on the refusal path.
			name:   "ordinary same-origin fetch",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
				"Accept": "*/*", "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "same-origin fetch from a program, no browser user agent",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": "python-requests/2.31",
			},
			want: false,
		},
		{
			name:   "cross-origin fetch is programmatic by construction",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "no-cors fetch",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "websocket handshake",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "websocket", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "subresource claiming to be a navigation",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "image",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "script subresource",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "script",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "htmx fragment is not a navigation however it is labelled",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA, "HX-Request": "true",
			},
			want: false,
		},
		{
			name:   "turbo frame",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
				"Accept": htmlAccept, "User-Agent": browserUA, "Turbo-Frame": "modal",
			},
			want: false,
		},
		{
			name:   "xhr announcing itself",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "same-origin", "Sec-Fetch-Dest": "empty",
				"Accept": htmlAccept, "User-Agent": browserUA, "X-Requested-With": "XMLHttpRequest",
			},
			want: false,
		},
		{
			name:    "older browser with no fetch metadata at all",
			method:  "GET",
			headers: map[string]string{"Accept": htmlAccept, "User-Agent": browserUA},
			want:    true,
		},
		{
			name:    "curl",
			method:  "GET",
			headers: map[string]string{"Accept": "*/*", "User-Agent": "curl/8.5.0"},
			want:    false,
		},
		{
			name:   "a client that prefers markdown gets the machine answer",
			method: "GET",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
				"Accept": "text/markdown", "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "POST is never a navigation we can serve a wait page for",
			method: "POST",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: false,
		},
		{
			name:   "HEAD navigation",
			method: "HEAD",
			headers: map[string]string{
				"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
				"Accept": htmlAccept, "User-Agent": browserUA,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "/", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := isBrowserNav(r); got != tt.want {
				t.Errorf("isBrowserNav = %v, want %v\nheaders: %v", got, tt.want, tt.headers)
			}
		})
	}
}

// A renewal challenge is graded with the difficulty chosen when it was issued,
// even if the pass expires before the answer arrives.
func TestRenewalStraddlingExpiryIsGradedAsIssued(t *testing.T) {
	g, _ := newTestGate(t, fastCfg) // pass_ttl = 10s
	base := time.Now()
	g.now = func() time.Time { return base }
	pass := solveAndGetCookie(t, g, nil) // pass expires at base+10s

	// Ask for a challenge while the pass is still live, with 1s to spare.
	g.now = func() time.Time { return base.Add(9 * time.Second) }
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	cr.AddCookie(pass)
	cw := do(g, cr)
	var ch challengeResponse
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		t.Fatalf("challenge JSON: %v", err)
	}
	if ch.Kind != "renew" {
		t.Fatalf("challenge kind = %q, want renew — the pass is still live here", ch.Kind)
	}
	th, err := hexTo32(ch.Threshold)
	if err != nil {
		t.Fatalf("threshold: %v", err)
	}
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		t.Fatal("no PoW solution found")
	}

	// The answer arrives after the OLD pass has expired, but well inside the
	// lifetime the new pass would have (issued at +9s, so good until +19s).
	g.now = func() time.Time { return base.Add(11 * time.Second) }
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	ar.AddCookie(pass)
	aw := do(g, ar)
	if aw.Code != 200 {
		t.Fatalf("honest renewal rejected: status %d body %s", aw.Code, aw.Body)
	}
	var res answerResponse
	if err := json.Unmarshal(aw.Body.Bytes(), &res); err != nil {
		t.Fatalf("answer JSON: %v", err)
	}
	if res.Kind != "renew" {
		t.Errorf("answer graded as %q, want renew", res.Kind)
	}
}

// The other half of the same rule: an answer arriving after the pass it would
// mint has itself expired is still refused. Grading as-issued must not become a
// way to redeem a stale challenge.
func TestRenewalAfterMintedLifetimeStillRefused(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	base := time.Now()
	g.now = func() time.Time { return base }
	pass := solveAndGetCookie(t, g, nil)

	g.now = func() time.Time { return base.Add(9 * time.Second) }
	cr := httptest.NewRequest("GET", pathChallenge, nil)
	cr.AddCookie(pass)
	cw := do(g, cr)
	var ch challengeResponse
	json.Unmarshal(cw.Body.Bytes(), &ch)
	th, _ := hexTo32(ch.Threshold)
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}

	// Past issuedAt+pass_ttl (9s + 10s = 19s).
	g.now = func() time.Time { return base.Add(20 * time.Second) }
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})
	ar := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
	ar.Header.Set("Content-Type", "application/json")
	ar.AddCookie(pass)
	// Refused, and the door it is refused at does not matter: the challenge's
	// own freshness window and the minted pass's remaining lifetime both expire
	// here, and which one speaks first depends on how the two are configured
	// relative to each other. Asserting one specific status pins a coincidence.
	if aw := do(g, ar); aw.Code < 400 {
		t.Fatalf("stale challenge accepted: status %d body %s", aw.Code, aw.Body)
	}
}

// The cookie must outlive the pass so a renewal answer crossing pass expiry
// still carries the evidence needed to select renewal difficulty.
func TestPassCookieOutlivesThePass(t *testing.T) {
	g, _ := newTestGate(t, fastCfg) // pass_ttl = 10s
	base := time.Now()
	g.now = func() time.Time { return base }

	w := httptest.NewRecorder()
	exp := base.Add(10 * time.Second)
	if err := g.setPassCookie(w, httptest.NewRequest("GET", "/", nil),
		token.Pass{Kind: token.KindPoW, Scope: "*"}, exp, base); err != nil {
		t.Fatalf("minting: %v", err)
	}
	var c *http.Cookie
	for _, got := range w.Result().Cookies() {
		if got.Name == cookieName {
			c = got
		}
	}
	if c == nil {
		t.Fatal("no pass cookie")
	}
	remaining := int(exp.Sub(base) / time.Second)
	if c.MaxAge <= remaining {
		t.Errorf("cookie Max-Age %ds does not outlive the %ds pass: a renewal round "+
			"crossing expiry posts cookieless and is graded at admission difficulty",
			c.MaxAge, remaining)
	}
}
