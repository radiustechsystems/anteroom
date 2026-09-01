package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/payment"
	"github.com/radiustechsystems/anteroom/internal/token"
)

// payGate stands up a gate with a pay door in front of a marker upstream, with
// a facilitator that always settles successfully unless told otherwise.
func payGate(t *testing.T, rules string, settle http.HandlerFunc) (*Gate, *httptest.Server) {
	t.Helper()

	fac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/verify"):
			json.NewEncoder(w).Encode(payment.VerifyResponse{IsValid: true, Payer: "0xpayer"})
		case strings.HasSuffix(r.URL.Path, "/settle"):
			if settle != nil {
				settle(w, r)
				return
			}
			json.NewEncoder(w).Encode(payment.SettleResponse{
				Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
		}
	}))
	t.Cleanup(fac.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	body := "upstream = \"" + up.URL + "\"\ndifficulty = 6\n\n" +
		"[payments]\npay_to = \"0x000000000000000000000000000000000000dEaD\"\nfacilitator = \"" + fac.URL + "\"\n" +
		"max_timeout_seconds = 300\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:72344\"\nasset = \"0xasset\"\ndecimals = 6\n" +
		"asset_name = \"Stable Coin\"\nasset_version = \"1\"\nasset_transfer_method = \"permit2\"\n\n" +
		rules

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v\n%s", err, body)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return g, up
}

// present builds a PAYMENT-SIGNATURE header. extra lets a test tamper with the
// parts of the document the client controls.
func present(t *testing.T, accepted map[string]any, extra map[string]any) string {
	t.Helper()
	sig := "0xsig"
	if payload, ok := extra["payload"].(map[string]any); ok {
		if v, ok := payload["signature"].(string); ok {
			sig = v
		}
	}
	method := "eip3009"
	if railExtra, ok := accepted["extra"].(map[string]any); ok {
		if v, ok := railExtra["assetTransferMethod"].(string); ok {
			method = v
		}
	}
	authKey := "authorization"
	if method == "permit2" {
		authKey = "permit2Authorization"
	}
	nonce := sha256.Sum256([]byte(sig))
	doc := map[string]any{
		"x402Version": 2,
		"payload": map[string]any{
			"signature": sig,
			authKey: map[string]any{
				"from":  "0xpayer",
				"nonce": fmt.Sprintf("0x%x", nonce),
			},
		},
		"accepted": accepted,
	}
	for k, v := range extra {
		if k == "payload" {
			continue
		}
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// presentSigned builds a presentation carrying a specific signature. Tests that
// need several distinct payments vary the signature and its authorization
// nonce together, as a real client does for independently spendable payments.
func presentSigned(t *testing.T, accepted map[string]any, sig string) string {
	t.Helper()
	return present(t, accepted, map[string]any{
		"payload": map[string]any{"signature": sig},
	})
}

func offered(g *Gate, t *testing.T, path string) map[string]any {
	t.Helper()
	return offeredForRequest(g, t, agentReq(path))
}

func offeredForRequest(g *Gate, t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	w := do(g, r)
	hdr := w.Header().Get(payment.HeaderRequired)
	if hdr == "" {
		t.Fatalf("no %s header on the 402", payment.HeaderRequired)
	}
	raw, err := base64.StdEncoding.DecodeString(hdr)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accepts []map[string]any `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Accepts) == 0 {
		t.Fatal("offer carried no accepts[]")
	}
	return doc.Accepts[0]
}

const oneRule = `[[payments.rules]]
name = "site"
paths = ["/*"]
price = "$0.01"
paid_ttl = "1h"
`

func TestVerifiedCrawlerBypassesPaidRoute(t *testing.T) {
	g, _ := payGate(t, oneRule+`
[bypass]
verified_crawlers = ["googlebot"]
`, nil)
	g.crawlers = &testCrawlerVerifier{verified: netip.MustParseAddr("192.0.2.2")}
	r := agentReq("/report")
	r.RemoteAddr = "192.0.2.2:1234"
	r.Header.Set("User-Agent", "Googlebot/2.1")
	w := do(g, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("verified crawler did not bypass paid route: %d %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get(payment.HeaderRequired); got != "" {
		t.Fatalf("verified crawler received a payment offer: %q", got)
	}

	spoof := agentReq("/report")
	spoof.RemoteAddr = "192.0.2.3:1234"
	spoof.Header.Set("User-Agent", "Googlebot/2.1")
	w = do(g, spoof)
	if w.Code != http.StatusForbidden {
		t.Fatalf("spoofed crawler status = %d, want 403", w.Code)
	}
	if got := w.Header().Get(payment.HeaderRequired); got != "" {
		t.Fatalf("spoofed crawler received a payment offer: %q", got)
	}
}

func TestHostedFetcherTriagePrecedesPayment(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	g.hosted = &testHostedVerifier{verified: netip.MustParseAddr("192.0.2.2")}

	web := agentReq("/report")
	web.RemoteAddr = "192.0.2.2:1234"
	web.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)")
	w := do(g, web)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("verified hosted fetcher did not bypass paid route: %d %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get(payment.HeaderRequired); got != "" {
		t.Fatalf("verified hosted fetcher received a payment offer: %q", got)
	}

	cli := agentReq("/report")
	cli.Header.Set("User-Agent", "Claude-User (claude-code/2.1.250; +https://support.anthropic.com/)")
	w = do(g, cli)
	if got := w.Header().Get(payment.HeaderRequired); got == "" {
		t.Fatalf("Claude Code did not receive an x402 offer: status %d body %q", w.Code, w.Body.String())
	}
}

// facFake is one fake facilitator with per-endpoint counters, for tests that
// need to know WHICH facilitator was called.
type facFake struct {
	srv              *httptest.Server
	calls            atomic.Int32
	verifyN, settleN atomic.Int32
	sawAuth          atomic.Value // last Authorization header on /verify
}

func newFacFake(t *testing.T, network string) *facFake {
	t.Helper()
	f := &facFake{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, "/verify"):
			f.verifyN.Add(1)
			f.sawAuth.Store(r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(payment.VerifyResponse{IsValid: true, Payer: "0xpayer"})
		case strings.HasSuffix(r.URL.Path, "/settle"):
			f.settleN.Add(1)
			json.NewEncoder(w).Encode(payment.SettleResponse{
				Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: network})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// payGateTwoFacilitators is payGate with two rails on two facilitators: rail A
// (eip155:72344) inherits the global facilitator facA; rail B (eip155:8453)
// names facB per-rail. railBExtra is spliced into rail B's TOML.
func payGateTwoFacilitators(t *testing.T, railBExtra string) (*Gate, *facFake, *facFake) {
	t.Helper()
	facA := newFacFake(t, "eip155:72344")
	facB := newFacFake(t, "eip155:8453")

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	t.Cleanup(up.Close)

	body := "upstream = \"" + up.URL + "\"\ndifficulty = 6\n\n" +
		"[payments]\npay_to = \"0x000000000000000000000000000000000000dEaD\"\nfacilitator = \"" + facA.srv.URL + "\"\n" +
		"max_timeout_seconds = 300\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:72344\"\nasset = \"0xasset\"\ndecimals = 6\n" +
		"asset_name = \"Stable Coin\"\nasset_version = \"1\"\nasset_transfer_method = \"permit2\"\n\n" +
		"[[payments.rails]]\nnetwork = \"eip155:8453\"\nasset = \"0xusdc\"\ndecimals = 6\n" +
		"asset_name = \"USD Coin\"\nasset_version = \"2\"\nasset_transfer_method = \"eip3009\"\n" +
		"facilitator = \"" + facB.srv.URL + "\"\n" + railBExtra + "\n" +
		oneRule

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v\n%s", err, body)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return g, facA, facB
}

// offeredNet picks the accepts[] entry for one network out of a multi-rail 402.
func offeredNet(g *Gate, t *testing.T, path, network string) map[string]any {
	t.Helper()
	r := agentReq(path)
	w := do(g, r)
	hdr := w.Header().Get(payment.HeaderRequired)
	if hdr == "" {
		t.Fatalf("no %s header on the 402", payment.HeaderRequired)
	}
	raw, err := base64.StdEncoding.DecodeString(hdr)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accepts []map[string]any `json:"accepts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, a := range doc.Accepts {
		if a["network"] == network {
			return a
		}
	}
	t.Fatalf("no accepts[] entry for %s in %v", network, doc.Accepts)
	return nil
}

// TestPaymentRoutesToTheMatchedRailsFacilitator: the whole point of per-rail
// facilitators — a payment on rail B settles at B's facilitator and touches
// A's not at all, and vice versa.
func TestPaymentRoutesToTheMatchedRailsFacilitator(t *testing.T) {
	g, facA, facB := payGateTwoFacilitators(t, "")

	payOn := func(network, sig string) *httptest.ResponseRecorder {
		acc := offeredNet(g, t, "/x", network)
		r := agentReq("/x")
		r.Header.Set(payment.HeaderSignature, presentSigned(t, acc, sig))
		return do(g, r)
	}

	if w := payOn("eip155:8453", "0xsigB"); !strings.Contains(w.Body.String(), "UPSTREAM:/x") {
		t.Fatalf("rail-B payment not served: %d %s", w.Code, w.Body.String())
	}
	if facB.verifyN.Load() != 1 || facB.settleN.Load() != 1 {
		t.Errorf("facB verify/settle = %d/%d, want 1/1", facB.verifyN.Load(), facB.settleN.Load())
	}
	if facA.verifyN.Load() != 0 || facA.settleN.Load() != 0 {
		t.Errorf("rail-B payment leaked to facA: verify/settle = %d/%d", facA.verifyN.Load(), facA.settleN.Load())
	}

	if w := payOn("eip155:72344", "0xsigA"); !strings.Contains(w.Body.String(), "UPSTREAM:/x") {
		t.Fatalf("rail-A payment not served: %d %s", w.Code, w.Body.String())
	}
	if facA.verifyN.Load() != 1 || facA.settleN.Load() != 1 {
		t.Errorf("facA verify/settle = %d/%d, want 1/1", facA.verifyN.Load(), facA.settleN.Load())
	}
	if facB.verifyN.Load() != 1 {
		t.Errorf("rail-A payment leaked to facB: verify = %d, want still 1", facB.verifyN.Load())
	}
}

// TestClientFieldsCannotSteerTheFacilitator: junk client fields naming the
// other facilitator's URL must not move the call. Routing keys off the gate's
// own requirements for the matched rail, and nothing the client writes can
// reach that decision.
func TestClientFieldsCannotSteerTheFacilitator(t *testing.T) {
	g, facA, facB := payGateTwoFacilitators(t, "")
	acc := offeredNet(g, t, "/x", "eip155:72344") // rail A

	hdr := present(t, acc, map[string]any{
		"facilitator": facB.srv.URL, // no such protocol field; must be inert
		"resource":    map[string]any{"url": facB.srv.URL, "description": "steer"},
	})
	r := agentReq("/x")
	r.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/x") {
		t.Fatalf("rail-A payment refused: %d %s", w.Code, w.Body.String())
	}
	if facA.verifyN.Load() != 1 {
		t.Errorf("facA verify = %d, want 1", facA.verifyN.Load())
	}
	if facB.verifyN.Load() != 0 || facB.settleN.Load() != 0 {
		t.Errorf("client fields steered egress to facB: verify/settle = %d/%d", facB.verifyN.Load(), facB.settleN.Load())
	}
}

// TestPerRailFacilitatorAuthHeaders: rail B's credential (arriving via env)
// reaches B's facilitator, and A's facilitator never sees it — the
// all-or-nothing inheritance rule, observed on the wire.
func TestPerRailFacilitatorAuthHeaders(t *testing.T) {
	t.Setenv("TEST_GATE_FAC_KEY", "railb-key")
	g, facA, facB := payGateTwoFacilitators(t,
		"facilitator_headers = [\"Authorization: Bearer ${TEST_GATE_FAC_KEY}\"]\n")

	payOn := func(network, sig string) {
		acc := offeredNet(g, t, "/x", network)
		r := agentReq("/x")
		r.Header.Set(payment.HeaderSignature, presentSigned(t, acc, sig))
		if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:/x") {
			t.Fatalf("payment on %s not served: %d %s", network, w.Code, w.Body.String())
		}
	}
	payOn("eip155:8453", "0xsigB")
	payOn("eip155:72344", "0xsigA")

	if got, _ := facB.sawAuth.Load().(string); got != "Bearer railb-key" {
		t.Errorf("facB Authorization = %q, want the rail-B credential", got)
	}
	if got, _ := facA.sawAuth.Load().(string); got != "" {
		t.Errorf("facA saw rail-B's credential: %q", got)
	}
}

// TestPaidPassScopeAndTTLComeFromTheRule is the scope-escalation guard.
//
// The client echoes our own extensions back to us, and those extensions carry
// `scope` and `paidTtlSeconds`. A payload therefore arrives containing values
// that look exactly like policy and are entirely attacker-chosen. If either were
// read, one cent paid under the cheapest rule would mint a pass scoped to the
// most expensive one, lasting as long as the payer asked for.
//
// The structural defence is that payment.Payload has no field for them, so
// nothing can read them. This asserts the resulting behaviour.
func TestPaidPassScopeAndTTLComeFromTheRule(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	acc := offered(g, t, "/")

	hdr := present(t, acc, map[string]any{
		"resource": map[string]any{"url": "http://evil/", "description": "attacker"},
		"extensions": map[string]any{
			"dev.anteroom": map[string]any{
				"scope":          "reports",          // a scope we never sold them
				"paidTtlSeconds": 60 * 60 * 24 * 365, // a year, for one cent
				"price":          "$0.00",
			},
		},
	})

	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, hdr)
	w := do(g, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	var pass *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie minted")
	}
	p, err := g.keyring.Verify(pass.Value, g.now())
	if err != nil {
		t.Fatalf("minted pass does not verify: %v", err)
	}

	if p.Scope != g.routes[0].scope {
		t.Errorf("pass scope = %q, want the compiled route scope %q", p.Scope, g.routes[0].scope)
	}
	if p.Kind != token.KindPaid {
		t.Errorf("pass kind = %q, want paid", p.Kind)
	}
	// One hour from the rule, not a year from the payload.
	if life := p.Exp - p.Iat; life > 3600+60 {
		t.Errorf("pass lifetime %ds — the payload's paidTtlSeconds was honoured", life)
	}
}

func TestPaidTTLDoesNotLoseTheFractionalSecond(t *testing.T) {
	g, _ := payGate(t, strings.Replace(oneRule, `paid_ttl = "1h"`, `paid_ttl = "1s"`, 1), nil)
	now := time.Unix(1_700_000_000, 999_000_000)
	g.now = func() time.Time { return now }
	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, offered(g, t, "/"), nil))
	w := do(g, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var pass *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no paid pass")
	}
	p, err := g.keyring.Verify(pass.Value, now)
	if err != nil {
		t.Fatal(err)
	}
	remaining := time.Unix(p.Exp, 0).Sub(now)
	if remaining < time.Second || remaining >= 2*time.Second {
		t.Fatalf("one-second paid TTL became %s", remaining)
	}
}

func TestPaidAdmissionsDoNotInstallPoWRenewal(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	originalUpstream := g.upstream
	var encodings []string
	g.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodings = append(encodings, r.Header.Get("Accept-Encoding"))
		originalUpstream.ServeHTTP(w, r)
	})

	acc := offered(g, t, "/")
	paid := browserReq("/")
	paid.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	first := do(g, paid)
	if first.Code != http.StatusOK {
		t.Fatalf("payment status = %d, want 200", first.Code)
	}
	var pass *http.Cookie
	for _, c := range first.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("payment minted no pass")
	}

	returning := browserReq("/")
	returning.AddCookie(pass)
	if got := do(g, returning); got.Code != http.StatusOK {
		t.Fatalf("paid pass status = %d, want 200", got.Code)
	}
	if len(encodings) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(encodings))
	}
	for i, encoding := range encodings {
		if encoding == "identity" {
			t.Errorf("paid request %d entered the PoW injection path", i)
		}
	}
}

// TestPaymentUnderACheapRuleCannotUnlockAnExpensivePath. The rule is chosen by
// the request path, and the amount is checked against that rule — so presenting
// a cheap rail against an expensive route is refused before any egress.
func TestPaymentUnderACheapRuleCannotUnlockAnExpensivePath(t *testing.T) {
	rules := `[[payments.rules]]
name = "reports"
paths = ["/reports/*"]
price = "$2.50"
paid_ttl = "24h"

[[payments.rules]]
name = "site"
paths = ["/*"]
price = "$0.01"
paid_ttl = "1h"
`
	g, _ := payGate(t, rules, nil)

	cheap := offered(g, t, "/")               // $0.01
	expensive := offered(g, t, "/reports/q1") // $2.50
	if cheap["amount"] == expensive["amount"] {
		t.Fatalf("fixture broken: both rules priced %v", cheap["amount"])
	}

	// Pay the cheap price, ask for the expensive resource.
	r := agentReq("/reports/q1")
	r.Header.Set(payment.HeaderSignature, present(t, cheap, nil))
	w := do(g, r)

	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("a $0.01 payment unlocked a $2.50 resource")
	}
	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402", w.Code)
	}
}

// TestTamperedTermsAreRefusedBeforeEgress. The requirements the gate forwards
// are always its own, so rewriting them cannot move value — but the gate should
// also not spend a facilitator round trip discovering that.
func TestTamperedTermsAreRefusedBeforeEgress(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Transaction: "0xtx"})
	})

	for name, tamper := range map[string]func(map[string]any){
		"lowered amount":    func(m map[string]any) { m["amount"] = "1" },
		"redirected payTo":  func(m map[string]any) { m["payTo"] = "0xattacker" },
		"substituted asset": func(m map[string]any) { m["asset"] = "0xother" },
		"unoffered network": func(m map[string]any) { m["network"] = "eip155:8453" },
	} {
		t.Run(name, func(t *testing.T) {
			acc := offered(g, t, "/")
			tamper(acc)
			before := egress

			r := agentReq("/")
			r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
			w := do(g, r)

			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "UPSTREAM:") {
				t.Error("tampered terms were served")
			}
			if egress != before {
				t.Error("a tampered presentation reached the facilitator; " +
					"it should be refused locally")
			}
		})
	}
}

// TestGarbagePresentationCausesNoEgress. A bogus PAYMENT-SIGNATURE must not
// purchase a facilitator round trip, or an attacker gets to spend the
// operator's rate limit for free.
func TestGarbagePresentationCausesNoEgress(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{Success: true, Transaction: "0xtx"})
	})

	for _, hdr := range []string{"", "!!!!", base64.StdEncoding.EncodeToString([]byte("hello")),
		base64.StdEncoding.EncodeToString([]byte(`{"x402Version":2}`))} {
		r := agentReq("/")
		if hdr != "" {
			r.Header.Set(payment.HeaderSignature, hdr)
		}
		// Both halves. "No egress" alone is also what a gate that SERVED these
		// would do, and the rule here is paths = ["/*"], so a garbage header
		// treated as a valid payment proxies straight through — refused-for-free
		// and served-for-free are indistinguishable by the egress counter, and
		// only one of them is the property this test is named for.
		if w := do(g, r); strings.Contains(w.Body.String(), "UPSTREAM:") {
			t.Errorf("garbage PAYMENT-SIGNATURE %q was served content", hdr)
		}
	}
	if egress != 0 {
		t.Errorf("%d facilitator calls from garbage headers, want 0", egress)
	}
}

func TestDuplicatePaymentHeadersCauseNoEgress(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{Success: true, Transaction: "0xtx"})
	})
	acc := offered(g, t, "/")
	r := agentReq("/")
	r.Header.Add(payment.HeaderSignature, present(t, acc, nil))
	r.Header.Add(payment.HeaderSignature, presentSigned(t, acc, "0xother"))
	w := do(g, r)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", w.Code)
	}
	if egress != 0 {
		t.Fatalf("duplicate headers caused %d facilitator calls", egress)
	}
}

func TestPaymentUpgradeIsRefusedBeforeSettlement(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{Success: true, Transaction: "0xtx"})
	})
	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, offered(g, t, "/"), nil))
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "websocket")
	if got := do(g, r); got.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", got.Code)
	}
	if egress != 0 {
		t.Fatalf("upgrade payment caused %d facilitator calls", egress)
	}
}

// TestPaymentPresentationCannotExecuteAnUpstreamMutation separates the
// settlement transaction from the application transaction. If a POST carrying
// a payment were allowed through, a lost response would leave the client unable
// to know whether retrying duplicates the upstream mutation. The paid cookie
// acquired on GET still authorizes POST normally.
func TestPaymentPresentationCannotExecuteAnUpstreamMutation(t *testing.T) {
	var settles, upstreamCalls int
	var upstreamMethod, upstreamBody string
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	g.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		upstreamMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		upstreamBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	})
	hdr := present(t, offered(g, t, "/action"), nil)

	post := httptest.NewRequest(http.MethodPost, "http://example.com/action", strings.NewReader("change=1"))
	post.Header.Set("Accept", "*/*")
	post.Header.Set(payment.HeaderSignature, hdr)
	post.RemoteAddr = "192.0.2.10:44321"
	refused := do(g, post)
	if refused.Code != http.StatusPaymentRequired {
		t.Fatalf("payment POST status = %d, want 402", refused.Code)
	}
	if settles != 0 || upstreamCalls != 0 {
		t.Fatalf("payment POST caused settles=%d upstream=%d, want zero", settles, upstreamCalls)
	}
	if !strings.Contains(refused.Body.String(), "GET or HEAD") {
		t.Fatalf("refusal did not explain admission request: %q", refused.Body.String())
	}

	get := agentReq("/action")
	get.Header.Set(payment.HeaderSignature, hdr)
	paid := do(g, get)
	if paid.Code != http.StatusNoContent || settles != 1 || upstreamCalls != 1 {
		t.Fatalf("admission GET = status %d settles=%d upstream=%d", paid.Code, settles, upstreamCalls)
	}
	cookies := paid.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("admission GET set no pass cookie")
	}

	retry := httptest.NewRequest(http.MethodPost, "http://example.com/action", strings.NewReader("change=1"))
	retry.Header.Set("Accept", "*/*")
	retry.Header.Set("User-Agent", "curl/8.0")
	retry.RemoteAddr = "192.0.2.10:44321"
	retry.AddCookie(cookies[0])
	got := do(g, retry)
	if got.Code != http.StatusNoContent {
		t.Fatalf("authorized POST status = %d, want 204", got.Code)
	}
	if settles != 1 || upstreamCalls != 2 || upstreamMethod != http.MethodPost || upstreamBody != "change=1" {
		t.Fatalf("authorized POST: settles=%d upstream=%d method=%q body=%q",
			settles, upstreamCalls, upstreamMethod, upstreamBody)
	}
}

// TestPaymentRetryRecoversTheDurableGrant. A retry may be the first request's
// lost response, so it receives the same entitlement without another settle.
func TestPaymentRetryRecoversTheDurableGrant(t *testing.T) {
	var settles int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	acc := offered(g, t, "/")
	hdr := present(t, acc, nil)

	first := agentReq("/")
	first.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, first); w.Code != http.StatusOK {
		t.Fatalf("first presentation: status %d", w.Code)
	}

	second := agentReq("/")
	second.Header.Set(payment.HeaderSignature, hdr)
	w := do(g, second)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("retry did not recover the grant: status=%d body=%q", w.Code, w.Body.String())
	}
	if settles != 1 {
		t.Fatalf("retry caused %d settlements, want 1", settles)
	}
}

func TestPaymentGrantRecoversAcrossGateRestart(t *testing.T) {
	var settles int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	hdr := present(t, offered(g, t, "/"), nil)
	first := agentReq("/")
	first.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, first); w.Code != http.StatusOK {
		t.Fatalf("first presentation: status %d", w.Code)
	}

	restarted, err := New(g.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("restart gate.New: %v", err)
	}
	retry := agentReq("/")
	retry.Header.Set(payment.HeaderSignature, hdr)
	if w := do(restarted, retry); w.Code != http.StatusOK {
		t.Fatalf("restart retry: status %d body=%q", w.Code, w.Body.String())
	}
	if settles != 1 {
		t.Fatalf("restart recovery caused %d settlements, want 1", settles)
	}
}

func TestPaymentGrantRecoversAfterUpstreamFailure(t *testing.T) {
	var settles int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	var upstreamCalls int
	g.upstream = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if upstreamCalls == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, "RECOVERED")
	})
	hdr := present(t, offered(g, t, "/"), nil)
	first := agentReq("/")
	first.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, first); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("first upstream response: status %d, want 503", w.Code)
	}

	retry := agentReq("/")
	retry.Header.Set(payment.HeaderSignature, hdr)
	w := do(g, retry)
	if w.Code != http.StatusOK || w.Body.String() != "RECOVERED" {
		t.Fatalf("retry = status %d body %q", w.Code, w.Body.String())
	}
	if settles != 1 {
		t.Fatalf("upstream recovery caused %d settlements, want 1", settles)
	}
}

func TestRecoveredGrantCannotChangeScopeOrAudience(t *testing.T) {
	t.Run("scope", func(t *testing.T) {
		var settles int
		g, _ := payGate(t, twoRules, func(w http.ResponseWriter, r *http.Request) {
			settles++
			json.NewEncoder(w).Encode(payment.SettleResponse{
				Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
		})
		first := agentReq("/reports/a")
		first.Header.Set(payment.HeaderSignature, present(t, offered(g, t, "/reports/a"), nil))
		if w := do(g, first); w.Code != http.StatusOK {
			t.Fatalf("first presentation: status %d", w.Code)
		}
		other := agentReq("/other")
		other.Header.Set(payment.HeaderSignature, present(t, offered(g, t, "/other"), nil))
		if w := do(g, other); w.Code != http.StatusPaymentRequired {
			t.Fatalf("cross-scope retry: status %d, want 402", w.Code)
		}
		if settles != 1 {
			t.Fatalf("cross-scope retry caused %d settlements, want 1", settles)
		}
	})

	t.Run("audience", func(t *testing.T) {
		var settles int
		g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
			settles++
			json.NewEncoder(w).Encode(payment.SettleResponse{
				Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
		})
		first := agentReq("/")
		first.Header.Set(payment.HeaderSignature, present(t, offered(g, t, "/"), nil))
		if w := do(g, first); w.Code != http.StatusOK {
			t.Fatalf("first presentation: status %d", w.Code)
		}
		offerReq := agentReq("/")
		offerReq.Host = "other.example"
		acc := offeredForRequest(g, t, offerReq)
		other := agentReq("/")
		other.Host = "other.example"
		other.Header.Set(payment.HeaderSignature, present(t, acc, nil))
		if w := do(g, other); w.Code != http.StatusPaymentRequired {
			t.Fatalf("cross-audience retry: status %d, want 402", w.Code)
		}
		if settles != 1 {
			t.Fatalf("cross-audience retry caused %d settlements, want 1", settles)
		}
	})
}

// TestRewrappedPaymentRecoversOneSemanticGrant.
//
// Client-authored envelope metadata must not change the authorization identity.
// A harmlessly rewrapped retry may recover the existing grant but must never
// reach the facilitator again.
func TestRewrappedPaymentRecoversOneSemanticGrant(t *testing.T) {
	rewrappings := map[string]map[string]any{
		"padded extensions": {"extensions": map[string]any{
			"dev.anteroom": map[string]any{"pad": "aaaaaaaa"}}},
		"echoed resource":       {"resource": map[string]any{"url": "http://anything/"}},
		"unknown top-level key": {"nonceSalt": "1"},
		"version omitted":       {"x402Version": nil},
	}

	for name, envelope := range rewrappings {
		t.Run(name, func(t *testing.T) {
			var settles int
			g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
				settles++
				json.NewEncoder(w).Encode(payment.SettleResponse{
					Success: true, Payer: "0xpayer", Transaction: "0xtx",
					Network: "eip155:72344"})
			})
			acc := offered(g, t, "/")

			first := agentReq("/")
			first.Header.Set(payment.HeaderSignature, present(t, acc, nil))
			if w := do(g, first); w.Code != http.StatusOK {
				t.Fatalf("first presentation: status %d — fixture broken", w.Code)
			}

			// Same signature, different wrapping paper.
			second := agentReq("/")
			second.Header.Set(payment.HeaderSignature, present(t, acc, envelope))
			w := do(g, second)

			// Strict version validation rejects the omitted-version envelope.
			// Other harmless wrapping differences recover the existing grant.
			if name != "version omitted" && w.Code != http.StatusOK {
				t.Errorf("rewrapped retry was not recovered (%s): status %d", name, w.Code)
			}
			if settles != 1 {
				t.Errorf("%d settle calls for one authorization; the replay reached the "+
					"facilitator instead of being refused locally", settles)
			}
		})
	}
}

// TestConcurrentPresentationsOfOnePaymentSettleOnce.
//
// Concurrent requests may recover the same entitlement after commit. The
// durable reservation must still permit exactly one facilitator settlement.
func TestConcurrentPresentationsOfOnePaymentSettleOnce(t *testing.T) {
	var settles atomic.Int64
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles.Add(1)
		// Slow enough that the presentations genuinely overlap.
		time.Sleep(20 * time.Millisecond)
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})
	acc := offered(g, t, "/")
	hdr := present(t, acc, nil)

	const racers = 16
	var served, passes atomic.Int64
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := agentReq("/")
			// Distinct source addresses, so the per-client rate limit is not
			// what is being measured.
			r.RemoteAddr = "192.0.2." + strconv.Itoa(i+1) + ":1234"
			r.Header.Set(payment.HeaderSignature, hdr)
			w := do(g, r)
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "UPSTREAM:") {
				served.Add(1)
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == cookieName {
					passes.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()

	if got := served.Load(); got < 1 || got > racers {
		t.Errorf("%d of %d concurrent presentations were served", got, racers)
	}
	if got := passes.Load(); got != served.Load() {
		t.Errorf("%d served responses but %d passes", served.Load(), got)
	}
	if got := settles.Load(); got != 1 {
		t.Errorf("%d settle calls for one authorization, want 1", got)
	}
}

// TestPaidResponseSealsUpstreamCacheHeaders is invariant 6, tested against an
// upstream that disagrees.
//
// Paid content is very often exactly the kind of thing a web server marks
// cacheable on its own — a report, a PDF, a static asset. The reverse proxy
// merges the upstream's headers in with Add, so setting Cache-Control before
// proxying leaves BOTH directives on the response and lets a lenient shared
// cache pick the permissive one. That is attack III with the operator's own
// server supplying the ammunition.
func TestPaidResponseSealsUpstreamCacheHeaders(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")
		// An upstream that speaks x402 itself, or simply echoes headers.
		w.Header().Set(payment.HeaderResponse, "dXBzdHJlYW0tZm9yZ2Vk")
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g.upstream = newProxy(u, "", g.match, g.lg, g.met.upstreamErr)

	acc := offered(g, t, "/")
	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	w := do(g, r)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("payment did not serve: status %d", w.Code)
	}
	cc := w.Header().Values("Cache-Control")
	if len(cc) != 1 {
		t.Errorf("Cache-Control = %q — a paid response carrying two policies lets a "+
			"cache choose the permissive one", cc)
	}
	for _, v := range cc {
		if strings.Contains(v, "public") || strings.Contains(v, "max-age=3600") {
			t.Errorf("Cache-Control = %q — the upstream's cacheability survived onto paid content", v)
		}
	}
	if joined := strings.Join(cc, ", "); !strings.Contains(joined, "no-store") ||
		!strings.Contains(joined, "private") {
		t.Errorf("Cache-Control = %q, want no-store and private", joined)
	}
	if exp := w.Header().Get("Expires"); exp != "" {
		t.Errorf("Expires = %q survived onto a paid response; an HTTP/1.0 cache "+
			"stores by Expires alone", exp)
	}
	// PAYMENT-RESPONSE is the gate's receipt for the settlement the gate made.
	// Two field lines means a client reads one of them at random.
	if pr := w.Header().Values(payment.HeaderResponse); len(pr) != 1 {
		t.Errorf("%s = %q, want exactly the gate's own", payment.HeaderResponse, pr)
	} else if pr[0] == "dXBzdHJlYW0tZm9yZ2Vk" {
		t.Errorf("%s came from the upstream, not from the settlement", payment.HeaderResponse)
	}
}

// TestPresentationsAreRateLimitedEvenWhenTheClientCannotBeResolved.
//
// The token bucket is the defence that stops a bogus header buying a facilitator
// round trip per request. If it is skipped whenever the client address does not
// resolve, the defence has an off switch — and invariant 3 says the unknown case
// resolves to "no", not to "yes".
func TestPresentationsAreRateLimitedEvenWhenTheClientCannotBeResolved(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: false, ErrorReason: "no"})
	})
	acc := offered(g, t, "/")

	// The limiter is 6/min, burst 6. Twenty presentations, each a distinct
	// payment so dedup is not what refuses them, from a peer nothing can parse.
	for i := range 20 {
		r := agentReq("/")
		r.RemoteAddr = "not-an-address"
		r.Header.Set(payment.HeaderSignature, presentSigned(t, acc, "0xsig"+strconv.Itoa(i)))
		do(g, r)
	}
	if egress > 6 {
		t.Errorf("%d facilitator round trips from an unresolvable client; the rate "+
			"limit is skipped rather than failing closed", egress)
	}
}

// TestAmbiguousSettleServesNothingAndStaysRetryable. Money may have moved, so
// the gate serves nothing and claims nothing — the payer's own retry is the
// recovery path, and refusing it as a replay would be paid-but-denied.
func TestAmbiguousSettleServesNothingAndStaysRetryable(t *testing.T) {
	var settles int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		if settles == 1 {
			// Settled, then failed to say so.
			json.NewEncoder(w).Encode(payment.SettleResponse{Success: true, Payer: "0xpayer"})
			return
		}
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0xpayer", Transaction: "0xtx", Network: "eip155:72344"})
	})

	acc := offered(g, t, "/")
	hdr := present(t, acc, nil)

	r1 := agentReq("/")
	r1.Header.Set(payment.HeaderSignature, hdr)
	w1 := do(g, r1)
	if w1.Code == http.StatusOK && strings.Contains(w1.Body.String(), "UPSTREAM:") {
		t.Fatal("an evidence-free settle success served content")
	}
	if !strings.Contains(w1.Body.String(), "may have been charged") {
		t.Errorf("the payer was not warned they may have been charged:\n%s", w1.Body.String())
	}

	// The identical payload must still be redeemable: it was never claimed.
	r2 := agentReq("/")
	r2.Header.Set(payment.HeaderSignature, hdr)
	w2 := do(g, r2)
	if w2.Code != http.StatusOK || !strings.Contains(w2.Body.String(), "UPSTREAM:") {
		t.Errorf("the recovery retry was refused (status %d) — this is paid-but-denied:\n%s",
			w2.Code, w2.Body.String())
	}
}

// TestBrowsersStillGetTheWaitPageWhenPaymentsAreOn. The free door stays open;
// enabling payments must not wall humans behind a wallet.
func TestBrowsersStillGetTheWaitPageWhenPaymentsAreOn(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	w := do(g, browserReq("/"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "anteroom-status") {
		t.Errorf("a browser did not get the wait page:\n%.300s", w.Body.String())
	}
}

// TestInboundPaymentResponseHeaderIsStripped. PAYMENT-RESPONSE is gate-authored;
// an inbound copy is a forgery attempt and the upstream must only ever see ours.
func TestInboundPaymentResponseHeaderIsStripped(t *testing.T) {
	var saw string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get(payment.HeaderResponse)
	}))
	defer up.Close()

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\ndifficulty = 6\n"), 0o600)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	cookie := solveAndGetCookie(t, g, nil)
	r := browserReq("/")
	r.AddCookie(cookie)
	r.Header.Set(payment.HeaderResponse, "Zm9yZ2Vk")
	do(g, r)

	if saw != "" {
		t.Errorf("upstream received a client-supplied %s: %q", payment.HeaderResponse, saw)
	}
}

// twoRules prices a narrow expensive path above a broad cheap one — the
// ordering the pricing model exists to support, and the one that turns a weak
// pass-scope check into an escalation.
const twoRules = `[[payments.rules]]
name = "reports"
paths = ["/reports/*"]
price = "$2.50"
paid_ttl = "24h"

[[payments.rules]]
name = "site"
paths = ["/*"]
price = "$0.01"
paid_ttl = "1h"
`

// paidCookie buys a path honestly and returns the pass the gate minted for it.
func paidCookie(t *testing.T, g *Gate, path string) *http.Cookie {
	t.Helper()
	r := agentReq(path)
	r.Header.Set(payment.HeaderSignature, present(t, offered(g, t, path), nil))
	w := do(g, r)
	if w.Code != http.StatusOK {
		t.Fatalf("buying %s: status %d: %s", path, w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatalf("buying %s minted no pass cookie", path)
	return nil
}

// TestCheapPassCannotEnterAnExpensiveRule is the escalation that survives the
// pre-egress price check, because nothing about the purchase is dishonest: pay
// the cheap price at a cheap path, then present the cookie it minted at the
// expensive one. The cheap rule's matcher covers "/reports/q1" — being the
// catch-all is what makes it cheap — so a scope check that asks only "does the
// rule I bought match this path?" lets a cent walk into a $2.50 resource.
func TestCheapPassCannotEnterAnExpensiveRule(t *testing.T) {
	g, _ := payGate(t, twoRules, nil)

	cookie := paidCookie(t, g, "/")

	r := agentReq("/reports/q1")
	r.AddCookie(cookie)
	w := do(g, r)

	if strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("a $0.01 pass admitted a $2.50 path: status %d", w.Code)
	}
	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402 carrying the expensive rule's offer", w.Code)
	}
	// The pass must still open what it actually bought.
	r = agentReq("/other")
	r.AddCookie(cookie)
	if w := do(g, r); !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Errorf("the pass stopped opening what it bought: status %d", w.Code)
	}
}

// TestEveryPaidPassResponseIsSealed. Sealing only the request that carries the
// payment protects the one response nobody re-fetches. The paid pass exists so
// the payer can come back — and every one of those later responses is the same
// paid content, admitted through the ordinary pass branch, carrying whatever
// cacheability the upstream put on it. A shared cache in front of the gate then
// serves the report to people who never paid, which is the attack the
// presentation seal was written for.
func TestEveryPaidPassResponseIsSealed(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Entirely ordinary headers for a report, a PDF or a static asset.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")
		w.Header().Set(payment.HeaderResponse, "dXBzdHJlYW0tZm9yZ2Vk")
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g.upstream = newProxy(u, "", g.match, g.lg, g.met.upstreamErr)

	cookie := paidCookie(t, g, "/")

	// A later request, admitted by the cookie rather than by a payment.
	r := agentReq("/report.pdf")
	r.AddCookie(cookie)
	w := do(g, r)
	if !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("the paid pass did not admit: status %d", w.Code)
	}

	cc := w.Header().Values("Cache-Control")
	if len(cc) != 1 {
		t.Errorf("Cache-Control = %q — two policies let a cache pick the permissive one", cc)
	}
	joined := strings.Join(cc, ", ")
	if strings.Contains(joined, "public") || strings.Contains(joined, "max-age=3600") {
		t.Errorf("Cache-Control = %q — paid content is publicly cacheable on the second request", joined)
	}
	if !strings.Contains(joined, "no-store") || !strings.Contains(joined, "private") {
		t.Errorf("Cache-Control = %q, want no-store and private", joined)
	}
	if exp := w.Header().Get("Expires"); exp != "" {
		t.Errorf("Expires = %q survived; an HTTP/1.0 cache stores by Expires alone", exp)
	}
	// No settlement happened on this request, so there is no receipt — and the
	// upstream's copy must not become one.
	if pr := w.Header().Values(payment.HeaderResponse); len(pr) != 0 {
		t.Errorf("%s = %q on a request that settled nothing", payment.HeaderResponse, pr)
	}

	// A proof-of-work pass is not paid content, and must not be sealed into
	// uncacheability: that would throw away the upstream's caching for everyone
	// who solves a puzzle.
	free, _ := newTestGate(t, fastCfg)
	fr := browserReq("/")
	fr.AddCookie(solveAndGetCookie(t, free, nil))
	if cc := do(free, fr).Header().Get("Cache-Control"); strings.Contains(cc, "no-store") {
		t.Errorf("a proof-of-work response was sealed no-store (%q); only paid content is", cc)
	}
}

// permit2Present builds a presentation carrying a realistic exact/permit2
// scheme payload: a signature over an authorization, in the shape the reference
// client emits.
func permit2Present(t *testing.T, accepted map[string]any, sig string, auth map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"payload":     map[string]any{"signature": sig, "permit2Authorization": auth},
		"accepted":    accepted,
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// TestTwoSignaturesOverOneAuthorizationRecoverOneGrant.
//
// The chain spends the nonce, not a signature serialization. Re-signing the
// same authorization may recover its existing grant but cannot settle again.
func TestTwoSignaturesOverOneAuthorizationRecoverOneGrant(t *testing.T) {
	var settles int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		settles++
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: true, Payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
			Transaction: "0xtx", Network: "eip155:72344"})
	})
	acc := offered(g, t, "/")
	auth := map[string]any{
		"permitted": map[string]any{"token": "0xasset", "amount": "10000"},
		"from":      "0x857b06519E91e3A54538791bDbb0E22373e36b66",
		"spender":   "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
		"nonce":     "33247007178036348590600198031289925668252061821958005840077069883511451257277",
		"deadline":  "1740672154",
	}

	first := agentReq("/")
	first.Header.Set(payment.HeaderSignature, permit2Present(t, acc, "0xsigA", auth))
	if w := do(g, first); w.Code != http.StatusOK {
		t.Fatalf("first presentation: status %d — fixture broken: %s", w.Code, w.Body.String())
	}

	second := agentReq("/")
	second.Header.Set(payment.HeaderSignature, permit2Present(t, acc, "0xsigB", auth))
	w := do(g, second)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Errorf("re-signed authorization did not recover its grant: status=%d", w.Code)
	}
	if settles != 1 {
		t.Errorf("%d settle calls for one authorization; the re-signed replay reached "+
			"the facilitator instead of being refused locally", settles)
	}
}

// TestTheVendorExtensionHasTheShapeTheSpecificationRequires.
//
// x402 v2 §5.1.2: every value in `extensions` carries `info` (the server's
// data) and `schema` (a JSON Schema for it). Anteroom shipped its fields bare
// at the top of the extension object, which a strict client rejects — and which
// leaves a client that has never heard of this extension nothing to interpret
// the fields with.
func TestTheVendorExtensionHasTheShapeTheSpecificationRequires(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	raw, err := base64.StdEncoding.DecodeString(
		do(g, agentReq("/")).Header().Get(payment.HeaderRequired))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Extensions map[string]map[string]any `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	ext, ok := doc.Extensions["dev.anteroom"]
	if !ok {
		t.Fatalf("no vendor extension in the offer: %v", doc.Extensions)
	}
	for _, key := range []string{"info", "schema"} {
		v, ok := ext[key]
		if !ok {
			t.Errorf("extension has no %q", key)
			continue
		}
		if _, ok := v.(map[string]any); !ok {
			t.Errorf("extension %q is %T, want an object", key, v)
		}
	}
	// Nothing may sit beside them: a stray sibling is the old shape leaking.
	if len(ext) != 2 {
		t.Errorf("extension has %d keys (%v), want exactly info and schema", len(ext), ext)
	}
	info, _ := ext["info"].(map[string]any)
	if info["scope"] != "site" || info["price"] != "$0.01" {
		t.Errorf("info lost its fields in the move: %v", info)
	}
	presentation, _ := info["presentation"].(map[string]any)
	if presentation["result"] != "admission-pass" || presentation["retryOriginal"] != true {
		t.Errorf("offer does not describe its non-standard admission result: %v", presentation)
	}
	methods, _ := presentation["methods"].([]any)
	if !reflect.DeepEqual(methods, []any{"GET", "HEAD"}) {
		t.Errorf("presentation methods = %v, want GET/HEAD", methods)
	}
	// The schema travels by reference — an absolute $ref at the request's own
	// origin — because inline it was 1.2KB in a header with a hard external
	// budget (see TestOfferHeaderFitsDefaultProxyBuffers). A $ref-only object
	// is still a valid JSON Schema, so the {info, schema} wrapper stays intact.
	schema, _ := ext["schema"].(map[string]any)
	ref, _ := schema["$ref"].(string)
	if ref == "" {
		t.Fatalf("schema is not a $ref: %v", schema)
	}
	refURL, err := url.Parse(ref)
	if err != nil || refURL.Host == "" || refURL.Path != pathSchema {
		t.Fatalf("schema $ref = %q, want an absolute URL at %s", ref, pathSchema)
	}

	// The referenced document has to describe that info, not merely exist —
	// fetched through the gate exactly as a client following the $ref would.
	sw := do(g, agentReq(refURL.Path))
	if sw.Code != 200 {
		t.Fatalf("GET %s: status %d", refURL.Path, sw.Code)
	}
	var fetched map[string]any
	if err := json.Unmarshal(sw.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("schema endpoint is not JSON: %v", err)
	}
	props, _ := fetched["properties"].(map[string]any)
	for key := range info {
		if _, ok := props[key]; !ok {
			t.Errorf("schema does not describe info.%s", key)
		}
	}
}

// TestOfferHeaderFitsDefaultProxyBuffers pins the PAYMENT-REQUIRED header to a
// byte budget. Nginx's default proxy_buffer_size is 4KB for the entire response
// header block, so two rails must stay under 3KB and leave room for other fields.
func TestOfferHeaderFitsDefaultProxyBuffers(t *testing.T) {
	g, _, _ := payGateTwoFacilitators(t, "")
	hdr := do(g, agentReq("/")).Header().Get(payment.HeaderRequired)
	if hdr == "" {
		t.Fatal("no PAYMENT-REQUIRED header on the 402")
	}
	if len(hdr) > 3*1024 {
		t.Errorf("PAYMENT-REQUIRED is %d bytes with two rails; the budget is 3072 "+
			"— did the schema get inlined again, or did a new field bloat the offer?", len(hdr))
	}
}

// TestTheApprovalInstructionsAreNotDangerousToFollow.
//
// The 402 body is copy-and-paste instructions handed to every agent and every
// human who curls a protected URL, so its shell commands are shipped advice.
// Two things were wrong with the one it printed: it approved 2^256-1, which is
// standing permission over the payer's whole balance for as long as the wallet
// exists, and it passed the private key as `--private-key`, which on Linux puts
// it in /proc/<pid>/cmdline where every other account on the machine can read
// it.
func TestTheApprovalInstructionsAreNotDangerousToFollow(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	body := do(g, agentReq("/")).Body.String()

	if !strings.Contains(body, "approve(address,uint256)") {
		t.Fatal("the Permit2 prerequisite is not explained at all")
	}
	if strings.Contains(strings.ToLower(body), "0xffffffffffffffff") {
		t.Error("the offer teaches an unlimited approval")
	}
	// The flag may be named while explaining why not to use it; what must not
	// appear is an invocation that passes a key to it.
	if strings.Contains(body, "--private-key $") {
		t.Error("the offer teaches passing a private key on a command line")
	}
	if !strings.Contains(body, "--interactive") {
		t.Error("no key-entry method that keeps the key off the command line")
	}
	// $0.01 at six decimals is 10000 atomic units; a hundred of those is the
	// suggested budget, and it has to be a number the reader can act on.
	if !strings.Contains(body, "1000000") {
		t.Errorf("no concrete approval budget in the instructions:\n%s", body)
	}
}

// TestTheOfferDoesNotDiscloseTheQuery.
//
// The resource URL in a 402 is quoted back by the client inside its payment
// payload, and that payload is forwarded verbatim to the facilitator — a party
// to the payment, not to the application. A query string is where session
// tokens, search terms and customer references live, so including it hands
// those to a payment processor as a side effect of naming a price.
func TestTheOfferDoesNotDiscloseTheQuery(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)

	r := agentReq("/report?token=s3cr3t&customer=acme&q=merger+terms")
	w := do(g, r)
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status %d, want 402", w.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(w.Header().Get(payment.HeaderRequired))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Resource struct {
			URL string `json:"url"`
		} `json:"resource"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(doc.Resource.URL, "?&") {
		t.Errorf("resource.url = %q — the query reaches the facilitator with the payment", doc.Resource.URL)
	}
	if !strings.HasSuffix(doc.Resource.URL, "/report") {
		t.Errorf("resource.url = %q, want it to still name the path", doc.Resource.URL)
	}
	// The body an agent reads must not reintroduce it.
	if strings.Contains(w.Body.String(), "s3cr3t") {
		t.Error("the 402 body quoted the query back")
	}
}

// TestThePaymentNamespaceStopsAtTheGate.
//
// PAYMENT-* is a protocol namespace with exactly one author on a paid path: the
// gate. Three boundaries, all of which leaked.
//
// The payer's signed authorization was forwarded upstream after the gate had
// already consumed it — an upstream with its own x402 middleware would verify
// or settle it a second time, and every other upstream simply gained a signed
// payment instrument in its logs. A client-supplied PAYMENT-REQUIRED reached
// the upstream, where an application that echoes or logs it is quoting an offer
// the client wrote. And an upstream's own PAYMENT-REQUIRED rode out on a paid
// response, which is an offer with someone else's payTo carrying the gate's
// authority.
func TestThePaymentNamespaceStopsAtTheGate(t *testing.T) {
	var sawSig, sawRequired string
	g, _ := payGate(t, oneRule, nil)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSig = r.Header.Get(payment.HeaderSignature)
		sawRequired = r.Header.Get(payment.HeaderRequired)
		// An upstream speaking x402 for itself, or one with a header-injection
		// bug: either way the client must not read this as the gate's offer.
		w.Header().Set(payment.HeaderRequired, "dXBzdHJlYW0tb2ZmZXI=")
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	defer up.Close()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g.upstream = newProxy(u, "", g.match, g.lg, g.met.upstreamErr)

	acc := offered(g, t, "/")
	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	r.Header.Set(payment.HeaderRequired, "Y2xpZW50LWZvcmdlZA==")
	w := do(g, r)
	if !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatalf("payment did not serve: status %d", w.Code)
	}

	if sawSig != "" {
		t.Errorf("upstream received the payer's authorization: %.40s…", sawSig)
	}
	if sawRequired != "" {
		t.Errorf("upstream received a client-supplied %s: %q", payment.HeaderRequired, sawRequired)
	}
	if got := w.Header().Get(payment.HeaderRequired); got != "" {
		t.Errorf("the upstream authored a %s on a paid response: %q", payment.HeaderRequired, got)
	}
}

// TestPendingSettlementReturnsTheTransactionAndNeverAFreshPrice.
//
// `settlement_pending` is defined as non-terminal: the transfer was broadcast
// and only its confirmation is unknown, which is why the specification requires
// the transaction and network to come with it. Mapping it to a rejection throws
// away the only evidence that exists and answers with a price — and an
// automated payer does what a 402 tells it, so the first transfer confirming a
// second later means one resource paid for twice.
func TestPendingSettlementReturnsTheTransactionAndNeverAFreshPrice(t *testing.T) {
	pending := func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(payment.SettleResponse{
			Success: false, ErrorReason: payment.ErrorSettlementPending,
			Transaction: "0xpending", Network: "eip155:72344", Payer: "0xpayer"})
	}
	g, _ := payGate(t, oneRule, pending)
	acc := offered(g, t, "/")
	hdr := present(t, acc, nil)

	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, hdr)
	w := do(g, r)

	if strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Fatal("an unconfirmed settlement served the resource")
	}
	if got := w.Header().Get(payment.HeaderRequired); got != "" {
		raw, _ := base64.StdEncoding.DecodeString(got)
		t.Errorf("a fresh payment was demanded for a transaction already broadcast: %.160s", raw)
	}
	// The receipt has to carry what a payer needs to reconcile.
	rec := w.Header().Get(payment.HeaderResponse)
	if rec == "" {
		t.Fatalf("no %s on a pending settlement", payment.HeaderResponse)
	}
	raw, err := base64.StdEncoding.DecodeString(rec)
	if err != nil {
		t.Fatalf("decoding %s: %v", payment.HeaderResponse, err)
	}
	var sr payment.SettleResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		t.Fatalf("decoding %s: %v", payment.HeaderResponse, err)
	}
	if sr.Success {
		t.Error("a pending settlement was reported as success")
	}
	if sr.Transaction != "0xpending" || sr.Network != "eip155:72344" {
		t.Errorf("receipt = %+v, want the broadcast transaction and its network", sr)
	}
	if sr.ErrorReason != payment.ErrorSettlementPending {
		t.Errorf("errorReason = %q, want %q", sr.ErrorReason, payment.ErrorSettlementPending)
	}
	// The body is what most agents actually read.
	if !strings.Contains(w.Body.String(), "0xpending") {
		t.Errorf("the body does not name the transaction:\n%s", w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on a pending settlement")
	}

	// Nothing was claimed, so the payer's own re-presentation still works once
	// the transaction confirms — that is the recovery path, and refusing it as a
	// replay would be paid-but-denied.
	g2, _ := payGate(t, oneRule, func() http.HandlerFunc {
		var n int
		return func(w http.ResponseWriter, r *http.Request) {
			n++
			if n == 1 {
				pending(w, r)
				return
			}
			json.NewEncoder(w).Encode(payment.SettleResponse{
				Success: true, Payer: "0xpayer", Transaction: "0xpending",
				Network: "eip155:72344"})
		}
	}())
	acc2 := offered(g2, t, "/")
	hdr2 := present(t, acc2, nil)
	r1 := agentReq("/")
	r1.Header.Set(payment.HeaderSignature, hdr2)
	do(g2, r1)
	r2 := agentReq("/")
	r2.Header.Set(payment.HeaderSignature, hdr2)
	if w := do(g2, r2); !strings.Contains(w.Body.String(), "UPSTREAM:") {
		t.Errorf("re-presenting after a pending settlement was refused (status %d) — "+
			"this is paid-but-denied:\n%s", w.Code, w.Body.String())
	}
}

// TestAnUnidentifiableAuthorizationIsRefusedBeforeEgress. A payment whose
// authorization names no payer and nonce cannot be deduplicated, and a payment
// that cannot be deduplicated must not be settled: the alternative is a
// per-presentation identity, which is the double-redeem again.
func TestAnUnidentifiableAuthorizationIsRefusedBeforeEgress(t *testing.T) {
	var egress int
	g, _ := payGate(t, oneRule, func(w http.ResponseWriter, r *http.Request) {
		egress++
		json.NewEncoder(w).Encode(payment.SettleResponse{Success: true, Transaction: "0xtx"})
	})
	acc := offered(g, t, "/")

	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, permit2Present(t, acc, "0xsig",
		map[string]any{"permitted": map[string]any{"token": "0xasset", "amount": "10000"}}))
	w := do(g, r)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402", w.Code)
	}
	if egress != 0 {
		t.Errorf("%d facilitator round trips for a payment the gate cannot identify, want 0", egress)
	}
}

// TestPaidPassRecordsTheSettlementThatBoughtIt.
//
// The pass IS the entitlement a payment bought, and until it names that payment
// the two are related only by a log line. `token.Pass` has carried `payer` and
// `tx` fields since the format was written and nothing ever filled them, so
// every paid pass is indistinguishable from every other paid pass under the
// same rule.
//
// This is the correspondence half of a binding the exact-EVM signature cannot
// provide. The gate cannot make the chain sign the resource, the rule or the
// price; it can record which settlement minted which entitlement, so a
// duplicate grant, a reverted transaction or a disputed charge is traceable
// from a presented cookie to a transaction hash without trusting log retention.
func TestPaidPassRecordsTheSettlementThatBoughtIt(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	acc := offered(g, t, "/")

	r := agentReq("/")
	r.Header.Set(payment.HeaderSignature, present(t, acc, nil))
	w := do(g, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}

	var pass *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie minted")
	}
	p, err := g.keyring.Verify(pass.Value, g.now())
	if err != nil {
		t.Fatalf("minted pass does not verify: %v", err)
	}
	if p.Payer != "0xpayer" {
		t.Errorf("pass payer = %q, want %q — the pass does not name who paid for it",
			p.Payer, "0xpayer")
	}
	if p.Tx != "0xtx" {
		t.Errorf("pass tx = %q, want %q — the pass does not name the settlement that bought it",
			p.Tx, "0xtx")
	}
}

// TestTheAuthorizationNeverReachesTheUpstream.
//
// PAYMENT-SIGNATURE carries the payer's signed authorization: a bearer
// capability over their funds that anyone holding can submit, which is the
// five-attacks paper's settlement preemption (I-B). The gate cannot repair a
// caller-unbound authorization, but it can refuse to spread it. By the time a
// request is proxied the gate has already spent it, so forwarding it only adds
// components that have seen it — application logs, error trackers, request
// dumps, and any middleware inclined to settle it a second time.
//
// Both paths matter: the settlement request itself, and any later request the
// client re-attaches the header to while riding the pass it bought.
func TestTheAuthorizationNeverReachesTheUpstream(t *testing.T) {
	var saw string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(payment.HeaderSignature); v != "" {
			saw = v
		}
		io.WriteString(w, "UPSTREAM:"+r.URL.Path)
	}))
	defer up.Close()

	g, _ := payGate(t, oneRule, nil)
	// Re-point the gate at an upstream that watches for the header.
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	g.upstream = newProxy(u, "", g.match, slog.New(slog.NewTextHandler(io.Discard, nil)), g.met.upstreamErr)

	acc := offered(g, t, "/")
	hdr := present(t, acc, nil)

	first := agentReq("/")
	first.Header.Set(payment.HeaderSignature, hdr)
	w := do(g, first)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	if saw != "" {
		t.Errorf("the upstream received the raw authorization on the settlement request: %.32q…", saw)
	}

	var pass *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			pass = c
		}
	}
	if pass == nil {
		t.Fatal("no pass cookie minted")
	}

	// Riding the pass, with the spent header still attached.
	second := agentReq("/")
	second.AddCookie(pass)
	second.Header.Set(payment.HeaderSignature, hdr)
	if w := do(g, second); w.Code != http.StatusOK {
		t.Fatalf("paid follow-up: status %d, want 200", w.Code)
	}
	if saw != "" {
		t.Errorf("the upstream received the raw authorization on a paid follow-up: %.32q…", saw)
	}
}

// TestFreePassesCarryNoSettlementFields. A proof-of-work pass names no payer
// and no transaction: there was none, and inventing one would make the paid
// and free ladders indistinguishable to anything reading a pass.
func TestFreePassesCarryNoSettlementFields(t *testing.T) {
	g, _ := payGate(t, oneRule, nil)
	c := solveAndGetCookie(t, g, nil)
	p, err := g.keyring.Verify(c.Value, g.now())
	if err != nil {
		t.Fatalf("pow pass does not verify: %v", err)
	}
	if p.Payer != "" || p.Tx != "" {
		t.Errorf("pow pass carries payer=%q tx=%q, want both empty", p.Payer, p.Tx)
	}
}
