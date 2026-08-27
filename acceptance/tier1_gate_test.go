//go:build e2e

// Tier 1: the gate as deployed.
//
// Everything here runs against a real container pair on a real Docker network:
// the gate published on the host, the application reachable only inside. Where
// a test claims a response was forwarded unchanged, it proves it by fetching
// the same path directly from the application through a test-only overlay and
// diffing the bytes.
package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/acceptance/harness"
)

// The reference deployment is stood up once for the whole tier and torn down
// in TestMain. Bring-up dominates this tier's runtime, and none of the tests
// sharing it mutate its configuration — the ones that need different settings
// (short TTLs, two instances) stand up their own project.
//
// TestMain owns the lifecycle deliberately: t.Cleanup fires when the *first*
// test finishes, which would pull the deployment out from under everything
// after it.
var (
	shared    *harness.Deployment
	sharedErr error
)

func TestMain(m *testing.M) {
	if err := exec.Command("docker", "info").Run(); err != nil {
		// Without Docker every test in this package skips itself with an
		// actionable message; standing up nothing here is correct.
		os.Exit(m.Run())
	}
	root, err := findRepoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance:", err)
		os.Exit(1)
	}
	// The suite normally tests the reference deployment. These variables allow
	// the same checks to run against another compatible Compose deployment.
	dir := root + "/examples/anteroomized"
	if v := os.Getenv("ANTEROOM_ACCEPTANCE_DIR"); v != "" {
		dir = v
	}
	composeFile := "compose.yaml"
	if v := os.Getenv("ANTEROOM_ACCEPTANCE_COMPOSE"); v != "" {
		composeFile = v
	}

	var stop func()
	shared, stop, sharedErr = harness.Start("artest-tier1", dir,
		[]string{composeFile, root + "/acceptance/fixtures/compose.probe.yaml"},
		nil)
	code := m.Run()
	if stop != nil {
		stop()
	}
	os.Exit(code)
}

func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("could not locate the repository root")
}

func tier1(t *testing.T) *harness.Deployment {
	t.Helper()
	harness.RequireDocker(t)
	if sharedErr != nil {
		t.Fatalf("the shared tier-1 deployment did not come up: %v", sharedErr)
	}
	if shared == nil {
		t.Skip("no shared deployment")
	}
	return shared
}

func ctxFor(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// admitted returns a client that already holds a valid PoW pass.
func admitted(t *testing.T, d *harness.Deployment) *harness.Client {
	t.Helper()
	c := d.Client(t)
	if _, err := c.Solve(ctxFor(t)); err != nil {
		t.Fatalf("could not get through the gate: %v\n%s", err, d.Logs())
	}
	return c
}

// ---------------------------------------------------------------------------
// T1.0 — the deployment shape
// ---------------------------------------------------------------------------

// TestT1_0_AppIsNotReachableFromTheHost is the whole point of putting a gate in
// front of something. It runs against the base compose file alone, without the
// probe overlay, because the overlay deliberately breaks exactly this property.
func TestT1_0_AppIsNotReachableFromTheHost(t *testing.T) {
	harness.RequireDocker(t)
	dir := harness.RepoRoot(t) + "/examples/anteroomized"
	if v := os.Getenv("ANTEROOM_ACCEPTANCE_DIR"); v != "" {
		dir = v
	}
	composeFile := "compose.yaml"
	if v := os.Getenv("ANTEROOM_ACCEPTANCE_COMPOSE"); v != "" {
		composeFile = v
	}
	d := harness.ComposeUp(t, dir, []string{composeFile}, nil)

	ctx := ctxFor(t)
	ports, err := d.HostPorts(ctx)
	if err != nil {
		t.Fatalf("compose ps: %v", err)
	}

	var exposed []string
	for service, published := range ports {
		if service == "anteroom" {
			continue
		}
		if len(published) > 0 {
			exposed = append(exposed, fmt.Sprintf("%s -> %v", service, published))
		}
	}
	if len(exposed) > 0 {
		t.Errorf("a service other than the gate publishes a host port, "+
			"so the gate can simply be walked around: %v", exposed)
	}
	if len(ports["anteroom"]) == 0 {
		t.Errorf("the gate publishes no host port, so nothing is reachable at all: %v", ports)
	}
}

// ---------------------------------------------------------------------------
// T1.1-T1.7 — the ladder
// ---------------------------------------------------------------------------

func TestT1_1_Healthz(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), harness.PathHealthz)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("body %q, want ok", body)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control %q lacks no-store", cc)
	}
}

// TestT1_2_MachineRefusal is one of the two highest-value tests in the suite.
// This response is the entire contract for automated access: if it regresses,
// every well-behaved non-browser client silently loses its way through the gate
// and the failure looks, from outside, like a site that is simply down.
func TestT1_2_MachineRefusal(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), "/",
		harness.Header("User-Agent", "curl/8.5.0"),
		harness.Header("Accept", "*/*"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Anteroom ") {
		// The scheme token must stay "Anteroom": at least one popular agent
		// skill reads `WWW-Authenticate: Payment …` as a different payment
		// protocol entirely and would route agents into the wrong rail.
		t.Errorf("WWW-Authenticate = %q, want an Anteroom challenge", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/markdown") {
		t.Errorf("Content-Type %q, want text/markdown", ct)
	}
	text := string(body)
	for _, want := range []string{harness.PathChallenge, harness.PathAnswer, harness.CookieName, "sha-256", "threshold"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(want)) {
			t.Errorf("refusal body never mentions %q — a client cannot act on it:\n%s", want, text)
		}
	}
}

func TestT1_3_JSONRefusal(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), "/",
		harness.Header("Accept", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	var doc struct {
		Error         string `json:"error"`
		FreeChallenge struct {
			ChallengeURL string `json:"challenge_url"`
			AnswerURL    string `json:"answer_url"`
			How          string `json:"how"`
		} `json:"free_challenge"`
		Human string `json:"human"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	if doc.FreeChallenge.ChallengeURL != harness.PathChallenge {
		t.Errorf("challenge_url = %q, want %q", doc.FreeChallenge.ChallengeURL, harness.PathChallenge)
	}
	if doc.FreeChallenge.AnswerURL != harness.PathAnswer {
		t.Errorf("answer_url = %q, want %q", doc.FreeChallenge.AnswerURL, harness.PathAnswer)
	}
	if doc.FreeChallenge.How == "" {
		t.Error("free_challenge.how is empty; the JSON refusal has to be self-contained too")
	}
}

// TestT1_4_OKBodyAgents covers the triage row that exists because some agentic
// fetch tools discard the body of any non-2xx response. For those clients a 401
// carrying instructions is invisible, so the instructions arrive as a 200 —
// the only status they surface.
func TestT1_4_OKBodyAgents(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), "/",
		harness.Header("User-Agent", "claude-user/1.0"),
		harness.Header("Accept", "*/*"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200 for a listed 2xx-only agent", resp.StatusCode)
	}
	if !strings.Contains(string(body), harness.PathChallenge) {
		t.Errorf("200 variant carries no instructions:\n%s", body)
	}
	// Matching must be case-insensitive and substring-based, as documented.
	resp2, _, err := d.Client(t).Get(ctxFor(t), "/",
		harness.Header("User-Agent", "Mozilla/5.0 CLAUDE-USER extra"),
		harness.Header("Accept", "*/*"))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("status %d for a case-different substring match, want 200", resp2.StatusCode)
	}
}

func TestT1_5_WaitPage(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), "/", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type %q, want text/html", ct)
	}
	page := string(body)
	for _, want := range []string{"anteroom-status", "__ANTEROOM__", "Pardon us"} {
		if !strings.Contains(page, want) {
			t.Errorf("wait page missing %q", want)
		}
	}
	// The operator's own header.html must be served. The reference page includes
	// Open Graph tags so link previews are not broken.
	if !strings.Contains(page, `property="og:title"`) {
		t.Error("wait page carries no Open Graph tags; every shared link would preview as the interstitial")
	}
}

func TestT1_6_Instructions(t *testing.T) {
	d := tier1(t)
	resp, body, err := d.Client(t).Get(ctxFor(t), harness.PathInstructions)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Robots-Tag"); !strings.Contains(got, "noindex") {
		t.Errorf("X-Robots-Tag = %q, want noindex", got)
	}
	if !strings.Contains(string(body), harness.PathChallenge) {
		t.Error("instructions do not name the challenge endpoint")
	}
}

func TestT1_7_UnknownOwnEndpoint(t *testing.T) {
	d := tier1(t)
	resp, _, err := d.Client(t).Get(ctxFor(t), "/.anteroom/definitely-not-a-thing")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404 — /.anteroom/* must never fall through to the upstream", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// T1.10-T1.18 — the solve loop, exactly as documented
// ---------------------------------------------------------------------------

func TestT1_10_ChallengeShape(t *testing.T) {
	d := tier1(t)
	ch, err := d.Client(t).FetchChallenge(ctxFor(t))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Challenge == "" {
		t.Error("empty challenge")
	}
	if ch.Kind != "admit" {
		t.Errorf("kind = %q for an anonymous client, want admit", ch.Kind)
	}
	if ch.PassTTLMs <= 0 {
		t.Errorf("pass_ttl_ms = %d", ch.PassTTLMs)
	}
	if time.Until(ch.Deadline()) <= 0 {
		t.Errorf("deadline_unix_ms is already past: %s", ch.Deadline())
	}
	// Two challenges must differ: a reused challenge would make one solve
	// reusable, which is the anti-sharing property gone.
	ch2, err := d.Client(t).FetchChallenge(ctxFor(t))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Challenge == ch2.Challenge {
		t.Error("two challenges were identical")
	}
}

// TestT1_11_SolveAndAdmit walks the documented four steps and checks the pass
// cookie's flags. HttpOnly and SameSite are not decoration: the pass is a
// bearer credential.
func TestT1_11_SolveAndAdmit(t *testing.T) {
	d := tier1(t)
	c := d.Client(t)
	ctx := ctxFor(t)

	res, err := c.Solve(ctx)
	if err != nil {
		t.Fatalf("solve: %v\n%s", err, d.Logs())
	}
	if res.Kind != "admit" {
		t.Errorf("kind = %q, want admit", res.Kind)
	}
	if c.Pass() == "" {
		t.Fatal("no pass cookie after a successful answer")
	}

	// Re-fetch the answer response to inspect cookie attributes directly.
	ch, err := c.FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _, err := harness.SolveChallenge(ch, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]string{"challenge": ch.Challenge, "nonce": nonce})
	resp, _, err := c.Do(ctx, http.MethodPost, harness.PathAnswer, payload,
		harness.Header("Content-Type", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	var found *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == harness.CookieName {
			found = ck
		}
	}
	if found == nil {
		t.Fatal("answer set no pass cookie")
	}
	if !found.HttpOnly {
		t.Error("pass cookie is not HttpOnly; script access to a bearer credential is free to any XSS")
	}
	if found.SameSite != http.SameSiteLaxMode && found.SameSite != http.SameSiteStrictMode {
		t.Errorf("pass cookie SameSite = %v, want Lax or Strict", found.SameSite)
	}
	if found.Path != "/" {
		t.Errorf("pass cookie Path = %q, want /", found.Path)
	}

	// And the pass actually admits.
	got, body, err := c.Get(ctx, "/", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d with a valid pass, want 200", got.StatusCode)
	}
	if !strings.Contains(string(body), "hello from the app") {
		t.Errorf("admitted response is not the application's page:\n%s", body)
	}
}

func TestT1_13_WrongNonceRefused(t *testing.T) {
	d := tier1(t)
	c := d.Client(t)
	ctx := ctxFor(t)
	ch, err := c.FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitAnswer(ctx, ch.Challenge, "definitely-not-a-solution"); err == nil {
		t.Fatal("a wrong nonce was accepted")
	}
	if c.Pass() != "" {
		t.Error("a pass was minted for a wrong nonce")
	}
}

// TestT1_14_TamperedPass. The pass is a signed cookie, and nothing else stands
// between a forged one and the application.
//
// Note where the mutations land. Flipping the *last* character of the MAC would
// be a broken test rather than a strict one: a 32-byte MAC is 43 base64url
// characters, its final character carries only two significant bits, and Go's
// decoder ignores the four slack bits — so four different final characters
// decode to the identical 32 bytes and the signature verifies, correctly. That
// is encoding malleability, not forgery, and accepting it is right. Mutate a
// byte that actually changes the decoded value.
func TestT1_14_TamperedPass(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	good := c.Pass()
	dot := strings.IndexByte(good, '.')
	if dot < 0 {
		t.Fatalf("pass has no payload/signature separator: %q", good)
	}
	payload, sig := good[:dot], good[dot+1:]

	tampered := map[string]string{
		"flipped payload byte":   flipAt(payload, len(payload)/2) + "." + sig,
		"flipped signature byte": payload + "." + flipAt(sig, len(sig)/2),
		"swapped halves":         sig + "." + payload,
		"truncated signature":    payload + "." + sig[:len(sig)-4],
		"empty":                  "",
		"not a token":            "aaaa.bbbb",
		"no separator":           payload + sig,
	}

	for name, bad := range tampered {
		t.Run(name, func(t *testing.T) {
			c2 := d.Client(t)
			c2.SetPass(bad)
			// A browser navigation with an invalid pass earns the wait page,
			// which is also a 200 — so the status says nothing here. What
			// matters is whether the application's bytes came back.
			_, body, err := c2.Get(ctxFor(t), "/", harness.Browser())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "hello from the app") {
				t.Errorf("a tampered pass was accepted (%s)", name)
			}
		})
	}
}

// flipAt returns s with the byte at i changed to a different base64url
// character, so the decoded value genuinely differs.
func flipAt(s string, i int) string {
	if i >= len(s) {
		return s
	}
	repl := byte('A')
	if s[i] == 'A' {
		repl = 'B'
	}
	return s[:i] + string(repl) + s[i+1:]
}

// TestT1_16_StaleSolveRefused is the anti-sharing property, and it is the one
// place the design deliberately fails closed against a *correct* answer: a
// (challenge, nonce) pair handed to a botnet must buy nothing once the window
// has elapsed.
func TestT1_16_StaleSolveRefused(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	writeShortTTLDeployment(t, root, dir, "2s", "30m")
	d := harness.ComposeUp(t, dir, []string{"compose.yaml"}, nil)

	c := d.Client(t)
	ctx := ctxFor(t)
	ch, err := c.FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _, err := harness.SolveChallenge(ch, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the correct answer until the challenge's own deadline has passed.
	time.Sleep(time.Until(ch.Deadline()) + 500*time.Millisecond)

	if _, err := c.SubmitAnswer(ctx, ch.Challenge, nonce); err == nil {
		t.Fatal("a correct but stale solve was redeemed for a pass")
	}
}

// TestT1_15_PassExpires. Short passes are the design's central bet; if they
// outlive their TTL the bet is off.
func TestT1_15_PassExpires(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	writeShortTTLDeployment(t, root, dir, "3s", "30m")
	d := harness.ComposeUp(t, dir, []string{"compose.yaml"}, nil)

	c := d.Client(t)
	ctx := ctxFor(t)
	if _, err := c.Solve(ctx); err != nil {
		t.Fatalf("solve: %v\n%s", err, d.Logs())
	}
	resp, body, err := c.Get(ctx, "/", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello from the app") {
		t.Fatalf("not admitted immediately after solving: status %d", resp.StatusCode)
	}

	time.Sleep(5 * time.Second)
	_, body2, err := c.Get(ctx, "/", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body2), "hello from the app") {
		t.Error("the application was served with an expired pass")
	}
}

// TestT1_17_RenewIsCheaper. Renewal has to be cheap or it is a battery tax on
// every phone that visits; it has to require a live pass or it is a free tier.
func TestT1_17_RenewIsCheaper(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)

	anon, err := d.Client(t).FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := admitted(t, d)
	renew, err := c.FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if renew.Kind != "renew" {
		t.Errorf("kind = %q for a client holding a live pass, want renew", renew.Kind)
	}
	if anon.Kind != "admit" {
		t.Errorf("kind = %q for an anonymous client, want admit", anon.Kind)
	}
	// A higher threshold is an easier puzzle: the digest has more room below it.
	if !(renew.Threshold > anon.Threshold) {
		t.Errorf("renew threshold %q is not easier than admission threshold %q",
			renew.Threshold, anon.Threshold)
	}

	// And a renewal actually mints a fresh pass.
	before := c.Pass()
	res, err := c.Solve(ctx)
	if err != nil {
		t.Fatalf("renewal solve: %v", err)
	}
	if res.Kind != "renew" {
		t.Errorf("answer kind = %q, want renew", res.Kind)
	}
	if c.Pass() == before {
		t.Error("renewal did not replace the pass")
	}
}

// TestT1_18_MaxSessionCapsTheChain. Renewals are far cheaper than admission, so
// without a cap one admission would buy unlimited time and the difficulty dial
// would mean nothing.
func TestT1_18_MaxSessionCapsTheChain(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	// max_session must be at least pass_ttl (config rejects otherwise), so the
	// chain cannot be aged by simply waiting: the pass would lapse first and
	// the next challenge would be an admission for that reason instead. It has
	// to be aged the way a real browser ages it — by renewing.
	writeShortTTLDeployment(t, root, dir, "3s", "4s")
	d := harness.ComposeUp(t, dir, []string{"compose.yaml"}, nil)

	c := d.Client(t)
	ctx := ctxFor(t)
	if _, err := c.Solve(ctx); err != nil {
		t.Fatalf("solve: %v\n%s", err, d.Logs())
	}
	ch, err := c.FetchChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind != "renew" {
		t.Fatalf("kind = %q immediately after admission, want renew", ch.Kind)
	}

	// Renew repeatedly, as the background worker would, until the chain passes
	// max_session and the gate demands admission again.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		next, err := c.FetchChallenge(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if next.Kind == "admit" {
			return // the chain was capped, which is the assertion
		}
		if _, err := c.Solve(ctx); err != nil {
			t.Fatalf("renewal solve: %v", err)
		}
		time.Sleep(time.Second)
	}
	t.Error("the renewal chain never demanded admission again: max_session is not capping it, " +
		"which would make the difficulty dial meaningless")
}

// writeShortTTLDeployment materializes a compose project whose gate uses the
// given pass_ttl and max_session. Liveness properties are only observable in a
// test if the clock they run on is short enough to wait for.
func writeShortTTLDeployment(t *testing.T, root, dir, passTTL, maxSession string) {
	t.Helper()
	cfg := fmt.Sprintf(`listen = ":8080"
pass_ttl = %q
max_session = %q
difficulty = 10
renew_difficulty = 4
inject = true
allow_insecure_context = false
trusted_proxies = []

[bypass]
paths = ["/robots.txt", "/sitemap.xml", "/feed.xml", "/.well-known/*", "/webhooks/*", "/healthz"]
cidrs = []

[triage]
json_accept = true
ok_body_agents = ["claude-user"]
`, passTTL, maxSession)
	writeFile(t, dir+"/anteroom.toml", cfg)

	compose := fmt.Sprintf(`services:
  anteroom:
    build:
      context: %s
      dockerfile: Dockerfile
    image: anteroom:local
    ports:
      - "${GATE_PORT:-8080}:8080"
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=${ANTEROOM_HMAC_KEY}
    depends_on:
      app:
        condition: service_started
  app:
    build: %s/examples/hello-app
    image: hello-app:local
    expose:
      - "3000"
    environment:
      - HELLO_LISTEN=:3000
`, root, root)
	writeFile(t, dir+"/compose.yaml", compose)
}

// ---------------------------------------------------------------------------
// T1.20-T1.25 — bypass and path canonicalization
// ---------------------------------------------------------------------------

// TestT1_20_BypassIsByteIdentical. A bypass exists because something needs the
// bytes untouched — a signed feed, a well-known document, a webhook body. If
// the gate is "mostly transparent" on a bypassed path, the bypass has failed.
func TestT1_20_BypassIsByteIdentical(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	gate := d.Client(t) // deliberately anonymous: bypass must not need a pass
	direct := d.Direct(t)

	for _, path := range []string{"/robots.txt", "/sitemap.xml", "/feed.xml"} {
		t.Run(path, func(t *testing.T) {
			gResp, gBody, err := gate.Get(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if gResp.StatusCode != http.StatusOK {
				t.Fatalf("status %d through the gate with no pass, want 200", gResp.StatusCode)
			}
			_, dBody, err := direct.Get(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gBody, dBody) {
				t.Errorf("bypassed path was modified in transit:\n gate: %q\ndirect: %q", gBody, dBody)
			}
			if bytes.Contains(gBody, []byte("/.anteroom/renew.js")) {
				t.Error("a bypassed path was injected into")
			}
		})
	}
}

// TestT1_21_NonCanonicalPathsRefused and TestT1_22 are a deliberate pair: the
// first proves the check works, the second proves it is narrow. A change that
// breaks T1.22 in order to strengthen T1.21 is the overreach the design argues
// against — rejecting percent-encoding would break ordinary API URLs for no
// security gain, because every hazardous %2F decodes into a visible dot-segment
// and is caught by the same rule.
func TestT1_21_NonCanonicalPathsRefused(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := admitted(t, d)

	for _, path := range []string{
		"/.well-known/../admin",
		"/a/./b",
		"//double//slash",
		`/pub/\..\admin`,
		"/%2e%2e/admin",
	} {
		t.Run(path, func(t *testing.T) {
			resp, _, err := c.Get(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400 for a non-canonical path", resp.StatusCode)
			}
		})
	}
}

func TestT1_22_PercentEncodingPassesThrough(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := admitted(t, d)

	for _, path := range []string{
		"/echo?repo=owner%2Frepo",
		"/echo?name=file%20name.txt",
	} {
		t.Run(path, func(t *testing.T) {
			resp, body, err := c.Get(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status %d, want 200 — percent-encoding is not restricted:\n%s",
					resp.StatusCode, body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// T1.30-T1.34 — header hygiene, verified from the application's side
// ---------------------------------------------------------------------------

type echoDoc struct {
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Host      string              `json:"host"`
	Headers   map[string][]string `json:"headers"`
	CookieRaw string              `json:"cookie_raw"`
}

func fetchEcho(t *testing.T, c *harness.Client, opts ...harness.Option) echoDoc {
	t.Helper()
	resp, body, err := c.Get(ctxFor(t), "/echo", opts...)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/echo status %d:\n%s", resp.StatusCode, body)
	}
	var doc echoDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("parsing /echo: %v\n%s", err, body)
	}
	return doc
}

// TestT1_30_GateAuthoredHeadersAreStripped. An inbound X-Anteroom-Status is a
// forgery attempt; the upstream must only ever see the gate's own value.
func TestT1_30_GateAuthoredHeadersAreStripped(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	doc := fetchEcho(t, c, harness.Header("X-Anteroom-Status", "pass-paid"))

	got := doc.Headers["X-Anteroom-Status"]
	if len(got) != 1 {
		t.Fatalf("X-Anteroom-Status = %v, want exactly one gate-authored value", got)
	}
	if got[0] == "pass-paid" {
		t.Error("the client's forged X-Anteroom-Status reached the application")
	}
	if !strings.HasPrefix(got[0], "pass-") {
		t.Errorf("X-Anteroom-Status = %q, want the gate's own pass-* value", got[0])
	}
}

// TestT1_31_PassCookieIsStripped. The pass is a credential for the gate; the
// application has no use for it and should never be able to leak it.
func TestT1_31_PassCookieIsStripped(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	// The pass has to be the real one, and it has to be the only one: setting a
	// Cookie header explicitly does not replace what the jar contributes, so a
	// decoy pass would arrive alongside the genuine article and the gate would
	// (correctly) strip both, leaving the request unauthenticated.
	doc := fetchEcho(t, c, harness.Header("Cookie",
		"first=1; "+harness.CookieName+"="+c.Pass()+"; last=2"))

	if strings.Contains(doc.CookieRaw, harness.CookieName) {
		t.Errorf("the pass cookie reached the application: %q", doc.CookieRaw)
	}
	// Every other cookie must survive, in order and unmangled: re-serializing
	// the header would silently drop cookies Go considers invalid, and only on
	// gated requests, which is a miserable bug to chase.
	for _, want := range []string{"first=1", "last=2"} {
		if !strings.Contains(doc.CookieRaw, want) {
			t.Errorf("cookie %q did not survive stripping: %q", want, doc.CookieRaw)
		}
	}
	if strings.Index(doc.CookieRaw, "first=1") > strings.Index(doc.CookieRaw, "last=2") {
		t.Errorf("cookie order changed: %q", doc.CookieRaw)
	}
}

// TestT1_32_ForgedForwardedForIgnored. trusted_proxies is empty in this
// deployment, so no X-Forwarded-For may be believed — otherwise any client
// could claim any address and walk through a CIDR allowlist.
func TestT1_32_ForgedForwardedForIgnored(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	doc := fetchEcho(t, c,
		harness.Header("X-Forwarded-For", "203.0.113.9"),
		harness.Header("X-Real-IP", "203.0.113.9"),
		harness.Header("CF-Connecting-IP", "203.0.113.9"),
		harness.Header("True-Client-IP", "203.0.113.9"))

	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip", "True-Client-Ip"} {
		for _, v := range doc.Headers[h] {
			if strings.Contains(v, "203.0.113.9") {
				t.Errorf("%s = %q: an untrusted client's claimed address reached the application", h, v)
			}
		}
	}
}

func TestT1_34_HostIsPreserved(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	// The pass is authority-bound, so use the deployment's real public authority
	// rather than moving the pass to a synthetic Host. This still distinguishes
	// it from the private `app:3000` authority ReverseProxy would install by
	// default. Paired with the old assertion — doc.Host != "" — this test was
	// unfailable: deleting
	// `r.Out.Host = r.In.Host` from the proxy leaves SetURL putting the upstream
	// authority there, which is non-empty. That deletion is the DEFAULT
	// ReverseProxy behaviour this line exists to override, and it is what breaks
	// a vhosted upstream and every absolute URL the application generates.
	want := strings.TrimPrefix(d.GateURL, "http://")
	doc := fetchEcho(t, c)
	if doc.Host != want {
		t.Errorf("the application saw Host %q, want %q — the gate rewrote it to its "+
			"own upstream authority, so a vhosted app serves the wrong site and "+
			"every absolute URL it builds points at the wrong name", doc.Host, want)
	}
}

// ---------------------------------------------------------------------------
// T1.40-T1.47 — injection
// ---------------------------------------------------------------------------

// TestT1_40_InjectsIntoDocuments. Injection keeps renewal running after the
// visitor leaves the wait page.
func TestT1_40_InjectsIntoDocuments(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	resp, body, err := c.Get(ctxFor(t), "/", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	page := string(body)
	if !strings.Contains(page, harness.PathRenew) {
		t.Fatalf("no renewal script injected into an admitted document:\n%s", page)
	}
	// Root-absolute, so a <base href> cannot retarget it.
	if !strings.Contains(page, `src="/.anteroom/renew.js"`) {
		t.Errorf("injected script is not root-absolute:\n%s", page)
	}
	head := strings.Index(page, "<head>")
	script := strings.Index(page, harness.PathRenew)
	if head < 0 || script < head {
		t.Errorf("script was not inserted after the opening <head>")
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if got, want := len(body), cl; fmt.Sprint(got) != want {
			t.Errorf("Content-Length %s does not match the %d bytes actually sent", want, got)
		}
	}
	if v := resp.Header.Get("Vary"); !strings.Contains(v, "Cookie") {
		t.Errorf("Vary = %q, want it to include Cookie", v)
	}
}

// TestT1_41_NonDocumentsUntouched proves the negative, byte for byte. "Never
// rewrite a response we did not have to" is a design rule, and the failure mode
// it prevents — a JSON API silently gaining a script tag — is catastrophic and
// quiet.
func TestT1_41_NonDocumentsUntouched(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := admitted(t, d)
	direct := d.Direct(t)

	cases := []struct {
		name string
		path string
		opts []harness.Option
	}{
		{"json api", "/api/items", nil},
		{"css asset", "/static/app.css", nil},
		{"html fetched as an htmx fragment", "/about", []harness.Option{
			harness.Header("HX-Request", "true"),
			harness.Header("Accept", "text/html"),
		}},
		{"html fetched as an xhr", "/about", []harness.Option{
			harness.Header("X-Requested-With", "XMLHttpRequest"),
			harness.Header("Accept", "text/html"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, gBody, err := c.Get(ctx, tc.path, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			_, dBody, err := direct.Get(ctx, tc.path, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gBody, dBody) {
				t.Errorf("response was modified in transit\n gate (%d B): %.200q\ndirect (%d B): %.200q",
					len(gBody), gBody, len(dBody), dBody)
			}
		})
	}
}

// TestT1_42_EventStreamNotBuffered. Buffering an SSE stream to look for an
// injection point would break every live feature the application has, and the
// symptom — "events arrive in a burst at the end" — is easy to misattribute.
func TestT1_42_EventStreamNotBuffered(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL("/events"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", harness.DefaultUserAgent)
	req.AddCookie(&http.Cookie{Name: harness.CookieName, Value: c.Pass()})

	start := time.Now()
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 128)
	n, err := resp.Body.Read(buf)
	firstChunk := time.Since(start)
	if err != nil && n == 0 {
		t.Fatalf("reading the first chunk: %v", err)
	}
	// The app emits five ticks 150 ms apart. Receiving the first well before
	// the stream ends is the assertion; a buffering proxy would deliver
	// nothing until roughly 750 ms.
	if firstChunk > 600*time.Millisecond {
		t.Errorf("first chunk arrived after %s, which suggests the stream was buffered", firstChunk)
	}
	if !bytes.Contains(buf[:n], []byte("tick")) {
		t.Errorf("first chunk is not stream data: %q", buf[:n])
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Error("event stream was relabelled as HTML")
	}
}

// TestT1_45_CSPLadder walks the documented decision table end to end. The unit
// suite proves the algorithm; this proves the algorithm is what reaches the
// wire through a real proxy and a real upstream.
func TestT1_45_CSPLadder(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := admitted(t, d)

	cases := []struct {
		path         string
		wantInjected bool
		why          string
	}{
		{"/csp/none", true, "no policy means nothing to satisfy"},
		{"/csp/self", true, "'self' permits an external same-origin script; no header change needed"},
		{"/csp/unsafe-inline", true, "inline is permitted; the policy must not be touched"},
		{"/csp/strict-dynamic", true, "an external src is blocked, so a nonced inline loader is used"},
		{"/csp/hash", true, "a hash of the exact inline script is added"},
		{"/csp/host-allowlist", true, "a hash is added; the allowlist has no 'self'"},
		{"/csp/none-directive", false, "'none' means no script can run at all"},
		{"/csp/sandbox", false, "a sandbox without allow-scripts can run nothing"},
		// A meta policy allowing 'self' is satisfied by the external script as it
		// stands, so injection proceeds and nothing is modified. Only a meta
		// policy that would have to be REWRITTEN is fatal — see meta-strict.
		{"/csp/meta", true, "a meta policy allowing 'self' needs no rewrite"},
		{"/csp/meta-strict", false, "a hash-only meta policy cannot be rewritten from the headers"},
		{"/csp/report-only", true, "report-only cannot block, so it never changes the decision"},
	}

	for _, tc := range cases {
		t.Run(strings.TrimPrefix(tc.path, "/csp/"), func(t *testing.T) {
			resp, body, err := c.Get(ctx, tc.path, harness.Browser())
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d", resp.StatusCode)
			}
			injected := strings.Contains(string(body), "anteroom")
			if injected != tc.wantInjected {
				t.Errorf("injected = %v, want %v (%s)\nCSP: %q\nbody: %.400q",
					injected, tc.wantInjected, tc.why,
					resp.Header.Get("Content-Security-Policy"), body)
			}

			if !tc.wantInjected {
				// Declining to inject must be byte-for-byte non-interference,
				// not "inject a little less".
				_, dBody, err := d.Direct(t).Get(ctx, tc.path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(body, dBody) {
					t.Errorf("declined to inject but still modified the response:\n gate: %.300q\ndirect: %.300q",
						body, dBody)
				}
			}
		})
	}
}

// TestT1_45b_UnsafeInlinePolicyUntouched. Adding a nonce or hash to a policy
// carrying 'unsafe-inline' disables it under CSP3 and kills the operator's own
// inline scripts — a gate that "hardens" someone else's policy has broken their
// site to install itself.
func TestT1_45b_UnsafeInlinePolicyUntouched(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := admitted(t, d)

	gResp, _, err := c.Get(ctx, "/csp/unsafe-inline", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	dResp, _, err := d.Direct(t).Get(ctx, "/csp/unsafe-inline")
	if err != nil {
		t.Fatal(err)
	}
	got := gResp.Header.Get("Content-Security-Policy")
	want := dResp.Header.Get("Content-Security-Policy")
	if got != want {
		t.Errorf("CSP was modified on an unsafe-inline policy:\n got %q\nwant %q", got, want)
	}
}

// TestT1_46_BypassedPathsNeverInjected. A bypass is a promise about bytes.
func TestT1_46_BypassedPathsNeverInjected(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)
	_, body, err := c.Get(ctxFor(t), "/robots.txt", harness.Browser())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "anteroom") {
		t.Errorf("a bypassed path was injected into:\n%s", body)
	}
}

// TestT1_47_AssetsKeepTheirCompression verifies at the upstream that identity
// encoding is requested only for responses that could carry an injection.
func TestT1_47_AssetsKeepTheirCompression(t *testing.T) {
	d := tier1(t)
	c := admitted(t, d)

	// An asset-shaped request: nothing here could carry an injection, so the
	// client's own encoding preference must reach the application untouched.
	asset := fetchEcho(t, c,
		harness.Header("Accept-Encoding", "gzip"),
		harness.Header("Sec-Fetch-Mode", "no-cors"),
		harness.Header("Sec-Fetch-Dest", "image"),
		harness.Header("Accept", "image/avif,image/webp,*/*"))
	if got := strings.Join(asset.Headers["Accept-Encoding"], ","); !strings.Contains(got, "gzip") {
		t.Errorf("the application was asked for %q on a request the gate never reads; "+
			"every asset on the site is now served uncompressed", got)
	}

	// And the other half, or a gate that simply never asks for identity would
	// pass the first: a document navigation IS read, so it must be identity.
	doc := fetchEcho(t, c, harness.Browser(), harness.Header("Accept-Encoding", "gzip"))
	if got := strings.Join(doc.Headers["Accept-Encoding"], ","); !strings.Contains(got, "identity") {
		t.Errorf("a document navigation reached the application with Accept-Encoding %q; "+
			"the gate cannot inject into a response it cannot read", got)
	}
}

// ---------------------------------------------------------------------------
// T1.50-T1.54 — "what Anteroom breaks", and the documented fix
// ---------------------------------------------------------------------------

// TestT1_51_WebhookBypassDeliversTheBody is the row that costs real money. A
// gate that silently eats a payment provider's webhooks is worse than no gate,
// so the documented fix is executed rather than asserted in prose.
func TestT1_51_WebhookBypassDeliversTheBody(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	payload := []byte(`{"id":"evt_123","type":"payment_intent.succeeded"}`)

	// No pass: a webhook sender has no browser and no cookie jar.
	resp, body, err := d.Client(t).Do(ctx, http.MethodPost, "/webhooks/inbound", payload,
		harness.Header("Content-Type", "application/json"),
		harness.Header("User-Agent", "Stripe/1.0"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d for a bypassed webhook, want 200:\n%s", resp.StatusCode, body)
	}
	var echoed struct {
		Received string `json:"received"`
		Bytes    int    `json:"bytes"`
	}
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("parsing webhook echo: %v\n%s", err, body)
	}
	if echoed.Received != string(payload) {
		t.Errorf("webhook body did not survive:\n got %q\nwant %q", echoed.Received, payload)
	}
}

// TestT1_50_UnbypassedWebhookIsRefused documents the breakage itself. This test
// passing is not good news — it is the reason the bypass rule has to exist, and
// it fails loudly if the refusal ever becomes something other than a clean
// machine-readable answer.
func TestT1_50_UnbypassedWebhookIsRefused(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	// /api/* is not in the reference deployment's bypass list.
	resp, body, err := d.Client(t).Do(ctx, http.MethodPost, "/api/items",
		[]byte(`{"x":1}`), harness.Header("Content-Type", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(string(body), harness.PathChallenge) {
		t.Error("the refusal does not explain how to get past it")
	}
}

// TestT1_53_APIClientCanSolveItsWayIn. The refusal is not a wall for a
// well-behaved program: it is instructions. This is the property that lets an
// operator gate /api/* without bypassing it.
func TestT1_53_APIClientCanSolveItsWayIn(t *testing.T) {
	d := tier1(t)
	ctx := ctxFor(t)
	c := d.Client(t)

	resp, _, err := c.Get(ctx, "/api/items", harness.Header("Accept", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d before solving, want 401", resp.StatusCode)
	}
	if _, err := c.Solve(ctx); err != nil {
		t.Fatalf("solve: %v", err)
	}
	resp2, body, err := c.Get(ctx, "/api/items", harness.Header("Accept", "application/json"))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status %d after solving, want 200:\n%s", resp2.StatusCode, body)
	}
	if !strings.Contains(string(body), `"items"`) {
		t.Errorf("admitted API response is not the application's JSON:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// T1.60-T1.62 — fleet
// ---------------------------------------------------------------------------

// TestT1_60_PassesAreFleetValid. Sharing hmac_keys is the whole multi-instance
// story, and it costs nothing — but only if it actually works.
func TestT1_60_PassesAreFleetValid(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	writeFleetDeployment(t, root, dir)
	d := harness.ComposeUp(t, dir, []string{"compose.yaml"}, nil)

	ctx := ctxFor(t)
	a := d.Client(t)
	if _, err := a.Solve(ctx); err != nil {
		t.Fatalf("solve at instance A: %v\n%s", err, d.Logs())
	}
	pass := a.Pass()
	if pass == "" {
		t.Fatal("no pass minted")
	}

	// Instance B shares the key and has never seen this client.
	b, err := harness.NewClient(d.AppURL) // AppURL is instance B in this fixture
	if err != nil {
		t.Fatal(err)
	}
	b.SetPass(pass)
	authority := strings.TrimPrefix(d.GateURL, "http://")
	resp, body, err := b.Get(ctx, "/", harness.Browser(), harness.Host(authority), b.SendPass())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "hello from the app") {
		t.Errorf("instance B rejected a pass minted by instance A (status %d); "+
			"stateless fleet validity is broken:\n%s", resp.StatusCode, body)
	}
}

// TestT1_61_DifferentKeysDoNotInteroperate is the other half: if any key
// validated any pass, the signature would be decoration.
func TestT1_61_DifferentKeysDoNotInteroperate(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)
	dir := t.TempDir()
	writeFleetDeployment(t, root, dir)
	d := harness.ComposeUp(t, dir, []string{"compose.yaml"}, map[string]string{
		"ANTEROOM_HMAC_KEY_B": harness.RandomKey(t),
	})

	ctx := ctxFor(t)
	ca := d.Client(t)
	if _, err := ca.Solve(ctx); err != nil {
		t.Fatalf("solve at A: %v", err)
	}

	cb, err := harness.NewClient(d.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	cb.SetPass(ca.Pass())
	authority := strings.TrimPrefix(d.GateURL, "http://")
	_, body, err := cb.Get(ctx, "/", harness.Browser(), harness.Host(authority), cb.SendPass())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hello from the app") {
		t.Error("a pass signed with one key was accepted by an instance holding another")
	}
}

// writeFleetDeployment stands up two gate instances sharing one HMAC key in
// front of one application. The second gate is published on APP_PORT, which the
// fleet test uses as "instance B".
func writeFleetDeployment(t *testing.T, root, dir string) {
	t.Helper()
	writeFile(t, dir+"/anteroom.toml", `listen = ":8080"
pass_ttl = "60s"
max_session = "30m"
difficulty = 10
renew_difficulty = 4
inject = true
trusted_proxies = []

[bypass]
paths = ["/robots.txt", "/healthz"]
cidrs = []
`)
	writeFile(t, dir+"/compose.yaml", fmt.Sprintf(`services:
  anteroom-a:
    build:
      context: %[1]s
      dockerfile: Dockerfile
    image: anteroom:local
    ports:
      - "${GATE_PORT:-8080}:8080"
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=${ANTEROOM_HMAC_KEY}
    depends_on:
      app:
        condition: service_started
  anteroom-b:
    image: anteroom:local
    ports:
      - "${APP_PORT:-13000}:8080"
    volumes:
      - ./anteroom.toml:/etc/anteroom/anteroom.toml:ro
    environment:
      - ANTEROOM_UPSTREAM=app:3000
      - ANTEROOM_HMAC_KEY=${ANTEROOM_HMAC_KEY_B}
    depends_on:
      anteroom-a:
        condition: service_started
  app:
    build: %[1]s/examples/hello-app
    image: hello-app:local
    expose:
      - "3000"
    environment:
      - HELLO_LISTEN=:3000
`, root))
}
