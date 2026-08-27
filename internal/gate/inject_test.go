package gate

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

// Injection is tested at three levels, because each catches a different class of
// failure and none of them catches the others:
//
//  1. the pure decision functions (does the contract in docs/operating.md hold?);
//  2. end-to-end through the real ReverseProxy with a pass cookie (does a script
//     tag actually reach a browser, and is the rest of the document untouched?);
//  3. non-interference (for every response we must NOT rewrite, is the output
//     byte-identical to the upstream's?).
//
// Level 3 is the one that matters most for a proxy. An injector that fails to
// inject is a missed renewal; an injector that mangles a response the operator
// never expected us to read is a corrupted site.

// upstreamGate builds a gate in front of an upstream handler the test controls.
func upstreamGate(t *testing.T, cfgBody string, h http.HandlerFunc) (*Gate, *http.Cookie) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + fastCfg + cfgBody
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
	return g, solveAndGetCookie(t, g, nil)
}

// docReq is a top-level navigation carrying a pass: the only shape of request
// that may be injected into.
func docReq(path string, pass *http.Cookie) *http.Request {
	r := browserReq(path)
	r.AddCookie(pass)
	return r
}

const simplePage = `<!doctype html>
<html><head><title>Hi</title></head><body><p>content</p></body></html>`

// ---------------------------------------------------------------------------
// Level 2: it actually works
// ---------------------------------------------------------------------------

func TestInjectionEndToEnd(t *testing.T) {
	var sawAcceptEncoding string
	g, pass := upstreamGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		sawAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", fmt.Sprint(len(simplePage)))
		io.WriteString(w, simplePage)
	})

	res := do(g, docReq("/page", pass))
	body := res.Body.String()

	if res.Code != 200 {
		t.Fatalf("status %d", res.Code)
	}
	if n := strings.Count(body, externalTag); n != 1 {
		t.Fatalf("want exactly one injected tag, got %d\n%s", n, body)
	}
	// Position matters: immediately after the opening <head>, so renewal starts
	// before the operator's own scripts and before anything can <base>-retarget us.
	if want := "<head>" + externalTag; !strings.Contains(body, want) {
		t.Errorf("tag is not right after <head>:\n%s", body)
	}
	// The document must be otherwise identical — removing our tag reconstructs the
	// upstream's bytes exactly.
	if got := strings.Replace(body, externalTag, "", 1); got != simplePage {
		t.Errorf("document altered beyond the injection:\n got %q\nwant %q", got, simplePage)
	}
	// A byte count and a strong validator would both now be lies.
	if cl := res.Header().Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length survived injection: %q", cl)
	}
	if et := res.Header().Get("ETag"); et != `W/"v1"` {
		t.Errorf("ETag = %q, want it weakened to W/\"v1\"", et)
	}
	if v := res.Header().Get("Vary"); !strings.Contains(v, "Cookie") {
		t.Errorf("Vary = %q, want it to include Cookie", v)
	}
	// We only ask for identity encoding where we mean to read the body.
	if sawAcceptEncoding != "identity" {
		t.Errorf("upstream saw Accept-Encoding %q, want identity", sawAcceptEncoding)
	}
	// No CSP on the response, so nothing to add.
	if csp := res.Header().Get("Content-Security-Policy"); csp != "" {
		t.Errorf("invented a CSP where the upstream had none: %q", csp)
	}
}

// TestInjectedScriptIsServed closes the loop that a tag alone does not: the URL
// we inject must be one the gate answers. A typo in either constant would leave
// every injected page fetching a 404.
func TestInjectedScriptIsServed(t *testing.T) {
	g, pass := upstreamGate(t, "", htmlHandler(simplePage))

	body := do(g, docReq("/page", pass)).Body.String()
	src := between(body, `<script src="`, `"`)
	if src == "" {
		t.Fatal("no script src in the injected page")
	}

	res := do(g, httptest.NewRequest("GET", src, nil))
	if res.Code != 200 {
		t.Fatalf("GET %s: status %d", src, res.Code)
	}
	if ct := res.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q", ct)
	}
	js := res.Body.String()
	// The renewal driver's whole job: register the worker and keep pinging it.
	for _, want := range []string{pathSW, "postMessage", "ping", "visibilitychange", "pageshow"} {
		if !strings.Contains(js, want) {
			t.Errorf("renew.js does not mention %q", want)
		}
	}
	// It must never become an interception surface, exactly like the worker.
	if strings.Contains(js, `addEventListener("fetch"`) {
		t.Error("renew.js registers a fetch handler")
	}
}

// ---------------------------------------------------------------------------
// Level 3: non-interference
// ---------------------------------------------------------------------------

// TestNoInjectionLeavesResponseIdentical is the important test. For every reason
// to decline, the bytes and the headers must come through untouched.
func TestNoInjectionLeavesResponseIdentical(t *testing.T) {
	longComment := "<!--" + strings.Repeat("x", headBudget+1024) + "-->"

	tests := []struct {
		name   string
		status int
		header map[string]string
		body   string
		reason string
	}{
		{
			name: "json mislabelled as html", header: map[string]string{"Content-Type": "text/html"},
			body: `{"ok":true}`, reason: "the bytes get a vote, not just the Content-Type",
		},
		{
			name:   "xhtml is XML, not HTML",
			header: map[string]string{"Content-Type": "application/xhtml+xml"},
			body:   simplePage, reason: "an unclosed tag is a parse error in XML",
		},
		{
			name: "not found", status: 404,
			header: map[string]string{"Content-Type": "text/html"}, body: simplePage,
			reason: "rewriting an error page helps no one",
		},
		{
			name: "partial content", status: 206,
			header: map[string]string{"Content-Type": "text/html"}, body: simplePage,
			reason: "a byte range is not a document",
		},
		{
			name: "redirect", status: 302,
			header: map[string]string{"Content-Type": "text/html", "Location": "/elsewhere"},
			body:   simplePage, reason: "nowhere to put a script",
		},
		{
			name:   "already compressed",
			header: map[string]string{"Content-Type": "text/html", "Content-Encoding": "gzip"},
			body:   simplePage, reason: "we will not decompress to insert 40 bytes",
		},
		{
			name:   "utf-16 charset",
			header: map[string]string{"Content-Type": "text/html; charset=utf-16"},
			body:   simplePage, reason: "an ASCII byte search cannot walk it safely",
		},
		{
			name:   "signed response",
			header: map[string]string{"Content-Type": "text/html", "Content-Digest": "sha-256=:abc:"},
			body:   simplePage, reason: "never break a digest to make room",
		},
		{
			name:   "repr-digest",
			header: map[string]string{"Content-Type": "text/html", "Repr-Digest": "sha-256=:abc:"},
			body:   simplePage, reason: "same",
		},
		{
			name:   "no head element",
			header: map[string]string{"Content-Type": "text/html"},
			body:   "<!doctype html><html><body>bare</body></html>",
			reason: "nowhere well-defined to inject",
		},
		{
			name:   "head never closes inside the budget",
			header: map[string]string{"Content-Type": "text/html"},
			body:   "<!doctype html><html><head>" + longComment + "</head><body>x</body></html>",
			reason: "a meta CSP could be in the part we never read",
		},
		{
			name:   "server-sent events",
			header: map[string]string{"Content-Type": "text/event-stream"},
			body:   "data: one\n\ndata: two\n\n",
			reason: "a stream must never be held",
		},
		{
			name:   "empty body",
			header: map[string]string{"Content-Type": "text/html"},
			body:   "",
			reason: "nothing to inject into",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, pass := upstreamGate(t, "", func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tt.header {
					w.Header().Set(k, v)
				}
				if tt.body != "" {
					w.Header().Set("Content-Length", fmt.Sprint(len(tt.body)))
				}
				w.Header().Set("ETag", `"strong"`)
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				io.WriteString(w, tt.body)
			})

			res := do(g, docReq("/page", pass))

			if got := res.Body.String(); got != tt.body {
				t.Errorf("body changed (%s):\n got %q\nwant %q", tt.reason, got, tt.body)
			}
			if strings.Contains(res.Body.String(), pathRenew) {
				t.Errorf("injected anyway (%s)", tt.reason)
			}
			if et := res.Header().Get("ETag"); et != `"strong"` {
				t.Errorf("ETag weakened without injecting: %q", et)
			}
			if tt.body != "" && res.Header().Get("Content-Length") == "" {
				t.Error("Content-Length dropped without injecting")
			}
		})
	}
}

// TestInjectionDeclinedByRequestShape covers the cheap half of the decision,
// which runs before the upstream call.
func TestInjectionDeclinedByRequestShape(t *testing.T) {
	tests := []struct {
		name   string
		cfg    string
		mutate func(*http.Request)
		path   string
	}{
		{name: "inject turned off", cfg: "inject = false\n"},
		{
			name:   "htmx fragment",
			mutate: func(r *http.Request) { r.Header.Set("HX-Request", "true") },
		},
		{
			name:   "turbo frame",
			mutate: func(r *http.Request) { r.Header.Set("Turbo-Frame", "sidebar") },
		},
		{
			name:   "xhr",
			mutate: func(r *http.Request) { r.Header.Set("X-Requested-With", "XMLHttpRequest") },
		},
		{
			// A subresource is identified by the complete request shape; dest=empty
			// is also used for browser navigations re-issued by a service worker.
			name: "xhr subresource, not a document",
			mutate: func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Mode", "cors")
				r.Header.Set("Sec-Fetch-Dest", "empty")
				r.Header.Set("Accept", "application/json, text/plain, */*")
			},
		},
		{
			// A non-browser that forges the fetch metadata of a worker-re-issued
			// navigation. dest=empty is corroborated, never obeyed.
			name: "dest=empty from something that is not a browser",
			mutate: func(r *http.Request) {
				r.Header.Set("Sec-Fetch-Mode", "same-origin")
				r.Header.Set("Sec-Fetch-Dest", "empty")
				r.Header.Set("User-Agent", "curl/8.5.0")
			},
		},
		{
			name:   "iframe",
			mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Dest", "iframe") },
		},
		{
			name: "bypassed path is never rewritten",
			cfg:  "[bypass]\npaths = [\"/public/*\"]\n",
			path: "/public/page",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, _ := upstreamGate(t, tt.cfg, htmlHandler(simplePage))
			path := tt.path
			if path == "" {
				path = "/page"
			}
			// The pass must be earned under the UA this shape presents —
			// spending it under a different UA is walled by the binding, and
			// what's under test here is injection shape, not the binding.
			probe := browserReq(path)
			if tt.mutate != nil {
				tt.mutate(probe)
			}
			pass := solveAndGetCookie(t, g, nil, func(cr *http.Request) {
				cr.Header.Set("User-Agent", probe.Header.Get("User-Agent"))
			})
			r := docReq(path, pass)
			if tt.mutate != nil {
				tt.mutate(r)
			}
			if body := do(g, r).Body.String(); body != simplePage {
				t.Errorf("response was rewritten:\n%s", body)
			}
		})
	}
}

// TestPostIsNeverInjected keeps the method check honest: a POST response is often
// HTML, and injecting there would mean buffering form submissions.
func TestPostIsNeverInjected(t *testing.T) {
	g, pass := upstreamGate(t, "", htmlHandler(simplePage))
	r := httptest.NewRequest("POST", "/submit", strings.NewReader("a=1"))
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.Header.Set("Accept", "text/html")
	r.RemoteAddr = "192.0.2.10:1234"
	r.AddCookie(pass)
	if body := do(g, r).Body.String(); body != simplePage {
		t.Errorf("POST response was rewritten:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// Level 1: the CSP decision table (docs/operating.md's test matrix)
// ---------------------------------------------------------------------------

func TestPlanCSP(t *testing.T) {
	tests := []struct {
		name    string
		enforce []string
		report  []string
		meta    []string
		want    injectMode
		// wantSrc, when set, must appear in the rewritten enforcing policy.
		wantSrc  string
		unchange bool // policies must come back untouched
	}{
		{name: "no CSP at all", want: modeExternal, unchange: true},
		{
			name: "script-src self", enforce: []string{"script-src 'self'"},
			want: modeExternal, unchange: true,
		},
		{
			name: "default-src self", enforce: []string{"default-src 'self'"},
			want: modeExternal, unchange: true,
		},
		{
			name: "script-src-elem wins over script-src",
			// script-src would refuse, script-src-elem allows: the elem directive is
			// what governs a <script> element.
			enforce: []string{"script-src 'none'; script-src-elem 'self'"},
			want:    modeExternal, unchange: true,
		},
		{
			name: "scripts forbidden outright", enforce: []string{"script-src 'none'"},
			want: modeSkip,
		},
		{
			name:    "unsafe-inline, nothing to change",
			enforce: []string{"script-src 'unsafe-inline'"},
			want:    modeInline, unchange: true,
		},
		{
			name: "unsafe-inline with a nonce is not unsafe-inline",
			// CSP3: a nonce or hash disables unsafe-inline, so we must not rely on it.
			enforce: []string{"script-src 'unsafe-inline' 'nonce-abc'"},
			want:    modeInlineHash, wantSrc: "'sha256-",
		},
		{
			name:    "strict-dynamic needs a nonce",
			enforce: []string{"script-src 'nonce-abc' 'strict-dynamic'"},
			want:    modeInlineNonce, wantSrc: "'nonce-",
		},
		{
			name:    "hash-only policy gets our hash",
			enforce: []string{"script-src 'sha256-Zm9v'"},
			want:    modeInlineHash, wantSrc: "'sha256-",
		},
		{
			name:    "host allowlist without self",
			enforce: []string{"script-src https://cdn.example.com"},
			want:    modeInlineHash, wantSrc: "'sha256-",
		},
		{
			name:    "two headers intersect, strictest wins",
			enforce: []string{"script-src 'self'", "script-src 'sha256-Zm9v'"},
			want:    modeInlineHash, wantSrc: "'sha256-",
		},
		{
			name:    "comma-separated policies in one header",
			enforce: []string{"script-src 'self', script-src 'sha256-Zm9v'"},
			want:    modeInlineHash, wantSrc: "'sha256-",
		},
		{
			name:    "sandbox without allow-scripts",
			enforce: []string{"sandbox; script-src 'self'"},
			want:    modeSkip,
		},
		{
			name:    "sandbox without allow-same-origin has no cookie to renew",
			enforce: []string{"sandbox allow-scripts; script-src 'self'"},
			want:    modeSkip,
		},
		{
			name:    "sandbox that permits both",
			enforce: []string{"sandbox allow-scripts allow-same-origin; script-src 'self'"},
			want:    modeExternal, unchange: true,
		},
		{
			name: "report-only cannot veto",
			// It reports; it never blocks. So it must not change the decision.
			report: []string{"script-src 'none'"},
			want:   modeExternal, unchange: true,
		},
		{
			name: "meta policy allowing self is fine", meta: []string{"script-src 'self'"},
			want: modeExternal, unchange: true,
		},
		{
			name: "meta policy we cannot rewrite",
			// A restricting meta policy that needs modification is fatal: we cannot
			// edit a tag we may have already streamed past.
			meta: []string{"script-src 'sha256-Zm9v'"},
			want: modeSkip,
		},
		{
			name:    "unrelated directives are not script directives",
			enforce: []string{"img-src 'none'; style-src 'self'"},
			want:    modeExternal, unchange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planCSP(tt.enforce, tt.report, tt.meta)
			if got.mode != tt.want {
				t.Fatalf("mode = %v, want %v", got.mode, tt.want)
			}
			if tt.unchange {
				if got.enforce != nil || got.report != nil {
					t.Errorf("policies rewritten when they should not be: %v / %v",
						got.enforce, got.report)
				}
				return
			}
			if tt.wantSrc == "" {
				return
			}
			if len(got.enforce) != len(tt.enforce) {
				t.Fatalf("rewrote %d policies, want %d", len(got.enforce), len(tt.enforce))
			}
			for i, p := range got.enforce {
				if !strings.Contains(p, tt.wantSrc) {
					t.Errorf("policy %d = %q, want it to contain %q", i, p, tt.wantSrc)
				}
			}
		})
	}
}

// TestPlanCSPRewritesReportOnlyToo pins rule 8: a correct injection must not
// flood the operator's report endpoint.
func TestPlanCSPRewritesReportOnlyToo(t *testing.T) {
	p := planCSP([]string{"script-src 'sha256-Zm9v'"}, []string{"script-src 'sha256-Zm9v'"}, nil)
	if p.mode != modeInlineHash {
		t.Fatalf("mode = %v", p.mode)
	}
	if len(p.report) != 1 || !strings.Contains(p.report[0], "'sha256-") {
		t.Errorf("report-only policy not given the hash: %v", p.report)
	}
}

// TestPlanCSPLeavesUnrestrictingPolicyAlone: adding a directive where the
// operator had none would newly restrict scripts they had allowed.
func TestPlanCSPLeavesUnrestrictingPolicyAlone(t *testing.T) {
	p := planCSP([]string{"script-src 'sha256-Zm9v'", "img-src 'self'"}, nil, nil)
	if p.mode != modeInlineHash {
		t.Fatalf("mode = %v", p.mode)
	}
	if strings.Contains(p.enforce[1], "sha256") {
		t.Errorf("hash added to a policy that says nothing about scripts: %q", p.enforce[1])
	}
	if p.enforce[1] != "img-src 'self'" {
		t.Errorf("unrelated policy altered: %q", p.enforce[1])
	}
}

// TestInlineHashMatchesTheScriptWeSend is the drift test. The hash and the script
// are computed in different places, and if they ever disagree the injected script
// is blocked by the very policy we rewrote to allow it — a failure that shows up
// only in a browser console.
func TestInlineHashMatchesTheScriptWeSend(t *testing.T) {
	g, pass := upstreamGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "script-src 'sha256-Zm9v'")
		io.WriteString(w, simplePage)
	})

	res := do(g, docReq("/page", pass))
	body := res.Body.String()

	script := between(body, "<script>", "</script>")
	if script == "" {
		t.Fatalf("no inline script injected:\n%s", body)
	}
	sum := sha256.Sum256([]byte(script))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	csp := res.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, want) {
		t.Errorf("CSP does not authorize the script we sent.\n  script: %q\n  want source: %s\n  got CSP: %s",
			script, want, csp)
	}
	if !strings.Contains(csp, "'sha256-Zm9v'") {
		t.Errorf("the operator's own hash was dropped: %s", csp)
	}
}

// TestNonceModeIsNotCacheable: a nonce in a shared cache is a nonce published to
// every visitor.
func TestNonceModeIsNotCacheable(t *testing.T) {
	g, pass := upstreamGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "script-src 'nonce-abc' 'strict-dynamic'")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		io.WriteString(w, simplePage)
	})

	res := do(g, docReq("/page", pass))
	if cc := res.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store alongside a nonce", cc)
	}
	nonce := between(res.Body.String(), `<script nonce="`, `"`)
	if nonce == "" {
		t.Fatal("no nonce on the injected script")
	}
	if !strings.Contains(res.Header().Get("Content-Security-Policy"), "'nonce-"+nonce+"'") {
		t.Error("the nonce on the tag is not the nonce in the policy")
	}

	// And it must differ per response, or it is not a nonce.
	other := between(do(g, docReq("/page", pass)).Body.String(), `<script nonce="`, `"`)
	if other == nonce {
		t.Error("the same nonce was reused across responses")
	}
}

// ---------------------------------------------------------------------------
// Level 1: the byte-level helpers
// ---------------------------------------------------------------------------

func TestResponseSkipReasonsHaveBoundedCardinality(t *testing.T) {
	for _, status := range []int{201, 404, 599, 999999} {
		if got := responseSkipReason(status, http.Header{}); got != "response-status-is-not-200" {
			t.Errorf("status %d reason = %q", status, got)
		}
	}
	for _, charset := range []string{"utf-16", "x-attacker-1", "x-attacker-2"} {
		h := http.Header{"Content-Type": {"text/html; charset=" + charset}}
		if got := responseSkipReason(http.StatusOK, h); got != "charset-is-not-ascii-compatible" {
			t.Errorf("charset %q reason = %q", charset, got)
		}
	}
}

func TestInsertionPoint(t *testing.T) {
	tests := []struct {
		name, in string
		want     string // the text our tag would be inserted before, or "" for none
		none     bool
	}{
		{name: "simple", in: "<html><head><title>x</title>", want: "<title>x</title>"},
		{name: "attributes", in: `<html><head lang="en" data-a="b"><meta>`, want: "<meta>"},
		{name: "uppercase", in: "<HTML><HEAD><TITLE>", want: "<TITLE>"},
		{name: "newline in tag", in: "<html><head\n><x>", want: "<x>"},
		{name: "self-closing-ish", in: "<html><head/><x>", want: "<x>"},
		{name: "header is not head", in: "<html><body><header>x</header>", none: true},
		{name: "headers is not head", in: "<html><headers>x", none: true},
		{
			name: "head inside a comment is skipped",
			in:   "<html><!-- <head> not this one --><head><real>",
			want: "<real>",
		},
		{
			name: "unterminated comment yields nothing yet",
			in:   "<html><!-- <head> still going",
			none: true,
		},
		{name: "tag still arriving", in: "<html><head", none: true},
		{name: "no head at all", in: "<html><body>x</body></html>", none: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := insertionPoint([]byte(tt.in))
			if tt.none {
				if got != -1 {
					t.Fatalf("insertionPoint = %d, want -1 (rest: %q)", got, tt.in[got:])
				}
				return
			}
			if got < 0 {
				t.Fatalf("insertionPoint = -1, want a position before %q", tt.want)
			}
			if rest := tt.in[got:]; rest != tt.want {
				t.Errorf("would insert before %q, want before %q", rest, tt.want)
			}
		})
	}
}

func TestLooksLikeDocument(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"doctype", "<!doctype html><html>", true},
		{"uppercase doctype", "<!DOCTYPE HTML>", true},
		{"bare html", "<html lang=en>", true},
		{"bare head", "<head>", true},
		{"leading whitespace", "\n\n  <!doctype html>", true},
		{"utf-8 bom", "\xEF\xBB\xBF<!doctype html>", true},
		{"still arriving", "<!doc", true},
		{"json", `{"a":1}`, false},
		{"xml declaration", `<?xml version="1.0"?>`, false},
		{"utf-16 bom", "\xFF\xFE<\x00h\x00", false},
		{"plain text", "hello", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeDocument([]byte(tt.in)); got != tt.want {
				t.Errorf("looksLikeDocument(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMetaPolicies(t *testing.T) {
	tests := []struct {
		name, in string
		want     []string
	}{
		{
			name: "double quoted",
			in:   `<head><meta http-equiv="Content-Security-Policy" content="script-src 'self'">`,
			want: []string{"script-src 'self'"},
		},
		{
			name: "single quoted and reordered",
			in:   `<meta content='default-src *' http-equiv='content-security-policy'>`,
			want: []string{"default-src *"},
		},
		{
			name: "unquoted",
			in:   `<meta http-equiv=content-security-policy content=script-src>`,
			want: []string{"script-src"},
		},
		{
			name: "other meta tags ignored",
			in:   `<meta charset="utf-8"><meta http-equiv="refresh" content="5">`,
			want: nil,
		},
		{
			name: "report-only meta is not a policy we honour",
			in:   `<meta http-equiv="Content-Security-Policy-Report-Only" content="script-src 'none'">`,
			want: nil,
		},
		{
			name: "two policies",
			in: `<meta http-equiv="content-security-policy" content="a">` +
				`<meta http-equiv="content-security-policy" content="b">`,
			want: []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := metaPolicies([]byte(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("metaPolicies = %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("policy %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestMetaCSPInTheDocumentStopsInjection is the end-to-end form of the meta case:
// the policy is discovered by reading the body, not the headers.
func TestMetaCSPInTheDocumentStopsInjection(t *testing.T) {
	page := `<!doctype html><html><head>` +
		`<meta http-equiv="Content-Security-Policy" content="script-src 'sha256-Zm9v'">` +
		`</head><body>x</body></html>`
	g, pass := upstreamGate(t, "", htmlHandler(page))
	if body := do(g, docReq("/page", pass)).Body.String(); body != page {
		t.Errorf("injected despite an unrewritable meta policy:\n%s", body)
	}
}

// TestInjectionAcrossChunkedWrites: the head can arrive one byte at a time, and
// ReverseProxy flushes after every write. Buffering must survive that.
func TestInjectionAcrossChunkedWrites(t *testing.T) {
	g, pass := upstreamGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for _, b := range []byte(simplePage) {
			w.Write([]byte{b})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})
	body := do(g, docReq("/page", pass)).Body.String()
	if strings.Count(body, externalTag) != 1 {
		t.Fatalf("byte-at-a-time document not injected once:\n%s", body)
	}
	if got := strings.Replace(body, externalTag, "", 1); got != simplePage {
		t.Errorf("document altered:\n got %q\nwant %q", got, simplePage)
	}
}

func htmlHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, body)
	}
}

// between returns the text between the first occurrence of start and the next
// occurrence of end after it.
func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	i += len(start)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

// A site's own root-scoped service worker that re-issues navigations —
// `e.respondWith(fetch(e.request))`, the Workbox default and the shape of every
// offline shell — makes the browser rewrite Sec-Fetch-Dest to "empty". Refusing
// to inject into those admitted the visitor and then withheld the script that
// keeps them admitted, so they lapsed and were re-challenged forever. Both
// header shapes below were measured from real browsers against the demo app.
func TestInjectableThroughSiteServiceWorker(t *testing.T) {
	nav := func(mode, dest, accept, ua string) *http.Request {
		r := httptest.NewRequest("GET", "/page", nil)
		r.Header.Set("Sec-Fetch-Mode", mode)
		r.Header.Set("Sec-Fetch-Dest", dest)
		r.Header.Set("Accept", accept)
		r.Header.Set("User-Agent", ua)
		return r
	}
	const html = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	const moz = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"

	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"plain navigation", nav("navigate", "document", html, moz), true},
		{"chromium via site worker", nav("navigate", "empty", html, moz), true},
		{"firefox via site worker", nav("same-origin", "empty", html, moz), true},
		// The reason "empty" cannot simply be waved through.
		{"json xhr", nav("cors", "empty", "application/json, text/plain, */*", moz), false},
		{"non-browser fetch", nav("cors", "empty", html, "curl/8.5.0"), false},
		{"iframe", nav("navigate", "iframe", html, moz), false},
		{"script subresource", nav("no-cors", "script", "*/*", moz), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := injectable(c.r); got != c.want {
				t.Errorf("injectable = %v, want %v", got, c.want)
			}
		})
	}
}

// Every GET recognized as a browser navigation must also be injectable. The
// exhaustive header matrix includes service workers that rebuild a request and
// consequently drop its Accept header.
func TestInjectableAgreesWithIsBrowserNav(t *testing.T) {
	modes := []string{"", "navigate", "same-origin", "cors", "no-cors", "websocket"}
	dests := []string{"", "document", "empty", "iframe", "script", "image", "style"}
	accepts := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"text/html",
		"*/*",
		"application/json, text/plain, */*",
		"text/markdown, text/html, */*",
		"",
	}
	uas := []string{
		"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0",
		"curl/8.5.0",
		"",
	}
	for _, mode := range modes {
		for _, dest := range dests {
			for _, accept := range accepts {
				for _, ua := range uas {
					r := httptest.NewRequest("GET", "/page", nil)
					for k, v := range map[string]string{
						"Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest,
						"Accept": accept, "User-Agent": ua,
					} {
						if v != "" {
							r.Header.Set(k, v)
						}
					}
					if isBrowserNav(r) && !injectable(r) {
						t.Errorf("mode=%q dest=%q accept=%q ua=%q: admitted as a browser navigation but not injectable — "+
							"this visitor is let in and then never renewed", mode, dest, accept, ua)
					}
				}
			}
		}
	}
}

// Every browser shape offered a wait page must receive the renewal driver after
// admission, including navigations re-issued by a site service worker.
func TestEveryShapeGivenTheWaitPageIsAlsoRenewed(t *testing.T) {
	const html = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	const firefox = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/140.0"
	const chrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0"

	shapes := []struct{ name, mode, dest, accept, ua string }{
		{"plain navigation", "navigate", "document", html, chrome},
		// Measured through a site's own root-scoped service worker.
		{"chromium behind a site worker", "navigate", "empty", html, chrome},
		{"firefox behind a site worker", "same-origin", "empty", html, firefox},
		// A worker that re-issues as fetch(e.request.url) rather than
		// fetch(e.request) drops the browser's Accept header. Still a person,
		// still a navigation, still has to be renewed.
		{"site worker that rebuilt the request", "navigate", "empty", "*/*", chrome},
		// No fetch metadata: older browsers, and anything behind a header-
		// stripping intermediary.
		{"no fetch metadata", "", "", html, firefox},
	}

	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			g, _ := upstreamGate(t, "", htmlHandler(simplePage))
			req := func(pass *http.Cookie) *http.Request {
				r := httptest.NewRequest("GET", "/page", nil)
				for k, v := range map[string]string{
					"Sec-Fetch-Mode": s.mode, "Sec-Fetch-Dest": s.dest,
					"Accept": s.accept, "User-Agent": s.ua,
				} {
					if v != "" {
						r.Header.Set(k, v)
					}
				}
				r.RemoteAddr = "192.0.2.10:44321"
				if pass != nil {
					r.AddCookie(pass)
				}
				return r
			}

			// Half one: this shape is treated as a person and gets the solver.
			got := do(g, req(nil)).Body.String()
			if !strings.Contains(got, "__ANTEROOM__") {
				t.Fatalf("no wait page for this shape — it got the machine refusal instead:\n%s", got)
			}

			// Half two: the pass that wait page earns comes back injected. A
			// visitor admitted without the script lapses at DRIVER_STALE_MS and
			// is re-challenged on every navigation from then on.
			pass := solveAndGetCookie(t, g, nil, func(cr *http.Request) {
				if s.ua != "" {
					cr.Header.Set("User-Agent", s.ua)
				}
			})
			got = do(g, req(pass)).Body.String()
			if !strings.Contains(got, pathRenew) {
				t.Errorf("admitted but not injected — this visitor can get in and cannot stay in:\n%s", got)
			}
		})
	}
}

// The implication is one-way by design, and saying so keeps someone from
// "fixing" the asymmetry by widening isBrowserNav. A HEAD navigation gets the
// wait page and has no body to inject into; a fragment request from HTMX is
// neither. Injection is also reachable without the wait page — an operator's own
// XHR for a document — which is why injectable is not simply isBrowserNav.
func TestInjectableIsNotIsBrowserNav(t *testing.T) {
	head := httptest.NewRequest("HEAD", "/page", nil)
	head.Header.Set("Sec-Fetch-Mode", "navigate")
	head.Header.Set("Sec-Fetch-Dest", "document")
	head.Header.Set("Accept", "text/html")
	head.Header.Set("User-Agent", "Mozilla/5.0")
	if !isBrowserNav(head) {
		t.Error("HEAD navigation should still be a browser navigation")
	}
	if injectable(head) {
		t.Error("HEAD has no body: it must never be injectable")
	}

	frag := httptest.NewRequest("GET", "/page", nil)
	frag.Header.Set("Sec-Fetch-Mode", "navigate")
	frag.Header.Set("Sec-Fetch-Dest", "document")
	frag.Header.Set("Accept", "text/html")
	frag.Header.Set("User-Agent", "Mozilla/5.0")
	frag.Header.Set("HX-Request", "true")
	if isBrowserNav(frag) || injectable(frag) {
		t.Error("an HTMX fragment is neither a navigation nor injectable")
	}
}
