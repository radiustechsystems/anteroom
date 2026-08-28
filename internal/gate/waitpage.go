package gate

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/radiustechsystems/anteroom/internal/payment"
)

//go:embed assets
var assets embed.FS

var (
	defaultHeader  = mustAsset("assets/header.html")
	defaultFooter  = mustAsset("assets/footer.html")
	coreJS         = mustAsset("assets/core.js")
	pageJS         = mustAsset("assets/page.js")
	swShellJS      = mustAsset("assets/sw.js")
	sha256VendorJS = mustAsset("assets/sha256-vendor.js")
	sha256JS       = mustAsset("assets/sha256.js")
	renewJS        = mustAsset("assets/renew.js")
	uninstallHTML  = mustAsset("assets/uninstall.html")
	// swJS is the served worker: the shared solver core plus the worker shell —
	// one solver implementation, assembled per artifact.
	swJS = append(append([]byte{}, coreJS...), swShellJS...)
)

// buildSolver assembles the wait page's solver and the URL it is served from.
//
// The bundle is external rather than inlined, and that is a bandwidth decision:
// the wait page is served on every unadmitted navigation, so inlining meant
// paying for the whole solver again on every lapse, every re-admission, and
// every visitor a crawl wave sends at us. As its own URL it is fetched once and
// then read from cache, which is the difference between roughly nine kilobytes
// per challenge and roughly one.
//
// The URL carries a content hash so the response can be immutable: caching a
// solver forever is only safe if upgrading the binary cannot be shadowed by a
// stale copy, and a hash of the exact bytes guarantees that. It also varies with
// allow_insecure_context, which is why this is per-gate and not a package var —
// the SHA-256 fallback ships only when the operator asked for it.
//
// The digest is in the path rather than a query parameter, and it is 128 bits
// rather than 48. Both are consequences of the guarantee being adversarial: a
// query string is the part of a URL a CDN may normalise away (collapsing every
// version onto one immutable cache entry), and 48 bits is inside collision
// reach for someone who wants their chosen bytes to answer to a future
// release's address. serveSolver enforces the other half — no other spelling of
// this URL is ever stored.
func buildSolver(allowInsecure bool) (body []byte, url string) {
	if allowInsecure {
		body = append(body, sha256VendorJS...)
		body = append(body, '\n')
		body = append(body, sha256JS...)
		body = append(body, '\n')
	}
	body = append(body, coreJS...)
	body = append(body, pageJS...)
	sum := sha256.Sum256(body)
	return body, pathSolverPrefix + hex.EncodeToString(sum[:16]) + ".js"
}

func mustAsset(name string) []byte {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic("gate: missing embedded asset " + name + ": " + err.Error())
	}
	return b
}

// maxPageBytes caps an operator wait-page file. Generous for hand-written HTML,
// small enough that an unauthenticated request can never make the gate read a
// huge file into memory.
const maxPageBytes = 1 << 20 // 1 MiB

// pageSource yields the wait page's header and footer. With a pages dir
// configured, edits are live instantly (the flagship customization promise) —
// but rather than re-reading on every challenge, files are cached and
// revalidated by mtime+size, so an unauthenticated request costs a stat rather
// than a full read. Failures fall back to the embedded defaults instead of
// breaking the gate.
type pageSource struct {
	dir string

	mu    sync.Mutex
	cache map[string]cachedPage
}

type cachedPage struct {
	body    []byte
	modTime time.Time
	size    int64
}

func newPageSource(dir string) *pageSource {
	return &pageSource{dir: dir, cache: map[string]cachedPage{}}
}

func (p *pageSource) header() []byte { return p.read("header.html", defaultHeader) }
func (p *pageSource) footer() []byte { return p.read("footer.html", defaultFooter) }

func (p *pageSource) read(name string, fallback []byte) []byte {
	if p.dir == "" {
		return fallback
	}
	path := filepath.Join(p.dir, name)
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return fallback
	}
	if fi.Size() > maxPageBytes {
		return fallback
	}

	p.mu.Lock()
	c, cached := p.cache[name]
	p.mu.Unlock()
	if cached && c.modTime.Equal(fi.ModTime()) && c.size == fi.Size() {
		return c.body
	}

	// Read outside the lock: a slow pages directory must not serialize every
	// walled request. A concurrent duplicate read is cheaper than that.
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	p.mu.Lock()
	p.cache[name] = cachedPage{body: b, modTime: fi.ModTime(), size: fi.Size()}
	p.mu.Unlock()
	return b
}

// serveWaitPage renders header + solver + footer. Always no-store and
// noindex: the wait page is a checkpoint, never content.
func (g *Gate) serveWaitPage(w http.ResponseWriter, r *http.Request) {
	challengeRequired(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	// The wait page carries the original URL; an operator header.html that pulls
	// a third-party asset must not leak it.
	w.Header().Set("Referrer-Policy", "same-origin")
	// Agent detection is a heuristic and will sometimes hand this HTML page to a
	// non-browser, which has no JavaScript and would otherwise see nothing
	// useful. Advertise the machine-readable instructions three ways, because
	// different clients notice different things: a Link header (HTTP-level, seen
	// without parsing HTML), a <link rel="alternate"> (found by HTML parsers),
	// and a <noscript> block (surfaced by text extractors and by any agent that
	// renders the page as text).
	w.Header().Add("Link", "<"+pathInstructions+`>; rel="alternate"; type="text/markdown"`)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == http.MethodHead {
		return
	}

	cfg, _ := json.Marshal(map[string]any{
		"challengeURL": pathChallenge,
		"answerURL":    pathAnswer,
		"swURL":        pathSW,
	})

	w.Write(g.pages.header())
	fmt.Fprintf(w, "\n<link rel=\"alternate\" type=\"text/markdown\" href=%q title=\"How to pass this gate without a browser\">\n", pathInstructions)
	// Visible body text, not just <noscript>. Measured: agentic fetch tools
	// convert HTML to markdown readability-style, which drops <head>, <noscript>,
	// and comments — visible text is the ONLY thing that reaches the model. A
	// browser dismisses this page in about a second, so one muted line costs
	// nothing; operators who dislike it can hide .anteroom-agent-note.
	fmt.Fprintf(w, `<p class="anteroom-agent-note" style="font-size:.78rem;color:#9aa3af;margin-top:1.2rem">
Automated client? This page runs a browser check you cannot complete.
Fetch <a href=%q>%s</a> for machine-readable instructions instead.</p>
<noscript><p>This page needs JavaScript to complete an automatic check.
Machine-readable instructions: <a href=%q>%s</a></p></noscript>`+"\n",
		pathInstructions, pathInstructions, pathInstructions, pathInstructions)
	// The per-request challenge stays inline — it is different every time and
	// must never be cached. Everything static lives behind solverURL. `defer`
	// so the solver runs against a complete document; it reads the config
	// object this line just defined, which is set before any parsing continues.
	fmt.Fprintf(w, "<script>window.__ANTEROOM__ = %s;</script>\n<script src=%q defer></script>\n", cfg, g.solverURL)
	w.Write(g.pages.footer())
}

// instructionsMarkdown is the machine-readable "how to get in" sheet. It is the
// body of a refusal AND is served standalone at /.anteroom/instructions.md, so
// that a client which was handed the HTML wait page by mistake — agent detection
// is a heuristic and will misfire — still has one URL to fetch for the real
// answer. Kept free of request-specific data so it is a stable, cacheable
// artifact an agent can be pointed at.
func (g *Gate) instructionsMarkdown() string {
	return `# Pass required

This site is protected by Anteroom, a self-hosted bot gate. No account is
needed; access is earned, not registered.

## If you are automating

Solve the free proof-of-work challenge:

1. ` + "`GET " + pathChallenge + "`" + ` → JSON ` + "`{challenge, threshold, pass_ttl_ms, deadline_unix_ms}`" + `.
2. Find a nonce such that the SHA-256 digest of ` + "`challenge + nonce`" + `, compared
   as bytes, sorts strictly below ` + "`threshold`" + ` (64 hex characters).
3. ` + "`POST " + pathAnswer + "`" + ` with JSON ` + "`{\"challenge\": ..., \"nonce\": ...}`" + `.
4. Retry your request with the ` + "`" + cookieName + "`" + ` cookie the answer sets.

The pass is short-lived; re-solve when it lapses. Redeem promptly — a pass
expires a fixed time after its challenge was *issued*, so a stale solve is
worthless (` + "`deadline_unix_ms`" + ` tells you when to abandon and refetch).

## If a human sent you

Tell them to open the URL in a normal browser. The check runs automatically, is
free, and takes about a second.

## Notes

- Nothing here requires payment, an account, or an API key.
- This document is served at ` + pathInstructions + ` and does not change per
  request; fetch it any time.
`
}

// serveInstructions serves the markdown sheet standalone. Unlike the refusal it
// is a fixed document, so it may be cached briefly.
func (g *Gate) serveInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=300")
	w.Header().Set("X-Robots-Tag", "noindex")
	io.WriteString(w, g.instructionsMarkdown())
}

// serveRefusal is the non-browser answer: machine-readable instructions in
// markdown (default) or JSON (Accept: application/json). Status is 403 —
// except for configured 2xx-only fetch tools, which discard non-2xx bodies
// and would otherwise see nothing at all. When configured, the x402 payment
// offer is included in this response.
//
// Deliberately omit WWW-Authenticate: 403 does not require it, and advertising
// a Payment scheme there makes some agent clients mistake x402 for HTTP auth.
func (g *Gate) serveRefusal(w http.ResponseWriter, r *http.Request) {
	status := http.StatusForbidden
	if g.okBodyAgent(r) {
		status = http.StatusOK
	}
	g.renderRefusal(w, r, status)
}

func (g *Gate) serveStrictRefusal(w http.ResponseWriter, r *http.Request) {
	g.renderRefusal(w, r, http.StatusForbidden)
}

func (g *Gate) renderRefusal(w http.ResponseWriter, r *http.Request, status int) {
	challengeRequired(w)

	if g.cfg.Triage.JSONAccept && wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"error": "a pass is required",
			"free_challenge": map[string]any{
				"challenge_url": pathChallenge,
				"answer_url":    pathAnswer,
				"how":           "GET challenge_url → {challenge, threshold}; find nonce where sha256(challenge+nonce) < threshold (hex compare); POST {challenge, nonce} to answer_url; retry with the " + cookieName + " cookie",
			},
			"human": "open this URL in a browser — the check is free and takes about a second",
		})
		return
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, g.instructionsMarkdown())
}

// okBodyAgent reports whether this client needs its instructions with a 200
// status because it discards non-2xx bodies.
//
// The user-agent match is necessary but not sufficient: downgrading the status
// for a client that is actually protocol-capable would be harmful, since such a
// client keys off the status and would read 200 as "served" and never pay or
// solve. So the downgrade is withheld from any request showing protocol
// competence — it already carries a payment, or it asks for JSON rather than
// prose. Both are signals that the honest status is more useful than a readable
// body.
func (g *Gate) okBodyAgent(r *http.Request) bool {
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		return false
	}
	// The constant, not a copy of its value. This and the ladder in gate.serve
	// both answer "does this request carry a payment", and a spelling that lives
	// in two places is a spelling that can be corrected in one. ("X-PAYMENT" has
	// no constant deliberately: it is the v1 name, which the gate neither emits
	// nor reads — it is recognised here only as evidence that the client speaks
	// SOME payment protocol and would rather have an honest status than a
	// readable body.)
	if r.Header.Get(payment.HeaderSignature) != "" || r.Header.Get("X-PAYMENT") != "" {
		return false
	}
	if wantsJSON(r) {
		return false
	}
	l := strings.ToLower(ua)
	for _, a := range g.cfg.Triage.OKBodyAgents {
		if a != "" && strings.Contains(l, strings.ToLower(a)) {
			return true
		}
	}
	return false
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}
