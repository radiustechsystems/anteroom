package gate

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/radiustechsystems/anteroom/internal/challenge"
	"github.com/radiustechsystems/anteroom/internal/token"
)

// The gate's own endpoints. All responses are no-store: nothing under
// /.anteroom/ is cacheable except the service worker script, which carries its
// own short max-age so registration updates propagate.
const (
	pathChallenge = prefix + "challenge"
	pathAnswer    = prefix + "answer"
	pathSW        = prefix + "sw.js"
	// The solver's digest lives in the path, not in a query parameter: a
	// query is the part of a URL intermediaries feel free to normalise away,
	// and a CDN that drops it would collapse every version onto one cache key
	// while the response still says `immutable`. pathSolverPrefix + digest +
	// ".js" is the whole address.
	pathSolverPrefix = prefix + "solver."
	pathRenew        = prefix + "renew.js"
	pathUninstall    = prefix + "uninstall"
	pathInstructions = prefix + "instructions.md"
	// pathSchema is the JSON Schema for the dev.anteroom offer extension,
	// referenced by $ref from every PAYMENT-REQUIRED offer rather than inlined
	// (see offer()). The URL is stable across versions on purpose: offers cite
	// it, and a cached copy going briefly stale only ever staled documentation.
	pathSchema = prefix + "x402-schema.json"
)

// HealthPath is where the gate answers a liveness probe. It is the one endpoint
// address another package needs to know: the binary's own -healthcheck mode
// probes it, and the container image has no shell to run curl in, so a literal
// copied into cmd would be a second spelling of the gate's URL that nothing
// would catch drifting.
const HealthPath = prefix + "healthz"

func (g *Gate) serveOwn(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case HealthPath:
		g.serveHealthz(w, r)
	case pathChallenge:
		g.serveChallenge(w, r)
	case pathAnswer:
		g.serveAnswer(w, r)
	case pathSW:
		g.serveSW(w, r)
	case pathRenew:
		g.serveRenew(w, r)
	case pathUninstall:
		g.serveUninstall(w, r)
	case pathInstructions:
		g.serveInstructions(w, r)
	case pathSchema:
		g.serveSchema(w, r)
	default:
		// Any /.anteroom/solver.<digest>.js, whether or not the digest is the
		// one this binary serves. serveSolver decides what that means.
		if strings.HasPrefix(r.URL.Path, pathSolverPrefix) && strings.HasSuffix(r.URL.Path, ".js") {
			g.serveSolver(w, r)
			return
		}
		noStore(w)
		http.NotFound(w, r)
	}
}

// noStore marks a gate-authored response uncacheable. Vary is as important as
// Cache-Control here: these responses sit at the URLs of real content and their
// bodies depend on the request, so an intermediary that ignores no-store must at
// least not serve one visitor's wall to everyone.
func noStore(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0, private")
	h.Set("Pragma", "no-cache")
	h.Set("Vary", "Cookie, Accept, Sec-Fetch-Mode, User-Agent")
}

const actionHeader = "X-Anteroom-Action"

func challengeRequired(w http.ResponseWriter) {
	noStore(w)
	w.Header().Set(actionHeader, "challenge")
}

// serveSchema hands out the offer extension's JSON Schema — the target of the
// $ref every PAYMENT-REQUIRED offer carries. Cacheable for an hour: the
// document changes only when the binary does, and it is advisory field
// documentation, so a stale copy misleads no payment.
func (g *Gate) serveSchema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/schema+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Robots-Tag", "noindex")
	json.NewEncoder(w).Encode(extensionSchema())
}

func (g *Gate) serveHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}

// challengeResponse is what solvers work from. The threshold is sent as hex
// bytes so the client compares digests without knowing the difficulty math.
type challengeResponse struct {
	Challenge string `json:"challenge"`
	Threshold string `json:"threshold"` // 64 hex chars; hash must be < this
	Kind      string `json:"kind"`      // "admit" or "renew"
	PassTTLMs int64  `json:"pass_ttl_ms"`
	// DeadlineMs is when this challenge stops being redeemable for a usable
	// pass. A solver that passes it must abandon and fetch a fresh challenge
	// rather than submit work that can only be refused — the difference
	// between a slow device getting in late and never getting in at all.
	DeadlineMs int64 `json:"deadline_unix_ms"`
}

// serveChallenge issues a fresh challenge. Holding a still-valid pass earns
// the cheap renew threshold; everyone else pays admission. The complete
// profile is signed into the challenge and enforced at answer time.
func (g *Gate) serveChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	now := g.now()
	profile := g.admit
	if _, ok := g.mayRenew(r, now); ok {
		profile = g.renew
	}
	c, issuedAt, err := g.issuer.Issue(now, requestAudience(r), profile)
	if err != nil {
		g.lg.Error("issuing challenge", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := challengeResponse{
		Challenge: c,
		Threshold: hex.EncodeToString(profile.Threshold[:]),
		Kind:      profile.Kind.String(),
		PassTTLMs: profile.TTL.Milliseconds(),
		// The same expression serveAnswer evaluates over the same instant, so
		// the number advertised here is the number enforced there rather than a
		// second computation of it that happens to agree.
		DeadlineMs: issuedAt.Add(profile.TTL).UnixMilli(),
	}
	g.met.issued.With(resp.Kind).Inc()
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type answerRequest struct {
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
}

type answerResponse struct {
	OK        bool   `json:"ok"`
	Kind      string `json:"kind,omitempty"`
	ExpUnixMs int64  `json:"exp_unix_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// serveAnswer verifies a solution and mints a pass. Renewal (the cheap
// threshold) is accepted only while the presented pass is still valid — an
// expired pass means paying admission again; that asymmetry is the liveness
// economics, enforced server-side.
func (g *Gate) serveAnswer(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(answerResponse{Error: "POST only"})
		return
	}
	// MaxBytesReader caps size but not time: without a read deadline a trickled
	// 4 KB body pins a goroutine indefinitely. This is safe here (unlike on the
	// proxy path) because the gate's own endpoints take tiny bodies.
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetReadDeadline(g.now().Add(10 * time.Second))
	}
	var req answerRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		g.noteAnswer("malformed", r)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(answerResponse{Error: "body must be JSON {challenge, nonce}"})
		return
	}
	issuedAt, profile, err := g.issuer.Verify(req.Challenge, requestAudience(r), g.now())
	if err != nil {
		msg, outcome := "invalid challenge", "malformed"
		if errors.Is(err, challenge.ErrStale) {
			msg = "challenge expired; fetch a fresh one from " + pathChallenge
			outcome = "stale"
		}
		g.noteAnswer(outcome, r)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(answerResponse{Error: msg})
		return
	}

	kind := profile.Kind.String()
	rootAt := time.Time{}
	if profile.Kind == challenge.KindRenew {
		// A signed renewal profile is necessary but not sufficient: the answer
		// still has to present a pass that was renewable when the challenge was
		// issued. This prevents a shared cheap solve from becoming admission.
		var renewing bool
		rootAt, renewing = g.mayRenew(r, issuedAt)
		if !renewing {
			g.noteAnswer("bad_pow", r)
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(answerResponse{Error: "renewal challenge requires the pass that earned it"})
			return
		}
	}
	if err := challenge.CheckPoW(req.Challenge, req.Nonce, profile.Threshold); err != nil {
		g.noteAnswer("bad_pow", r)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(answerResponse{Error: "solution does not meet the required threshold"})
		return
	}

	// The pass expires pass_ttl after the CHALLENGE was issued, not after the
	// solve arrived. A (challenge, nonce) pair is therefore worth less the
	// longer it is held: redeeming it later yields only the remaining lifetime,
	// and past the TTL nothing at all.
	//
	// What that buys is a bound on STALE reuse, and it is worth being precise
	// about, because the stronger claim is false: a pass and a solved challenge
	// are bearer capabilities, and a group actively redistributing fresh ones
	// defeats this entirely. Proof of work here is admission friction with a
	// short shelf life, not proof that each machine did its own work.
	exp := issuedAt.Add(profile.TTL)
	remaining := exp.Sub(g.now())
	if remaining <= 0 {
		g.noteAnswer("window_elapsed", r)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(answerResponse{Error: "this challenge's pass window has already elapsed; fetch a fresh challenge from " + pathChallenge})
		return
	}
	if err := g.setPassCookie(w, r, token.Pass{Kind: token.KindPoW, Scope: token.ScopeAll}, exp, rootAt); err != nil {
		g.lg.Error("minting pass", "err", err)
		g.noteAnswer("error", r)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(answerResponse{Error: "internal error"})
		return
	}
	g.noteAnswer("ok_"+kind, r)
	// Solve time is issue-to-answer, recovered from the timestamp the challenge
	// itself carries — no correlation table, exactly because challenges are
	// stateless. Observed only on success: a refused answer has no solve time.
	g.met.solveTime.With(kind).Observe(g.now().Sub(issuedAt).Seconds())
	g.met.minted.With("pow").Inc()
	json.NewEncoder(w).Encode(answerResponse{OK: true, Kind: kind, ExpUnixMs: exp.UnixMilli()})
}

// serveSW hands out the renewal service worker. Short max-age (not no-store):
// the browser refetches it on registration checks, so updates propagate within
// a minute without hammering the gate.
//
// The worker is deliberately registered at the DEFAULT /.anteroom/ scope — no
// Service-Worker-Allowed header, no root scope. Only one worker can own a
// scope, so claiming "/" would evict an operator's own PWA/offline worker (and
// be evicted by it). Renewal does not need to control any page: an uncontrolled
// page reaches us through getRegistration() + postMessage. This worker has no
// fetch handler and must never gain one — that would turn a renewal helper into
// a full-origin interception surface.
func (g *Gate) serveSW(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=60")
	w.Write(swJS)
}

// serveSolver hands out the wait page's solver. Unlike everything else the gate
// serves, the one URL that names these exact bytes is immutable: a cached copy
// can never be the wrong one, and a visitor pays for the solver once rather
// than once per challenge.
//
// Every other spelling of the URL gets the same bytes with no-store, and that
// asymmetry is the whole point. Serving the current solver under an address
// that does not name it, with a year-long immutable policy, lets anyone prime a
// shared cache with today's bundle under the digest a future release will use;
// after the upgrade the wait page asks for that digest and the cache answers
// with the old solver for a year. Refusing outright would be safe too, but it
// would also wall the browser that loaded a wait page seconds before a deploy
// and asks for the previous digest — so that request is answered, just never
// stored.
func (g *Gate) serveSolver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	if r.URL.Path == g.solverURL && r.URL.RawQuery == "" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		noStore(w)
	}
	w.Write(g.solverJS)
}

// serveRenew hands out the script injected into proxied pages. Cacheable for a
// few minutes, unlike the gate's other responses: it is a static asset that does
// not vary per visitor, and it is requested on every navigation, so making the
// browser refetch it each time would tax exactly the pages injection exists to
// keep fast.
func (g *Gate) serveRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=300")
	w.Write(renewJS)
}

// serveUninstall is the kill switch: a page that unregisters the worker. A
// worker outlives the software that installed it, so removing Anteroom without
// this would leave browsers polling dead endpoints indefinitely. The worker also
// self-unregisters when it sees this endpoint's marker disappear (see sw.js).
func (g *Gate) serveUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		noStore(w)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Write(uninstallHTML)
}
