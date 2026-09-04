package gate

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/payment"
	"github.com/radiustechsystems/anteroom/internal/token"
)

// The pay door. The free path never reaches any of this: proof-of-work
// admission makes no external call, so a facilitator having a bad day cannot
// affect a human solving a puzzle. That is invariant 2, and it is the reason a
// facilitator outage is never a site outage.

// The egress breaker's dial. Named rather than written inline at the call site
// because Retry-After is derived from the cooldown and has to agree with it: a
// gate that tells a client to come back before it will try again sends every one
// of them back into a closed door, and they arrive together when it opens. A
// test that asserts Retry-After has to read the same constant, or it is checking
// a number someone typed twice.
const (
	breakerThreshold = 3
	breakerWindow    = 30 * time.Second
	breakerCooldown  = 30 * time.Second
)

func paidExpiry(now time.Time, ttl time.Duration) time.Time {
	exp := now.Add(ttl)
	if exp.Nanosecond() == 0 {
		return exp
	}
	return exp.Truncate(time.Second).Add(time.Second)
}

// matchRoute finds the pricing rule covering a path. Rules are evaluated in
// configured order and the first path match wins, so an operator can put a
// narrow expensive rule above a broad cheap one.
func (g *Gate) matchRoute(path string) (*paidRoute, bool) {
	for i := range g.routes {
		if g.routes[i].matcher.Path(path) {
			return &g.routes[i], true
		}
	}
	return nil, false
}

// offer builds the PaymentRequired document for a rule: one accepts[] entry per
// configured rail.
//
// Ordering is a pricing decision, not an implementation detail. A client filters
// accepts[] down to the networks its wallet registered and pays the first
// survivor, so configured order is preserved exactly.
func (g *Gate) offer(r *config.Rule, req *http.Request, errMsg string) payment.Required {
	p := g.cfg.Payments
	accepts := make([]payment.Requirements, 0, len(p.Rails))
	for i := range p.Rails {
		rail := &p.Rails[i]
		amount, ok := r.PriceAtomic[rail.Network]
		if !ok {
			continue // resolved at config load; a missing entry is a config bug
		}
		payTo := rail.PayTo
		if payTo == "" {
			payTo = p.PayTo
		}
		extra := map[string]any{
			// The TOKEN's EIP-712 domain, not ours. A client cannot construct
			// the transfer signature without these, and the config refuses to
			// start without them for exactly that reason.
			"name":                rail.AssetName,
			"version":             rail.AssetVersion,
			"assetTransferMethod": rail.AssetTransferMethod,
		}
		accepts = append(accepts, payment.Requirements{
			Scheme:            "exact",
			Network:           rail.Network,
			Asset:             rail.Asset,
			Amount:            amount.String(),
			PayTo:             payTo,
			MaxTimeoutSeconds: p.MaxTimeoutSeconds,
			Extra:             extra,
		})
	}

	desc := p.ResourceDescription
	if desc == "" {
		desc = "Admission pass for protected content"
	}
	return payment.Required{
		X402Version: payment.Version,
		Error:       errMsg,
		Resource: &payment.Resource{
			URL:         g.resourceURL(req),
			Description: desc,
		},
		Accepts: accepts,
		// Display values and the free alternative go under a vendor-namespaced
		// key, never in `extra`: facilitators validate `extra` per scheme and
		// may reject keys they do not know.
		//
		// The {info, schema} wrapper is the specification's shape, not a
		// flourish. An extension value is required to carry both, so a client
		// validating the document strictly rejects a bare object — and a client
		// that has never heard of this extension can still find out what the
		// fields mean without reading our documentation.
		//
		// The schema travels BY REFERENCE — a one-line JSON Schema whose $ref
		// points at the gate's own static copy — not inline. Inlined it was
		// 1.2KB of self-description in every offer, and the offer rides in the
		// PAYMENT-REQUIRED header, which has a hard external budget: nginx's
		// default proxy_buffer_size is 4KB for the ENTIRE response header
		// block, and the inline schema plus two rails was measured blowing it —
		// every machine 402 through a default nginx became a 502. A $ref is
		// still a valid JSON Schema, so strict {info, schema} validation holds;
		// a client that wants the field semantics fetches a cacheable URL once.
		Extensions: map[string]any{
			extensionKey: map[string]any{
				"info": map[string]any{
					"price":          r.Price,
					"scope":          r.Name,
					"paidTtlSeconds": int(r.PaidTTL.D().Seconds()),
					"presentation": map[string]any{
						"methods":       []string{http.MethodGet, http.MethodHead},
						"result":        "admission-pass",
						"retryOriginal": true,
					},
					"prerequisites": prerequisites(p.Rails),
					"rails":         railDisplay(p.Rails),
					"freeAlternative": map[string]any{
						"kind":         "proof-of-work",
						"challengeUrl": pathChallenge,
						"answerUrl":    pathAnswer,
						"instructions": pathInstructions,
					},
				},
				"schema": map[string]any{"$ref": g.absoluteURL(req, pathSchema)},
			},
		},
	}
}

// extensionKey is Anteroom's extension identifier, vendor-namespaced because
// the registry it would otherwise collide with is everyone else's.
const extensionKey = "dev.anteroom"

// extensionSchema describes the `info` object above. Hand-written rather than
// generated on purpose: it is small, it is part of the wire contract, and a
// reader comparing it to the object beside it should be able to do so at a
// glance. It is served at pathSchema and reached from every offer through the
// schema $ref — never inlined into the offer itself; see the wrapper comment
// in offer() for the header-budget arithmetic behind that.
func extensionSchema() map[string]any {
	str := map[string]any{"type": "string"}
	obj := map[string]any{"type": "object"}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"price": map[string]any{
				"type": "string", "description": "display price, e.g. $0.01",
			},
			"scope": map[string]any{
				"type": "string", "description": "display name of the matched pricing rule; the server binds the pass to its compiled path scope",
			},
			"paidTtlSeconds": map[string]any{
				"type": "integer", "description": "how long that admission pass lives (at least one second)",
			},
			"presentation": map[string]any{
				"type":        "object",
				"description": "non-standard admission-capability contract: present on GET/HEAD, then retry the original operation with the cookie",
				"properties": map[string]any{
					"methods": map[string]any{"type": "array", "items": str},
					"result":  str, "retryOriginal": map[string]any{"type": "boolean"},
				},
			},
			"prerequisites": map[string]any{
				"type": "array", "items": obj,
				"description": "one-time on-chain steps a payer must complete first",
			},
			"rails": map[string]any{
				"type": "array", "items": obj,
				"description": "display data the protocol object omits: decimals, RPC endpoint",
			},
			"freeAlternative": map[string]any{
				"type":        "object",
				"description": "the way in that costs nothing",
				"properties": map[string]any{
					"kind": str, "challengeUrl": str, "answerUrl": str, "instructions": str,
				},
			},
		},
		"required": []string{"price", "scope", "paidTtlSeconds", "presentation", "freeAlternative"},
	}
}

// resourceURL names what the client asked for. `resource` is required by the
// specification even though the reference Go struct tags it omitempty.
//
// The query string is deliberately not included. This URL is quoted back by the
// client inside its payment payload, and that payload is forwarded verbatim to
// the facilitator — a third party in the payment, not in the application — so
// anything in the query travels with it. Queries are where session tokens,
// search terms, document identifiers and customer references live, and none of
// that is any of a payment processor's business. Pricing is decided by path
// match, so the query is not needed to identify what is being sold either.
func (g *Gate) resourceURL(r *http.Request) string {
	return g.absoluteURL(r, r.URL.EscapedPath())
}

// absoluteURL renders a path as an absolute URL at the request's own origin.
// The offer travels off-origin — quoted into payment payloads, forwarded to
// facilitators — so a relative reference inside it would have nothing to be
// relative to.
func (g *Gate) absoluteURL(r *http.Request, p string) string {
	scheme := "http"
	if g.requestIsTLS(r) {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "unknown"
	}
	return scheme + "://" + host + p
}

// servePaymentRequired emits a 402 — or the 200 variant for measured 2xx-only
// agents. The PAYMENT-REQUIRED header goes on every one of them, always.
//
// A bare 402 is a bug, not a lenient response: conformant clients exist that
// read only the header and have no body fallback at all, and at least one reads
// "402 without the header" as "free tier, retry unchanged", which turns a
// malformed response into a retry loop.
func (g *Gate) servePaymentRequired(w http.ResponseWriter, r *http.Request,
	rule *config.Rule, errMsg string, retryAfter time.Duration) {

	doc := g.offer(rule, r, errMsg)
	noStore(w)

	if enc, err := doc.Encode(); err == nil {
		w.Header().Set(payment.HeaderRequired, enc)
	} else {
		g.lg.ErrorContext(r.Context(), "encoding the payment offer", "err", err)
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(retryAfter.Seconds())))
	}

	status := http.StatusPaymentRequired
	if g.okBodyAgent(r) {
		// Some configured clients discard non-2xx bodies; 200 keeps the
		// instructions visible while the payment header remains authoritative.
		status = http.StatusOK
	}

	if g.cfg.Triage.JSONAccept && wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(doc)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, g.payMarkdown(doc, rule))
}

// servePaymentPending answers a settlement that was broadcast but not
// confirmed. It is the one payment outcome that must NOT carry a price.
//
// A fresh PAYMENT-REQUIRED here is an instruction to sign again, and an
// automated payer will follow it: the first transfer may confirm a second later
// and the second is then a duplicate charge for one resource. So the offer is
// omitted deliberately — the only correct next action is to reconcile the
// transaction the facilitator already broadcast and re-present the SAME
// authorization, which settle idempotency answers without moving money twice.
//
// The settlement result goes back in PAYMENT-RESPONSE, exactly as the
// specification says protocol information travels, so a client that parses
// headers gets the transaction and network without reading prose.
func (g *Gate) servePaymentPending(w http.ResponseWriter, r *http.Request, res payment.Result) {
	noStore(w)
	if enc, err := json.Marshal(payment.SettleResponse{
		Success:     false,
		ErrorReason: payment.ErrorSettlementPending,
		Payer:       res.Payer,
		Transaction: res.Tx,
		Network:     res.Network,
	}); err == nil {
		w.Header().Set(payment.HeaderResponse, b64Std(enc))
	} else {
		g.lg.ErrorContext(r.Context(), "encoding the pending settlement receipt", "err", err)
	}
	retry := res.RetryAfter
	if retry < time.Second {
		retry = 5 * time.Second
	}
	w.Header().Set("Retry-After", fmt.Sprint(int(retry.Seconds())))

	status := http.StatusPaymentRequired
	if g.okBodyAgent(r) {
		status = http.StatusOK
	}
	if g.cfg.Triage.JSONAccept && wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"x402Version": payment.Version,
			"error":       payment.ErrorSettlementPending,
			"settlement": map[string]any{
				"transaction": res.Tx,
				"network":     res.Network,
				"payer":       res.Payer,
				"status":      "broadcast, confirmation unknown",
			},
			"next": "do NOT sign a new payment; check the transaction on chain, then " +
				"re-present the SAME PAYMENT-SIGNATURE",
		})
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(status)
	var b strings.Builder
	b.WriteString("# Payment settlement pending\n\n")
	b.WriteString("Your payment was broadcast. Its confirmation could not be established yet, so\n")
	b.WriteString("this resource is not being served — but **you may already have been charged**.\n\n")
	fmt.Fprintf(&b, "- transaction: `%s`\n", res.Tx)
	if res.Network != "" {
		fmt.Fprintf(&b, "- network: `%s`\n", res.Network)
	}
	if res.Payer != "" {
		fmt.Fprintf(&b, "- payer: `%s`\n", res.Payer)
	}
	b.WriteString("\n## What to do\n\n")
	b.WriteString("**Do not sign a new payment.** Signing again risks paying twice for one\n")
	b.WriteString("resource: the transaction above may confirm at any moment.\n\n")
	fmt.Fprintf(&b, "1. Check the transaction on `%s`.\n", cmp.Or(res.Network, "the network you paid on"))
	b.WriteString("2. If it confirmed, retry this request with the **same** `PAYMENT-SIGNATURE`.\n")
	b.WriteString("   Its token authorization cannot transfer the amount twice, but x402 does not\n")
	b.WriteString("   require every facilitator to cache a successful settlement response.\n")
	b.WriteString("3. If it failed on chain, sign a fresh payment — the original was never spent.\n\n")
	b.WriteString("The free proof-of-work door is open either way and costs nothing:\n")
	fmt.Fprintf(&b, "see `%s`.\n", pathInstructions)
	io.WriteString(w, b.String())
}

// payMarkdown is the instruction sheet for an agent that cannot parse the
// header — which is most of them, and which is why the body earns its place
// even in a header-canonical protocol. An agent's first naive request is
// usually `curl https://site/thing` with no -i, so the header is invisible to
// whatever it actually captured.
func (g *Gate) payMarkdown(doc payment.Required, rule *config.Rule) string {
	var b strings.Builder
	b.WriteString("# Payment required\n\n")
	b.WriteString("This resource is behind Anteroom, a self-hosted gate. There are two ways in and\n")
	b.WriteString("**both are open to you**: pay the price below, or solve a free puzzle.\n\n")

	// The human answer goes first as well as last. Someone who curls a URL and
	// gets a wall of payment JSON should not have to read to the end to find out
	// that opening it in a browser costs nothing — and an agent deciding whether
	// to spend money on an unfamiliar address should meet the free option before
	// the price, not after it.
	b.WriteString("**If a person sent you here:** open this URL in a normal browser. The check runs\n")
	b.WriteString("automatically, costs nothing, and takes about a second. Nothing below is needed.\n\n")

	fmt.Fprintf(&b, "## Option 1 — pay %s (x402)\n\n", rule.Price)
	b.WriteString("Sign an x402 `exact` payment against one of the rails below, then present it\n")
	b.WriteString("on a GET or HEAD request for this URL. The response sets an admission cookie;\n")
	b.WriteString("send the original request with that cookie and without `PAYMENT-SIGNATURE`.\n\n")
	b.WriteString("The same document is in the `PAYMENT-REQUIRED` response header, base64-encoded.\n\n")

	if enc, err := json.MarshalIndent(doc, "", "  "); err == nil {
		b.WriteString("```json\n")
		b.Write(enc)
		b.WriteString("\n```\n\n")
	}

	b.WriteString("Amounts are atomic units: divide by the asset's decimals for a display value.\n")
	b.WriteString("`extra.name` and `extra.version` are the **token contract's** EIP-712 domain and\n")
	b.WriteString("are required to construct the signature.\n\n")

	b.WriteString(permit2Section(g.cfg.Payments.Rails, rule))

	b.WriteString("## Option 2 — solve the puzzle, free\n\n")
	b.WriteString("No payment, no account, no key. This is the right default for an unattended\n")
	b.WriteString("agent that should not be spending money on an unfamiliar address:\n\n")
	fmt.Fprintf(&b, "1. `GET %s` → JSON `{challenge, threshold, deadline_unix_ms}`.\n", pathChallenge)
	b.WriteString("2. Find a nonce whose SHA-256 digest of `challenge + nonce`, compared as bytes,\n")
	b.WriteString("   sorts strictly below `threshold`.\n")
	fmt.Fprintf(&b, "3. `POST %s` with `{\"challenge\": ..., \"nonce\": ...}`.\n", pathAnswer)
	fmt.Fprintf(&b, "4. Retry with the `%s` cookie the answer sets.\n\n", cookieName)
	fmt.Fprintf(&b, "Full instructions: `%s`\n\n", pathInstructions)

	b.WriteString("## If a human sent you\n\n")
	b.WriteString("Open the URL in a normal browser. The puzzle runs automatically, costs nothing,\n")
	b.WriteString("and takes about a second.\n")
	return b.String()
}

// servePayment handles a presented PAYMENT-SIGNATURE. It returns the ladder
// decision for logging.
//
// The ordering here is the security design, and every step before the facilitator
// call is there so that a garbage header costs the gate nothing: decode,
// structural match against the rule's own requirements, single-use pre-check,
// then rate limit, and only then egress.
func (g *Gate) servePayment(w http.ResponseWriter, r *http.Request, route *paidRoute, header string) decision {
	rule := &route.rule
	// Settlement acquires an admission capability; it does not execute an
	// application operation. Coupling settlement to POST/PATCH/etc. creates an
	// impossible retry contract: a lost response cannot tell the client whether
	// the payment, the upstream mutation, both, or neither happened. Require a
	// safe admission request first, then let the resulting pass authorize the
	// original method through the ordinary proxy path.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		g.servePaymentRequired(w, r, rule,
			"present payments on GET or HEAD to acquire a pass, then retry the original request with the pass cookie", 0)
		return decisionPayMethodRefused
	}
	if isUpgradeRequest(r) {
		g.servePaymentRequired(w, r, rule,
			"payments cannot be presented on protocol-upgrade requests", 0)
		return decisionPayUpgradeRefused
	}
	p, err := payment.DecodePayload(header)
	if err != nil {
		g.lg.DebugContext(r.Context(), "malformed payment presentation", "err", err)
		g.servePaymentRequired(w, r, rule, "PAYMENT-SIGNATURE could not be decoded", 0)
		return decisionPayMalformed
	}

	doc := g.offer(rule, r, "")
	req, err := payment.MatchRail(p, doc.Accepts)
	if err != nil {
		// The gate never offered this rail. Refused locally, no egress.
		g.lg.DebugContext(r.Context(), "payment presented on an unoffered rail",
			"network", p.Network(), "scheme", p.Scheme())
		g.servePaymentRequired(w, r,
			rule, "payment presented on a network or scheme this resource does not accept", 0)
		return decisionPayUnoffered
	}

	// A payment the gate cannot name is a payment it cannot deduplicate, and
	// the honest answer is to refuse it before any egress rather than invent a
	// per-presentation identity that would let one authorization be spent twice.
	// req is the gate's OWN requirements object for the matched rail, not the
	// client's echo of it, so the transfer method that selects which
	// authorization identifies this payment cannot be chosen by the payer.
	id, err := payment.ID(p, req)
	if err != nil {
		g.lg.DebugContext(r.Context(), "payment presentation could not be identified", "err", err)
		g.servePaymentRequired(w, r, rule,
			"the authorization in this payment names no payer and nonce to identify it by", 0)
		return decisionPayUnidentified
	}

	state, lease, prior, err := g.grants.Begin(id)
	if err != nil {
		g.lg.ErrorContext(r.Context(), "payment state unavailable", "pay_id", id[:16], "err", err)
		g.servePaymentRequired(w, r, rule,
			"payment recovery state is temporarily unavailable; retry the same payment", 5*time.Second)
		return decisionPayStateUnavailable
	}
	switch state {
	case payment.BeginRecoverable:
		if prior.Scope != route.scope || prior.Audience != requestAudience(r) {
			g.servePaymentRequired(w, r, rule,
				"this payment has already been used for another resource", 0)
			return decisionPayReplay
		}
		return g.servePaidGrant(w, r, rule, id, prior, true)
	case payment.BeginSpent:
		g.lg.DebugContext(r.Context(), "payment entitlement expired", "pay_id", id[:16])
		g.servePaymentRequired(w, r, rule,
			"this payment has already been used; sign a fresh one", 0)
		return decisionPayReplay
	case payment.BeginInFlight:
		g.servePaymentRequired(w, r, rule,
			"this payment is already being processed; retry the same payment", 2*time.Second)
		return decisionPayInflight
	}
	defer func() {
		if err := g.grants.Release(id, lease); err != nil {
			g.lg.ErrorContext(r.Context(), "releasing payment reservation", "pay_id", id[:16], "err", err)
		}
	}()

	// Rate limit before any egress: a bogus header must not purchase a
	// facilitator round trip.
	//
	// An unresolvable client address shares one bucket rather than skipping the
	// limit. Failing open on the defence that exists to stop free egress is the
	// wrong direction (invariant 3), and the shared bucket costs nothing in
	// practice: the gate listens on TCP, so every real request has a parseable
	// peer and lands in its own bucket.
	limitKey := "unresolved-client"
	if ip, ipErr := g.match.ClientIP(r); ipErr == nil {
		limitKey = ip.String()
	}
	if !g.payLimit.Allow(limitKey) {
		g.lg.WarnContext(r.Context(), "payment presentation rate limited", "client", limitKey)
		g.servePaymentRequired(w, r, rule,
			"too many payment attempts; slow down and retry", 10*time.Second)
		return decisionPayRateLimited
	}

	v := g.verifierFor(req.Network)
	if v == nil {
		// Impossible by construction — every offered rail got a verifier at
		// New() and MatchRail only returns offered rails — so reaching this is
		// a gate bug, not a payment problem. Still 402, never 500: the free
		// door remains the honest answer while the bug is fixed.
		g.lg.ErrorContext(r.Context(), "no verifier for an offered rail — gate construction bug", "network", req.Network)
		g.servePaymentRequired(w, r, rule,
			"the gate cannot reach a settlement service right now; retry shortly or use the free challenge", 5*time.Second)
		return decisionPayInfra
	}
	res := v.Verify(r.Context(), p, req)

	switch res.Verdict {
	case payment.Valid:
		exp := paidExpiry(g.now(), rule.PaidTTL.D())
		grant, _, err := g.grants.Commit(id, lease, payment.Grant{
			Scope:       route.scope,
			Audience:    requestAudience(r),
			Payer:       res.Payer,
			Transaction: res.Tx,
			Amount:      res.Amount,
			Network:     req.Network,
			ExpiresAt:   exp.Unix(),
		})
		if err != nil {
			g.lg.ErrorContext(r.Context(), "persisting a settled payment grant", "pay_id", id, "err", err)
			g.servePaymentRequired(w, r, rule, ambiguousGrantFailure, 2*time.Second)
			return decisionPayGrantFailed
		}
		if grant.Scope != route.scope || grant.Audience != requestAudience(r) {
			g.lg.ErrorContext(r.Context(), "settled payment raced with a different durable grant", "pay_id", id)
			g.servePaymentRequired(w, r, rule, ambiguousGrantFailure, 2*time.Second)
			return decisionPayGrantConflict
		}
		g.countPaidValue(r.Context(), grant.Amount, req.Network, rule)
		return g.servePaidGrant(w, r, rule, id, grant, false)

	case payment.Invalid:
		reason := res.Reason
		if reason == "" {
			reason = "payment rejected"
		}
		g.lg.WarnContext(r.Context(), "payment rejected by the facilitator",
			"reason", reason, "payer", res.Payer, "scope", rule.Name)
		g.servePaymentRequired(w, r, rule, reason, 0)
		return decisionPayRejected

	case payment.Pending:
		// Broadcast, confirmation unknown. Nothing is claimed, so the payer's
		// own re-presentation of the identical payload is still the recovery
		// path — but unlike an ambiguous settle there is a transaction to name,
		// and naming it is the difference between "reconcile this" and "pay
		// again".
		g.lg.WarnContext(r.Context(), "settlement pending — the payer holds a broadcast transaction",
			"pay_id", id[:16], "tx", res.Tx, "network", res.Network,
			"payer", res.Payer, "scope", rule.Name)
		g.servePaymentPending(w, r, res)
		return decisionPayPending

	case payment.Ambiguous:
		retry := res.RetryAfter
		if retry < 2*time.Second {
			retry = 2 * time.Second
		}
		// Serve nothing, claim nothing. The payer's own retry is the recovery
		// path, and the payment ID is quotable because both sides can compute it.
		g.lg.ErrorContext(r.Context(), "settle ambiguous — reconcile against the facilitator or chain",
			"pay_id", id, "payer", res.Payer, "scope", rule.Name, "err", res.Err)
		g.servePaymentRequired(w, r, rule, res.Reason, retry)
		return decisionPayAmbiguous

	default: // Indeterminate
		g.lg.WarnContext(r.Context(), "facilitator unavailable; payments degraded, free path unaffected",
			"err", res.Err, "scope", rule.Name)
		// Tell the client how long the gate will actually refuse to try. Advising
		// a retry sooner guarantees a wasted round trip, and synchronises every
		// client's retry onto the moment the door reopens.
		retry := res.RetryAfter
		if retry < 5*time.Second {
			retry = 5 * time.Second
		}
		// 402, never 503. A 503 would claim the site is down, which is false —
		// the free door works. A bare challenge would strand the agent.
		g.servePaymentRequired(w, r, rule, res.Reason, retry)
		return decisionPayInfra
	}
}

// servePaidGrant turns one durable settlement record into a pass and a proxied
// response. Fresh settlement and retry recovery deliberately share this path:
// once the record exists, neither facilitator state nor process history changes
// the entitlement it represents.
func (g *Gate) servePaidGrant(w http.ResponseWriter, r *http.Request, rule *config.Rule,
	id string, grant payment.Grant, recovered bool,
) decision {
	exp := time.Unix(grant.ExpiresAt, 0)
	if !g.now().Before(exp) {
		g.servePaymentRequired(w, r, rule,
			"this payment's access period has expired; sign a fresh one", 0)
		return decisionPayReplay
	}
	if err := g.setPassCookie(w, r, token.Pass{
		Kind:  token.KindPaid,
		Scope: grant.Scope,
		Payer: g.settlementField(r.Context(), "payer", grant.Payer),
		Tx:    g.settlementField(r.Context(), "tx", grant.Transaction),
	}, exp, time.Time{}); err != nil {
		g.lg.ErrorContext(r.Context(), "minting a durable paid pass", "pay_id", id, "err", err)
		g.servePaymentRequired(w, r, rule, ambiguousGrantFailure, 2*time.Second)
		return decisionPayGrantFailed
	}
	g.met.minted.With("paid").Inc()

	message := "payment settled"
	if recovered {
		message = "payment grant recovered"
	}
	g.lg.InfoContext(r.Context(), message,
		"pay_id", id[:16], "scope", rule.Name, "payer", grant.Payer,
		"tx", grant.Transaction, "amount", grant.Amount, "network", grant.Network)

	enc, _ := json.Marshal(payment.SettleResponse{
		Success: true, Payer: grant.Payer, Transaction: grant.Transaction,
		Network: grant.Network, Amount: grant.Amount,
	})
	r.Header.Set("X-Anteroom-Status", "pass-paid")
	g.stripPassCookie(r)
	// The gate consumed PAYMENT-SIGNATURE. Forwarding it could make upstream
	// x402 middleware settle it again and would leak a signed instrument to
	// every other upstream.
	r.Header.Del(payment.HeaderSignature)
	// paidWriter applies the final no-store seal after upstream headers arrive.
	g.forward(&paidWriter{ResponseWriter: w, settle: b64Std(enc)}, r)
	return decisionPassPaid
}

// countPaidValue records a fresh settlement's value, normalized from the
// rail's atomic units to millionths of the display currency so one counter can
// aggregate rails with different decimals. The facilitator-reported amount is
// preferred (Verify already refused any mismatch); when x402's optional amount
// is absent, the rail's asking price is what the facilitator settled against.
func (g *Gate) countPaidValue(ctx context.Context, amount, network string, rule *config.Rule) {
	atomic, ok := new(big.Int).SetString(amount, 10)
	if !ok || atomic.Sign() < 0 {
		atomic = rule.PriceAtomic[network]
	}
	if atomic == nil {
		return
	}
	decimals := 6
	for i := range g.cfg.Payments.Rails {
		if g.cfg.Payments.Rails[i].Network == network {
			decimals = g.cfg.Payments.Rails[i].Decimals
			break
		}
	}
	micros := new(big.Int).Mul(atomic, big.NewInt(1_000_000))
	micros.Quo(micros, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil))
	if !micros.IsUint64() {
		g.lg.WarnContext(ctx, "settled payment value overflows the metric; not counted",
			"amount", amount, "network", network)
		return
	}
	g.met.paidValue.Add(micros.Uint64())
}

const ambiguousGrantFailure = "payment settled but the pass could not be issued; " +
	"retry with the SAME PAYMENT-SIGNATURE inside its validity window"

// maxSettlementField bounds a facilitator-supplied value on its way into a
// signed cookie. An EVM transaction hash is 66 characters and a base58 Solana
// signature 88; anything past this is not an identifier the gate can use.
const maxSettlementField = 128

// settlementField admits a facilitator-supplied identifier into the pass, or
// drops it.
//
// The facilitator is trusted to settle, not to bound its own response: an
// oversized value here becomes an oversized Set-Cookie the client silently
// discards, which would turn a successful payment into no pass at all. Dropping
// it costs the audit trail for that grant and nothing else, and a TRUNCATED
// hash would be worse than an absent one — it looks like evidence and matches
// no transaction.
func (g *Gate) settlementField(ctx context.Context, name, v string) string {
	if len(v) <= maxSettlementField {
		return v
	}
	g.lg.WarnContext(ctx, "facilitator returned an oversized settlement field; omitting it from the pass",
		"field", name, "bytes", len(v), "cap", maxSettlementField,
		"consequence", "this grant is not traceable from its pass; the settlement log line still has it")
	return ""
}

// paidWriter is invariant 6 enforced where it can actually hold: on the way out,
// after the upstream's own headers have been merged in.
//
// It also re-states the gate's PAYMENT-RESPONSE. That header is the gate's
// receipt for the settlement the gate performed; an upstream copy appended after
// ours would tell an x402 client about a settlement nobody made, and which of
// the two field lines a client reads is a coin flip.
type paidWriter struct {
	http.ResponseWriter
	settle      string
	sealed      bool
	passCookies []string
}

// seal is idempotent and runs before any byte of the response reaches the wire.
func (p *paidWriter) seal() {
	if p.sealed {
		return
	}
	p.sealed = true
	h := p.Header()
	for _, cookie := range p.passCookies {
		h.Add("Set-Cookie", cookie)
	}
	h.Set("Cache-Control", "no-store, private")
	h.Set("Pragma", "no-cache")
	h.Del("Expires")
	if p.settle != "" {
		h.Set(payment.HeaderResponse, p.settle)
	} else {
		h.Del(payment.HeaderResponse)
	}
	// On a paid path the gate is the payment authority, so it authors the whole
	// protocol namespace. An upstream PAYMENT-REQUIRED riding out on a response
	// the gate already collected for is an offer with somebody else's payTo,
	// arriving with the gate's authority behind it.
	h.Del(payment.HeaderRequired)
}

func (p *paidWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		p.holdPassCookies()
		p.ResponseWriter.WriteHeader(status)
		return
	}
	p.seal()
	p.ResponseWriter.WriteHeader(status)
}

// holdPassCookies keeps a grant out of an informational response and restores
// it on the final response. ReverseProxy clears the shared header map after
// each 1xx response.
func (p *paidWriter) holdPassCookies() {
	h := p.Header()
	values := h.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, value := range values {
		name, _, ok := strings.Cut(value, "=")
		if ok && strings.TrimSpace(name) == cookieName {
			p.passCookies = append(p.passCookies, value)
			continue
		}
		h.Add("Set-Cookie", value)
	}
}

// Write covers the handler that writes a body without calling WriteHeader,
// which is an implicit 200 and would otherwise flush unsealed headers.
func (p *paidWriter) Write(b []byte) (int, error) {
	p.seal()
	return p.ResponseWriter.Write(b)
}

// Flush and Unwrap keep streaming, hijacking and deadlines reachable: a wrapper
// that swallowed them would break server-sent events and WebSockets on exactly
// the responses someone paid for.
func (p *paidWriter) Flush() {
	if f, ok := p.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *paidWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

// paymentsEnabled reports whether the pay door is configured.
func (g *Gate) paymentsEnabled() bool {
	return g.cfg.Payments != nil && len(g.verifiers) > 0
}

// verifierFor resolves the verifier for the rail MatchRail chose. req.Network
// is the GATE's own requirements field for that rail — never a client echo —
// so the client selects which offered rail to pay on, and nothing more: which
// facilitator is called stays entirely the operator's decision.
func (g *Gate) verifierFor(network string) payment.Verifier {
	return g.verifiers[network]
}

// b64Std encodes a gate-authored header payload: base64, standard alphabet,
// padded, matching what the specification says these headers carry.
func b64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// permit2Address is the canonical Permit2 contract. It is the same address on
// every chain — Permit2 is deployed with CREATE2 from a fixed salt — so it is a
// constant rather than a config key.
const permit2Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

// usesPermit2 reports whether any offered rail settles through Permit2.
func usesPermit2(rails []config.Rail) bool {
	for _, r := range rails {
		if r.AssetTransferMethod == "permit2" {
			return true
		}
	}
	return false
}

// prerequisites describes, machine-readably, what a payer must have done before
// a payment on these rails can succeed.
//
// This exists because the failure it prevents is undiagnosable from the wire: a
// payer with a funded wallet and a correctly signed authorization is rejected
// with a bare reason like "invalid_transaction_state", which names neither the
// cause nor the fix. Telling them up front costs one field.
func prerequisites(rails []config.Rail) []map[string]any {
	if !usesPermit2(rails) {
		return nil
	}
	tokens := make([]string, 0, len(rails))
	for _, r := range rails {
		if r.AssetTransferMethod == "permit2" {
			tokens = append(tokens, r.Asset)
		}
	}
	return []map[string]any{{
		"kind":    "erc20-approval",
		"reason":  "permit2 transfers require a one-time ERC-20 approval of the Permit2 contract",
		"spender": permit2Address,
		"tokens":  tokens,
		"oneTime": true,
		"symptom": "an otherwise valid payment is rejected by the facilitator",
	}}
}

// railDisplay carries what the protocol object leaves out. PaymentRequirements
// is machine-complete and human-incomplete: it has an atomic `amount` and a
// contract address, and nothing that says how many decimals that asset has or
// where to reach the chain. A client that must show a confirmation prompt — or
// an agent that wants to sanity-check whether it is about to spend one cent or
// ten thousand dollars — otherwise has to hardcode a table.
func railDisplay(rails []config.Rail) []map[string]any {
	out := make([]map[string]any, 0, len(rails))
	for _, r := range rails {
		d := map[string]any{
			"network":             r.Network,
			"asset":               r.Asset,
			"assetDecimals":       r.Decimals,
			"assetTransferMethod": r.AssetTransferMethod,
		}
		if r.RPCURL != "" {
			d["rpcUrl"] = r.RPCURL
		}
		out = append(out, d)
	}
	return out
}

// permit2Section is the human- and agent-readable form of the prerequisite.
//
// It names the actual asset and, where the operator configured one, the actual
// RPC endpoint — because a command ending in `--rpc-url <rpc>` leaves the reader
// exactly one unanswered question, and that question turned out to be the most
// expensive part of paying.
func permit2Section(rails []config.Rail, rule *config.Rule) string {
	if !usesPermit2(rails) {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Before your first payment on this rail\n\n")
	b.WriteString("Rails using `assetTransferMethod: \"permit2\"` need a **one-time ERC-20 approval**\n")
	b.WriteString("of the Permit2 contract, per token, per wallet. Without it the facilitator\n")
	b.WriteString("rejects an otherwise perfectly signed payment, and the reason it returns does\n")
	b.WriteString("not say why. A funded wallet is not sufficient.\n\n")
	fmt.Fprintf(&b, "Permit2 is at `%s` on every chain.\n\n", permit2Address)

	for _, r := range rails {
		if r.AssetTransferMethod != "permit2" {
			continue
		}
		rpc := r.RPCURL
		if rpc == "" {
			rpc = "<an RPC endpoint for " + r.Network + ">"
		}
		fmt.Fprintf(&b, "For `%s` on `%s`:\n\n", r.Asset, r.Network)
		b.WriteString("```sh\n")
		b.WriteString("# Already approved? A result at or above your budget means you are done.\n")
		fmt.Fprintf(&b, "cast call %s \\\n  \"allowance(address,address)(uint256)\" $YOUR_ADDRESS %s \\\n  --rpc-url %s\n\n",
			r.Asset, permit2Address, rpc)
		fmt.Fprintf(&b, "# Approve a budget — %s here, which is %d requests at this price.\n",
			approvalBudget(rule, r.Network), approvalMultiple)
		fmt.Fprintf(&b, "cast send %s \\\n  \"approve(address,uint256)\" %s %s \\\n  --rpc-url %s --interactive\n",
			r.Asset, permit2Address, approvalBudget(rule, r.Network), rpc)
		b.WriteString("```\n\n")
	}

	b.WriteString("Two things about that command are deliberate. `--interactive` prompts for the\n")
	b.WriteString("key instead of taking `--private-key`, which puts it in the process argument\n")
	b.WriteString("list where any other account on the machine can read it. And the amount is a\n")
	b.WriteString("budget rather than the usual `0xffff…ff`: an allowance is standing permission,\n")
	b.WriteString("so whatever is left of it can be moved at any time in the future. Approve what\n")
	b.WriteString("you mean to spend, and re-approve when it runs out.\n\n")
	b.WriteString("Budget for gas too: the approval is an ordinary transaction and costs gas, which\n")
	b.WriteString("on a stablecoin-fee chain comes out of the same token you are paying with — in\n")
	b.WriteString("practice roughly the price of one payment. Every payment afterwards needs no\n")
	b.WriteString("on-chain step from you at all.\n\n")
	return b.String()
}

// approvalMultiple is how many requests at the offered price the suggested
// approval covers. Big enough that a paying client is not re-approving all day,
// small enough that a forgotten allowance is a bounded loss.
const approvalMultiple = 100

// approvalBudget renders the suggested allowance in atomic units for one rail.
// A price the gate cannot resolve for that rail yields the price of nothing, so
// the fallback names the unit rather than inventing a number.
func approvalBudget(rule *config.Rule, network string) string {
	if rule != nil {
		if price, ok := rule.PriceAtomic[network]; ok && price != nil {
			return new(big.Int).Mul(price, big.NewInt(approvalMultiple)).String()
		}
	}
	return "<the amount you intend to spend, in atomic units>"
}
