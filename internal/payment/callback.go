package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// These budgets are code constants because they bound protocol operations, not
// operator preferences.
const (
	// verifyBudget: a signature check is tens of milliseconds honestly.
	verifyBudget = 2 * time.Second
	// verifyAttempts: at most two, and only for connection-class errors where
	// no bytes were sent.
	verifyAttempts = 2
	// settleBudget bounds at chain inclusion — about a second on Radius, a few
	// elsewhere. A facilitator that cannot answer in ten seconds is
	// indistinguishable from a dead one, and waiting longer turns its problem
	// into a client-visible hang.
	settleBudget = 10 * time.Second
	// pathBudget bounds the whole paid path.
	pathBudget = 15 * time.Second
	// maxInFlight caps concurrent facilitator calls. Sized for a facilitator
	// answering in tens of milliseconds: at that speed this is far more
	// throughput than a single gate will ever need, and when the facilitator
	// slows down it is the point at which the gate stops queueing and starts
	// telling clients to come back — which is the honest answer anyway.
	//
	// Exported so a test can assert against the actual cap rather than a number
	// transcribed next to it. A test that hardcodes its own copy of a bound is
	// a test that keeps passing after the bound moves.
	maxInFlight = 16
)

// CallbackVerifier is the v0 verifier: it forwards the client's opaque payload
// and the gate's policy-derived requirements to the operator's facilitator.
//
// The client cannot choose the facilitator — there is no field in x402 in which
// to name one, and the gate calls only what its operator configured. That closes
// facilitator substitution by construction. The claim to make is "the client has
// no facilitator choice", never "the server advertises one".
//
// It is NOT a defence against the five-attacks paper's attack IV, whatever the
// symmetry of the names suggests: that attack is a malicious discovery listing
// steering an agent to a malicious resource server before any payment exists,
// and no configuration of the server being chosen against can affect it.
type CallbackVerifier struct {
	base    string
	headers http.Header // extra headers (auth) on every request; values never logged
	http    *http.Client
	lg      *slog.Logger
	breaker *Breaker

	// egress bounds concurrent calls TO THIS FACILITATOR — a gate with N
	// distinct facilitators holds at most N x maxInFlight in flight, which is
	// the isolation the per-rail split exists for: one facilitator having a
	// bad minute must not consume the slots another rail needs. The
	// per-client rate limit does not help here: it is per client, and a slow
	// facilitator turns every distinct client's presentation into fifteen
	// seconds of held goroutine, connection and memory. Without a cap, a
	// facilitator having a bad minute becomes unbounded in-flight work in the
	// gate — which is the failure the free path must never be dragged into.
	egress chan struct{}

	// Budgets, defaulted from the constants above. They are fields rather than
	// constants at the call site only so tests can shrink them: a suite that
	// waits out a real ten-second settle budget to assert one timeout is a
	// suite people stop running.
	verifyBudget time.Duration
	settleBudget time.Duration
	pathBudget   time.Duration
}

// NewCallbackVerifier builds a verifier against a facilitator base URL.
// headers (nil for none) are sent on every request to this facilitator — the
// auth story for hosted facilitators that require an API key. They are cloned,
// applied before the verifier's own protocol headers so those always win, and
// their values are never logged.
func NewCallbackVerifier(base string, headers http.Header, lg *slog.Logger, breaker *Breaker) *CallbackVerifier {
	if lg == nil {
		lg = slog.Default()
	}
	if breaker == nil {
		breaker = NewBreaker(3, 30*time.Second, 30*time.Second)
	}
	return &CallbackVerifier{
		base:         strings.TrimSuffix(base, "/"),
		headers:      headers.Clone(),
		lg:           lg,
		breaker:      breaker,
		egress:       make(chan struct{}, maxInFlight),
		verifyBudget: verifyBudget,
		settleBudget: settleBudget,
		pathBudget:   pathBudget,
		http: &http.Client{
			// No redirects, ever. A 3xx on a POST re-targets the trust anchor
			// and may drop the body; treating it as an infrastructure error
			// whose message names the fix is strictly better than following it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				// Certificate verification is always on and there is no
				// skip-verify flag to turn it off.
			},
		},
	}
}

// Verify runs verify-then-settle and classifies every outcome.
func (c *CallbackVerifier) Verify(ctx context.Context, p Payload, req Requirements) Result {
	auth, err := authorization(p.Payload, req.TransferMethod())
	if err != nil || auth == nil {
		return Result{Verdict: Invalid, Reason: "payment has no valid selected authorization"}
	}
	ctx, cancel := context.WithTimeout(ctx, c.pathBudget)
	defer cancel()

	if c.breaker.Open() {
		return Result{
			Verdict:    Indeterminate,
			Reason:     "payments are temporarily unavailable; you were not charged",
			Err:        errors.New("circuit breaker open"),
			RetryAfter: c.breaker.RetryAfter(),
		}
	}

	// Take an egress slot or give up immediately. Queueing here would be the
	// wrong kindness: the client is already waiting, and joining a queue behind
	// a facilitator that is not answering converts one slow dependency into a
	// pile of held requests.
	select {
	case c.egress <- struct{}{}:
		defer func() { <-c.egress }()
	default:
		c.lg.WarnContext(ctx, "facilitator egress saturated; shedding a payment presentation",
			"in_flight", len(c.egress), "cap", maxInFlight,
			"consequence", "the client is told to retry; the free path is unaffected")
		return Result{
			Verdict:    Indeterminate,
			Reason:     infraReason,
			Err:        errors.New("facilitator egress saturated"),
			RetryAfter: 2 * time.Second,
		}
	}

	// --- verify -------------------------------------------------------------
	var vr VerifyResponse
	res, err := c.call(ctx, "/verify", p, req, c.verifyBudget, verifyAttempts, &vr)
	if err != nil {
		if res.transport {
			if opened := c.breaker.Fail(); opened {
				c.lg.ErrorContext(ctx, "facilitator circuit breaker opened",
					"consequence", "payment presentations skip egress and fall back until it closes",
					"free_path", "unaffected")
			}
		}
		return Result{Verdict: Indeterminate, Reason: infraReason, Err: err,
			RetryAfter: c.breaker.RetryAfter()}
	}

	if !vr.IsValid {
		c.breaker.Succeed() // a definitive answer is a working facilitator
		return Result{Verdict: Invalid, Reason: vr.InvalidReason, Payer: vr.Payer}
	}

	// --- settle -------------------------------------------------------------
	// Exactly one attempt, never retried in flight: a retry after the bytes
	// left is a second settlement request for the same authorization.
	var sr SettleResponse
	res, err = c.call(ctx, "/settle", p, req, c.settleBudget, 1, &sr)
	if err != nil {
		if res.transport {
			if opened := c.breaker.Fail(); opened {
				c.lg.ErrorContext(ctx, "facilitator circuit breaker opened",
					"consequence", "payment presentations skip egress and fall back until it closes")
			}
		}
		// Anything that goes wrong once /settle has left the gate is ambiguous.
		// A facilitator that settled and then crashed mid-response looks exactly
		// like one that never received the request.
		return Result{Verdict: Ambiguous, Reason: ambiguousReason, Err: err,
			RetryAfter: c.breaker.RetryAfter()}
	}
	c.breaker.Succeed()

	if !sr.Success {
		// `settlement_pending` is not a rejection. The specification defines it
		// as non-terminal — the transaction was broadcast and only its
		// confirmation is unknown — and requires the transaction and network to
		// come with it so the caller can reconcile on chain (spec v2 §9).
		// Treating it as Invalid discards the one piece of evidence that exists
		// and answers with a fresh price, which invites a second payment for a
		// transfer that may be about to confirm.
		if sr.ErrorReason == ErrorSettlementPending {
			if sr.Transaction == "" || sr.Network == "" {
				// A facilitator that says pending without saying what was
				// broadcast leaves nothing to reconcile against. That is the
				// ambiguous case, with the same recovery: re-present the
				// identical payload and let settle idempotency answer.
				c.lg.ErrorContext(ctx, "facilitator reported settlement_pending with no transaction",
					"payer", sr.Payer, "network", sr.Network,
					"action", "treating as ambiguous; the payer may retry the identical payload")
				return Result{Verdict: Ambiguous, Reason: ambiguousReason,
					Err: errors.New("settlement_pending carried incomplete transaction evidence")}
			}
			if sr.Network != req.Network {
				return Result{Verdict: Ambiguous, Reason: ambiguousReason,
					Err: fmt.Errorf("pending settlement reported network %q, requested %q", sr.Network, req.Network)}
			}
			c.lg.WarnContext(ctx, "settlement pending — broadcast, confirmation unknown",
				"tx", sr.Transaction, "network", sr.Network, "payer", sr.Payer,
				"action", "no pass minted, payment not claimed; the payer reconciles and re-presents")
			return Result{
				Verdict: Pending, Reason: pendingReason, Payer: sr.Payer,
				Tx: sr.Transaction, Network: sr.Network, RetryAfter: pendingRetryAfter,
			}
		}
		return Result{Verdict: Invalid, Reason: sr.ErrorReason, Payer: sr.Payer}
	}
	if sr.Transaction == "" {
		// A settlement claim with no evidence must never mint a pass that
		// embeds a transaction. Ambiguous, never success.
		c.lg.ErrorContext(ctx, "facilitator claimed settle success without a transaction hash",
			"payer", sr.Payer, "network", sr.Network,
			"action", "treating as ambiguous; the payer may retry the identical payload")
		return Result{Verdict: Ambiguous, Reason: ambiguousReason,
			Err: errors.New("settle success carried no transaction hash")}
	}

	if sr.Network == "" || sr.Network != req.Network {
		// A settlement on a chain the gate did not price is not the payment the
		// gate asked for, whatever it says about success. Ambiguous rather than
		// invalid: something may well have moved on that other chain, and the
		// operator needs to know rather than have the payer told to sign again.
		c.lg.ErrorContext(ctx, "facilitator settled on a different network than requested",
			"requested", req.Network, "settled", sr.Network, "tx", sr.Transaction,
			"payer", sr.Payer, "action", "no pass minted; reconcile against the chain")
		return Result{Verdict: Ambiguous, Reason: ambiguousReason,
			Err: fmt.Errorf("settle reported network %q, requested %q", sr.Network, req.Network)}
	}

	if sr.Payer != "" && !strings.EqualFold(sr.Payer, auth.from) {
		return Result{Verdict: Ambiguous, Reason: ambiguousReason,
			Err: fmt.Errorf("settle reported payer %q, authorization names %q", sr.Payer, auth.from)}
	}
	amount := ""
	if sr.Amount != "" {
		settledAmount, settledOK := canonicalInteger(sr.Amount)
		requestedAmount, requestedOK := canonicalInteger(req.Amount)
		if !settledOK || !requestedOK || settledAmount != requestedAmount {
			return Result{Verdict: Ambiguous, Reason: ambiguousReason,
				Err: fmt.Errorf("settle reported amount %q, requested %q", sr.Amount, req.Amount)}
		}
		amount = settledAmount
	}
	return Result{Verdict: Valid, Payer: sr.Payer, Tx: sr.Transaction,
		Amount: amount, Network: sr.Network}
}

// ErrorSettlementPending is the facilitator error code for a settlement
// transaction that was broadcast but whose confirmation could not be
// established. The specification marks it non-terminal and requires it to carry
// the transaction and network.
const ErrorSettlementPending = "settlement_pending"

// pendingRetryAfter is how long a payer is asked to wait before re-presenting.
// Long enough for an ordinary block to confirm; short enough that a client
// which does no reconciliation of its own still comes back rather than giving
// up on a payment it has already made.
const pendingRetryAfter = 15 * time.Second

const (
	infraReason = "temporarily unable to process payments — you were not charged, " +
		"retry with the same payload"
	pendingReason = "settlement was broadcast but is not yet confirmed — do NOT sign a new " +
		"payment. Check the transaction below, then re-present the SAME PAYMENT-SIGNATURE; " +
		"the authorization cannot transfer its token amount twice, but x402 does not guarantee " +
		"that every facilitator caches settlement results."
	ambiguousReason = "settlement outcome unknown — you may have been charged. " +
		"Retry with the SAME PAYMENT-SIGNATURE inside its validity window; " +
		"do not sign a replacement until you reconcile the original transaction."
)

// callResult reports whether a failure was transport-class, which is the only
// kind that counts toward the breaker.
type callResult struct{ transport bool }

// call performs one facilitator endpoint round trip, decoding into out.
//
// Retries happen only for connection-class errors on an idempotent budget, and
// only when no bytes reached the server; attempts is 1 for /settle.
func (c *CallbackVerifier) call(ctx context.Context, path string, p Payload, req Requirements,
	budget time.Duration, attempts int, out any) (callResult, error) {

	body, err := json.Marshal(facilitatorRequest{
		X402Version:         Version,
		PaymentPayload:      p.Raw(),
		PaymentRequirements: req,
	})
	if err != nil {
		return callResult{}, fmt.Errorf("encoding %s request: %w", path, err)
	}

	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, budget)
		start := time.Now()
		r, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, c.base+path,
			bytes.NewReader(body))
		if err != nil {
			cancel()
			return callResult{}, err
		}
		c.applyHeaders(r)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(r)
		if err != nil {
			cancel()
			last = fmt.Errorf("%s: %w", path, err)
			c.lg.WarnContext(ctx, "facilitator call failed",
				"endpoint", path, "attempt", attempt, "elapsed", time.Since(start),
				"budget", budget, "err", err)
			if attempt < attempts && retryable(err) {
				continue
			}
			return callResult{transport: true}, last
		}

		res, err := c.decode(ctx, path, resp, out)
		cancel()
		if err != nil {
			return res, err
		}
		return callResult{}, nil
	}
	return callResult{transport: true}, last
}

// decode turns a facilitator response into either a decoded document or a
// classified failure.
func (c *CallbackVerifier) decode(ctx context.Context, path string, resp *http.Response, out any) (callResult, error) {
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		c.lg.ErrorContext(ctx, "facilitator redirected",
			"endpoint", path, "status", resp.StatusCode, "location", loc,
			"fix", "set the canonical facilitator URL in anteroom.toml; redirects are never followed on a POST")
		return callResult{transport: true},
			fmt.Errorf("%s: redirected to %q", path, loc)

	case resp.StatusCode == http.StatusTooManyRequests:
		c.lg.WarnContext(ctx, "facilitator rate limited us", "endpoint", path,
			"retry_after", resp.Header.Get("Retry-After"))
		return callResult{transport: true}, fmt.Errorf("%s: rate limited", path)

	case resp.StatusCode >= 500:
		c.lg.WarnContext(ctx, "facilitator server error", "endpoint", path,
			"status", resp.StatusCode, "body", snippet(raw))
		return callResult{transport: true},
			fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}

	if readErr != nil {
		return callResult{transport: true}, fmt.Errorf("%s: reading body: %w", path, readErr)
	}

	if err := json.Unmarshal(raw, out); err != nil {
		// A 4xx that does not decode is still a failure of this call, and on
		// /settle it is ambiguous — which the caller decides, not us.
		c.lg.WarnContext(ctx, "facilitator response did not decode",
			"endpoint", path, "status", resp.StatusCode, "body", snippet(raw), "err", err)
		return callResult{}, fmt.Errorf("%s: malformed response: %w", path, err)
	}
	if resp.StatusCode >= 400 {
		// Decoded, but an error status. The document is authoritative if it
		// carried a reason; otherwise this is a failure of the call.
		if hasReason(out) {
			return callResult{}, nil
		}
		return callResult{}, fmt.Errorf("%s: status %d with no reason", path, resp.StatusCode)
	}
	return callResult{}, nil
}

func hasReason(out any) bool {
	switch v := out.(type) {
	case *VerifyResponse:
		return v.InvalidReason != ""
	case *SettleResponse:
		return v.ErrorReason != ""
	}
	return false
}

// retryable reports whether an error is connection-class, i.e. the request
// plausibly never reached the server. A timeout is deliberately excluded: the
// server may well have received it.
func retryable(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	var oe *net.OpError
	if errors.As(err, &oe) {
		return oe.Op == "dial"
	}
	return false
}

func snippet(b []byte) string {
	const max = 256
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// applyHeaders adds the operator-configured facilitator headers. Callers set
// the verifier's own protocol headers afterwards, so those are the last word
// even if config validation ever stops rejecting the reserved names.
func (c *CallbackVerifier) applyHeaders(r *http.Request) {
	for k, vs := range c.headers {
		for _, v := range vs {
			r.Header.Set(k, v)
		}
	}
}
