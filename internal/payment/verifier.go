package payment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Verdict classifies every facilitator interaction. The classification is the
// whole design: each verdict has exactly one behaviour, and only one of them
// serves content.
//
// The three harm classes these exist to separate are unpaid service (grant
// without settlement — the operator loses), paid but
// denied (settlement without grant — the payer loses), and availability harm
// (nobody paid, nobody served).
type Verdict int

const (
	// Valid is a parseable settle success carrying a transaction hash. Serve,
	// and mint the paid pass. Nothing else serves.
	Valid Verdict = iota

	// Invalid is a parseable rejection: isValid:false or success:false. Answer
	// with a fresh 402 and relay the reason.
	Invalid

	// Indeterminate is any failure before /settle left the gate. The payer's
	// exposure is zero — a verified-but-unsettled authorization is unspent and
	// fully retryable — so this falls back without ceremony.
	Indeterminate

	// Ambiguous is /settle sent, outcome unknown. Money may have moved. Serve
	// nothing, claim nothing, and tell the payer to re-present the identical
	// payload: their own retry is the recovery path.
	Ambiguous

	// Pending is the facilitator's own `settlement_pending`: a transaction was
	// broadcast and its confirmation could not be established. The spec calls
	// this non-terminal and requires the transaction and network to come with
	// it, precisely so the caller can reconcile on chain before deciding
	// anything. It is Ambiguous with evidence — serve nothing, claim nothing,
	// and hand the payer the transaction rather than a fresh price.
	Pending
)

func (v Verdict) String() string {
	switch v {
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	case Indeterminate:
		return "indeterminate"
	case Ambiguous:
		return "ambiguous"
	case Pending:
		return "pending"
	}
	return "unknown"
}

// Result is what a Verifier reports. It is deliberately not an error-or-value:
// the interesting cases are all "no pass" with materially different reasons,
// and collapsing them loses exactly the distinction the design turns on.
type Result struct {
	Verdict Verdict
	// Reason is the facilitator's own words where it gave any, relayed to the
	// client and logged. Never fabricated.
	Reason string
	Payer  string
	Tx     string
	Amount string
	// Network is the facilitator's own CAIP-2 identifier for the chain a
	// transaction was broadcast to. Carried for reconciliation: a transaction
	// hash without the chain it lives on is not something a payer can look up.
	Network string
	// Err carries the transport or decode failure behind an Indeterminate or
	// Ambiguous verdict, for the operator's log. It is never shown to a client.
	Err error

	// RetryAfter is how long the client should actually wait, when the gate
	// knows. Advising a retry sooner than the gate will be willing to try
	// guarantees a wasted round trip — and, worse, synchronises every client's
	// retry onto the moment the door reopens.
	RetryAfter time.Duration
}

// Verifier is the seam every payment backend sits behind. The shipped
// implementation is CallbackVerifier.
type Verifier interface {
	// Verify runs the full verify-then-settle round for one presented payment.
	// It returns a Result for every outcome including failure; a non-nil error
	// is reserved for programmer error, not for the facilitator misbehaving.
	Verify(ctx context.Context, p Payload, req Requirements) Result
}

// ID names the chain object that can be consumed once. The server-selected
// requirements are part of that name: authorizer/nonce namespaces are distinct
// across transfer methods, chains, and token contracts.
func ID(p Payload, req Requirements) (string, error) {
	method := req.TransferMethod()
	if req.Scheme != "exact" || (method != "eip3009" && method != "permit2") {
		return "", fmt.Errorf("%w: unsupported %s/%s", ErrUnidentifiedPayment, req.Scheme, method)
	}
	auth, err := authorization(p.Payload, method)
	if err != nil {
		return "", err
	}
	if auth == nil {
		return "", fmt.Errorf("%w: missing %s authorization", ErrUnidentifiedPayment, method)
	}

	h := sha256.New()
	_ = json.NewEncoder(h).Encode([]string{
		"anteroom/x402-payment/v1",
		req.Scheme,
		req.Network,
		strings.ToLower(req.Asset),
		auth.method,
		auth.from,
		auth.nonce,
	})
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ErrUnidentifiedPayment is a presentation the gate cannot name: it carries an
// authorization object of a shape the gate models, but not the fields the chain
// spends. It is a refusal, never an infrastructure error.
var ErrUnidentifiedPayment = errors.New("payment: authorization carries no from/nonce to identify it by")

// authIdentity is the part of an authorization that can be spent once.
type authIdentity struct {
	method string // the payload key it came from, so two nonce namespaces stay apart
	from   string
	nonce  string
}

// authKeys are the scheme-payload keys that hold an authorization, in the order
// they are preferred. Fixed and small on purpose: it is the set of transfer
// methods the config will let an operator offer.
// authKeyFor maps a server-side asset transfer method to the single scheme-payload
// object that carries the authorization the chain will consume.
var authKeyFor = map[string]string{
	"permit2": "permit2Authorization",
	"eip3009": "authorization",
}

// authKeys is every object this package recognises, used only to detect a
// payload that carries more than one.
var authKeys = []string{"permit2Authorization", "authorization"}

// authorization derives replay identity only from the object selected by the
// server's transfer method. Payloads with multiple recognized authorization
// objects are refused so the client cannot choose the identity being settled.
//
// It returns (nil, nil) when the payload models no authorization the gate knows,
// and an error when it names one but not the fields that identify it.
func authorization(schemePayload []byte, method string) (*authIdentity, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(schemePayload, &obj); err != nil {
		return nil, nil
	}
	present := 0
	for _, k := range authKeys {
		if _, ok := obj[k]; ok {
			present++
		}
	}
	if present > 1 {
		return nil, fmt.Errorf("%w: payload names more than one authorization object", ErrUnidentifiedPayment)
	}
	for _, key := range authKeys {
		if key != authKeyFor[method] {
			continue
		}
		raw, ok := obj[key]
		if !ok {
			continue
		}
		var a struct {
			From  scalar `json:"from"`
			Nonce scalar `json:"nonce"`
		}
		if err := json.Unmarshal(raw, &a); err != nil || a.From == "" || a.Nonce == "" {
			return nil, fmt.Errorf("%w: %s", ErrUnidentifiedPayment, key)
		}
		// One authorization must not have two identities because the client
		// re-spelled it. Addresses are case-insensitive outside their EIP-55
		// checksum, and a nonce is a number however it was encoded.
		nonce, ok := canonicalInteger(string(a.Nonce))
		if !ok {
			return nil, fmt.Errorf("%w: %s nonce is not an unsigned 256-bit integer", ErrUnidentifiedPayment, key)
		}
		return &authIdentity{
			method: key,
			from:   strings.ToLower(string(a.From)),
			nonce:  nonce,
		}, nil
	}
	return nil, nil
}

// scalar accepts a JSON string or number and keeps its literal text. Clients
// differ on whether a 256-bit nonce is quoted, and both are the same nonce.
type scalar string

func (s *scalar) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		*s = scalar(str)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil || n == "" {
		return errors.New("want a JSON string or number")
	}
	*s = scalar(n)
	return nil
}

// canonicalInteger renders a decimal or 0x-hex integer in one form, so the same
// nonce written two ways is one payment.
func canonicalInteger(s string) (string, bool) {
	t := strings.TrimSpace(s)
	base := 10
	if len(t) > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') {
		t, base = t[2:], 16
	}
	n, ok := new(big.Int).SetString(t, base)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return "", false
	}
	return n.String(), true
}

// Requirements matching, done locally before any egress.
//
// This is invariant 5 ("verify before serve; terms checked before verify") and
// also the cheapest DoS defence there is: a payment that does not match the
// rule it is presented against can be refused without spending a facilitator
// round trip on it.
var ErrRequirementsMismatch = errors.New("payment: presentation does not match the matched rule")

// MatchRail finds the advertised rail a presented payload is paying on, and
// checks that the terms the client echoed are the terms the gate actually
// offered.
//
// The returned Requirements are always the GATE'S, never the client's echo:
// that is what gets forwarded to the facilitator, so a client that rewrites the
// amount or the recipient in `accepted` cannot move a single unit of value. The
// comparison exists on top of that to fail fast and locally, before spending a
// facilitator round trip on a payment whose signature covers different terms
// than the ones we would ask to be settled.
//
// What it compares is scheme, network, asset, amount and payTo — not
// maxTimeoutSeconds, not scheme `extra`. Those two are omitted because the gate
// forwards its own requirements regardless, so a mismatch there costs a wasted
// round trip rather than value, while rejecting on a field clients echo
// inconsistently would cost real payments. It is a fail-fast check, not the
// "exact match" older prose called it, and it binds nothing: no exact-EVM
// signature covers the resource, the method or the rule.
func MatchRail(p Payload, accepts []Requirements) (Requirements, error) {
	for _, r := range accepts {
		if r.Network != p.Accepted.Network || r.Scheme != p.Accepted.Scheme {
			continue
		}
		// Same rail. Now the terms.
		switch {
		case !strings.EqualFold(r.Asset, p.Accepted.Asset):
			return Requirements{}, fmt.Errorf("%w: asset %q, offered %q",
				ErrRequirementsMismatch, p.Accepted.Asset, r.Asset)
		case r.Amount != p.Accepted.Amount:
			return Requirements{}, fmt.Errorf("%w: amount %q, offered %q",
				ErrRequirementsMismatch, p.Accepted.Amount, r.Amount)
		case !strings.EqualFold(r.PayTo, p.Accepted.PayTo):
			return Requirements{}, fmt.Errorf("%w: payTo %q, offered %q",
				ErrRequirementsMismatch, p.Accepted.PayTo, r.PayTo)
		}
		return r, nil
	}
	return Requirements{}, fmt.Errorf("%w: no offered rail for %s on %s",
		ErrRequirementsMismatch, p.Accepted.Scheme, p.Accepted.Network)
}
