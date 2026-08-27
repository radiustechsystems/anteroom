// Package payment implements the x402 pay door: the wire types, the seam every
// verifier sits behind, and the callback verifier that talks to an
// operator-designated facilitator.
//
// The wire format is x402 v2 and only v2. Where a field looks optional in Go
// and is not optional in the specification, the comment says so, because those
// are the fields that produce a 402 no client can act on.
package payment

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Version is the only protocol version the gate speaks. v1 carried requirements
// in the body, used maxAmountRequired rather than amount, and used non-CAIP
// network slugs; supporting it means a second field vocabulary for a wire that
// cannot even name Radius.
const Version = 2

// Header names. All three carry base64 JSON. X-PAYMENT and X-PAYMENT-RESPONSE
// are the v1 spellings: never emitted, and read in exactly one place —
// okBodyAgent treats an X-PAYMENT as proof that the client speaks the protocol,
// and so must be given a 402 rather than the 200-bodied consolation.
const (
	HeaderRequired  = "PAYMENT-REQUIRED"  // server → client
	HeaderSignature = "PAYMENT-SIGNATURE" // client → server
	HeaderResponse  = "PAYMENT-RESPONSE"  // server → client
)

// Requirements is one payable rail, as advertised in accepts[].
type Requirements struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"` // CAIP-2, e.g. "eip155:72344"
	Asset   string `json:"asset"`
	// Amount is atomic units as a STRING. Not a number: JSON numbers are
	// float64 in most decoders, and a token with 18 decimals overflows the
	// exactly-representable range long before it overflows the type.
	Amount string `json:"amount"`
	PayTo  string `json:"payTo"`
	// MaxTimeoutSeconds is required by the specification.
	MaxTimeoutSeconds int `json:"maxTimeoutSeconds"`
	// Extra is non-optional in the reference TypeScript type, so it is always
	// emitted — at minimum as {}. For `exact` on EVM it carries the TOKEN's
	// EIP-712 domain as name/version (not ours; a client cannot construct the
	// transfer signature without them) plus assetTransferMethod.
	Extra map[string]any `json:"extra"`
}

// TransferMethod is the asset transfer method these requirements were built
// with. Read it only from a requirements object the SERVER produced: the client
// echoes a copy back, and believing that copy would let a payer nominate which
// of its own authorization objects the gate identifies the payment by.
//
// The default matches the config default and the x402 `exact` default.
func (r Requirements) TransferMethod() string {
	if m, ok := r.Extra["assetTransferMethod"].(string); ok && m != "" {
		return m
	}
	return "eip3009"
}

// Resource identifies what is being sold. Required by the specification even
// though the reference Go struct tags it omitempty.
type Resource struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Required is the PaymentRequired document carried in the PAYMENT-REQUIRED
// header, and mirrored into the body for clients that never look at headers.
type Required struct {
	X402Version int            `json:"x402Version"`
	Error       string         `json:"error,omitempty"`
	Resource    *Resource      `json:"resource"`
	Accepts     []Requirements `json:"accepts"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// Encode renders the document for a header: base64, standard alphabet, padded.
func (r Required) Encode() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// VerifyResponse is the facilitator's answer to POST /verify.
type VerifyResponse struct {
	IsValid       bool           `json:"isValid"`
	InvalidReason string         `json:"invalidReason,omitempty"`
	Payer         string         `json:"payer,omitempty"`
	Extra         map[string]any `json:"extra,omitempty"`
}

// SettleResponse is the facilitator's answer to POST /settle.
type SettleResponse struct {
	Success     bool           `json:"success"`
	ErrorReason string         `json:"errorReason,omitempty"`
	Payer       string         `json:"payer,omitempty"`
	Transaction string         `json:"transaction,omitempty"`
	Network     string         `json:"network,omitempty"`
	Amount      string         `json:"amount,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// facilitatorRequest is the body both /verify and /settle take.
type facilitatorRequest struct {
	X402Version         int             `json:"x402Version"`
	PaymentPayload      json.RawMessage `json:"paymentPayload"`
	PaymentRequirements Requirements    `json:"paymentRequirements"`
}

// Payload is the client's signed authorization.
//
// The shape is worth writing down, because it is not the obvious one and the
// specification's prose does not spell it out. It matches the reference
// @x402/evm ExactEvmScheme client:
//
//	{
//	  "x402Version": 2,
//	  "payload":   { "signature": "0x…", "permit2Authorization": {…} },  // scheme-owned
//	  "accepted":  { scheme, network, asset, amount, payTo, … },          // the rail chosen
//	  "resource":  {…},
//	  "extensions": {…}
//	}
//
// `scheme` and `network` live inside `accepted`, not at the top level:
// the client echoes back the exact accepts[] entry it decided to pay. That echo
// is client-controlled and must never be trusted as policy — the gate uses it
// only to pick which of ITS OWN rails the payment is for, and forwards its own
// policy-derived requirements to the facilitator.
type Payload struct {
	X402Version int             `json:"x402Version"`
	Payload     json.RawMessage `json:"payload"`
	Accepted    Requirements    `json:"accepted"`

	// `resource` and `extensions` are deliberately ABSENT from this struct.
	//
	// The client echoes both back, and our own extensions carry the pass scope
	// and paid TTL — so a payload arriving on the wire contains an
	// attacker-chosen `scope` and `paidTtlSeconds` that look exactly like
	// policy. Reading either would be a scope escalation: one cent paid under
	// the cheapest rule would mint a pass scoped to the most expensive one, for
	// as long as the payer liked.
	//
	// Not decoding them is a stronger guarantee than remembering not to trust
	// them. Scope and TTL come from the rule the REQUEST PATH matched, and there
	// is no field here for anything else to come from. The bytes still reach the
	// facilitator untouched via raw, which is all they are for.

	// raw is the exact decoded bytes, forwarded verbatim. Re-marshalling would
	// reorder keys and could drop fields a future scheme adds, and the
	// facilitator validates a signature over the client's own encoding.
	raw json.RawMessage
}

// Scheme and Network report the rail the client chose to pay on.
func (p Payload) Scheme() string  { return p.Accepted.Scheme }
func (p Payload) Network() string { return p.Accepted.Network }

// Raw returns the payload exactly as the client encoded it.
func (p Payload) Raw() json.RawMessage { return p.raw }

var (
	// ErrMalformedPayload covers every way a PAYMENT-SIGNATURE header fails to
	// be a payment. All of them are refusals, never infrastructure errors: a
	// garbage header must not purchase a facilitator round trip.
	ErrMalformedPayload = errors.New("payment: malformed PAYMENT-SIGNATURE")
)

// maxPayloadBytes caps a presented payload. Signed authorizations are well
// under a kilobyte; the cap exists so a large header cannot make the gate
// allocate on an unauthenticated path.
const maxPayloadBytes = 8 << 10

// DecodePayload parses a PAYMENT-SIGNATURE header value.
//
// It accepts both padded and unpadded base64, and both the standard and URL
// alphabets, because clients in the wild differ and rejecting one costs a
// payment while accepting all four costs nothing — the signature inside is what
// actually authenticates.
func DecodePayload(header string) (Payload, error) {
	var p Payload
	if header == "" {
		return p, fmt.Errorf("%w: empty", ErrMalformedPayload)
	}
	if len(header) > maxPayloadBytes {
		return p, fmt.Errorf("%w: %d bytes exceeds the %d-byte cap",
			ErrMalformedPayload, len(header), maxPayloadBytes)
	}
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err = enc.DecodeString(header); err == nil {
			break
		}
	}
	if err != nil {
		return p, fmt.Errorf("%w: not base64", ErrMalformedPayload)
	}
	if len(raw) > maxPayloadBytes {
		return p, fmt.Errorf("%w: decoded body exceeds the cap", ErrMalformedPayload)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("%w: not JSON: %v", ErrMalformedPayload, err)
	}
	if p.Accepted.Scheme == "" || p.Accepted.Network == "" {
		return p, fmt.Errorf("%w: accepted.scheme or accepted.network missing — "+
			"the payload must echo the accepts[] entry it is paying", ErrMalformedPayload)
	}
	if len(p.Payload) == 0 {
		return p, fmt.Errorf("%w: no scheme payload (nothing is signed)", ErrMalformedPayload)
	}
	if p.X402Version != Version {
		return p, fmt.Errorf("%w: x402Version %d, this gate speaks %d",
			ErrMalformedPayload, p.X402Version, Version)
	}
	p.raw = json.RawMessage(raw)
	return p, nil
}
