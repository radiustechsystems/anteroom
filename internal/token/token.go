// Package token mints and verifies Anteroom pass tokens.
//
// A pass is the signed cookie a visitor holds after solving a challenge (kind
// "pow") or paying (kind "paid"). The format is deliberately minimal — JSON
// payload and an HMAC-SHA256 tag, both base64url without padding, joined by a
// dot:
//
//	b64url(payload) || "." || b64url(HMAC-SHA256(key, domain || payload))
//
// It is not a JWT: there is no header, no algorithm agility, and no dependency.
// The MAC is domain-separated so that a key shared with the challenge module
// can never produce a valid pass and vice versa.
//
// Passes are stateless: any instance holding the keyring validates any pass,
// which is the whole multi-instance story for the free path.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// domain separates this MAC use from every other HMAC use of the same key.
const domain = "anteroom-pass-v0."

// Version is the pass payload format version.
const Version = 1

// Kind says how a pass was earned.
type Kind string

const (
	KindPoW  Kind = "pow"  // solved a challenge; lives pass_ttl
	KindPaid Kind = "paid" // settled a payment; lives the rule's paid_ttl
)

// Sentinel errors, coarse on purpose: callers branch on them, logs carry detail.
var (
	ErrMalformed    = errors.New("token: malformed pass")
	ErrUnknownKid   = errors.New("token: unknown key id")
	ErrBadSignature = errors.New("token: bad signature")
	ErrExpired      = errors.New("token: pass expired")
	ErrFromFuture   = errors.New("token: pass issued in the future")
)

// ScopeAll is the wildcard scope: a pass carrying it is not bound to any one
// pricing rule. Proof-of-work passes are minted with it because the free door
// gates bots rather than value, so one solve covers the site.
//
// It is a reserved name, not a rule name, and that distinction crosses three
// packages: token mints it, gate special-cases it when deciding what a pass
// unlocks, and config refuses to let an operator name a payment rule "*" —
// which would otherwise mint site-wide paid passes regardless of the rule's
// paths. Naming it here puts the convention in the package that owns the field,
// so the three sites are greppable from one another instead of agreeing by
// coincidence.
const ScopeAll = "*"

// Pass is the payload carried by the cookie.
type Pass struct {
	V     int    `json:"v"`
	Kid   string `json:"kid"`
	Kind  Kind   `json:"kind"`
	Scope string `json:"scope"` // name of the rule that minted it; ScopeAll for PoW
	// Aud is the lowercase HTTP authority that minted the pass. It prevents a
	// key shared across virtual hosts from making their entitlements fungible.
	Aud string `json:"aud,omitempty"`
	Iat int64  `json:"iat"` // unix seconds
	Exp int64  `json:"exp"` // unix seconds
	// IPP is the network prefix the pass is bound to — the client's /24
	// (IPv4) or /48 (IPv6) as resolved at mint time. Verification refuses a
	// PoW pass presented from outside its prefix, which limits redistribution
	// of the minted pass. A challenge and its solution remain bearer material
	// until the answer is redeemed, so an active coordinator can still relay a
	// fresh pair from a worker on the target prefix. The prefix
	// turns the resulting pass into "bearer on the network that redeemed the
	// work". A /24
	// rather than the exact address absorbs carrier NAT and mobile IP drift
	// without re-admission. Empty means unbound (paid passes, and passes
	// minted before this field existed — the gate treats those as absent).
	IPP string `json:"ipp,omitempty"`
	// UAH is a short hash of the User-Agent the pass was minted under. The
	// A scraper can solve challenges under a real headless browser and then
	// spend the passes under rotating fake browser UAs. The IP prefix alone
	// permits that, since both personas live on
	// the same node. Binding the UA forces solver and consumer to be the
	// same declared client profile: rotating the presentation UA invalidates
	// the pass, but an active relay can copy the declaration too.
	// A hash rather than the string keeps the cookie small; empty means
	// unbound and, like IPP, fails closed for PoW passes.
	UAH string `json:"uah,omitempty"`
	// Rt is the unix time of the ROOT admission this pass descends from.
	// Cheap renewals carry it forward unchanged, so a renewal chain can be
	// capped: without it, one admission solve would sustain access forever at
	// renewal cost, and the difficulty dial would bound nothing.
	Rt    int64  `json:"rt,omitempty"`
	Payer string `json:"payer,omitempty"`
	Tx    string `json:"tx,omitempty"`
}

// RootAt returns the root admission time, treating a missing Rt as Iat so the
// zero value behaves like "this pass is its own root".
func (p Pass) RootAt() time.Time {
	if p.Rt == 0 {
		return time.Unix(p.Iat, 0)
	}
	return time.Unix(p.Rt, 0)
}

func (p Pass) validate() error {
	if p.Aud == "" || p.Scope == "" {
		return errors.New("missing audience or scope")
	}
	if p.Iat <= 0 || p.Exp <= p.Iat {
		return errors.New("invalid lifetime")
	}
	if p.Rt < 0 || p.Rt > p.Iat {
		return errors.New("invalid root admission time")
	}
	switch p.Kind {
	case KindPoW:
		if p.Scope != ScopeAll || p.IPP == "" || p.UAH == "" || p.Payer != "" || p.Tx != "" {
			return errors.New("invalid proof-of-work pass fields")
		}
	case KindPaid:
		if p.Scope == ScopeAll || p.IPP != "" || p.UAH != "" || p.Rt != 0 {
			return errors.New("invalid paid pass fields")
		}
	default:
		return errors.New("unknown pass kind")
	}
	return nil
}

// Key is one HMAC key with its identifier.
type Key struct {
	Kid string
	Key []byte
}

// Keyring holds the signing key (first) and any number of verify-only keys —
// the rotation story: append the new key first, keep the old until every pass
// signed by it has expired.
type Keyring struct {
	signKid string
	keys    map[string][]byte
}

// NewKeyring builds a keyring from an ordered key list; keys[0] signs.
func NewKeyring(keys []Key) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("token: keyring needs at least one key")
	}
	kr := &Keyring{signKid: keys[0].Kid, keys: make(map[string][]byte, len(keys))}
	for _, k := range keys {
		if k.Kid == "" || len(k.Key) < 16 {
			return nil, fmt.Errorf("token: key %q must have a kid and at least 16 bytes of key material", k.Kid)
		}
		if _, dup := kr.keys[k.Kid]; dup {
			return nil, fmt.Errorf("token: duplicate kid %q", k.Kid)
		}
		kr.keys[k.Kid] = k.Key
	}
	return kr, nil
}

// clockSkew is how far ahead a pass's iat may be before we refuse it.
const clockSkew = 60 * time.Second

var b64 = base64.RawURLEncoding

func tag(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write(payload)
	return m.Sum(nil)
}

// Mint validates and signs p with the keyring's signing key. V and Kid are set
// here; the caller owns every other field.
func (kr *Keyring) Mint(p Pass) (string, error) {
	if err := p.validate(); err != nil {
		return "", fmt.Errorf("token: refusing to mint invalid pass: %w", err)
	}
	p.V = Version
	p.Kid = kr.signKid
	payload, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("token: marshal: %w", err)
	}
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(tag(kr.keys[kr.signKid], payload)), nil
}

// Verify checks the signature, the closed pass variant, and time bounds. Route
// coverage and client binding still belong to the gate.
func (kr *Keyring) Verify(s string, now time.Time) (Pass, error) {
	payloadB64, tagB64, ok := strings.Cut(s, ".")
	if !ok {
		return Pass{}, ErrMalformed
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		return Pass{}, ErrMalformed
	}
	got, err := b64.DecodeString(tagB64)
	if err != nil {
		return Pass{}, ErrMalformed
	}
	var p Pass
	if err := json.Unmarshal(payload, &p); err != nil {
		return Pass{}, ErrMalformed
	}
	if p.V != Version {
		return Pass{}, ErrMalformed
	}
	key, ok := kr.keys[p.Kid]
	if !ok {
		return Pass{}, ErrUnknownKid
	}
	if !hmac.Equal(got, tag(key, payload)) {
		return Pass{}, ErrBadSignature
	}
	if err := p.validate(); err != nil {
		return Pass{}, ErrMalformed
	}
	// Time bounds only after the signature is known good, so attackers learn
	// nothing about clock handling from unsigned probes.
	if now.Unix() >= p.Exp {
		return Pass{}, ErrExpired
	}
	if p.Iat > now.Add(clockSkew).Unix() {
		return Pass{}, ErrFromFuture
	}
	return p, nil
}
