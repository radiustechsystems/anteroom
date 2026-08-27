// Package challenge issues and verifies Anteroom's stateless proof-of-work
// challenges.
//
// A challenge is self-authenticating — no instance stores anything:
//
//	b64url(ts[8] || rand[16] || profile[42] ||
//	       HMAC-SHA256(key, domain || ts || rand || profile || 0 || audience))
//
// Any instance holding the keyring can verify any instance's challenge. The MAC
// binds the challenge to the normalized request authority and to the exact
// proof profile the issuer advertised: admission/renewal class, threshold, and
// pass lifetime. It is domain-separated from the pass-token MAC. A solved
// challenge can therefore be shared only within the same authority and signed
// lifetime. This is a deliberate rate-limiting tradeoff: PoW proofs are not
// single-use credentials.
//
// The proof of work itself is a threshold comparison:
//
//	sha256(challenge + nonce) < 2^(256 - difficulty)
//
// Difficulty is in bits and may be fractional; the threshold is precomputed
// once. The browser solves with WebCrypto; the server verifies with one hash.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"
)

const (
	domain       = "anteroom-challenge-v2."
	tsLen        = 8
	randLen      = 16
	versionLen   = 1
	kindLen      = 1
	ttlLen       = 8
	thresholdLen = sha256.Size
	profileLen   = versionLen + kindLen + ttlLen + thresholdLen
	macLen       = sha256.Size
	bodyLen      = tsLen + randLen + profileLen
	rawLen       = bodyLen + macLen
	profileV1    = 1
	// skew tolerates instances with slightly fast clocks issuing challenges
	// that another instance sees as "from the future".
	skew = 60 * time.Second
)

var (
	ErrMalformed = errors.New("challenge: malformed")
	ErrBadMAC    = errors.New("challenge: bad MAC")
	ErrStale     = errors.New("challenge: outside freshness window")
	ErrProfile   = errors.New("challenge: invalid proof profile")
	ErrWrongPoW  = errors.New("challenge: hash does not meet the threshold")
)

var b64 = base64.RawURLEncoding

// Key mirrors token.Key: an HMAC key with its identifier. The keyring here is
// intentionally a plain slice — the first key signs new challenges, all keys
// verify — so config can hand the same material to both packages.
type Key struct {
	Kid string
	Key []byte
}

// Kind distinguishes a full admission proof from a cheaper renewal proof.
// It is signed because accepting a renewal threshold as admission is a direct
// authorization failure.
type Kind byte

const (
	KindAdmit Kind = 1
	KindRenew Kind = 2
)

func (k Kind) String() string {
	if k == KindRenew {
		return "renew"
	}
	return "admit"
}

// Profile is the complete promise a solver works against. Encoding it into the
// challenge lets a verifier honor the issuer's promise across config reloads or
// a mixed fleet. Rollouts therefore honor old profiles only for their signed
// TTL; after that they expire without server-side migration state.
type Profile struct {
	Kind      Kind
	TTL       time.Duration
	Threshold [thresholdLen]byte
}

func (p Profile) validate() error {
	if p.Kind != KindAdmit && p.Kind != KindRenew {
		return fmt.Errorf("%w: unknown kind %d", ErrProfile, p.Kind)
	}
	if p.TTL <= 0 {
		return fmt.Errorf("%w: non-positive TTL", ErrProfile)
	}
	return nil
}

func appendProfile(dst []byte, p Profile) []byte {
	dst = append(dst, profileV1, byte(p.Kind))
	dst = binary.BigEndian.AppendUint64(dst, uint64(p.TTL))
	return append(dst, p.Threshold[:]...)
}

func parseProfile(raw []byte) (Profile, error) {
	if len(raw) != profileLen || raw[0] != profileV1 {
		return Profile{}, ErrProfile
	}
	p := Profile{
		Kind: Kind(raw[1]),
		TTL:  time.Duration(binary.BigEndian.Uint64(raw[2 : 2+ttlLen])),
	}
	copy(p.Threshold[:], raw[2+ttlLen:])
	return p, p.validate()
}

// Issuer mints and verifies stateless challenges.
type Issuer struct {
	keys []Key
}

// NewIssuer builds an issuer; keys[0] signs.
func NewIssuer(keys []Key) (*Issuer, error) {
	if len(keys) == 0 {
		return nil, errors.New("challenge: issuer needs at least one key")
	}
	for _, k := range keys {
		if len(k.Key) < 16 {
			return nil, fmt.Errorf("challenge: key %q must have at least 16 bytes of key material", k.Kid)
		}
	}
	return &Issuer{keys: keys}, nil
}

func mac(key, body []byte, audience string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write(body)
	m.Write([]byte{0})
	m.Write([]byte(audience))
	return m.Sum(nil)
}

// Issue mints a fresh challenge bound to audience and reports the instant it
// was stamped with.
//
// That instant is returned rather than left for the caller to assume, because
// it is not the caller's `now`: the timestamp inside a challenge is whole
// seconds, and everything downstream is measured from it — Verify's freshness
// window, the deadline the gate advertises, and the expiry of the pass a solve
// buys. A caller deriving those from its own sub-second clock promises up to a
// second of work this issuer will refuse as stale, which is the one thing the
// advertised deadline exists to make impossible.
func (i *Issuer) Issue(now time.Time, audience string, profile Profile) (string, time.Time, error) {
	if err := profile.validate(); err != nil {
		return "", time.Time{}, err
	}
	issuedAt := time.Unix(now.Unix(), 0)
	raw := make([]byte, 0, rawLen)
	raw = binary.BigEndian.AppendUint64(raw, uint64(issuedAt.Unix()))
	var r [randLen]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", time.Time{}, fmt.Errorf("challenge: entropy: %w", err)
	}
	raw = append(raw, r[:]...)
	raw = appendProfile(raw, profile)
	raw = append(raw, mac(i.keys[0].Key, raw, audience)...)
	return b64.EncodeToString(raw), issuedAt, nil
}

// Verify checks that s is a challenge some instance of this fleet issued for
// audience within the freshness window, and returns the time it was issued.
// Callers derive a pass's expiry from that issue time, not from "now", so
// replaying an old solve cannot buy a fresh full-length pass.
func (i *Issuer) Verify(s, audience string, now time.Time) (time.Time, Profile, error) {
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != rawLen {
		return time.Time{}, Profile{}, ErrMalformed
	}
	body, got := raw[:bodyLen], raw[bodyLen:]
	ok := false
	for _, k := range i.keys {
		if hmac.Equal(got, mac(k.Key, body, audience)) {
			ok = true
			break
		}
	}
	if !ok {
		return time.Time{}, Profile{}, ErrBadMAC
	}
	profile, err := parseProfile(body[tsLen+randLen:])
	if err != nil {
		return time.Time{}, Profile{}, err
	}
	ts := time.Unix(int64(binary.BigEndian.Uint64(body[:tsLen])), 0)
	if now.Sub(ts) > profile.TTL || ts.Sub(now) > skew {
		return ts, profile, ErrStale
	}
	return ts, profile, nil
}

// Threshold converts a difficulty in bits (possibly fractional) into the
// 32-byte big-endian threshold a solution hash must be below:
// floor(2^(256-difficulty)). Computed once per config load.
func Threshold(difficulty float64) ([32]byte, error) {
	var t [32]byte
	if difficulty < 0 || difficulty > 255 || math.IsNaN(difficulty) {
		return t, fmt.Errorf("challenge: difficulty %v out of range [0, 255]", difficulty)
	}
	// 2^(256-d) = 2^frac * 2^int with frac in [0,1). big.Float carries the
	// fractional factor precisely enough for a 256-bit target.
	exp := 256 - difficulty
	intPart := int(math.Floor(exp))
	fracPart := exp - math.Floor(exp)
	f := new(big.Float).SetPrec(300)
	f.SetMantExp(big.NewFloat(math.Exp2(fracPart)), intPart) // (2^frac) * 2^int
	n, _ := f.Int(nil)
	// 2^256 (difficulty 0) does not fit 32 bytes; clamp to all-ones = "accept
	// any hash", which is what difficulty 0 means.
	if n.BitLen() > 256 {
		for j := range t {
			t[j] = 0xff
		}
		return t, nil
	}
	n.FillBytes(t[:])
	return t, nil
}

// CheckPoW verifies one candidate solution: sha256(challenge+nonce) must be
// numerically below threshold. One hash — this is the entire server-side cost.
func CheckPoW(challengeStr, nonce string, threshold [32]byte) error {
	h := sha256.Sum256([]byte(challengeStr + nonce))
	for j := range h {
		switch {
		case h[j] < threshold[j]:
			return nil
		case h[j] > threshold[j]:
			return ErrWrongPoW
		}
	}
	return ErrWrongPoW // exactly equal: not strictly below
}
