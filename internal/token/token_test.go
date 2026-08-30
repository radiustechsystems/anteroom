package token

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	keyA = Key{Kid: "a", Key: []byte("0123456789abcdef0123456789abcdef")}
	keyB = Key{Kid: "b", Key: []byte("fedcba9876543210fedcba9876543210")}
)

func powPass(now time.Time) Pass {
	return Pass{
		Kind: KindPoW, Scope: ScopeAll, Aud: "example.com",
		IPP: "192.0.2.0/24", UAH: "test-ua-hash",
		Iat: now.Unix(), Exp: now.Add(time.Minute).Unix(),
	}
}

func paidPass(now time.Time) Pass {
	return Pass{
		Kind: KindPaid, Scope: "reports", Aud: "example.com",
		Iat: now.Unix(), Exp: now.Add(time.Hour).Unix(),
	}
}

func signUnchecked(t *testing.T, kr *Keyring, p Pass) string {
	t.Helper()
	p.V = Version
	p.Kid = kr.signKid
	payload, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(tag(kr.keys[kr.signKid], payload))
}

func ring(t testing.TB, keys ...Key) *Keyring {
	t.Helper()
	kr, err := NewKeyring(keys)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return kr
}

func TestNewKeyring(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keys    []Key
		wantErr bool
	}{
		{"one key", []Key{keyA}, false},
		{"two keys", []Key{keyA, keyB}, false},
		{"empty", nil, true},
		{"no kid", []Key{{Kid: "", Key: keyA.Key}}, true},
		{"short key", []Key{{Kid: "a", Key: []byte("short")}}, true},
		{"duplicate kid", []Key{keyA, {Kid: "a", Key: keyB.Key}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewKeyring(tc.keys)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NewKeyring err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	kr := ring(t, keyA)
	now := time.Unix(1_700_000_000, 0)
	in := Pass{
		Kind:  KindPaid,
		Scope: "reports",
		Aud:   "example.com",
		Iat:   now.Unix(),
		Exp:   now.Add(time.Hour).Unix(),
		Payer: "0xpayer",
		Tx:    "0xtx",
	}
	s, err := kr.Mint(in)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	out, err := kr.Verify(s, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.V != Version || out.Kid != "a" {
		t.Errorf("V/Kid = %d/%q, want %d/%q", out.V, out.Kid, Version, "a")
	}
	if out.Kind != in.Kind || out.Scope != in.Scope || out.Payer != in.Payer || out.Tx != in.Tx {
		t.Errorf("round trip mismatch: got %+v", out)
	}
}

func TestVerifyRejects(t *testing.T) {
	kr := ring(t, keyA)
	now := time.Unix(1_700_000_000, 0)
	mint := func(p Pass) string {
		t.Helper()
		s, err := kr.Mint(p)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		return s
	}
	validPass := powPass(now)
	validPass.Exp = now.Add(10 * time.Second).Unix()
	valid := mint(validPass)

	// Tamper with the payload but keep the tag.
	payload, tag, _ := strings.Cut(valid, ".")
	tampered := payload[:len(payload)-2] + "xx." + tag

	// Sign with a key the verifier does not know.
	other := ring(t, Key{Kid: "z", Key: []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")})
	unknownKid := func() string {
		s, _ := other.Mint(powPass(now))
		return s
	}()

	// Same kid, wrong key material.
	forged := func() string {
		evil := ring(t, Key{Kid: "a", Key: []byte("attacker-key-attacker-key-attack")})
		s, _ := evil.Mint(paidPass(now))
		return s
	}()

	for _, tc := range []struct {
		name string
		in   string
		at   time.Time
		want error
	}{
		{"empty", "", now, ErrMalformed},
		{"no dot", "abcdef", now, ErrMalformed},
		{"not base64", "!!!.###", now, ErrMalformed},
		{"not json", b64.EncodeToString([]byte("hi")) + "." + b64.EncodeToString([]byte("hi")), now, ErrMalformed},
		{"tampered payload", tampered, now, ErrMalformed}, // payload no longer valid JSON/b64 → malformed or bad sig; see below
		{"unknown kid", unknownKid, now, ErrUnknownKid},
		{"forged same kid", forged, now, ErrBadSignature},
		{"expired", valid, now.Add(11 * time.Second), ErrExpired},
		{"exp boundary is expired", valid, now.Add(10 * time.Second), ErrExpired},
		{"from the future", func() string {
			p := powPass(now.Add(2 * time.Minute))
			return mint(p)
		}(), now, ErrFromFuture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kr.Verify(tc.in, tc.at)
			if err == nil {
				t.Fatal("Verify accepted a bad pass")
			}
			// Tampered payloads may fail as malformed or as bad signature
			// depending on where the corruption lands; both are rejections at
			// the right layer.
			if tc.name == "tampered payload" {
				if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrBadSignature) {
					t.Fatalf("err = %v, want malformed or bad signature", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestRotation(t *testing.T) {
	old := ring(t, keyB)
	now := time.Unix(1_700_000_000, 0)
	oldPass, err := old.Mint(powPass(now))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Rotated ring: new key signs, old key still verifies.
	rotated := ring(t, keyA, keyB)
	if _, err := rotated.Verify(oldPass, now); err != nil {
		t.Fatalf("old pass should verify during rotation overlap: %v", err)
	}
	newPass, err := rotated.Mint(powPass(now))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.Contains(newPass, ".") {
		t.Fatal("mint produced garbage")
	}
	got, err := rotated.Verify(newPass, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Kid != "a" {
		t.Errorf("new pass signed by kid %q, want %q (first key signs)", got.Kid, "a")
	}

	// After the old key is dropped, its passes stop verifying.
	dropped := ring(t, keyA)
	if _, err := dropped.Verify(oldPass, now); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("err = %v, want ErrUnknownKid after key removal", err)
	}
}

func TestDomainSeparation(t *testing.T) {
	// A MAC computed over the same bytes WITHOUT the pass domain must not
	// verify: this is what keeps a shared key's other uses (challenges) from
	// ever producing a valid pass.
	kr := ring(t, keyA)
	now := time.Unix(1_700_000_000, 0)
	p := paidPass(now)
	s, err := kr.Mint(p)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	payloadB64, _, _ := strings.Cut(s, ".")
	payload, _ := b64.DecodeString(payloadB64)

	undomained := hmacNoDomain(keyA.Key, payload)
	forged := payloadB64 + "." + b64.EncodeToString(undomained)
	if _, err := kr.Verify(forged, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature for undomained MAC", err)
	}
}

// TestMintRefusesAPassWithNoExpiry: the zero Pass is not a valid pass, and the
// mint is the last moment anyone can be told so.
func TestMintRefusesAPassWithNoExpiry(t *testing.T) {
	kr := ring(t, keyA)
	now := time.Unix(1_700_000_000, 0)
	p := powPass(now)
	p.Exp = 0
	if _, err := kr.Mint(p); err == nil {
		t.Fatal("minted a pass with no expiry; Verify refuses it the instant it exists " +
			"and the visitor gets a cookie that can never work")
	}
}

func TestPassVariantsAreClosedAtMintAndVerify(t *testing.T) {
	kr := ring(t, keyA)
	now := time.Unix(1_700_000_000, 0)
	cases := map[string]Pass{
		"unknown kind": func() Pass {
			p := paidPass(now)
			p.Kind = "other"
			return p
		}(),
		"PoW with paid scope": func() Pass {
			p := powPass(now)
			p.Scope = "reports"
			return p
		}(),
		"PoW without client binding": func() Pass {
			p := powPass(now)
			p.IPP = ""
			return p
		}(),
		"PoW with settlement": func() Pass {
			p := powPass(now)
			p.Tx = "0xtx"
			return p
		}(),
		"paid wildcard": func() Pass {
			p := paidPass(now)
			p.Scope = ScopeAll
			return p
		}(),
		"paid with network binding": func() Pass {
			p := paidPass(now)
			p.IPP = "192.0.2.0/24"
			return p
		}(),
		"missing audience": func() Pass {
			p := paidPass(now)
			p.Aud = ""
			return p
		}(),
		"backwards lifetime": func() Pass {
			p := paidPass(now)
			p.Exp = p.Iat
			return p
		}(),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := kr.Mint(p); err == nil {
				t.Error("Mint accepted an invalid pass shape")
			}
			if _, err := kr.Verify(signUnchecked(t, kr, p), now); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify = %v, want ErrMalformed", err)
			}
		})
	}
}
