package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"
)

var testKeys = []Key{{Kid: "a", Key: []byte("0123456789abcdef0123456789abcdef")}}

var testProfile = func() Profile {
	threshold, _ := Threshold(8)
	return Profile{Kind: KindAdmit, TTL: 60 * time.Second, Threshold: threshold}
}()

func issuer(t *testing.T, keys ...Key) *Issuer {
	t.Helper()
	if keys == nil {
		keys = testKeys
	}
	i, err := NewIssuer(keys)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return i
}

func TestIssueVerify(t *testing.T) {
	i := issuer(t)
	now := time.Unix(1_700_000_000, 0)
	c, _, err := i.Issue(now, "example.com", testProfile)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		want error
	}{
		{"immediately", now, nil},
		{"within window", now.Add(testProfile.TTL - time.Second), nil},
		{"stale", now.Add(testProfile.TTL + time.Second), ErrStale},
		{"far future clock", now.Add(-2 * time.Minute), ErrStale},
		{"small negative skew ok", now.Add(-30 * time.Second), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuedAt, profile, err := i.Verify(c, "example.com", tc.at)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
			if tc.want == nil && !issuedAt.Equal(now) {
				t.Fatalf("issuedAt = %v, want %v (pass expiry derives from it)", issuedAt, now)
			}
			if tc.want == nil && profile != testProfile {
				t.Fatalf("profile = %+v, want %+v", profile, testProfile)
			}
		})
	}
}

func TestChallengeIsBoundToAudience(t *testing.T) {
	i := issuer(t)
	now := time.Unix(1_700_000_000, 0)
	c, _, err := i.Issue(now, "one.example", testProfile)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := i.Verify(c, "two.example", now); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("Verify for another audience = %v, want %v", err, ErrBadMAC)
	}
}

func TestVerifyRejectsForgeries(t *testing.T) {
	i := issuer(t)
	now := time.Unix(1_700_000_000, 0)
	c, _, _ := i.Issue(now, "example.com", testProfile)
	raw, _ := base64.RawURLEncoding.DecodeString(c)

	flip := func(pos int) string {
		b := append([]byte(nil), raw...)
		b[pos] ^= 1
		return base64.RawURLEncoding.EncodeToString(b)
	}

	other := issuer(t, Key{Kid: "z", Key: []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")})
	foreign, _, _ := other.Issue(now, "example.com", testProfile)

	for _, tc := range []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"not base64", "!!!!", ErrMalformed},
		{"truncated", c[:10], ErrMalformed},
		{"flipped ts bit", flip(3), ErrBadMAC},
		{"flipped rand bit", flip(tsLen + 2), ErrBadMAC},
		{"flipped profile kind", flip(tsLen + randLen + versionLen), ErrBadMAC},
		{"flipped profile ttl", flip(tsLen + randLen + versionLen + kindLen), ErrBadMAC},
		{"flipped profile threshold", flip(tsLen + randLen + versionLen + kindLen + ttlLen), ErrBadMAC},
		{"flipped mac bit", flip(bodyLen + 5), ErrBadMAC},
		{"foreign key", foreign, ErrBadMAC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := i.Verify(tc.in, "example.com", now); !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestKeyRotation(t *testing.T) {
	old := issuer(t, Key{Kid: "old", Key: []byte("old-key-old-key-old-key-old-key!")})
	now := time.Unix(1_700_000_000, 0)
	c, _, _ := old.Issue(now, "example.com", testProfile)

	rotated := issuer(t,
		Key{Kid: "new", Key: []byte("new-key-new-key-new-key-new-key!")},
		Key{Kid: "old", Key: []byte("old-key-old-key-old-key-old-key!")},
	)
	if _, _, err := rotated.Verify(c, "example.com", now); err != nil {
		t.Fatalf("old challenge should verify during rotation overlap: %v", err)
	}
}

func TestThreshold(t *testing.T) {
	// Exact checks: difficulty 8 → threshold = 2^248 = 0x01 then 31 zero bytes.
	// Compare semantics: "hash < threshold" ⇔ first byte == 0 ⇔ 8 leading zero
	// bits, which is what difficulty 8 must mean.
	t8, _ := Threshold(8)
	if t8[0] != 0x01 {
		t.Errorf("Threshold(8)[0] = %#x, want 0x01", t8[0])
	}
	for j := 1; j < 32; j++ {
		if t8[j] != 0 {
			t.Fatalf("Threshold(8)[%d] = %#x, want 0", j, t8[j])
		}
	}
	// difficulty 0 → all ones (accept any hash).
	t0, _ := Threshold(0)
	if t0[0] != 0xff || t0[31] != 0xff {
		t.Errorf("Threshold(0) not saturated: % x", t0[:4])
	}
	// Fractional difficulty sits strictly between its integer neighbors.
	lo, _ := Threshold(9)
	mid, _ := Threshold(8.5)
	hi, _ := Threshold(8)
	if !(lessThan(lo, mid) && lessThan(mid, hi)) {
		t.Errorf("Threshold not monotone: T(9)=%x T(8.5)=%x T(8)=%x", lo[:3], mid[:3], hi[:3])
	}
	// Out of range.
	if _, err := Threshold(-1); err == nil {
		t.Error("Threshold(-1) accepted")
	}
	if _, err := Threshold(256); err == nil {
		t.Error("Threshold(256) accepted")
	}
}

func lessThan(a, b [32]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func TestCheckPoW(t *testing.T) {
	// Known-answer test: find a nonce by brute force at a tiny difficulty,
	// confirm CheckPoW accepts it and rejects its neighbor.
	th, _ := Threshold(8) // 1-in-256 hashes
	c := "test-challenge"
	nonce := solve(t, c, th)
	if err := CheckPoW(c, nonce, th); err != nil {
		t.Fatalf("CheckPoW rejected a valid solution: %v", err)
	}
	if err := CheckPoW(c, nonce+"x", th); err == nil {
		// Overwhelmingly likely to fail; if this ever flakes the nonce+“x”
		// hash happened to meet difficulty 8 (p = 1/256) — tighten if seen.
		t.Fatal("CheckPoW accepted a mutated solution")
	}
	// Equality is rejected: craft threshold equal to the hash itself.
	h := sha256.Sum256([]byte(c + nonce))
	if err := CheckPoW(c, nonce, h); !errors.Is(err, ErrWrongPoW) {
		t.Fatalf("hash == threshold must be rejected, got %v", err)
	}
}

func solve(t *testing.T, challenge string, threshold [32]byte) string {
	t.Helper()
	for n := 0; n < 1_000_000; n++ {
		nonce := strconv.Itoa(n)
		if CheckPoW(challenge, nonce, threshold) == nil {
			return nonce
		}
	}
	t.Fatal("no solution found in 1e6 attempts")
	return ""
}

func TestVerifyReturnsIssueTimeForPassExpiry(t *testing.T) {
	// The security property behind the returned timestamp: a solved challenge
	// stays verifiable inside the window (no single-use bookkeeping), but
	// because callers derive the pass expiry from the ISSUE time, redeeming a
	// solve late buys only the remaining lifetime — so a (challenge, nonce)
	// pair decays rather than lasting. Sharing a FRESH one still works; short
	// lifetimes bound stale reuse, not active coordination.
	i := issuer(t)
	now := time.Unix(1_700_000_000, 0)
	c, _, _ := i.Issue(now, "example.com", testProfile)

	issuedAt, profile, err := i.Verify(c, "example.com", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("replay inside window should verify: %v", err)
	}
	if !issuedAt.Equal(now) {
		t.Fatalf("issuedAt = %v, want the original issue time %v", issuedAt, now)
	}
	if profile != testProfile {
		t.Fatalf("verified profile = %+v, want %+v", profile, testProfile)
	}
	// A pass_ttl of 10s derived from issuedAt is already dead 30s later.
	if exp := issuedAt.Add(10 * time.Second); !exp.Before(now.Add(30 * time.Second)) {
		t.Fatal("late redemption should yield an already-expired pass window")
	}
	if _, _, err := i.Verify(c, "example.com", now.Add(testProfile.TTL+time.Minute)); !errors.Is(err, ErrStale) {
		t.Fatalf("replay outside window = %v, want ErrStale", err)
	}
}
