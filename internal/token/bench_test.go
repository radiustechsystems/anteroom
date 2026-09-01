package token

import (
	"testing"
	"time"
)

// The pass cookie: Mint is JSON + one HMAC; Verify is base64 + one HMAC + JSON.
// Verify runs on every request that carries a cookie, so it is the per-request
// floor for an admitted visitor.

func BenchmarkMint(b *testing.B) {
	kr := ring(b, keyA)
	p := powPass(time.Unix(1_700_000_000, 0))
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := kr.Mint(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	kr := ring(b, keyA)
	s, err := kr.Mint(powPass(now))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := kr.Verify(s, now); err != nil {
			b.Fatal(err)
		}
	}
}

// Two keys in the ring: the cost of rotation is that a cookie signed by the
// older key is still one lookup, not one attempt per key.
func BenchmarkVerify_RotatedKey(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	old := ring(b, keyA)
	s, err := old.Mint(powPass(now))
	if err != nil {
		b.Fatal(err)
	}
	kr := ring(b, keyB, keyA) // keyB signs now; keyA still verifies
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := kr.Verify(s, now); err != nil {
			b.Fatal(err)
		}
	}
}
