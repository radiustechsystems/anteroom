package challenge

import (
	"strconv"
	"testing"
	"time"
)

// The stateless puzzle, piece by piece. Issue and Verify are one HMAC each;
// CheckPoW is one SHA-256 — "the entire server-side cost" of an answer. The
// numbers here bound what the answer endpoint can ever cost before HTTP.

func benchIssuer(b *testing.B) *Issuer {
	b.Helper()
	i, err := NewIssuer(testKeys)
	if err != nil {
		b.Fatal(err)
	}
	return i
}

func BenchmarkIssue(b *testing.B) {
	i := benchIssuer(b)
	now := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, _, err := i.Issue(now, "example.com", testProfile); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	i := benchIssuer(b)
	now := time.Unix(1_700_000_000, 0)
	c, _, err := i.Issue(now, "example.com", testProfile)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, _, err := i.Verify(c, "example.com", now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkThreshold(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := Threshold(14); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckPoW(b *testing.B) {
	i := benchIssuer(b)
	c, _, err := i.Issue(time.Unix(1_700_000_000, 0), "example.com", testProfile)
	if err != nil {
		b.Fatal(err)
	}
	th := testProfile.Threshold
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if CheckPoW(c, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		b.Fatal("no solution")
	}
	b.Run("accept", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if err := CheckPoW(c, nonce, th); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reject", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if err := CheckPoW(c, nonce+"x", th); err == nil {
				b.Fatal("accepted a wrong nonce")
			}
		}
	})
}

// How long a solve takes in Go, per bit of difficulty: the client's side of the
// bargain, for calibrating `difficulty` against the docs' "about a second".
// Expect the time to double per bit.
func BenchmarkSolve(b *testing.B) {
	i := benchIssuer(b)
	for _, bits := range []float64{8, 10, 12} {
		th, err := Threshold(bits)
		if err != nil {
			b.Fatal(err)
		}
		p := Profile{Kind: KindAdmit, TTL: time.Minute, Threshold: th}
		b.Run("difficulty="+strconv.Itoa(int(bits)), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				c, _, err := i.Issue(time.Unix(1_700_000_000+int64(n), 0), "example.com", p)
				if err != nil {
					b.Fatal(err)
				}
				found := false
				for k := 0; k < 1<<24; k++ {
					if CheckPoW(c, strconv.Itoa(k), th) == nil {
						found = true
						break
					}
				}
				if !found {
					b.Fatal("no solution")
				}
			}
		})
	}
}
