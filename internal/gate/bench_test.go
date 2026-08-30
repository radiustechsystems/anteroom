package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/challenge"
)

// What one request costs at each rung of the ladder, with the network taken
// out: the handler is called directly, the upstream is an in-process
// httptest server. These are the per-component numbers the k6 harness in
// bench/ cannot isolate, and the k6 numbers are the ones with the network back
// in. Run `make bench-go`; compare with benchstat, on one machine.
//
// The upstream serves a small HTML page so the injection rungs have something
// to rewrite. Requests are built once and cloned per iteration: the request
// object is part of the cost being measured only insofar as the gate reads it.

// upstreamGate prepends fastCfg (low difficulty, short pass_ttl); top-level
// keys must come before the [bypass] table, so variants prepend to this.
const benchCfg = `
[bypass]
paths = ["/robots.txt", "/.well-known/*"]
`

func benchGate(b *testing.B, cfg string) *Gate {
	b.Helper()
	g, _ := upstreamGate(b, cfg, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/items" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"items":[1,2,3]}`)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, simplePage)
	})
	return g
}

// serve runs the request through the gate b.N times, serially, and reports
// allocations. A fresh recorder per iteration (a ResponseRecorder cannot be
// reset once written to); its cost is the same constant in every row.
func serve(b *testing.B, g *Gate, r *http.Request) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r.Clone(r.Context()))
		if w.Code == 0 || w.Code >= 500 {
			b.Fatalf("status %d", w.Code)
		}
	}
}

// serveParallel does the same across GOMAXPROCS goroutines: what the gate's
// shared state (metrics, keyring) costs under contention.
func serveParallel(b *testing.B, g *Gate, r *http.Request) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			g.ServeHTTP(w, r.Clone(r.Context()))
			if w.Code == 0 || w.Code >= 500 {
				b.Fatalf("status %d", w.Code)
			}
		}
	})
}

func BenchmarkServeHTTP(b *testing.B) {
	g := benchGate(b, benchCfg)
	pass := solveAndGetCookie(b, g, nil)

	b.Run("bypass", func(b *testing.B) { serve(b, g, agentReq("/robots.txt")) })
	b.Run("refusal", func(b *testing.B) { serve(b, g, agentReq("/api/items")) })
	b.Run("refusal_json", func(b *testing.B) {
		r := agentReq("/api/items")
		r.Header.Set("Accept", "application/json")
		serve(b, g, r)
	})
	b.Run("wait_page", func(b *testing.B) { serve(b, g, browserReq("/")) })
	b.Run("challenge", func(b *testing.B) { serve(b, g, httptest.NewRequest("GET", pathChallenge, nil)) })
	b.Run("pass_json", func(b *testing.B) {
		r := browserReq("/api/items")
		r.Header.Set("Sec-Fetch-Mode", "cors")
		r.Header.Set("Sec-Fetch-Dest", "empty")
		r.AddCookie(pass)
		serve(b, g, r)
	})
	b.Run("pass_html_inject", func(b *testing.B) { serve(b, g, docReq("/", pass)) })

	b.Run("parallel/refusal", func(b *testing.B) { serveParallel(b, g, agentReq("/api/items")) })
	b.Run("parallel/pass_html_inject", func(b *testing.B) { serveParallel(b, g, docReq("/", pass)) })
}

func BenchmarkServeHTTP_NoInject(b *testing.B) {
	g := benchGate(b, "inject = false\n"+benchCfg)
	pass := solveAndGetCookie(b, g, nil)
	b.Run("pass_html", func(b *testing.B) { serve(b, g, docReq("/", pass)) })
}

// The answer endpoint: one challenge is solved up front and the same answer is
// submitted b.N times. The first submission mints a pass; every later one is
// the identical verification path, which is what this measures. (Challenges
// are stateless, so a replay is not refused as such — the pass it mints is
// what the visitor gets, same as the first time.)
func BenchmarkAnswer(b *testing.B) {
	g := benchGate(b, benchCfg)
	cw := do(g, httptest.NewRequest("GET", pathChallenge, nil))
	if cw.Code != 200 {
		b.Fatalf("challenge: %d", cw.Code)
	}
	var ch challengeResponse
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		b.Fatal(err)
	}
	th, err := hexTo32(ch.Threshold)
	if err != nil {
		b.Fatal(err)
	}
	nonce := ""
	for n := 0; n < 1_000_000; n++ {
		if challenge.CheckPoW(ch.Challenge, strconv.Itoa(n), th) == nil {
			nonce = strconv.Itoa(n)
			break
		}
	}
	if nonce == "" {
		b.Fatal("no solution")
	}
	body, _ := json.Marshal(answerRequest{Challenge: ch.Challenge, Nonce: nonce})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", pathAnswer, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "192.0.2.10:44321"
		g.ServeHTTP(w, r)
		if w.Code != 200 {
			b.Fatalf("answer: %d %s", w.Code, w.Body)
		}
	}
}
