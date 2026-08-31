package gate

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

// The proxy must reuse its connections to the upstream. Go's default transport
// keeps two idle per host, which under load turns every request into a TCP
// handshake and a TIME_WAIT socket — measurably the gate's first ceiling, and
// nothing to do with the gate's own work. This test pins the property the fix
// provides: repeated bursts of concurrent requests reuse the connections the
// first burst opened. With two idle connections kept, each burst opens about
// `burst` new ones and the total grows every round; with the pool sized to the
// concurrency, the total stays near one round's worth. (Not exactly: a request
// that starts dialling just as another returns its connection may end up with
// both, so the bound leaves room for that race.)
func TestUpstreamConnectionsAreReused(t *testing.T) {
	const burst, rounds = 32, 5

	var opened atomic.Int32
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "User-agent: *\n")
	}))
	up.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	up.Start()
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + fastCfg + "[bypass]\npaths = [\"/robots.txt\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	g, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	fire := func() {
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if w := do(g, agentReq("/robots.txt")); w.Code != 200 {
					t.Errorf("bypass: status %d", w.Code)
				}
			}()
		}
		wg.Wait()
	}

	for i := 0; i < rounds; i++ {
		fire()
	}
	if n := opened.Load(); n > 2*burst {
		t.Fatalf("%d rounds of %d concurrent requests opened %d upstream connections; "+
			"a transport that keeps its idle connections opens about %d", rounds, burst, n, burst)
	}
}
