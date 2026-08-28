package gate

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

// verboseGate builds a gate logging at the level `anteroom -v` selects, plus the
// buffer it logs into.
func verboseGate(t *testing.T, cfgBody string, level slog.Level) (*Gate, *bytes.Buffer, *http.Cookie) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, simplePage)
	}))
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	body := "upstream = \"" + up.URL + "\"\n" + fastCfg + cfgBody
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	var buf bytes.Buffer
	g, err := New(cfg, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	pass := solveAndGetCookie(t, g, nil)
	buf.Reset() // drop the solve traffic; each test asserts on its own request
	return g, &buf, pass
}

// TestVerboseLogsTheRungThatAnswered pins the vocabulary of the log line to the
// rungs of the ladder. The point of -v is answering "why did this request get
// walled?", which only works if the decision names a rung.
func TestVerboseLogsTheRungThatAnswered(t *testing.T) {
	tests := []struct {
		name     string
		cfg      string
		request  func(pass *http.Cookie) *http.Request
		decision string
		status   string
	}{
		{
			name:     "admitted browser",
			request:  func(p *http.Cookie) *http.Request { return docReq("/page", p) },
			decision: "pass-pow",
			status:   "200",
		},
		{
			name:     "walled browser",
			request:  func(*http.Cookie) *http.Request { return browserReq("/page") },
			decision: "wait-page",
			status:   "403",
		},
		{
			name:     "refused agent",
			request:  func(*http.Cookie) *http.Request { return agentReq("/page") },
			decision: "refusal",
			status:   "403",
		},
		{
			name:     "bypassed path",
			cfg:      "[bypass]\npaths = [\"/robots.txt\"]\n",
			request:  func(*http.Cookie) *http.Request { return agentReq("/robots.txt") },
			decision: "bypass-path",
			status:   "200",
		},
		{
			name: "bypassed range",
			cfg:  "[bypass]\ncidrs = [\"203.0.113.0/24\"]\n",
			request: func(*http.Cookie) *http.Request {
				r := agentReq("/page")
				r.RemoteAddr = "203.0.113.5:1234"
				return r
			},
			decision: "bypass-ip",
			status:   "200",
		},
		{
			name:     "own endpoint",
			request:  func(*http.Cookie) *http.Request { return httptest.NewRequest("GET", HealthPath, nil) },
			decision: "own-endpoint",
			status:   "200",
		},
		{
			name: "non-canonical path",
			request: func(*http.Cookie) *http.Request {
				r := agentReq("/a")
				r.URL.Path = "/.well-known/../admin"
				return r
			},
			decision: "non-canonical-path",
			status:   "400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, buf, pass := verboseGate(t, tt.cfg, slog.LevelDebug)
			do(g, tt.request(pass))

			line := buf.String()
			if strings.Count(line, "msg=hit") != 1 {
				t.Fatalf("want exactly one hit line, got:\n%s", line)
			}
			if !strings.Contains(line, "decision="+tt.decision) {
				t.Errorf("decision missing from log line:\nwant decision=%s\ngot %s", tt.decision, line)
			}
			if !strings.Contains(line, "status="+tt.status) {
				t.Errorf("status missing from log line:\nwant status=%s\ngot %s", tt.status, line)
			}
			for _, want := range []string{"method=GET", "path=", "bytes=", "dur="} {
				if !strings.Contains(line, want) {
					t.Errorf("log line lacks %q: %s", want, line)
				}
			}
		})
	}
}

// TestQuietByDefault: per-request logging is opt-in. Verbosity by default
// trains operators to ignore logs.
func TestQuietByDefault(t *testing.T) {
	g, buf, pass := verboseGate(t, "", slog.LevelInfo)
	do(g, docReq("/page", pass))
	do(g, agentReq("/other"))
	if strings.Contains(buf.String(), "msg=hit") {
		t.Errorf("logged per-request without -v:\n%s", buf)
	}
}

// TestVerboseDoesNotAlterTheResponse is why the recorder exists as a thin
// wrapper: turning on logging must not change a single byte, a status, or the
// injection behaviour.
func TestVerboseDoesNotAlterTheResponse(t *testing.T) {
	quiet, _, qPass := verboseGate(t, "", slog.LevelInfo)
	loud, _, lPass := verboseGate(t, "", slog.LevelDebug)

	q := do(quiet, docReq("/page", qPass))
	l := do(loud, docReq("/page", lPass))

	if q.Code != l.Code {
		t.Errorf("status differs with -v: %d vs %d", q.Code, l.Code)
	}
	if q.Body.String() != l.Body.String() {
		t.Errorf("body differs with -v:\n quiet %q\n loud  %q", q.Body, l.Body)
	}
	// And the injection still happened, i.e. the recorder did not swallow the
	// injector's writes.
	if !strings.Contains(l.Body.String(), externalTag) {
		t.Error("injection lost when -v is on")
	}
}

// TestVerboseCountsBytesActuallyWritten guards against the recorder reporting the
// pre-injection length, which would make the log quietly wrong.
func TestVerboseCountsBytesActuallyWritten(t *testing.T) {
	g, buf, pass := verboseGate(t, "", slog.LevelDebug)
	res := do(g, docReq("/page", pass))

	want := "bytes=" + strconv.Itoa(res.Body.Len())
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log says something other than %q:\n%s", want, buf)
	}
	if res.Body.Len() <= len(simplePage) {
		t.Fatal("expected the injected body to be longer than the upstream's")
	}
}
