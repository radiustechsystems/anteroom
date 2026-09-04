package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/logging"
)

func TestRequestIDIsForwardedUpstream(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, simplePage)
	}))
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, logging.New(io.Discard, cfg.Log, false))
	if err != nil {
		t.Fatal(err)
	}
	pass := solveAndGetCookie(t, g, nil)

	r := docReq("/page", pass)
	r.Header.Set(logging.HeaderRequestID, "keep-me")
	r.Header.Set(logging.HeaderTraceparent, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	if res := do(g, r); res.Code != 200 {
		t.Fatalf("status %d", res.Code)
	}
	if got := seen.Get(logging.HeaderRequestID); got != "keep-me" {
		t.Errorf("upstream X-Request-ID = %q, want keep-me", got)
	}
	if got := seen.Get(logging.HeaderTraceparent); got != "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01" {
		t.Errorf("upstream traceparent = %q", got)
	}

	r = docReq("/page", pass)
	if res := do(g, r); res.Code != 200 {
		t.Fatalf("status %d", res.Code)
	}
	if got := seen.Get(logging.HeaderRequestID); got == "" || got == "keep-me" {
		t.Errorf("generated X-Request-ID missing or reused: %q", got)
	}
}

func TestHitLineCarriesRequestContext(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, simplePage)
	}))
	t.Cleanup(up.Close)

	cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
	if err := os.WriteFile(cfgPath, []byte("upstream = \""+up.URL+"\"\n"+fastCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	g, err := New(cfg, logging.New(&buf, config.Log{Level: "info", Format: "json"}, true))
	if err != nil {
		t.Fatal(err)
	}
	pass := solveAndGetCookie(t, g, nil)
	buf.Reset()

	r := docReq("/page", pass)
	r.Header.Set(logging.HeaderRequestID, "hit-req")
	r.Header.Set(logging.HeaderTraceparent, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	do(g, r)

	var rec map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if !bytes.Contains(line, []byte(`"msg":"hit"`)) {
			continue
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("json: %v\n%s", err, line)
		}
		break
	}
	if rec == nil {
		t.Fatalf("no hit line in:\n%s", buf.String())
	}
	if rec["request_id"] != "hit-req" {
		t.Errorf("request_id = %v", rec["request_id"])
	}
	if rec["trace_id"] != "0af7651916cd43dd8448eb211c80319c" || rec["span_id"] != "b7ad6b7169203331" {
		t.Errorf("trace = %v %v", rec["trace_id"], rec["span_id"])
	}
	if rec["decision"] != "pass-pow" {
		t.Errorf("decision = %v", rec["decision"])
	}
}
