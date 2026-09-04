package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "json"}, false)
	lg.Info("anteroom is up", "listen", "127.0.0.1:8080")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("json: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "anteroom is up" {
		t.Errorf("msg = %v", rec["msg"])
	}
	if rec["listen"] != "127.0.0.1:8080" {
		t.Errorf("listen = %v", rec["listen"])
	}
	if rec["level"] != "INFO" {
		t.Errorf("level = %v", rec["level"])
	}
}

func TestNewLogfmt(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "logfmt"}, false)
	lg.Info("anteroom is up", "listen", "127.0.0.1:8080")
	line := buf.String()
	for _, want := range []string{"ts=", "level=info", `msg="anteroom is up"`, "listen=127.0.0.1:8080"} {
		if !strings.Contains(line, want) {
			t.Errorf("logfmt line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "time=") {
		t.Errorf("logfmt still used time= rather than ts=:\n%s", line)
	}
}

func TestNewText(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "text"}, false)
	lg.Info("hit", "decision", "pass-pow")
	line := buf.String()
	if !strings.Contains(line, "msg=hit") || !strings.Contains(line, "decision=pass-pow") {
		t.Errorf("text line:\n%s", line)
	}
}

func TestVerboseForcesDebug(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "error", Format: "text"}, true)
	lg.Debug("hit", "decision", "wait-page")
	if !strings.Contains(buf.String(), "msg=hit") {
		t.Errorf("-v should force debug, got:\n%s", buf.String())
	}
}

func TestLabelsAreStableAndPresent(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{
		Level:  "info",
		Format: "json",
		Labels: map[string]string{"service": "anteroom", "cluster": "prod"},
	}, false)
	lg.Info("up")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["service"] != "anteroom" || rec["cluster"] != "prod" {
		t.Errorf("labels missing: %v", rec)
	}
}

func TestContextFieldsAttachOnlyWithContextMethods(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "json"}, false)
	ctx := Bind(context.Background(), Fields{
		RequestID: "req-1",
		TraceID:   "0af7651916cd43dd8448eb211c80319c",
		SpanID:    "b7ad6b7169203331",
	})
	lg.Info("without")
	lg.InfoContext(ctx, "with")

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), buf.String())
	}
	var without, with map[string]any
	if err := json.Unmarshal(lines[0], &without); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &with); err != nil {
		t.Fatal(err)
	}
	if _, ok := without["request_id"]; ok {
		t.Errorf("Info without context still has request_id: %v", without)
	}
	if with["request_id"] != "req-1" || with["trace_id"] != "0af7651916cd43dd8448eb211c80319c" || with["span_id"] != "b7ad6b7169203331" {
		t.Errorf("InfoContext missing fields: %v", with)
	}
}

func TestWithPreservesContextHandler(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "json", Labels: map[string]string{"service": "anteroom"}}, false)
	ctx := Bind(context.Background(), Fields{RequestID: "req-2"})
	lg.With("listen", ":8080").InfoContext(ctx, "up")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["service"] != "anteroom" || rec["listen"] != ":8080" || rec["request_id"] != "req-2" {
		t.Errorf("child logger dropped attrs: %v", rec)
	}
}

func TestQuietByDefaultHidesDebug(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, config.Log{Level: "info", Format: "text"}, false)
	lg.Debug("hit")
	if buf.Len() != 0 {
		t.Errorf("debug leaked at info: %s", buf.String())
	}
}
