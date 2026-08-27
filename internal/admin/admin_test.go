package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/internal/activity"
	"github.com/radiustechsystems/anteroom/internal/metrics"
)

func newTestAdmin(t *testing.T) *httptest.Server {
	return newTestAdminWith(t, nil)
}

func newTestAdminWith(t *testing.T, act *activity.Log) *httptest.Server {
	t.Helper()
	reg := metrics.NewRegistry()
	reg.Counter("anteroom_test_total", "A gate-owned counter.").Add(7)
	srv := httptest.NewServer(New(reg, act))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, string) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestAdmin(t)
	resp, body := get(t, srv, "/metrics")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Errorf("Content-Type = %q, want the exposition format", ct)
	}
	// The gate's counters and the runtime families both come through.
	for _, want := range []string{
		"anteroom_test_total 7",
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"process_start_time_seconds",
		"anteroom_build_info",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics lacks %q:\n%s", want, body)
		}
	}
}

func TestStatsEndpoint(t *testing.T) {
	srv := newTestAdmin(t)
	resp, body := get(t, srv, "/stats")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	if out["anteroom_test_total"] != float64(7) {
		t.Errorf("anteroom_test_total = %v, want 7", out["anteroom_test_total"])
	}
	if _, ok := out["go_goroutines"]; !ok {
		t.Error("runtime metrics missing from /stats")
	}
}

func TestHealthzAndIndex(t *testing.T) {
	srv := newTestAdmin(t)
	if resp, body := get(t, srv, "/healthz"); resp.StatusCode != 200 || body != "ok\n" {
		t.Errorf("/healthz = %d %q", resp.StatusCode, body)
	}
	resp, body := get(t, srv, "/")
	if resp.StatusCode != 200 || !strings.Contains(body, "/metrics") {
		t.Errorf("index = %d, should link the endpoints:\n%s", resp.StatusCode, body)
	}
}

// TestActivityDisabled pins the 404-with-hint contract: a poller aimed at a
// gate whose operator forgot the [activity] section fails loudly, and
// "disabled" is never confusable with "enabled but empty".
func TestActivityDisabled(t *testing.T) {
	srv := newTestAdmin(t) // nil log
	resp, body := get(t, srv, "/activity")
	if resp.StatusCode != 404 {
		t.Fatalf("/activity disabled = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(body, "[activity]") {
		t.Errorf("404 body should name the fix: %q", body)
	}
}

func TestActivityEndpoint(t *testing.T) {
	act := activity.New(10*time.Minute, 100)
	act.RecordFailure("203.0.113.9")
	act.RecordFailure("203.0.113.9")
	act.RecordAdmit("198.51.100.7")
	act.RecordRenew("198.51.100.7")
	act.RecordRenew("198.51.100.7")
	srv := newTestAdminWith(t, act)

	resp, body := get(t, srv, "/activity")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var out struct {
		Window      string `json:"window"`
		GeneratedAt string `json:"generated_at"`
		IPs         []struct {
			IP             string `json:"ip"`
			FirstSeen      string `json:"first_seen"`
			LastSeen       string `json:"last_seen"`
			Failed         uint64 `json:"failed"`
			SucceededAdmit uint64 `json:"succeeded_admit"`
			SucceededRenew uint64 `json:"succeeded_renew"`
		} `json:"ips"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, body)
	}
	if out.Window != "10m0s" {
		t.Errorf("window = %q", out.Window)
	}
	if _, err := time.Parse(time.RFC3339, out.GeneratedAt); err != nil {
		t.Errorf("generated_at %q not RFC3339: %v", out.GeneratedAt, err)
	}
	if len(out.IPs) != 2 {
		t.Fatalf("got %d entries: %s", len(out.IPs), body)
	}
	for _, e := range out.IPs {
		switch e.IP {
		case "203.0.113.9":
			if e.Failed != 2 || e.SucceededAdmit != 0 || e.SucceededRenew != 0 {
				t.Errorf("203.0.113.9: failed=%d admit=%d renew=%d", e.Failed, e.SucceededAdmit, e.SucceededRenew)
			}
		case "198.51.100.7":
			if e.Failed != 0 || e.SucceededAdmit != 1 || e.SucceededRenew != 2 {
				t.Errorf("198.51.100.7: failed=%d admit=%d renew=%d", e.Failed, e.SucceededAdmit, e.SucceededRenew)
			}
		default:
			t.Errorf("unexpected IP %q", e.IP)
		}
		if _, err := time.Parse(time.RFC3339, e.FirstSeen); err != nil {
			t.Errorf("first_seen %q not RFC3339", e.FirstSeen)
		}
		if _, err := time.Parse(time.RFC3339, e.LastSeen); err != nil {
			t.Errorf("last_seen %q not RFC3339", e.LastSeen)
		}
	}
}

// TestActivityEmptyIsArray: an enabled-but-quiet log answers 200 with
// "ips": [] — a consumer must never need a null branch, and "empty" must be
// distinguishable from the disabled 404.
func TestActivityEmptyIsArray(t *testing.T) {
	srv := newTestAdminWith(t, activity.New(10*time.Minute, 100))
	resp, body := get(t, srv, "/activity")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, `"ips": []`) {
		t.Errorf("empty log should marshal ips as [], got:\n%s", body)
	}
}

func TestActivityWrongMethod(t *testing.T) {
	srv := newTestAdminWith(t, activity.New(10*time.Minute, 100))
	resp, err := srv.Client().Post(srv.URL+"/activity", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /activity = %d, want 405", resp.StatusCode)
	}
}

func TestUnknownAndWrongMethod(t *testing.T) {
	srv := newTestAdmin(t)
	if resp, _ := get(t, srv, "/nope"); resp.StatusCode != 404 {
		t.Errorf("/nope = %d, want 404", resp.StatusCode)
	}
	resp, err := srv.Client().Post(srv.URL+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", resp.StatusCode)
	}
}
