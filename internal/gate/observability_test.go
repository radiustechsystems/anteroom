package gate

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

// loggingGate builds a gate in front of an upstream the test controls, logging
// at Info — the level an operator gets WITHOUT -v. Everything asserted here has
// to be audible without anyone having gone looking.
func loggingGate(t *testing.T, cfgBody string, h http.HandlerFunc) (*Gate, *bytes.Buffer, *http.Cookie) {
	t.Helper()
	up := httptest.NewServer(h)
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
	g, err := New(cfg, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	pass := solveAndGetCookie(t, g, nil)
	buf.Reset() // drop startup and solve traffic; each test asserts on its own
	return g, &buf, pass
}

// A skipped injection warns once per reason at the default log level, avoiding
// per-request noise while keeping silent renewal failures diagnosable.
func TestSkippedInjectionIsReportedOnceWithItsReason(t *testing.T) {
	// script-src 'none' admits no script of ours by any means — rule 3 of
	// docs/operating.md — so planCSP returns modeSkip.
	g, buf, pass := loggingGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "script-src 'none'")
		io.WriteString(w, simplePage)
	})

	for i := 0; i < 5; i++ {
		if body := do(g, docReq("/page", pass)).Body.String(); strings.Contains(body, pathRenew) {
			t.Fatal("this upstream's CSP should have blocked the injection")
		}
	}

	log := buf.String()
	if n := strings.Count(log, "renewal script not injected"); n != 1 {
		t.Errorf("five blocked page loads produced %d warnings, want exactly 1:\n%s", n, log)
	}
	// The reason has to be in the line. "Something was skipped" sends the
	// operator back to reading source; naming the policy sends them to the CSP.
	if !strings.Contains(log, "content-security-policy-forbids-our-script") {
		t.Errorf("the warning does not name why:\n%s", log)
	}
	// And the consequence, because "not injected" means nothing to someone who
	// has not read inject.go.
	if !strings.Contains(log, "lapse") {
		t.Errorf("the warning does not say what it costs the visitor:\n%s", log)
	}
}

// Different reasons are different diagnoses, so once-per-reason must not collapse
// into once-per-process. A site with a CSP problem on one route and a
// mislabelled response on another has two things to fix and must hear both.
func TestEachSkipReasonIsReportedSeparately(t *testing.T) {
	g, buf, pass := loggingGate(t, "", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/blocked" {
			w.Header().Set("Content-Security-Policy", "script-src 'none'")
			io.WriteString(w, simplePage)
			return
		}
		// text/html by Content-Type, JSON by content: believe the bytes.
		io.WriteString(w, `{"ok":true}`)
	})

	do(g, docReq("/blocked", pass))
	do(g, docReq("/json", pass))

	log := buf.String()
	for _, want := range []string{
		"content-security-policy-forbids-our-script",
		"body-is-not-a-document",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("reason %q never reported:\n%s", want, log)
		}
	}
}

// The counterpart, and the reason the warning is once-per-reason rather than
// simply rate-limited: a healthy site must produce none of this. A warning that
// fires on correct behaviour trains the operator to ignore the one that matters.
func TestASuccessfulInjectionSaysNothing(t *testing.T) {
	g, buf, pass := loggingGate(t, "", htmlHandler(simplePage))
	for i := 0; i < 3; i++ {
		if body := do(g, docReq("/page", pass)).Body.String(); !strings.Contains(body, pathRenew) {
			t.Fatal("expected the injection to happen")
		}
	}
	if log := buf.String(); strings.Contains(log, "not injected") {
		t.Errorf("a working injection logged a complaint:\n%s", log)
	}
}

// inject = false is an operator's choice, but it is also the setting that turns
// renewal off entirely, and it is set far more often by copying someone's config
// than by deciding. Say what it costs, once, at startup.
func TestInjectOffIsAnnouncedAtStartup(t *testing.T) {
	_, buf, _ := func() (*Gate, *bytes.Buffer, *http.Cookie) {
		up := httptest.NewServer(htmlHandler(simplePage))
		t.Cleanup(up.Close)
		cfgPath := filepath.Join(t.TempDir(), "anteroom.toml")
		body := "upstream = \"" + up.URL + "\"\ninject = false\n" + fastCfg
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		var buf bytes.Buffer
		g, err := New(cfg, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		if err != nil {
			t.Fatalf("gate.New: %v", err)
		}
		return g, &buf, nil
	}()
	log := buf.String()
	if !strings.Contains(log, "inject is off") {
		t.Errorf("turning renewal off said nothing at startup:\n%s", log)
	}
	if !strings.Contains(log, "re-challenged") {
		t.Errorf("the warning does not say what it costs the visitor:\n%s", log)
	}
}

// The browser half of the same silence. A visitor whose renewal worker never
// registers — private browsing, an enterprise policy, plain HTTP — browses a
// page that works and meets a checkpoint a minute later, and devtools shows
// nothing connecting the two, because the renewal fetches that are missing are
// invisible by construction. One console line is the entire difference between
// "the site is broken" and a cause.
//
// Pinned here rather than in a browser test because the failure mode is that the
// line is silently removed while the no-renewal behavior still looks normal.
func TestTheServedRenewalScriptSaysWhenItCannotRun(t *testing.T) {
	g, _, _ := loggingGate(t, "", htmlHandler(simplePage))
	w := do(g, httptest.NewRequest("GET", pathRenew, nil))
	if w.Code != 200 {
		t.Fatalf("%s: status %d", pathRenew, w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "console.warn") {
		t.Error("the served renewal script reports nothing when it cannot start; " +
			"a visitor whose worker never registers has no symptom at all")
	}
	// Both ways it can fail to start, or one of them goes quiet again.
	for _, want := range []string{"secure context", "could not be registered"} {
		if !strings.Contains(body, want) {
			t.Errorf("no message for the %q case:\n%s", want, body)
		}
	}
	// And it must stay a warning about renewal specifically. A bare
	// console.warn("error") in someone else's console is noise, not a
	// diagnosis.
	if !strings.Contains(body, "[anteroom]") {
		t.Error("the message does not identify itself as Anteroom's")
	}
}
