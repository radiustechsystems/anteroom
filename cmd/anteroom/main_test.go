package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestBindError pins which failures get the privileged-port explanation. Adding
// advice to the wrong error is worse than adding none: an operator chasing a
// capability grant will not notice that the port was simply already in use.
func TestBindError(t *testing.T) {
	perm := func(addr string) error {
		return fmt.Errorf("listen tcp %s: bind: %w", addr, syscall.EACCES)
	}
	inUse := func(addr string) error {
		return fmt.Errorf("listen tcp %s: bind: %w", addr, syscall.EADDRINUSE)
	}

	tests := []struct {
		name    string
		addr    string
		err     error
		explain bool
	}{
		{"permission denied on port 80", ":80", perm(":80"), true},
		{"permission denied on port 443 with host", "127.0.0.1:443", perm("127.0.0.1:443"), true},
		{"permission denied on the last privileged port", ":1023", perm(":1023"), true},
		{"permission denied on the first unprivileged port", ":1024", perm(":1024"), false},
		{"permission denied on 8080 is something else", ":8080", perm(":8080"), false},
		{"address in use is not a capability problem", ":80", inUse(":80"), false},
		{"unparseable address", "not-an-address", perm("not-an-address"), false},
		{"non-numeric port", ":http", perm(":http"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bindError(tt.addr, tt.err)

			// The cause must survive either way: callers and errors.Is must still
			// see the original syscall.
			if !errors.Is(got, tt.err) {
				t.Errorf("wrapped error lost its cause: %v", got)
			}
			explained := strings.Contains(got.Error(), "privileged")
			if explained != tt.explain {
				t.Errorf("explained = %v, want %v: %v", explained, tt.explain, got)
			}
			if !tt.explain && got.Error() != tt.err.Error() {
				t.Errorf("message changed when it should not have:\n got %v\nwant %v", got, tt.err)
			}
			if tt.explain && !errors.Is(got, os.ErrPermission) {
				t.Errorf("errors.Is(os.ErrPermission) broken by wrapping: %v", got)
			}
		})
	}
}

// TestHealthcheck covers the container's only way to check itself. The image is
// shell-less on purpose, so this probe is the whole HEALTHCHECK: a false
// "healthy" would let an orchestrator route traffic at a gate that cannot
// answer, and a false "unhealthy" restarts a working one.
func TestHealthcheck(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.anteroom/healthz" {
			t.Errorf("probed %q, want /.anteroom/healthz", r.URL.Path)
		}
		w.Write([]byte("ok\n"))
	}))
	defer healthy.Close()

	sick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer sick.Close()

	// A listener that is bound but never accepts stands in for a wedged gate.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close() // nothing listening now: connection refused

	tests := []struct {
		name   string
		listen string
		wantOK bool
	}{
		{"healthy gate", strings.TrimPrefix(healthy.URL, "http://"), true},
		{"non-200 is unhealthy", strings.TrimPrefix(sick.URL, "http://"), false},
		{"nothing listening", deadAddr, false},
		{"unparseable listen", "not-an-address", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := healthcheck(tt.listen)
			if (err == nil) != tt.wantOK {
				t.Fatalf("healthcheck(%q) = %v, wantOK %v", tt.listen, err, tt.wantOK)
			}
		})
	}
}

// TestHealthcheckWildcardHost pins the loopback rewrite. `listen = ":8080"` is
// the container default, and a probe that tried to dial the empty host would
// fail on every healthy gate there is.
func TestHealthcheckWildcardHost(t *testing.T) {
	var probed bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probed = true
		w.Write([]byte("ok\n"))
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, host := range []string{"", "0.0.0.0", "::"} {
		probed = false
		if err := healthcheck(net.JoinHostPort(host, port)); err != nil {
			t.Errorf("healthcheck with host %q: %v", host, err)
		}
		if !probed {
			t.Errorf("host %q never reached the server", host)
		}
	}
}
