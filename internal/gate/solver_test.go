package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
)

// An immutable URL is a promise that the bytes behind it never change. The gate
// keeps that promise only if a URL it did not author cannot receive an
// immutable response: otherwise anyone can ask for the address a future release
// will use, and a shared cache in front of the gate holds today's bytes under
// tomorrow's key for a year — walling every browser behind that cache once the
// binary is upgraded.
func TestSolverUnknownVersionIsNotImmutable(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)

	for _, path := range []string{
		pathSolverPrefix + "0123456789abcdef0123456789abcdef.js", // a plausible future digest
		pathSolverPrefix + "js",                                  // the pre-digest URL shape
		pathSolverPrefix + "js?v=0123456789ab",                   // ... and its old query form
		g.solverURL + "?v=0123456789ab",                          // the real digest, dressed up
	} {
		w := do(g, httptest.NewRequest("GET", path, nil))
		cc := w.Header().Get("Cache-Control")
		if w.Code == 200 && strings.Contains(cc, "immutable") {
			t.Errorf("%s: immutable 200 for bytes this URL does not name (Cache-Control: %q)", path, cc)
		}
		if w.Code == 200 && !strings.Contains(cc, "no-store") {
			t.Errorf("%s: served %q; an unrecognised solver URL must not be stored at all", path, cc)
		}
	}
}

// The digest in the URL must be a digest of exactly the bytes served, or the
// immutable policy on the matching URL is not justified either.
func TestSolverURLNamesItsBytes(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)

	w := do(g, httptest.NewRequest("GET", g.solverURL, nil))
	if w.Code != 200 {
		t.Fatalf("current solver URL %s: status %d", g.solverURL, w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("current solver is not immutably cacheable: %q", cc)
	}
	name := strings.TrimSuffix(strings.TrimPrefix(g.solverURL, pathSolverPrefix), ".js")
	sum := sha256.Sum256(w.Body.Bytes())
	if want := hex.EncodeToString(sum[:]); !strings.HasPrefix(want, name) {
		t.Errorf("solver URL names %q, bytes hash to %q", name, want)
	}
	// 48 bits was small enough to search for a collision against the bytes a
	// future release will publish; this namespace is adversarial.
	if len(name) < 32 {
		t.Errorf("solver digest %q is %d hex chars; want at least 32 (128 bits)", name, len(name))
	}
	// Two gates configured differently must not share an address.
	other, _ := newTestGate(t, fastCfg+"\nallow_insecure_context = true\n")
	if other.solverURL == g.solverURL {
		t.Error("different solver bundles served from the same immutable URL")
	}
}

// A browser that fetched a wait page seconds before an upgrade asks for the
// previous digest. Refusing it would wall that visitor for no security gain,
// since nothing is being cached either way — so the gate answers with the
// current solver, uncacheably.
func TestSolverStaleVersionStillWorks(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)

	w := do(g, httptest.NewRequest("GET", pathSolverPrefix+"00000000000000000000000000000000.js", nil))
	if w.Code != 200 {
		t.Fatalf("stale solver URL: status %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "anteroomSolve") {
		t.Error("stale solver URL did not return a working solver")
	}
}
