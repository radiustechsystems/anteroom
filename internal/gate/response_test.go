package gate

import (
	"bytes"
	"net/http"
	"reflect"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/payment"
)

type statusWriter struct {
	header   http.Header
	statuses []int
	body     bytes.Buffer
}

func (w *statusWriter) Header() http.Header { return w.header }
func (w *statusWriter) WriteHeader(status int) {
	w.statuses = append(w.statuses, status)
}
func (w *statusWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func TestPaidWriterSealsOnlyTheFinalResponse(t *testing.T) {
	base := &statusWriter{header: make(http.Header)}
	base.header.Set("Set-Cookie", cookieName+"=grant; Path=/")
	base.header.Set("Link", "</style.css>; rel=preload")
	p := &paidWriter{ResponseWriter: base, settle: "receipt"}
	p.WriteHeader(http.StatusEarlyHints)
	if p.sealed {
		t.Fatal("103 sealed the paid response")
	}
	if got := base.header.Get("Set-Cookie"); got != "" {
		t.Fatalf("grant cookie leaked into 103: %q", got)
	}

	// ReverseProxy clears the shared map after forwarding each informational
	// response, then populates it with the final upstream headers.
	clear(base.header)
	base.header.Set("Cache-Control", "public, max-age=3600")
	base.header.Set(payment.HeaderRequired, "upstream-offer")
	p.WriteHeader(http.StatusOK)
	if !reflect.DeepEqual(base.statuses, []int{http.StatusEarlyHints, http.StatusOK}) {
		t.Fatalf("statuses = %v", base.statuses)
	}
	if got := base.header.Get("Cache-Control"); got != "no-store, private" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := base.header.Get("Set-Cookie"); got == "" {
		t.Fatal("grant cookie was not restored on the final response")
	}
	if got := base.header.Get(payment.HeaderResponse); got != "receipt" {
		t.Fatalf("receipt = %q", got)
	}
	if got := base.header.Get(payment.HeaderRequired); got != "" {
		t.Fatalf("upstream offer survived: %q", got)
	}
}

func TestInjectorTreatsEarlyHintsAsInformational(t *testing.T) {
	base := &statusWriter{header: make(http.Header)}
	i := newInjector(base, nil)
	base.header.Set("Link", "</style.css>; rel=preload")
	i.WriteHeader(http.StatusEarlyHints)
	clear(base.header)
	base.header.Set("Content-Type", "text/plain")
	i.WriteHeader(http.StatusNotFound)
	_, _ = i.Write([]byte("missing"))
	i.finish()
	if !reflect.DeepEqual(base.statuses, []int{http.StatusEarlyHints, http.StatusNotFound}) {
		t.Fatalf("statuses = %v", base.statuses)
	}
	if got := base.body.String(); got != "missing" {
		t.Fatalf("body = %q", got)
	}
}

func TestRecorderReportsTheFinalStatusAfterEarlyHints(t *testing.T) {
	base := &statusWriter{header: make(http.Header)}
	rec := &recorder{ResponseWriter: base, status: http.StatusOK}
	rec.WriteHeader(http.StatusEarlyHints)
	rec.WriteHeader(http.StatusNoContent)

	if !reflect.DeepEqual(base.statuses, []int{http.StatusEarlyHints, http.StatusNoContent}) {
		t.Fatalf("forwarded statuses = %v", base.statuses)
	}
	if rec.status != http.StatusNoContent || !rec.wrote {
		t.Fatalf("recorded status = %d, wrote = %t", rec.status, rec.wrote)
	}
}
