package gate

import (
	"net/http"
	"strings"
	"testing"

	"github.com/radiustechsystems/anteroom/internal/config"
)

func TestPaidScopeIsThePathSetNotTheRuleName(t *testing.T) {
	compile := func(name string, paths ...string) string {
		t.Helper()
		routes, err := compilePaidRoutes(&config.Payments{Rules: []config.Rule{{
			Name: name, Paths: paths,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return routes[0].scope
	}
	base := compile("reports", "/reports/*", "/invoices/*")
	if renamed := compile("paid-content", "/invoices/*", "/reports/*"); renamed != base {
		t.Fatal("renaming or reordering an unchanged route invalidated its scope")
	}
	if widened := compile("reports", "/reports/*", "/invoices/*", "/admin/*"); widened == base {
		t.Fatal("widening a reused rule name preserved the old scope")
	}
}

func TestPassIsBoundToTheAuthorityThatMintedIt(t *testing.T) {
	g, _ := newTestGate(t, fastCfg)
	pass := solveAndGetCookie(t, g, nil)
	r := browserReq("/private")
	r.Host = "other.example"
	r.AddCookie(pass)
	if got := do(g, r); strings.Contains(got.Body.String(), "UPSTREAM:") {
		t.Fatal("a pass minted for example.com admitted other.example")
	}

	same := browserReq("/private")
	same.Host = "EXAMPLE.COM."
	same.AddCookie(pass)
	if got := do(g, same); got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "UPSTREAM:") {
		t.Fatalf("canonical spelling of the same authority was refused: %d", got.Code)
	}
}
