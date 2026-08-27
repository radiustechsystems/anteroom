package payment

import (
	"encoding/json"
	"errors"
	"testing"
)

// A payment's identity must come from the authorization the SERVER's rail
// selected, never from whichever recognised object the payer chose to include.
//
// Scanning for the first recognised object was an identity-forging primitive.
// An eip3009 payment carries its real authorization under `authorization`; a
// payer may bolt on a `permit2Authorization` that no rail selected, and a scan
// preferring permit2 hashes the decoy. Varying a field nobody settles then
// yields a fresh local identity for one settled authorization, and the recovery
// path — which exists so a payment with an unknown settle outcome can be
// re-presented — mints a second pass from the facilitator's cached success.
func TestIdentityIgnoresUnselectedAuthorizations(t *testing.T) {
	eip3009 := reqs()
	eip3009.Extra["assetTransferMethod"] = "eip3009"
	mk := func(decoyNonce string) Payload {
		sp, err := json.Marshal(map[string]any{
			"authorization": map[string]any{
				"from": "0xpayer", "nonce": "0x1234", "value": "10000",
			},
			"signature": "0xsig",
			"permit2Authorization": map[string]any{
				"from": "0xpayer", "nonce": decoyNonce,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return Payload{X402Version: Version, Payload: sp}
	}
	// Two recognised objects at once is refused outright: there is no honest
	// reason to send both, and choosing between them is the judgement that
	// produced the defect.
	if _, err := ID(mk("0xDECOY-1"), eip3009); !errors.Is(err, ErrUnidentifiedPayment) {
		t.Fatalf("a payload naming two authorization objects was accepted: err = %v", err)
	}

	// And with only the selected object present, identity is stable.
	clean := func() Payload {
		sp, _ := json.Marshal(map[string]any{
			"authorization": map[string]any{"from": "0xpayer", "nonce": "0x1234"},
			"signature":     "0xsig",
		})
		return Payload{X402Version: Version, Payload: sp}
	}
	a, err := ID(clean(), eip3009)
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	b, err := ID(clean(), eip3009)
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if a != b {
		t.Error("identity is not stable for one authorization")
	}

	// The same authorizer and nonce under a different transfer method is a
	// different nonce namespace, so it must not collide.
	sp, _ := json.Marshal(map[string]any{
		"permit2Authorization": map[string]any{"from": "0xpayer", "nonce": "0x1234"},
	})
	c, err := ID(Payload{X402Version: Version, Payload: sp}, reqs())
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if c == a {
		t.Error("permit2 and eip3009 nonce namespaces collide")
	}
}
