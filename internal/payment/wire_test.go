package payment

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// payload builds a presentable PAYMENT-SIGNATURE value.
func payload(t *testing.T, network, scheme string) (Payload, string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"payload": map[string]any{
			"signature": "0xdeadbeef",
			"permit2Authorization": map[string]any{
				"from": "0xpayer", "nonce": "1",
			},
		},
		// The client echoes the accepts[] entry it chose; scheme and network
		// live here, not at the top level.
		"accepted": map[string]any{
			"scheme": scheme, "network": network,
			"asset": "0x33ad", "amount": "10000", "payTo": "0xop",
			"maxTimeoutSeconds": 300,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hdr := base64.StdEncoding.EncodeToString(raw)
	p, err := DecodePayload(hdr)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	return p, hdr
}

func reqs() Requirements {
	return Requirements{
		Scheme: "exact", Network: "eip155:72344",
		Asset: "0x33ad", Amount: "10000", PayTo: "0xop",
		MaxTimeoutSeconds: 300,
		Extra: map[string]any{"name": "Stable Coin", "version": "1",
			"assetTransferMethod": "permit2"},
	}
}

// TestDecodePayload covers what a garbage header must not become.
func TestDecodePayload(t *testing.T) {
	good, _ := payload(t, "eip155:72344", "exact")
	if good.Network() != "eip155:72344" || good.Scheme() != "exact" {
		t.Fatalf("decoded = %+v", good)
	}
	if len(good.Raw()) == 0 {
		t.Error("raw payload not preserved; the facilitator validates a signature over the client's own bytes")
	}

	for name, hdr := range map[string]string{
		"empty":         "",
		"not base64":    "!!!!",
		"not json":      base64.StdEncoding.EncodeToString([]byte("hello")),
		"no scheme":     base64.StdEncoding.EncodeToString([]byte(`{"network":"eip155:1"}`)),
		"no network":    base64.StdEncoding.EncodeToString([]byte(`{"scheme":"exact"}`)),
		"no version":    base64.StdEncoding.EncodeToString([]byte(`{"payload":{},"accepted":{"scheme":"exact","network":"eip155:1"}}`)),
		"wrong version": base64.StdEncoding.EncodeToString([]byte(`{"x402Version":1,"scheme":"exact","network":"base"}`)),
		"oversized":     strings.Repeat("A", maxPayloadBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePayload(hdr); err == nil {
				t.Errorf("accepted %s", name)
			}
		})
	}
}

// TestMatchRailRefusesUnofferedRails. A payment on a rail we never advertised is
// refused locally, before any egress.
func TestMatchRailRefusesUnofferedRails(t *testing.T) {
	accepts := []Requirements{reqs()}
	ok, _ := payload(t, "eip155:72344", "exact")
	if _, err := MatchRail(ok, accepts); err != nil {
		t.Errorf("offered rail rejected: %v", err)
	}
	for _, bad := range [][2]string{
		{"eip155:8453", "exact"}, // network we do not offer
		{"eip155:72344", "upto"}, // scheme we do not offer
	} {
		p, _ := payload(t, bad[0], bad[1])
		if _, err := MatchRail(p, accepts); err == nil {
			t.Errorf("accepted an unoffered rail %v", bad)
		}
	}

	// A client rewriting the terms it echoes back must be refused locally,
	// before any egress. The signature covers the client's version, so the
	// facilitator would reject it anyway — but a gate that forwards it has
	// already spent a round trip an attacker did not pay for.
	for name, tamper := range map[string]func(m map[string]any){
		"lowered amount":    func(m map[string]any) { m["amount"] = "1" },
		"redirected payTo":  func(m map[string]any) { m["payTo"] = "0xattacker" },
		"substituted asset": func(m map[string]any) { m["asset"] = "0xother" },
	} {
		t.Run(name, func(t *testing.T) {
			acc := map[string]any{
				"scheme": "exact", "network": "eip155:72344",
				"asset": "0x33ad", "amount": "10000", "payTo": "0xop",
				"maxTimeoutSeconds": 300,
			}
			tamper(acc)
			raw, _ := json.Marshal(map[string]any{
				"x402Version": 2, "payload": map[string]any{"signature": "0x"}, "accepted": acc,
			})
			p, err := DecodePayload(base64.StdEncoding.EncodeToString(raw))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := MatchRail(p, accepts); err == nil {
				t.Errorf("accepted a payload with %s", name)
			}
		})
	}
}

// TestMatchRailReturnsTheGatesTerms is the other half of the invariant, and the
// half nothing asserted.
//
// MatchRail's doc comment calls it load-bearing: "The returned Requirements are
// always the GATE'S, never the client's echo: that is what gets forwarded to the
// facilitator." Every existing test discards the returned value and checks only
// the error, so the property was untested — verified by replacing `return r, nil`
// with `return p.Accepted, nil` and running the whole suite, which passed.
//
// It passes because the equality checks above cover asset, amount and payTo and
// nothing else. Extra and MaxTimeoutSeconds are never compared, and Extra is
// where the token's EIP-712 domain and assetTransferMethod live — so under that
// mutation a client authors the settlement terms the facilitator is asked to
// honour, and picks its own timeout window, having matched on three fields it
// copied correctly.
func TestMatchRailReturnsTheGatesTerms(t *testing.T) {
	// A client that echoes the three compared fields exactly and then attaches
	// its own everything-else. This is the shape the comparison cannot catch.
	raw, err := json.Marshal(map[string]any{
		"x402Version": 2,
		"payload":     map[string]any{"signature": "0xdeadbeef"},
		"accepted": map[string]any{
			"scheme": "exact", "network": "eip155:72344",
			"asset": "0x33ad", "amount": "10000", "payTo": "0xop",
			"maxTimeoutSeconds": 86400,
			"extra": map[string]any{
				"name": "Attacker Coin", "version": "9",
				"assetTransferMethod": "eip3009",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePayload(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}

	got, err := MatchRail(p, []Requirements{reqs()})
	if err != nil {
		t.Fatalf("a payload matching every compared field was refused: %v", err)
	}

	want := reqs()
	if got.MaxTimeoutSeconds != want.MaxTimeoutSeconds {
		t.Errorf("maxTimeoutSeconds = %d, want the gate's %d: the client chose how "+
			"long its own authorization stays valid", got.MaxTimeoutSeconds, want.MaxTimeoutSeconds)
	}
	for k, v := range want.Extra {
		if got.Extra[k] != v {
			t.Errorf("extra[%q] = %v, want the gate's %v: the client authored the "+
				"settlement terms forwarded to the facilitator", k, got.Extra[k], v)
		}
	}
	// And the three fields the comparison does cover, so a future rewrite that
	// drops the comparison and returns the echo fails here too rather than only
	// on Extra.
	if got.Asset != want.Asset || got.Amount != want.Amount || got.PayTo != want.PayTo {
		t.Errorf("returned terms are not the gate's: %+v", got)
	}
}

// TestIDIdentifiesTheAuthorizationNotTheEnvelope.
//
// The payment ID is the single-use key, so it has to name the thing that can
// only be spent once: the authorization the chain consumes. Two layers of
// wrapping around it are attacker-authored and covered by no signature —
// `accepted`, `resource`, `extensions`, whitespace and key order on the outside,
// and any unknown key inside the scheme payload — so anything of either that
// reaches the hash is padding a client can vary at will to mint fresh, unseen
// payment IDs from one payment. Both sides must still be able to compute it,
// because it is quoted in a recovery 402.
//
// Two earlier expectations were wrong in the dangerous direction and are now
// inverted: that two documents differing only in `accepted.network` must hash
// differently, and that two different signatures are two payments. Both describe
// one authorization presented twice.
func TestIDIdentifiesTheAuthorizationNotTheEnvelope(t *testing.T) {
	// The authorization from the exact/permit2 scheme example, which is what a
	// real client signs.
	auth := func(over map[string]any) map[string]any {
		a := map[string]any{
			"permitted": map[string]any{"token": "0x036CbD53", "amount": "10000"},
			"from":      "0x857b06519E91e3A54538791bDbb0E22373e36b66",
			"spender":   "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
			"nonce":     "33247007178036348590600198031289925668252061821958005840077069883511451257277",
			"deadline":  "1740672154",
		}
		for k, v := range over {
			if v == nil {
				delete(a, k)
				continue
			}
			a[k] = v
		}
		return a
	}

	// build assembles a document from parts, so each case varies exactly one
	// thing.
	build := func(t *testing.T, sig string, authz map[string]any, doc map[string]any) Payload {
		t.Helper()
		full := map[string]any{
			"x402Version": 2,
			"payload":     map[string]any{"signature": sig, "permit2Authorization": authz},
			"accepted": map[string]any{
				"scheme": "exact", "network": "eip155:72344",
				"asset": "0x33ad", "amount": "10000", "payTo": "0xop",
				"maxTimeoutSeconds": 300,
			},
		}
		for k, v := range doc {
			full[k] = v
		}
		raw, err := json.Marshal(full)
		if err != nil {
			t.Fatal(err)
		}
		p, err := DecodePayload(base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	id := func(t *testing.T, p Payload) string {
		t.Helper()
		got, err := ID(p, reqs())
		if err != nil {
			t.Fatalf("ID: %v", err)
		}
		return got
	}

	base := build(t, "0xdeadbeef", auth(nil), nil)

	t.Run("stable across repeat presentations", func(t *testing.T) {
		if id(t, base) != id(t, build(t, "0xdeadbeef", auth(nil), nil)) {
			t.Error("identical presentations produced different IDs; " +
				"the recovery retry would not be recognised as the same payment")
		}
	})

	// Each of these is one signed authorization re-wrapped. If any of them
	// yields a fresh ID, the dedup store can be walked past for free.
	for name, envelope := range map[string]map[string]any{
		"padded extensions": {"extensions": map[string]any{"pad": "aaaa"}},
		"echoed resource":   {"resource": map[string]any{"url": "http://anything/"}},
		"rewritten accepted": {"accepted": map[string]any{
			"scheme": "exact", "network": "eip155:8453",
			"asset": "0xother", "amount": "1", "payTo": "0xattacker",
			"maxTimeoutSeconds": 300,
		}},
		"unknown top-level key": {"nonceSalt": "17"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := id(t, build(t, "0xdeadbeef", auth(nil), envelope)); got != id(t, base) {
				t.Errorf("re-wrapping one authorization as %q minted a fresh payment ID — "+
					"the same payment can be redeemed again", name)
			}
		})
	}

	// ECDSA signing is randomised: a payer can always produce a second valid
	// signature over the same typed data. The chain spends the nonce, so both
	// documents are one payment, and treating them as two is the double-redeem
	// this key exists to prevent — the facilitator answers the second settle
	// from its idempotency cache and a second pass drops out.
	t.Run("a second signature over one authorization is one payment", func(t *testing.T) {
		if id(t, base) != id(t, build(t, "0xfeedface", auth(nil), nil)) {
			t.Error("re-signing one authorization minted a fresh payment ID")
		}
	})

	// The inner padding oracle: unknown keys inside the authorization object are
	// not covered by the typed data a facilitator reconstructs, so a client can
	// add them freely.
	for name, over := range map[string]map[string]any{
		"junk key in the authorization": {"pad": "aaaa"},
		"reordered witness":             {"witness": map[string]any{"to": "0xop", "validAfter": "1"}},
	} {
		t.Run(name, func(t *testing.T) {
			if id(t, build(t, "0xdeadbeef", auth(over), nil)) != id(t, base) {
				t.Errorf("%s minted a fresh payment ID", name)
			}
		})
	}

	// One authorization must not get two identities because the client spelled
	// it differently. Neither re-spelling changes what the chain consumes.
	t.Run("re-spelled payer and nonce are one payment", func(t *testing.T) {
		lower := auth(map[string]any{"from": "0x857b06519e91e3a54538791bdbb0e22373e36b66"})
		if id(t, build(t, "0xdeadbeef", lower, nil)) != id(t, base) {
			t.Error("EIP-55 checksum casing changed the payment ID")
		}
		hexNonce := id(t, build(t, "0x1", auth(map[string]any{"nonce": "0x1f"}), nil))
		decNonce := id(t, build(t, "0x1", auth(map[string]any{"nonce": "31"}), nil))
		if hexNonce != decNonce {
			t.Error("hex and decimal spellings of one nonce are two payment IDs")
		}
		numeric := id(t, build(t, "0x1", auth(map[string]any{"nonce": json.Number("31")}), nil))
		if numeric != decNonce {
			t.Error("quoting the nonce changed the payment ID")
		}
	})

	t.Run("a different authorization is a different payment", func(t *testing.T) {
		other := auth(map[string]any{"nonce": "8"})
		if id(t, base) == id(t, build(t, "0xdeadbeef", other, nil)) {
			t.Error("two distinct authorizations share an ID; the second payer " +
				"would be refused as a replay")
		}
		otherPayer := auth(map[string]any{"from": "0x0000000000000000000000000000000000000001"})
		if id(t, base) == id(t, build(t, "0xdeadbeef", otherPayer, nil)) {
			t.Error("two payers using the same nonce value share an ID")
		}
	})

	// An identity the gate cannot derive is one it cannot deduplicate. Inventing
	// a per-presentation one would hand back the double-redeem, so the
	// presentation is refused instead.
	t.Run("an unidentifiable authorization is refused", func(t *testing.T) {
		for name, over := range map[string]map[string]any{
			"no nonce":       {"nonce": nil},
			"no payer":       {"from": nil},
			"empty":          {"from": "", "nonce": ""},
			"boolean nonce":  {"nonce": true},
			"object nonce":   {"nonce": map[string]any{"n": 1}},
			"negative nonce": {"nonce": "-1"},
			"oversize nonce": {"nonce": "0x1" + strings.Repeat("0", 64)},
		} {
			if _, err := ID(build(t, "0xdeadbeef", auth(over), nil), reqs()); !errors.Is(err, ErrUnidentifiedPayment) {
				t.Errorf("%s: err = %v, want ErrUnidentifiedPayment", name, err)
			}
		}
	})

	// The supported exact rails cannot safely deduplicate an envelope that
	// omits the chain authorization, so no signature or JSON fallback exists.
	t.Run("payload with no selected authorization is refused", func(t *testing.T) {
		p := Payload{X402Version: Version, Payload: json.RawMessage(`{"signature":"0xsig"}`)}
		if _, err := ID(p, reqs()); !errors.Is(err, ErrUnidentifiedPayment) {
			t.Fatalf("err = %v, want ErrUnidentifiedPayment", err)
		}
	})

	t.Run("chain and token are nonce domains", func(t *testing.T) {
		baseID := id(t, base)
		otherChain := reqs()
		otherChain.Network = "eip155:8453"
		if got, err := ID(base, otherChain); err != nil || got == baseID {
			t.Fatalf("other chain ID = %q, %v; want a distinct ID", got, err)
		}
		otherAsset := reqs()
		otherAsset.Asset = "0x44be"
		if got, err := ID(base, otherAsset); err != nil || got == baseID {
			t.Fatalf("other asset ID = %q, %v; want a distinct ID", got, err)
		}
	})
}
