package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Non-custodial operation requires the dependency graph to contain no key
// generation, transaction signing, chain RPC client, or wallet code.

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

// walletShaped are substrings of module paths that mean the graph has grown a
// wallet. Matched case-insensitively against whole module lines, so a package
// named after one of these is caught wherever it sits in the graph.
var walletShaped = []string{
	"secp256k1",
	"keccak",
	"go-ethereum",
	"btcec",
	"btcd",
	"ethclient",
	"ethereum/go-",
	"web3",
	"solana",
	"tendermint",
	"cosmos-sdk",
	"blst",
	"bls12",
	"hdkeychain",
	"tyler-smith/go-bip39",
	"decred/dcrd/dcrec",
}

func TestNoWalletInTheDependencyGraph(t *testing.T) {
	root := repoRoot(t)
	// go.sum lists the transitive module graph, which is the thing the invariant
	// is about — and it is deliberately wider than the built binary, because a
	// module that is only nearly used is a module one import away from used.
	for _, name := range []string{"go.mod", "go.sum"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			if name == "go.sum" && os.IsNotExist(err) {
				continue // a graph of only the standard library has no go.sum
			}
			t.Fatal(err)
		}
		lower := strings.ToLower(string(b))
		for _, bad := range walletShaped {
			if strings.Contains(lower, bad) {
				t.Errorf("%s names %q. The non-custodial invariant says the binary contains no key "+
					"generation, no transaction signing and no chain RPC client, and that "+
					"wallet code is absent from the dependency graph. Either that is no longer "+
					"true — in which case Anteroom is not non-custodial and the invariant, the "+
					"README and the threat model all have to change — or this is a transitive "+
					"pull that should be dropped.", name, bad)
			}
		}
	}
}

// Standard-library EVM signing primitives are also excluded. Ed25519 is allowed
// because verification does not introduce wallet custody.
func TestNoTransactionSigningPrimitives(t *testing.T) {
	root := repoRoot(t)
	// Assembled rather than written out, so this file does not match its own ban
	// and need an exemption. An exemption is a hole somebody can later put an
	// import in.
	banned := make([]string, 0, 2)
	for _, pkg := range []string{"ecdsa", "elliptic"} {
		banned = append(banned, `"crypto/`+pkg+`"`)
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden directories are local tooling or repository metadata. This
			// deliberately includes .github: this audit scans shipped Go source,
			// not workflows (which need separate secret and action-pin checks).
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			switch d.Name() {
			case "node_modules", "vendor", "test-results":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(b)
		for _, imp := range banned {
			if strings.Contains(src, imp) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s imports %s. Signing a transaction needs no dependency — these are "+
					"in the standard library — so the non-custodial invariant has to be checkable "+
					"here too, not only in go.mod. HMAC and SHA-256 are the primitives this "+
					"project legitimately needs.", rel, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
