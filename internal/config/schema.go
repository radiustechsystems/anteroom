package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/BurntSushi/toml"
)

// The decoder accepts case-insensitive field matches. TOML keys are case
// sensitive: accepting both inject and Inject lets map iteration order decide
// the setting. Check every path, including tables and array-table members,
// against the exact schema before using the decoded configuration.
func validateConfigKeys(meta toml.MetaData) error {
	var problems []string
	seen := make(map[string]bool)
	for _, key := range meta.Keys() {
		path := key.String()
		canonical, known := canonicalConfigKey(key)
		if known && canonical.String() == path {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		hint := removedConfigKeyHint(path)
		if hint == "" {
			if known {
				hint = fmt.Sprintf("keys are case-sensitive; use %q", canonical.String())
			} else {
				hint = "check spelling and table placement against anteroom.example.toml"
			}
		}
		problems = append(problems, fmt.Sprintf("unknown key %q — %s", path, hint))
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// Use the struct tags as the single schema. Keep path components separate so
// a quoted literal key such as "triage.json_accept" is not treated as nesting.
func canonicalConfigKey(key toml.Key) (toml.Key, bool) {
	t := reflect.TypeOf(Config{})
	canonical := make(toml.Key, 0, len(key))
	for _, part := range key {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return nil, false
		}
		found := false
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			name := field.Tag.Get("toml")
			if name == "" || name == "-" || !strings.EqualFold(name, part) {
				continue
			}
			canonical = append(canonical, name)
			t = field.Type
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}
	return canonical, true
}

func removedConfigKeyHint(path string) string {
	switch path {
	case "bypass.crawlers":
		return "removed; use bypass.verified_crawlers for source-verified crawler bypass (including paid routes); the old setting did not enforce a bypass"
	case "payments.rails.v1_network":
		return "removed; use payments.rails.network with a CAIP-2 identifier (e.g. eip155:8453) and an x402 v2 client; x402 v1 is unsupported"
	case "payments.rules.grant":
		return "removed; configure paths, price, and paid_ttl on the rule for time-based access; request-count grants are unsupported"
	case "payments.rules.scheme":
		return "removed; exact is the only supported payment scheme; remove this key for exact (upto and batch-settlement are unsupported)"
	case "payments.rules.challenge":
		return "removed; configure PoW with top-level difficulty and renew_difficulty; per-rule challenges are unsupported"
	default:
		return ""
	}
}
