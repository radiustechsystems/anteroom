// Package useragent contains shared matching rules for authenticated machine
// identities. Header names are case-insensitive in net/http; advertised
// User-Agent product tokens are deliberately case-sensitive.
package useragent

import "strings"

// ContainsProduct recognizes an advertised UA product token either at the
// start of the field or after a separator used in composite browser UAs. It
// rejects embedded substrings such as NotGooglebot/1.0.
func ContainsProduct(value, product string) bool {
	for from := 0; ; {
		i := strings.Index(value[from:], product)
		if i < 0 {
			return false
		}
		i += from
		if i == 0 || strings.ContainsRune(" (\t;", rune(value[i-1])) {
			return true
		}
		from = i + len(product)
	}
}
