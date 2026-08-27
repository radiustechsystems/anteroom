package token

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hmacNoDomain computes HMAC-SHA256 without the pass domain prefix, for the
// domain-separation test.
func hmacNoDomain(key, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(payload)
	return m.Sum(nil)
}
