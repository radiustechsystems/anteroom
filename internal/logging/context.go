package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// Header names the gate reads and, for X-Request-ID, restates on the request
// so the upstream sees the same identifier the logs carry.
const (
	HeaderRequestID     = "X-Request-ID"
	HeaderCorrelationID = "X-Correlation-ID"
	HeaderTraceparent   = "Traceparent"
)

const maxRequestIDLen = 128

type ctxKey struct{}

// Fields are the request-scoped labels attached to every log line that is
// written with this context. RequestID is always set. TraceID and SpanID are
// set only when the inbound request carried a valid W3C traceparent — the gate
// propagates traces, it does not mint spans it never exports.
type Fields struct {
	RequestID string
	TraceID   string
	SpanID    string
}

// FromContext returns the Fields bound by Bind, if any.
func FromContext(ctx context.Context) (Fields, bool) {
	f, ok := ctx.Value(ctxKey{}).(Fields)
	return f, ok
}

// Bind stores f on ctx for the contextHandler to copy onto log records.
func Bind(ctx context.Context, f Fields) context.Context {
	return context.WithValue(ctx, ctxKey{}, f)
}

// BindRequest extracts Fields from r, generates a request ID if none was
// supplied, restates X-Request-ID on the request (so the reverse proxy
// forwards the identifier the logs use), and returns the request with those
// Fields on its context.
func BindRequest(r *http.Request) *http.Request {
	f := FieldsFromRequest(r)
	r.Header.Set(HeaderRequestID, f.RequestID)
	return r.WithContext(Bind(r.Context(), f))
}

// FieldsFromRequest reads inbound correlation headers. An absent or unusable
// request ID is replaced with a generated one; a missing traceparent is left
// empty rather than invented.
func FieldsFromRequest(r *http.Request) Fields {
	id := canonicalRequestID(r.Header.Get(HeaderRequestID))
	if id == "" {
		id = canonicalRequestID(r.Header.Get(HeaderCorrelationID))
	}
	if id == "" {
		id = newRequestID()
	}
	traceID, spanID := parseTraceparent(r.Header.Get(HeaderTraceparent))
	return Fields{RequestID: id, TraceID: traceID, SpanID: spanID}
}

func canonicalRequestID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxRequestIDLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return ""
		}
	}
	return s
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unheard of for 16 bytes; a degenerate
		// fallback still gives every request a distinct-enough join key.
		return "anteroom-unrandom"
	}
	return hex.EncodeToString(b[:])
}

// parseTraceparent reads a W3C traceparent. Version 00 layout is
// `{ver}-{32 hex trace}-{16 hex span}-{2 hex flags}`. All-zero ids are
// invalid. Future versions with the same four-field layout are accepted.
func parseTraceparent(s string) (traceID, spanID string) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "-")
	if len(parts) != 4 {
		return "", ""
	}
	ver, tid, sid, flags := parts[0], parts[1], parts[2], parts[3]
	if len(ver) != 2 || len(tid) != 32 || len(sid) != 16 || len(flags) != 2 {
		return "", ""
	}
	if !isHex(ver) || !isHex(tid) || !isHex(sid) || !isHex(flags) {
		return "", ""
	}
	if tid == "00000000000000000000000000000000" || sid == "00000000000000000000000000000000" {
		return "", ""
	}
	return strings.ToLower(tid), strings.ToLower(sid)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
