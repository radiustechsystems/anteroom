package gate

import (
	"bytes"
	"net/http"
	"strings"
)

// injector wraps the upstream's ResponseWriter and inserts the renewal script
// into an HTML document's <head>.
//
// It holds the response headers until it has decided, because the decision
// changes them (CSP, Content-Length, ETag, Vary). It holds body bytes only until
// the head is complete or the budget runs out, whichever comes first — never
// longer, so a streaming response cannot be stalled indefinitely by us.
type injector struct {
	w http.ResponseWriter

	// note reports why an injection the gate intended did not happen. Silence
	// here is the failure mode with no symptom: the visitor is admitted, the
	// page renders perfectly, and the renewal script that keeps them admitted
	// is simply absent. Nothing appears in devtools, nothing on the wire, and
	// they lapse at DRIVER_STALE_MS and are re-challenged forever.
	note func(reason string)

	status   int
	buf      []byte
	checked  bool // the response headers have been vetted
	resolved bool // the decision is made; nothing is buffered any more
	skipping bool // decision was "leave it alone"
	sent     bool // headers have gone out
}

func newInjector(w http.ResponseWriter, note func(reason string)) *injector {
	if note == nil {
		note = func(string) {}
	}
	return &injector{w: w, note: note, status: http.StatusOK}
}

func (i *injector) Header() http.Header { return i.w.Header() }

// Unwrap lets http.ResponseController reach the real writer for anything we do
// not implement (Hijack, SetWriteDeadline).
func (i *injector) Unwrap() http.ResponseWriter { return i.w }

func (i *injector) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		i.w.WriteHeader(status)
		return
	}
	if i.sent || i.checked {
		return
	}
	i.checked = true
	i.status = status
	if why := responseSkipReason(status, i.w.Header()); why != "" {
		// Nothing to decide: pass the response through from here on.
		i.note(why)
		i.resolved, i.skipping = true, true
		i.sent = true
		i.w.WriteHeader(status)
	}
	// Otherwise hold the header: the body decides, and the decision edits headers.
}

func (i *injector) Write(b []byte) (int, error) {
	// A handler may write a body without ever calling WriteHeader, which means an
	// implicit 200. Vet the headers now, or the response checks would be skipped
	// entirely and we would buffer things we must never touch.
	if !i.checked {
		i.WriteHeader(http.StatusOK)
	}
	if i.resolved {
		return i.w.Write(b)
	}
	i.buf = append(i.buf, b...)
	if !looksLikeDocument(i.buf) {
		// Content-Type said text/html and the bytes disagree. Believe the bytes.
		i.note("body-is-not-a-document")
		i.giveUp()
		return len(b), nil
	}
	if headEnd(i.buf) >= 0 || len(i.buf) >= headBudget {
		i.decide()
	}
	// Report the caller's bytes as written: they are ours now, and a short count
	// would make the proxy think the client hung up.
	return len(b), nil
}

// Flush is a no-op while buffering. ReverseProxy runs with FlushInterval -1, so
// it flushes after every write; honouring that during the head window would emit
// the document before we could rewrite it. Once resolved, flushes pass through.
func (i *injector) Flush() {
	if !i.resolved {
		return
	}
	if f, ok := i.w.(http.Flusher); ok {
		f.Flush()
	}
}

// finish flushes whatever is still held. It must run on every request that got
// an injector, including ones where the body ended mid-head or was empty.
func (i *injector) finish() {
	if !i.resolved {
		i.decide()
	}
	if !i.sent {
		i.sent = true
		i.w.WriteHeader(i.status)
	}
}

// giveUp abandons injection and emits what we were holding, unmodified.
func (i *injector) giveUp() {
	i.resolved, i.skipping = true, true
	if !i.sent {
		i.sent = true
		i.w.WriteHeader(i.status)
	}
	if len(i.buf) > 0 {
		i.w.Write(i.buf)
		i.buf = nil
	}
}

// decide makes the call once the head is in hand.
func (i *injector) decide() {
	point := insertionPoint(i.buf)
	// The budget is a property of where the head ENDS, not of when we happened to
	// look: a single proxy chunk can be 32 KiB, so testing only "have we buffered
	// past the budget" would let an oversized head through whenever it arrived in
	// one piece.
	end := headEnd(i.buf)
	if point < 0 || end < 0 || end > headBudget {
		// No <head>, or we never saw the end of it, or it is bigger than we are
		// willing to read. Either way we do not have the whole picture — a meta CSP
		// could be sitting in the part we skipped — so we do not rewrite.
		switch {
		case end > headBudget:
			i.note("head-exceeds-64KiB-budget")
		case point < 0:
			i.note("no-opening-head-tag")
		default:
			i.note("document-ended-inside-head")
		}
		i.giveUp()
		return
	}

	h := i.w.Header()
	plan := planCSP(h.Values("Content-Security-Policy"),
		h.Values("Content-Security-Policy-Report-Only"),
		metaPolicies(i.buf))
	if plan.mode == modeSkip {
		i.note("content-security-policy-forbids-our-script")
		i.giveUp()
		return
	}

	if plan.enforce != nil {
		h.Del("Content-Security-Policy")
		for _, v := range plan.enforce {
			h.Add("Content-Security-Policy", v)
		}
	}
	if plan.report != nil {
		h.Del("Content-Security-Policy-Report-Only")
		for _, v := range plan.report {
			h.Add("Content-Security-Policy-Report-Only", v)
		}
	}
	// The body is about to change length, so a byte count and a strong validator
	// would both be lies. Go will chunk the response without Content-Length.
	h.Del("Content-Length")
	if e := h.Get("ETag"); e != "" && !strings.HasPrefix(e, "W/") {
		h.Set("ETag", "W/"+e)
	}
	// The injected script depends on the visitor having a pass, which is a cookie.
	addVary(h, "Cookie")
	if plan.nonce != "" {
		// A nonce must never be shared between visitors, so this response cannot
		// be stored. This is the one mode that costs the operator cacheability,
		// which is why it is last in the ladder.
		h.Set("Cache-Control", "no-store")
	}

	tag := plan.tag()
	i.resolved = true
	i.sent = true
	i.w.WriteHeader(i.status)
	i.w.Write(i.buf[:point])
	i.w.Write([]byte(tag))
	i.w.Write(i.buf[point:])
	i.buf = nil
}

// addVary appends a field name to Vary without duplicating it.
func addVary(h http.Header, field string) {
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), field) {
				return
			}
			if strings.TrimSpace(f) == "*" {
				return
			}
		}
	}
	h.Add("Vary", field)
}

// headEnd returns where the document head ends — the last point at which a meta
// CSP could still be hiding — or -1 if it has not arrived. </head> is the
// explicit form; <body catches the implicit one, since the closing tag is
// optional in HTML.
func headEnd(b []byte) int {
	lower := bytes.ToLower(b)
	closing := bytes.Index(lower, []byte("</head"))
	body := bytes.Index(lower, []byte("<body"))
	switch {
	case closing < 0:
		return body
	case body < 0:
		return closing
	default:
		return min(closing, body)
	}
}

// metaPolicies extracts CSP policies declared with <meta http-equiv>. They are
// unmodifiable by us, so planCSP treats them as constraints that must already
// permit the injection.
func metaPolicies(b []byte) []string {
	lower := bytes.ToLower(b)
	var out []string
	for i := 0; ; {
		m := bytes.Index(lower[i:], []byte("<meta"))
		if m < 0 {
			return out
		}
		m += i
		end := bytes.IndexByte(b[m:], '>')
		if end < 0 {
			return out
		}
		tag := string(b[m : m+end])
		i = m + end
		equiv, ok := attr(tag, "http-equiv")
		if !ok || !strings.EqualFold(strings.TrimSpace(equiv), "content-security-policy") {
			continue
		}
		if content, ok := attr(tag, "content"); ok {
			out = append(out, content)
		}
	}
}

// attr pulls one attribute value out of a tag's source text. Quoted and unquoted
// forms both occur in the wild.
func attr(tag, name string) (string, bool) {
	lower := strings.ToLower(tag)
	for i := 0; ; {
		k := strings.Index(lower[i:], name)
		if k < 0 {
			return "", false
		}
		k += i
		i = k + len(name)
		// Must be preceded by whitespace so "content" does not match inside
		// "http-equiv-content" or similar.
		if k == 0 || !isSpace(tag[k-1]) {
			continue
		}
		rest := strings.TrimLeft(tag[i:], " \t\r\n")
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
		if rest == "" {
			return "", false
		}
		if q := rest[0]; q == '"' || q == '\'' {
			if e := strings.IndexByte(rest[1:], q); e >= 0 {
				return rest[1 : 1+e], true
			}
			return "", false
		}
		e := strings.IndexAny(rest, " \t\r\n")
		if e < 0 {
			return rest, true
		}
		return rest[:e], true
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
