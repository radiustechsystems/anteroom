package gate

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// HTML injection: how pass renewal continues after the visitor leaves the wait
// page. The contract is docs/operating.md "Guidance for HTML injection and CSP";
// this file implements it.
//
// An injection we are not certain of is skipped, not attempted. Every test
// below is a reason to pass the response through untouched, and the default
// answer is "don't".
// A gate that mangles one page in a thousand is worse than a gate that renews
// less often, because the first failure is invisible to us and fatal to the
// operator's trust.

// injectMode is how the renewal script gets onto the page, chosen by CSP.
type injectMode int

const (
	// modeSkip: leave the response alone.
	modeSkip injectMode = iota
	// modeExternal: <script src> and no header changes. The common case.
	modeExternal
	// modeInline: an inline loader, policies untouched (they allow it already).
	modeInline
	// modeInlineHash: an inline loader plus a 'sha256-…' source. Deterministic,
	// so it stays cache-safe.
	modeInlineHash
	// modeInlineNonce: an inline loader plus a fresh nonce. Forces no-store,
	// because a nonce in a shared cache is a nonce published to everyone.
	modeInlineNonce
)

// externalTag is root-absolute on purpose: a <base href> must not be able to
// retarget it. defer keeps it off the parser's critical path.
const externalTag = `<script src="` + pathRenew + `" defer></script>`

// inlineLoader is the one inline form used by every inline mode. Keeping it a
// single fixed string is what makes its hash deterministic — a per-response
// variation would mean a per-response hash and no cache safety. It appends the
// external script rather than inlining the logic, so 'strict-dynamic' propagates
// trust to it and there is only one copy of the renewal code.
//
// No DOM sinks (no eval, no innerHTML), so a require-trusted-types-for 'script'
// policy is satisfied without naming a policy.
const inlineLoader = `<script%s>(function(){var s=document.createElement("script");s.src="` +
	pathRenew + `";s.defer=true;document.head.appendChild(s);})();</script>`

// headBudget caps how much of the response we will hold while looking for the
// insertion point. A document that has not opened <head> within this much is not
// a document we want to rewrite.
const headBudget = 64 << 10

// injectable reports whether the REQUEST may carry an injected response. This is
// the cheap half of the decision and it runs before the upstream call, because a
// request that fails it keeps its compression (we only ask for identity encoding
// when we intend to read the body).
//
// The first rule is a relationship, not a test of this request: anything the
// ladder admitted as a browser navigation is injectable. Admitting a visitor and
// then withholding the renewal script is the one failure mode with no symptom —
// they are let in, they lapse at DRIVER_STALE_MS, and every later navigation is
// challenged again with nothing in devtools to explain it. Deriving one predicate
// from the other is what stops the two drifting apart again; asserting they agree
// (TestInjectableAgreesWithIsBrowserNav) is what stops it silently.
//
// This is safe in the direction it is generous: isBrowserNav is already the
// gate's answer to "is this a person's page load", these clients are already
// being handed HTML by the wait page, and responseSkipReason + looksLikeDocument
// still independently require a 200 text/html body that starts like a document,
// so an XHR forging Sec-Fetch-Mode: navigate earns an injection only if it is
// genuinely fetching a document.
func injectable(r *http.Request) bool {
	return injectableRequest(r, isBrowserNav(r))
}

// injectableRequest is injectable with the gate's already-computed navigation
// decision. Production passes requestFacts here so classification happens once;
// the wrapper above keeps the predicate directly testable.
func injectableRequest(r *http.Request, navigation bool) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if navigation {
		return true
	}
	// Fragment requests from HTMX/Turbo are not documents even though they are
	// text/html and may claim Accept: text/html. Injecting into a fragment puts a
	// script tag in the middle of someone's page, or worse, replaces a target.
	if isFragmentRequest(r) {
		return false
	}
	// Sec-Fetch-Dest is authoritative where it exists: "document" means a
	// top-level navigation. An iframe, a script, an image is not ours to touch.
	// Partitioned storage means an iframe often has no cookie and no worker
	// anyway, so renewal there could not work.
	//
	// A site's root-scoped service worker sends dest=empty when re-issuing a
	// navigation. Chromium keeps mode=navigate while Firefox sends same-origin.
	// Since XHR also uses dest=empty, require a browser HTML request shape; the
	// fragment headers above exclude partial-page fetches.
	if d := r.Header.Get("Sec-Fetch-Dest"); d != "" {
		if d == "empty" {
			return looksLikeBrowserHTML(r, r.Header.Get("Accept"))
		}
		return d == "document"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// responseSkipReason names why a response may not be rewritten, or "" if it may.
// The name is for the operator's log, which is why it is a phrase rather than a
// code: it has to be readable by someone who has never opened this file.
func responseSkipReason(status int, h http.Header) string {
	// Exactly 200. A 206 is a byte range, a 304 has no body, a 3xx has nowhere to
	// put a script, and rewriting an error page helps no one.
	if status != http.StatusOK {
		return "response-status-is-not-200"
	}
	// Never break a signature or digest to make room.
	for _, k := range []string{"Content-Digest", "Repr-Digest", "Digest", "Signature"} {
		if h.Get(k) != "" {
			return "response-carries-" + strings.ToLower(k)
		}
	}
	// We asked for identity. If the upstream sent something encoded anyway, we
	// are not going to decompress it to insert 40 bytes.
	if e := h.Get("Content-Encoding"); e != "" && !strings.EqualFold(e, "identity") {
		return "upstream-ignored-accept-encoding-identity"
	}
	ct, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || ct != "text/html" {
		// Note application/xhtml+xml is excluded deliberately: it is XML, where
		// an unclosed tag is a parse error rather than a quirk.
		return "content-type-is-not-text/html"
	}
	switch cs := strings.ToLower(params["charset"]); cs {
	case "", "utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1", "latin1",
		"windows-1252", "iso-8859-15":
		return ""
	default:
		// UTF-16/32 and other non-ASCII-compatible encodings: our ASCII byte
		// search would find nothing, or worse, match inside a character.
		// Keep this reason from incorporating an upstream-controlled charset.
		// noteInjectionSkipped retains reasons for process lifetime, so a dynamic
		// value here would turn response metadata into unbounded memory growth.
		return "charset-is-not-ascii-compatible"
	}
}

// utf16or32BOM reports a byte-order mark we must not write ASCII into.
func utf16or32BOM(b []byte) bool {
	// FF FE covers UTF-16LE and is also the prefix of the UTF-32LE mark; a leading
	// NUL pair is UTF-32BE or UTF-16BE text, neither of which our ASCII byte
	// search can walk safely.
	return bytes.HasPrefix(b, []byte{0xFF, 0xFE}) ||
		bytes.HasPrefix(b, []byte{0xFE, 0xFF}) ||
		bytes.HasPrefix(b, []byte{0x00, 0x00})
}

// looksLikeDocument reports whether the body actually starts like an HTML
// document. Content-Type lies often enough — JSON and templates served as
// text/html are common — that the bytes get a vote.
func looksLikeDocument(b []byte) bool {
	if utf16or32BOM(b) {
		return false
	}
	s := bytes.TrimLeft(b, "\xEF\xBB\xBF \t\r\n") // UTF-8 BOM and leading space
	for _, p := range []string{"<!doctype html", "<html", "<head"} {
		if len(s) >= len(p) && strings.EqualFold(string(s[:len(p)]), p) {
			return true
		}
		// Not enough bytes yet to rule this prefix in or out: undecided, so let
		// the caller keep buffering rather than declaring failure.
		if len(s) < len(p) && strings.EqualFold(string(s), p[:len(s)]) {
			return true
		}
	}
	return false
}

// insertionPoint returns the offset just past the opening <head> tag, or -1 if
// the tag has not arrived yet. Comments are skipped so that a <head> mentioned
// inside <!-- --> before the real one cannot misplace the script.
func insertionPoint(b []byte) int {
	i := 0
	for {
		lower := bytes.ToLower(b[i:])
		h := bytes.Index(lower, []byte("<head"))
		if h < 0 {
			return -1
		}
		h += i
		// Reject <header>, <headers> and friends: the next byte must end the tag
		// name.
		after := h + len("<head")
		if after < len(b) && !isTagNameEnd(b[after]) {
			i = after
			continue
		}
		if c := bytes.LastIndex(bytes.ToLower(b[:h]), []byte("<!--")); c >= 0 {
			if !bytes.Contains(b[c:h], []byte("-->")) {
				// This <head> is inside a comment. Resume after the comment ends —
				// not after its opener, which would rediscover this same match and
				// spin forever.
				e := bytes.Index(b[h:], []byte("-->"))
				if e < 0 {
					return -1 // comment still arriving
				}
				i = h + e + len("-->")
				continue
			}
		}
		end := bytes.IndexByte(b[h:], '>')
		if end < 0 {
			return -1 // tag still arriving
		}
		return h + end + 1
	}
}

func isTagNameEnd(c byte) bool {
	return c == '>' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/'
}

// cspPlan is the outcome of reading a response's policies.
type cspPlan struct {
	mode injectMode
	// enforce and report are rewritten header values, positionally matching the
	// input slices. Nil means "change nothing", which is the desirable answer.
	enforce []string
	report  []string
	// nonce is set for modeInlineNonce, and forces no-store.
	nonce string
}

// tag renders the script element this plan calls for.
func (p cspPlan) tag() string {
	switch p.mode {
	case modeExternal:
		return externalTag
	case modeInline, modeInlineHash:
		return fmt.Sprintf(inlineLoader, "")
	case modeInlineNonce:
		return fmt.Sprintf(inlineLoader, ` nonce="`+p.nonce+`"`)
	}
	return ""
}

// inlineHash is the CSP source expression for the exact inline script we emit.
func inlineHash() string {
	sum := sha256.Sum256([]byte(inlineBody()))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// inlineBody is the script element's text content — what CSP hashes. The hash
// covers the content only, never the tag or its attributes.
func inlineBody() string {
	tag := fmt.Sprintf(inlineLoader, "")
	start := strings.Index(tag, ">") + 1
	end := strings.LastIndex(tag, "</script>")
	return tag[start:end]
}

// planCSP decides how (or whether) to inject, given a response's enforcing and
// report-only policies plus any policy found in a <meta> tag.
//
// Policies intersect: our script must satisfy every enforcing one. Report-only
// policies cannot block, so they never veto the decision — but they do receive
// the same nonce or hash we add elsewhere, or a correct injection would flood the
// operator's report endpoint (docs/operating.md rule 8).
func planCSP(enforce, report, meta []string) cspPlan {
	skip := cspPlan{mode: modeSkip}

	// A policy in a <meta> tag is one we cannot rewrite — the head is already
	// being streamed past by the time we would need to change it — so any policy
	// there must permit the injection as-is.
	metaDirs := make([]sourceList, 0, len(meta))
	for _, p := range meta {
		metaDirs = append(metaDirs, policies(p)...)
	}

	var dirs []sourceList
	for _, p := range enforce {
		dirs = append(dirs, policies(p)...)
	}
	all := append(append([]sourceList{}, dirs...), metaDirs...)

	// Rule 3: cases where no script of ours can run at all.
	for _, d := range all {
		if d.sandboxBlocks {
			return skip
		}
		if d.restricting && d.has("'none'") {
			return skip
		}
	}

	restricting := func(ds []sourceList) []sourceList {
		out := make([]sourceList, 0, len(ds))
		for _, d := range ds {
			if d.restricting {
				out = append(out, d)
			}
		}
		return out
	}
	enforcingR := restricting(dirs)
	metaR := restricting(metaDirs)

	// Rule 4: everything allows 'self'. Inject an external script and touch
	// nothing — the common case, and the only one that is free.
	selfOK := true
	for _, d := range append(append([]sourceList{}, enforcingR...), metaR...) {
		if !d.has("'self'") {
			selfOK = false
			break
		}
	}
	if selfOK {
		return cspPlan{mode: modeExternal}
	}

	// Past here we must modify a policy, so a restricting <meta> policy is fatal.
	if len(metaR) > 0 {
		return skip
	}

	// Rule 5: 'strict-dynamic' discards host and 'self' sources, so an external
	// src cannot be allowed by any means except a nonce on a loader.
	for _, d := range enforcingR {
		if d.has("'strict-dynamic'") {
			nonce := newNonce()
			return cspPlan{
				mode:    modeInlineNonce,
				nonce:   nonce,
				enforce: rewrite(enforce, "'nonce-"+nonce+"'"),
				report:  rewrite(report, "'nonce-"+nonce+"'"),
			}
		}
	}

	// Rule 6: 'unsafe-inline' is in force everywhere, so an inline script already
	// runs. Adding a nonce or hash here would be actively harmful: under CSP3 a
	// nonce or hash DISABLES unsafe-inline, killing the operator's own inline
	// scripts. So inject and change nothing.
	unsafeEverywhere := len(enforcingR) > 0
	for _, d := range enforcingR {
		if !d.has("'unsafe-inline'") || d.hasNonceOrHash() {
			unsafeEverywhere = false
			break
		}
	}
	if unsafeEverywhere {
		return cspPlan{mode: modeInline}
	}

	// Rule 7: hash-only, nonce-based, or a host allowlist without 'self'. A hash
	// is deterministic, so it coexists with existing nonces and hashes and stays
	// cache-safe.
	h := inlineHash()
	return cspPlan{
		mode:    modeInlineHash,
		enforce: rewrite(enforce, h),
		report:  rewrite(report, h),
	}
}

func newNonce() string {
	var b [16]byte
	rand.Read(b[:]) // crypto/rand.Read never returns an error (Go 1.24+)
	return base64.RawStdEncoding.EncodeToString(b[:])
}

// sourceList is one policy's effective script directive.
type sourceList struct {
	name    string   // the directive we are extending: script-src-elem, script-src, default-src
	sources []string // lowercased tokens
	// restricting is false when the policy says nothing about scripts, in which
	// case it constrains nothing and needs no modification.
	restricting bool
	// sandboxBlocks is true when a sandbox directive makes renewal impossible:
	// without allow-scripts nothing runs, and without allow-same-origin there is
	// no cookie and no service worker to renew into.
	sandboxBlocks bool
}

func (s sourceList) has(tok string) bool {
	for _, v := range s.sources {
		if v == tok {
			return true
		}
	}
	return false
}

func (s sourceList) hasNonceOrHash() bool {
	for _, v := range s.sources {
		if strings.HasPrefix(v, "'nonce-") || strings.HasPrefix(v, "'sha256-") ||
			strings.HasPrefix(v, "'sha384-") || strings.HasPrefix(v, "'sha512-") {
			return true
		}
	}
	return false
}

// policies splits one header value into its comma-separated policies and reduces
// each to its effective script directive.
func policies(header string) []sourceList {
	var out []sourceList
	for _, p := range strings.Split(header, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, effective(p))
	}
	return out
}

// effective reduces one policy to the directive that governs script elements:
// script-src-elem, else script-src, else default-src.
func effective(policy string) sourceList {
	found := map[string][]string{}
	sandbox, sandboxSeen := []string{}, false
	for _, d := range strings.Split(policy, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		vals := make([]string, 0, len(fields)-1)
		for _, v := range fields[1:] {
			vals = append(vals, strings.ToLower(v))
		}
		switch name {
		case "script-src-elem", "script-src", "default-src":
			found[name] = vals
		case "sandbox":
			sandbox, sandboxSeen = vals, true
		}
	}
	s := sourceList{}
	if sandboxSeen {
		allowScripts, allowSameOrigin := false, false
		for _, v := range sandbox {
			switch v {
			case "allow-scripts":
				allowScripts = true
			case "allow-same-origin":
				allowSameOrigin = true
			}
		}
		s.sandboxBlocks = !allowScripts || !allowSameOrigin
	}
	for _, name := range []string{"script-src-elem", "script-src", "default-src"} {
		if v, ok := found[name]; ok {
			s.name, s.sources, s.restricting = name, v, true
			return s
		}
	}
	return s
}

// rewrite appends src to the effective script directive of every restricting
// policy in each header value, preserving everything else byte-for-byte.
//
// A policy that restricts nothing is left alone: adding a directive where none
// existed would newly restrict scripts the operator allowed.
func rewrite(headers []string, src string) []string {
	if len(headers) == 0 {
		return nil
	}
	out := make([]string, len(headers))
	for i, h := range headers {
		parts := strings.Split(h, ",")
		for j, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			eff := effective(p)
			if !eff.restricting {
				continue
			}
			parts[j] = appendSource(p, eff.name, src)
		}
		out[i] = strings.Join(parts, ",")
	}
	return out
}

// appendSource adds src to the named directive inside one policy.
func appendSource(policy, directive, src string) string {
	segs := strings.Split(policy, ";")
	for i, s := range segs {
		fields := strings.Fields(s)
		if len(fields) == 0 || strings.ToLower(fields[0]) != directive {
			continue
		}
		segs[i] = strings.TrimRight(s, " \t") + " " + src
		return strings.Join(segs, ";")
	}
	return policy
}
