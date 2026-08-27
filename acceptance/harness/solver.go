// Package harness is the shared machinery for the acceptance suite: a client
// that gets through the gate the way the documentation says to, and enough
// Docker Compose lifecycle to stand a deployment up and tear it down.
//
// One rule governs this package, and it is the reason the suite is worth
// running at all: **the solver below is written from the instructions the gate
// serves, not from the gate's source.** Read /.anteroom/instructions.md and
// then read Solve — they must say the same thing. If the implementation ever
// drifts from the document, the drift shows up here as a failure rather than as
// a silent breakage of every automated client on the internet.
package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// CookieName is the pass cookie, as named by the served instructions.
const CookieName = "anteroom_pass"

// Gate endpoints, as named by the served instructions.
const (
	PathChallenge    = "/.anteroom/challenge"
	PathAnswer       = "/.anteroom/answer"
	PathHealthz      = "/.anteroom/healthz"
	PathInstructions = "/.anteroom/instructions.md"
	PathRenew        = "/.anteroom/renew.js"
	PathSW           = "/.anteroom/sw.js"
	PathUninstall    = "/.anteroom/uninstall"
)

// Challenge is the documented shape of the challenge endpoint's response.
type Challenge struct {
	Challenge  string `json:"challenge"`
	Threshold  string `json:"threshold"`
	Kind       string `json:"kind"`
	PassTTLMs  int64  `json:"pass_ttl_ms"`
	DeadlineMs int64  `json:"deadline_unix_ms"`
}

// Deadline is when this challenge stops being redeemable for a usable pass.
func (c Challenge) Deadline() time.Time { return time.UnixMilli(c.DeadlineMs) }

// AnswerResult is what the answer endpoint reports back.
type AnswerResult struct {
	OK        bool   `json:"ok"`
	Kind      string `json:"kind"`
	ExpUnixMs int64  `json:"exp_unix_ms"`
	Error     string `json:"error"`
}

// FetchChallenge performs step 1 of the documented procedure.
func (c *Client) FetchChallenge(ctx context.Context) (Challenge, error) {
	var ch Challenge
	resp, body, err := c.Do(ctx, http.MethodGet, PathChallenge, nil)
	if err != nil {
		return ch, err
	}
	if resp.StatusCode != http.StatusOK {
		return ch, fmt.Errorf("%s: status %d: %s", PathChallenge, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &ch); err != nil {
		return ch, fmt.Errorf("%s: %w: %s", PathChallenge, err, body)
	}
	if len(ch.Threshold) != 64 {
		return ch, fmt.Errorf("%s: threshold is %d hex chars, want 64: %q",
			PathChallenge, len(ch.Threshold), ch.Threshold)
	}
	return ch, nil
}

// SolveChallenge performs step 2: find a nonce whose digest of challenge+nonce
// sorts strictly below the threshold, compared as bytes.
//
// maxAttempts bounds the search so a misconfigured difficulty fails the test
// instead of hanging it. It returns the nonce and how many hashes it took —
// the count is worth asserting on, because "eventually succeeded" and "did not
// spin" are different properties.
func SolveChallenge(ch Challenge, maxAttempts int) (nonce string, attempts int, err error) {
	threshold, err := hex.DecodeString(ch.Threshold)
	if err != nil {
		return "", 0, fmt.Errorf("threshold is not hex: %w", err)
	}
	prefix := []byte(ch.Challenge)
	buf := make([]byte, 0, len(prefix)+24)
	for n := range maxAttempts {
		candidate := strconv.Itoa(n)
		buf = append(buf[:0], prefix...)
		buf = append(buf, candidate...)
		sum := sha256.Sum256(buf)
		if bytes.Compare(sum[:], threshold) < 0 {
			return candidate, n + 1, nil
		}
	}
	return "", maxAttempts, fmt.Errorf("no nonce below threshold %s in %d attempts",
		ch.Threshold, maxAttempts)
}

// SubmitAnswer performs step 3.
func (c *Client) SubmitAnswer(ctx context.Context, challenge, nonce string) (AnswerResult, error) {
	var out AnswerResult
	payload, err := json.Marshal(map[string]string{"challenge": challenge, "nonce": nonce})
	if err != nil {
		return out, err
	}
	resp, body, err := c.Do(ctx, http.MethodPost, PathAnswer, payload,
		Header("Content-Type", "application/json"))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("%s: status %d: %w: %s", PathAnswer, resp.StatusCode, err, body)
	}
	if !out.OK {
		return out, fmt.Errorf("%s: status %d: %s", PathAnswer, resp.StatusCode, out.Error)
	}
	return out, nil
}

// Solve runs the whole documented procedure and leaves the pass in the client's
// cookie jar, ready for step 4 (retry the original request).
//
// It retries once on a deadline overrun, which is the behavior the document
// prescribes for a solver that runs out of time: abandon the work and fetch a
// fresh challenge rather than submit a solve that can only be refused.
func (c *Client) Solve(ctx context.Context) (AnswerResult, error) {
	const maxAttempts = 1 << 24 // ~16M: far above difficulty 14, far below a hang

	var last error
	for attempt := range 2 {
		ch, err := c.FetchChallenge(ctx)
		if err != nil {
			return AnswerResult{}, err
		}
		nonce, _, err := SolveChallenge(ch, maxAttempts)
		if err != nil {
			return AnswerResult{}, err
		}
		if time.Now().After(ch.Deadline()) {
			last = fmt.Errorf("solve overran the challenge deadline (attempt %d)", attempt+1)
			continue
		}
		res, err := c.SubmitAnswer(ctx, ch.Challenge, nonce)
		if err != nil {
			last = err
			continue
		}
		return res, nil
	}
	return AnswerResult{}, fmt.Errorf("could not obtain a pass: %w", last)
}

// Pass returns the current pass cookie value, or "" if the client holds none.
func (c *Client) Pass() string {
	for _, ck := range c.jar.Cookies(c.base) {
		if ck.Name == CookieName {
			return ck.Value
		}
	}
	return ""
}
