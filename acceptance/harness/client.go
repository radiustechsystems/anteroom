package harness

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Client is an HTTP client with a cookie jar, aimed at one deployment.
//
// Redirects are not followed: the suite asserts on the gate's own responses,
// and a client that quietly follows a 302 cannot tell "admitted" from
// "redirected to the wait page".
type Client struct {
	base *url.URL
	jar  *cookiejar.Jar
	http *http.Client
}

// Option modifies a request before it is sent.
type Option func(*http.Request)

// DefaultUserAgent is one stable client persona for an acceptance Client. PoW
// passes intentionally bind to the solver's User-Agent, so a harness that
// solves as Go-http-client and spends as Chrome is modeling a copied pass, not
// a browser completing the documented flow.
const DefaultUserAgent = "Mozilla/5.0 (acceptance) AppleWebKit/537.36 Chrome/120 Safari/537.36"

// Header sets a request header.
func Header(k, v string) Option {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

// Host sets the Host of the request line. Header("Host", …) does NOT do this:
// net/http writes the Host header from Request.Host (falling back to the URL)
// and silently ignores an entry in Request.Header, so a test using Header for it
// is asserting against a value that never left the machine.
//
// Pair it with SendPass on any request that needs a pass. net/http builds the
// cookie-jar lookup URL from Request.Host when it is set (Client.send, in
// net/http/client.go), so a jar keyed on the deployment's address returns
// nothing for a request claiming another name, and the request arrives at the
// gate anonymous.
func Host(v string) Option {
	return func(r *http.Request) { r.Host = v }
}

// Browser makes the request look like a browser document navigation, which is
// the signal that earns the wait page rather than the machine-readable refusal.
func Browser() Option {
	return func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		r.Header.Set("User-Agent", DefaultUserAgent)
	}
}

// NewClient aims a client at a base URL, e.g. "http://127.0.0.1:8080".
func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Client{
		base: u,
		jar:  jar,
		http: &http.Client{
			Jar:     jar,
			Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				// Compression is requested explicitly per test rather than by
				// the transport, because "did this response stay compressed?"
				// is one of the things under test and Go's automatic gzip
				// would hide the answer.
				DisableCompression: true,
				Proxy:              nil,
			},
		},
	}, nil
}

// Do issues a request against the deployment and reads the whole body.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, opts ...Option) (*http.Response, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL(path), rdr)
	if err != nil {
		return nil, nil, err
	}
	for _, o := range opts {
		o(req)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	return resp, got, err
}

// Get is Do with GET and no body.
func (c *Client) Get(ctx context.Context, path string, opts ...Option) (*http.Response, []byte, error) {
	return c.Do(ctx, http.MethodGet, path, nil, opts...)
}

// URL resolves a path against the deployment's base.
func (c *Client) URL(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	// Deliberately string concatenation rather than url.JoinPath: several tests
	// send paths that are *not* canonical ("/a/../b", "//x") precisely to check
	// that the gate refuses them, and JoinPath would normalize them away before
	// they ever reached the wire.
	return strings.TrimSuffix(c.base.String(), "/") + path
}

// ClearCookies drops every cookie, returning the client to an anonymous state.
func (c *Client) ClearCookies() error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	c.jar = jar
	c.http.Jar = jar
	return nil
}

// SendPass attaches the client's current pass as an explicit Cookie header,
// bypassing the jar. Needed alongside Host — see the note there — and harmless
// everywhere else, since it sends exactly what the jar would have sent.
func (c *Client) SendPass() Option {
	v := c.Pass()
	return func(r *http.Request) {
		if v != "" {
			r.Header.Set("Cookie", CookieName+"="+v)
		}
	}
}

// SetPass installs a pass cookie value directly, for tampering tests.
func (c *Client) SetPass(value string) {
	c.jar.SetCookies(c.base, []*http.Cookie{{Name: CookieName, Value: value, Path: "/"}})
}

// WaitReady polls the gate's liveness endpoint until it answers or the context
// is done. Compose reports a container "started" well before the process inside
// has bound its port.
func (c *Client) WaitReady(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	var last error
	for time.Now().Before(deadline) {
		resp, _, err := c.Get(ctx, PathHealthz)
		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}
		if err != nil {
			last = err
		} else {
			last = errors.New(PathHealthz + ": status " + resp.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return last
}

// FreePort asks the kernel for an unused TCP port. Tests bind published
// container ports dynamically so parallel runs do not collide.
func FreePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}
