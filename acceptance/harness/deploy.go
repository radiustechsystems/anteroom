package harness

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Deployment is a running Compose project under test.
type Deployment struct {
	Project string // compose project name, unique per test
	Dir     string // directory holding the compose file(s)
	Files   []string
	GateURL string // where the gate is published on the host
	AppURL  string // where the app is published, when a probe override is in use
	Env     []string
}

// RepoRoot locates the repository root from a test's working directory, so
// tests can reference examples/ and docker/ without hardcoding a depth.
func RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root (looked for go.mod + Dockerfile)")
	return ""
}

// RandomKey returns a fresh base64 HMAC key. Every deployment gets its own, so
// a pass minted in one test can never be accepted in another — which would turn
// a real isolation bug into a passing test.
func RandomKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ComposeUp brings up a Compose project and registers its teardown with t.
//
// Use this for a deployment owned by one test. A deployment shared across a
// whole tier must use Start instead: t.Cleanup fires when the *first* test
// finishes, which would tear the project down underneath everything after it.
func ComposeUp(t *testing.T, dir string, files []string, env map[string]string) *Deployment {
	t.Helper()
	RequireDocker(t)

	d, stop, err := Start(sanitizeProject("artest-"+t.Name()), dir, files, env)
	t.Cleanup(stop)
	if err != nil {
		t.Fatalf("compose up failed: %v", err)
	}
	return d
}

// Start brings up a Compose project and returns it with its teardown function.
// The teardown is safe to call even when Start returned an error, so a partial
// bring-up still cleans up after itself.
//
// The gate's published port is chosen dynamically and injected as GATE_PORT so
// that parallel tests — and a developer who already has something on 8080 — do
// not collide.
func Start(name, dir string, files []string, env map[string]string) (*Deployment, func(), error) {
	noop := func() {}

	gatePort, err := FreePort()
	if err != nil {
		return nil, noop, fmt.Errorf("free port: %w", err)
	}
	appPort, err := FreePort()
	if err != nil {
		return nil, noop, fmt.Errorf("free port: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, noop, err
	}

	d := &Deployment{
		Project: sanitizeProject(name + "-" + strconv.Itoa(gatePort)),
		Dir:     dir,
		Files:   files,
		GateURL: fmt.Sprintf("http://127.0.0.1:%d", gatePort),
		AppURL:  fmt.Sprintf("http://127.0.0.1:%d", appPort),
	}

	sharedKey := base64.StdEncoding.EncodeToString(key)
	full := map[string]string{
		"GATE_PORT":         strconv.Itoa(gatePort),
		"APP_PORT":          strconv.Itoa(appPort),
		"ANTEROOM_HMAC_KEY": sharedKey,
		// Two-instance fixtures default to the same key. A test that is proving
		// key separation overrides only B, while keeping network and authority
		// constant so neither client binding can make the assertion pass first.
		"ANTEROOM_HMAC_KEY_B": sharedKey,
	}
	for k, v := range env {
		full[k] = v
	}
	d.Env = os.Environ()
	for k, v := range full {
		d.Env = append(d.Env, k+"="+v)
	}

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		d.compose(ctx, "down", "--volumes", "--remove-orphans", "--timeout", "5")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if out, err := d.compose(ctx, "up", "-d", "--build"); err != nil {
		return d, stop, fmt.Errorf("compose up: %w\n%s", err, out)
	}

	client, err := NewClient(d.GateURL)
	if err != nil {
		return d, stop, err
	}
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	if err := client.WaitReady(readyCtx); err != nil {
		return d, stop, fmt.Errorf("gate never became ready at %s: %w\n%s", d.GateURL, err, d.Logs())
	}
	return d, stop, nil
}

func sanitizeProject(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return strings.Trim(string(out), "-")
}

func (d *Deployment) compose(ctx context.Context, args ...string) (string, error) {
	base := []string{"compose", "-p", d.Project}
	for _, f := range d.Files {
		base = append(base, "-f", f)
	}
	cmd := exec.CommandContext(ctx, "docker", append(base, args...)...)
	cmd.Dir = d.Dir
	cmd.Env = d.Env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Client returns a fresh anonymous client aimed at the gate.
func (d *Deployment) Client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(d.GateURL)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

// Direct returns a client aimed at the application, bypassing the gate
// entirely. It is how byte-identity is established: fetch the same path both
// ways and diff. It requires a compose overlay that publishes the app.
func (d *Deployment) Direct(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(d.AppURL)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

// Logs returns the combined container logs, for failure messages.
func (d *Deployment) Logs() string {
	out, _ := d.compose(context.Background(), "logs", "--no-color")
	return out
}

// Exec runs a command in a service container.
func (d *Deployment) Exec(ctx context.Context, service string, args ...string) (string, error) {
	return d.compose(ctx, append([]string{"exec", "-T", service}, args...)...)
}

// Restart restarts a service, for tests about what survives a restart.
func (d *Deployment) Restart(ctx context.Context, service string) (string, error) {
	return d.compose(ctx, "restart", service)
}

// RequireDocker skips the test when Docker is unusable, with a message that
// says what to do about it. A silently skipped acceptance suite is worse than
// a failing one, so this reports loudly.
func RequireDocker(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("docker is not usable (%v). "+
			"Add yourself to the docker group (sudo usermod -aG docker $USER) and log in again.", err)
	}
	if err := exec.CommandContext(ctx, "docker", "compose", "version").Run(); err != nil {
		t.Skipf("docker compose plugin is missing (%v). Install docker-compose-plugin.", err)
	}
}

// HostPorts reports, per service, the host ports Compose published for it. A
// service with an empty list publishes nothing, which is the assertion behind
// "the application must not be reachable from the host".
//
// It parses the JSON output rather than the table: `--format '{{.Publishers}}'`
// renders a Go struct slice, which has no stable textual marker for "there is a
// mapping here" and quietly makes a substring check pass for the wrong reason.
func (d *Deployment) HostPorts(ctx context.Context) (map[string][]uint16, error) {
	out, err := d.compose(ctx, "ps", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("compose ps: %w\n%s", err, out)
	}
	ports := map[string][]uint16{}
	// Compose emits one JSON object per line.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row struct {
			Service    string `json:"Service"`
			Publishers []struct {
				PublishedPort uint16 `json:"PublishedPort"`
			} `json:"Publishers"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("parsing compose ps output %q: %w", line, err)
		}
		if _, ok := ports[row.Service]; !ok {
			ports[row.Service] = nil
		}
		for _, p := range row.Publishers {
			// A published port of 0 means the container port is exposed but
			// not mapped to the host, which is exactly what `expose` does.
			if p.PublishedPort != 0 {
				ports[row.Service] = append(ports[row.Service], p.PublishedPort)
			}
		}
	}
	return ports, nil
}
