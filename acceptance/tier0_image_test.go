//go:build e2e

// Tier 0: the image and the container contract.
//
// These tests are about the thing that ships, not the thing that compiles. The
// unit suite exercises Gate as a Go value; nothing there can tell you that the
// image has no shell, runs as a non-root UID, starts from environment variables
// alone, or reports itself healthy without a curl to do it with.
package acceptance

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/radiustechsystems/anteroom/acceptance/harness"
)

// imageSizeBudgetMB is asserted, not aspirational. "Small enough to trust" is
// the project's stated selling point, and a selling point nobody measures is a
// selling point that erodes one convenience dependency at a time.
//
// Raise it deliberately, in a commit that says why.
const imageSizeBudgetMB = 20

// buildImage builds the gate image and returns its tag.
//
// Once per run, not once per test. Nine Tier 0 tests need the image, and the
// docker layer cache makes a repeat build cheap but not free — it was costing
// about four seconds each, so most of this tier's wall clock was spent
// rebuilding something that had not changed. The sync.Once is worth more than
// it looks: acceptance suites get run when someone is already impatient.
var (
	imageOnce sync.Once
	imageTag  string
	imageErr  error
)

func buildImage(t *testing.T) string {
	t.Helper()
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)

	imageOnce.Do(func() {
		const tag = "anteroom:acceptance"
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "build", "-t", tag, ".")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			imageErr = fmt.Errorf("docker build: %w\n%s", err, out)
			return
		}
		imageTag = tag
	})
	if imageErr != nil {
		t.Fatal(imageErr)
	}
	return imageTag
}

func dockerRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

// TestT0_2_BuildsForBothArchitectures pins multi-arch buildability. A gate that
// only builds for the maintainer's laptop is a gate half the fleet cannot run.
func TestT0_2_BuildsForBothArchitectures(t *testing.T) {
	harness.RequireDocker(t)
	root := harness.RepoRoot(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// --platform with two targets requires a buildx builder that can export
	// multi-platform results; building without --load verifies the compile for
	// both without needing a registry.
	cmd := exec.CommandContext(ctx, "docker", "buildx", "build",
		"--platform", "linux/amd64,linux/arm64", ".")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	// The default "docker" driver cannot export multi-platform results. That is
	// a property of the developer's machine, not of the Dockerfile, so it skips
	// rather than fails — CI installs a container driver
	// (docker/setup-buildx-action) and does run this for real.
	if strings.Contains(string(out), "Multi-platform build is not supported") {
		t.Skipf("this host's buildx uses the docker driver, which cannot build "+
			"multi-platform. Run `docker buildx create --use` to check this locally.\n%s", out)
	}
	t.Fatalf("multi-arch build failed: %v\n%s", err, out)
}

// TestT0_3_ImageSizeBudget prevents accidental growth in the artifact that
// ships.
func TestT0_3_ImageSizeBudget(t *testing.T) {
	tag := buildImage(t)
	out, err := dockerRun(t, "image", "inspect", tag, "--format", "{{.Size}}")
	if err != nil {
		t.Fatalf("image inspect: %v\n%s", err, out)
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("parsing size %q: %v", out, err)
	}
	mb := float64(bytes) / (1 << 20)
	t.Logf("image size: %.2f MB (budget %d MB)", mb, imageSizeBudgetMB)
	if mb > imageSizeBudgetMB {
		t.Errorf("image is %.2f MB, over the %d MB budget. "+
			"Either shrink it or raise the budget deliberately.", mb, imageSizeBudgetMB)
	}
}

// TestT0_4_RuntimeSurface asserts what is absent. Each of these is a rung an
// attacker who reaches code execution in the container would otherwise climb.
func TestT0_4_RuntimeSurface(t *testing.T) {
	tag := buildImage(t)

	t.Run("runs as a non-root uid", func(t *testing.T) {
		out, err := dockerRun(t, "image", "inspect", tag, "--format", "{{.Config.User}}")
		if err != nil {
			t.Fatalf("inspect: %v\n%s", err, out)
		}
		user := strings.TrimSpace(out)
		if user == "" || strings.HasPrefix(user, "0:") || user == "root" {
			t.Errorf("image runs as %q, want a non-root UID", user)
		}
	})

	t.Run("has no shell", func(t *testing.T) {
		for _, sh := range []string{"/bin/sh", "/bin/bash", "/usr/bin/env"} {
			out, err := dockerRun(t, "run", "--rm", "--entrypoint", sh, tag, "-c", "echo reachable")
			if err == nil {
				t.Errorf("%s executed in the image: %s", sh, out)
			}
		}
	})

	t.Run("runs read-only with all capabilities dropped", func(t *testing.T) {
		name := "t0-readonly"
		dockerRun(t, "rm", "-f", name)
		defer dockerRun(t, "rm", "-f", name)

		port, err := harness.FreePort()
		if err != nil {
			t.Fatal(err)
		}
		out, err := dockerRun(t, "run", "-d", "--name", name,
			"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
			"-e", "ANTEROOM_UPSTREAM=127.0.0.1:3000",
			"-p", strconv.Itoa(port)+":8080", tag)
		if err != nil {
			t.Fatalf("run: %v\n%s", err, out)
		}
		c, err := harness.NewClient("http://127.0.0.1:" + strconv.Itoa(port))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.WaitReady(ctx); err != nil {
			logs, _ := dockerRun(t, "logs", name)
			t.Fatalf("gate not ready with a read-only rootfs and no capabilities: %v\n%s", err, logs)
		}
	})
}

// TestT0_5_StartsFromEnvironmentAlone is the container contract in one test: an
// image that needs a config file mounted before it will start is an image that
// cannot be run with `docker run -e`.
func TestT0_5_StartsFromEnvironmentAlone(t *testing.T) {
	tag := buildImage(t)
	name := "t0-envonly"
	dockerRun(t, "rm", "-f", name)
	defer dockerRun(t, "rm", "-f", name)

	port, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := dockerRun(t, "run", "-d", "--name", name,
		"-e", "ANTEROOM_UPSTREAM=127.0.0.1:3000",
		"-p", strconv.Itoa(port)+":8080", tag); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	c, err := harness.NewClient("http://127.0.0.1:" + strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		logs, _ := dockerRun(t, "logs", name)
		t.Fatalf("gate never became ready from env alone: %v\n%s", err, logs)
	}
}

// TestT0_6_RefusesWithoutUpstream. A gate with no upstream has nothing to
// guard; starting anyway and refusing every request would be the worst of both.
func TestT0_6_RefusesWithoutUpstream(t *testing.T) {
	tag := buildImage(t)
	out, err := dockerRun(t, "run", "--rm", tag)
	if err == nil {
		t.Fatalf("started with no upstream configured; output:\n%s", out)
	}
	if !strings.Contains(out, "upstream") {
		t.Errorf("error does not name the missing key, so it is not actionable:\n%s", out)
	}
}

// TestT0_7_GracefulShutdown. Compose and Kubernetes both send SIGTERM and then
// wait; a gate that ignores it is killed mid-response on every deploy.
func TestT0_7_GracefulShutdown(t *testing.T) {
	tag := buildImage(t)
	name := "t0-sigterm"
	dockerRun(t, "rm", "-f", name)
	defer dockerRun(t, "rm", "-f", name)

	port, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := dockerRun(t, "run", "-d", "--name", name,
		"-e", "ANTEROOM_UPSTREAM=127.0.0.1:3000",
		"-p", strconv.Itoa(port)+":8080", tag); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	c, _ := harness.NewClient("http://127.0.0.1:" + strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Fatalf("not ready: %v", err)
	}

	start := time.Now()
	if out, err := dockerRun(t, "stop", "--time", "10", name); err != nil {
		t.Fatalf("stop: %v\n%s", err, out)
	}
	elapsed := time.Since(start)
	// Docker sends SIGTERM, then SIGKILL after the timeout. Taking the full
	// grace period means the signal was ignored.
	if elapsed > 8*time.Second {
		t.Errorf("shutdown took %s: SIGTERM appears to be ignored", elapsed)
	}

	out, err := dockerRun(t, "inspect", name, "--format", "{{.State.ExitCode}}")
	if err != nil {
		t.Fatalf("inspect: %v\n%s", err, out)
	}
	if code := strings.TrimSpace(out); code != "0" {
		t.Errorf("exit code %s after SIGTERM, want 0", code)
	}
}

// TestT0_8_HealthcheckWithoutAShell is why the -healthcheck flag exists. A
// distroless image has nothing for a shell-form HEALTHCHECK to run, so without
// it the image can only be probed from outside — which is precisely when nobody
// does it.
func TestT0_8_HealthcheckWithoutAShell(t *testing.T) {
	tag := buildImage(t)
	name := "t0-health"
	dockerRun(t, "rm", "-f", name)
	defer dockerRun(t, "rm", "-f", name)

	port, err := harness.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	// Override the cadence, not the check. The image declares a 30 s interval,
	// which is right for production and wrong for a test that would otherwise
	// spend half a minute watching a clock — this runs the identical
	// HEALTHCHECK command, just more often.
	if out, err := dockerRun(t, "run", "-d", "--name", name,
		"--health-interval=1s", "--health-start-period=1s", "--health-retries=3",
		"-e", "ANTEROOM_UPSTREAM=127.0.0.1:3000",
		"-p", strconv.Itoa(port)+":8080", tag); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	deadline := time.Now().Add(30 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		out, err := dockerRun(t, "inspect", name, "--format", "{{.State.Health.Status}}")
		if err != nil {
			t.Fatalf("inspect: %v\n%s", err, out)
		}
		status = strings.TrimSpace(out)
		if status == "healthy" {
			return
		}
		if status == "unhealthy" {
			logs, _ := dockerRun(t, "logs", name)
			t.Fatalf("container reported unhealthy\n%s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("container never reported healthy (last status %q)", status)
}

// TestT0_9_AutoGeneratedKeyWarning. The warning is the only thing standing
// between an operator and a fleet whose passes die on every restart, so it must
// fire when it should and stay quiet when it should not — a warning that cries
// wolf is one operators learn to scroll past.
func TestT0_9_AutoGeneratedKeyWarning(t *testing.T) {
	tag := buildImage(t)

	run := func(t *testing.T, extraEnv ...string) string {
		t.Helper()
		name := "t0-key-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		defer dockerRun(t, "rm", "-f", name)
		args := []string{"run", "-d", "--name", name, "-e", "ANTEROOM_UPSTREAM=127.0.0.1:3000"}
		for _, e := range extraEnv {
			args = append(args, "-e", e)
		}
		args = append(args, tag)
		if out, err := dockerRun(t, args...); err != nil {
			t.Fatalf("run: %v\n%s", err, out)
		}
		time.Sleep(2 * time.Second)
		logs, err := dockerRun(t, "logs", name)
		if err != nil {
			t.Fatalf("logs: %v\n%s", err, logs)
		}
		return logs
	}

	t.Run("warns when no key is configured", func(t *testing.T) {
		if logs := run(t); !strings.Contains(logs, "auto-generated") {
			t.Errorf("no auto-generated-key warning in logs:\n%s", logs)
		}
	})

	t.Run("silent when a key is supplied", func(t *testing.T) {
		key := harness.RandomKey(t)
		if logs := run(t, "ANTEROOM_HMAC_KEY="+key); strings.Contains(logs, "auto-generated") {
			t.Errorf("warned about an auto-generated key despite one being configured:\n%s", logs)
		}
	})
}

// TestT0_ImageHasNoSecrets guards the most ordinary supply-chain mistake there
// is: baking a signing key into a published image. The config shipped in the
// image must configure everything except the one value that must never be
// shared — because a key committed to an image is a published key, and every
// deployment pulling that tag would then share it.
func TestT0_ImageHasNoSecrets(t *testing.T) {
	tag := buildImage(t)

	name := "t0-secrets-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if out, err := dockerRun(t, "create", "--name", name, tag); err != nil {
		t.Fatalf("create: %v\n%s", err, out)
	}
	defer dockerRun(t, "rm", "-f", name)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "cp", name+":/etc/anteroom/anteroom.toml", "-")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker cp of the baked config: %v", err)
	}
	// `docker cp -` emits a tar stream; the config is small and plain text, so
	// scanning the stream is enough to tell whether a key is present.
	baked := string(out)

	// Grep only the settings, not the prose: the shipped config deliberately
	// *discusses* hmac_keys at length in a comment explaining why none is
	// present, and a naive substring match would flag exactly the thing that
	// makes the file good.
	for _, line := range strings.Split(baked, "\n") {
		code, _, _ := strings.Cut(line, "#")
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}
		if strings.HasPrefix(code, "[[hmac_keys]]") || strings.HasPrefix(code, "key") ||
			strings.HasPrefix(code, "kid") {
			t.Errorf("the image's baked config declares a signing key (%q). "+
				"An image is published, so a key in one is a published key.", code)
		}
	}
	// The same file must still be a working config in every other respect,
	// which T0.5 already proved by starting from it.
	if !strings.Contains(baked, "listen") {
		t.Errorf("baked config does not look like an anteroom.toml:\n%s", baked)
	}
}
