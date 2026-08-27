// Command anteroom runs the gate: a reverse proxy that challenges browsers
// with a quiet proof-of-work and optionally offers agents an x402 payment door.
//
//	anteroom -config /etc/anteroom/anteroom.toml
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/radiustechsystems/anteroom/internal/admin"
	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/gate"
)

// bindError supplies the context the standard library's message lacks: a
// "permission denied" on a port below 1024 is the privileged-port rule, not
// anything about the address or the file system, and the operator's three ways
// out are not obvious from "bind: permission denied".
func bindError(addr string, err error) error {
	if !errors.Is(err, os.ErrPermission) {
		return err
	}
	_, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return err
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n <= 0 || n >= 1024 {
		return err
	}
	return fmt.Errorf("%w: port %d is privileged. Bind an unprivileged port behind a TLS "+
		"terminator (the documented topology), or grant the capability — "+
		"setcap 'cap_net_bind_service=+ep' ./anteroom, or "+
		"AmbientCapabilities=CAP_NET_BIND_SERVICE in the systemd unit", err, n)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "anteroom:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "anteroom.toml", "path to anteroom.toml")
	verbose := flag.Bool("v", false, "log one line per request: which rung of the ladder answered, status, size, duration")
	check := flag.Bool("healthcheck", false, "probe the local gate's health endpoint and exit 0 (healthy) or 1; for container HEALTHCHECK, which has no shell to run curl in")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	lg := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	if *check {
		return healthcheck(cfg.Listen)
	}

	g, err := gate.New(cfg, lg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: g,
		// ReadHeaderTimeout and IdleTimeout only: a proxy must not impose
		// ReadTimeout or WriteTimeout, or it would cut off long uploads,
		// downloads, and server-sent events. Per-request read deadlines guard
		// the gate's own small JSON endpoints instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	// Bind before announcing. ListenAndServe would let the "up" line print for a
	// process that never acquired the port. Both listeners bind before either
	// serves: a gate that takes traffic for a moment and then dies on the admin
	// bind would look, from outside, like a crash under load.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return bindError(cfg.Listen, err)
	}

	// Capacity matches the number of servers: a Serve goroutine must never
	// block on this channel after run() has already returned on the other's
	// error, or it leaks.
	errCh := make(chan error, 2)

	var adminSrv *http.Server
	if cfg.AdminListen != "" {
		adminLn, err := net.Listen("tcp", cfg.AdminListen)
		if err != nil {
			ln.Close()
			return bindError(cfg.AdminListen, err)
		}
		adminSrv = &http.Server{
			Handler: admin.New(g.Metrics(), g.Activity()),
			// Unlike the proxy, full timeouts are safe here: every admin
			// response is small and finite.
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 14,
		}
		go func() {
			if err := adminSrv.Serve(adminLn); !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		lg.Info("admin server is up", "admin_listen", cfg.AdminListen)
		if host, _, err := net.SplitHostPort(cfg.AdminListen); err == nil && !isLoopback(host) {
			consequence := "metrics (traffic volumes, payment activity) are readable by anything that can reach the port, unauthenticated"
			if cfg.Activity != nil {
				consequence = "metrics (traffic volumes, payment activity) AND the /activity log — visitor IP addresses with challenge outcomes — are readable by anything that can reach the port, unauthenticated"
			}
			lg.Warn("admin_listen is reachable beyond loopback",
				"admin_listen", cfg.AdminListen,
				"consequence", consequence,
				"fix", "bind 127.0.0.1 and let a local scraper collect, or firewall the port to your monitoring network")
		}
	}

	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	lg.Info("anteroom is up",
		"listen", cfg.Listen,
		"upstream", cfg.Upstream,
		"pass_ttl", cfg.PassTTL.D().String(),
		"difficulty", cfg.Difficulty,
		"payments", cfg.Payments != nil)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		lg.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace.D())
		defer cancel()
		if adminSrv != nil {
			// Sequential and first, on the shared grace context: admin requests
			// are sub-second, so this consumes effectively none of the grace the
			// proxy's long-lived connections actually need.
			if err := adminSrv.Shutdown(ctx); err != nil {
				adminSrv.Close()
			}
		}
		if err := srv.Shutdown(ctx); err != nil {
			// The drain ran out of time. A proxy carries long-lived connections
			// by design — event streams, large downloads, upgraded sockets — and
			// nothing guarantees they end on their own, so a graceful shutdown
			// that only ever waits will sit there until something else kills it.
			// Close them and go.
			lg.Warn("shutdown grace expired; closing connections that were still open",
				"grace", cfg.ShutdownGrace.D())
			srv.Close()
		}
		// Being asked to stop, and stopping, is not a failure. Returning the
		// drain timeout here exited non-zero on an ordinary SIGTERM, which makes
		// systemd with Restart=always flap and makes every `docker stop` look
		// like a crash.
		return nil
	}
}

// isLoopback reports whether a listen host is unambiguously local. Empty and
// wildcard hosts are NOT loopback — ":8090" listens on every interface.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// healthcheck probes the gate this config describes and exits accordingly. It
// exists for the container image, which is deliberately shell-less and
// therefore has no curl for a HEALTHCHECK to invoke; without it the image can
// only be health-checked from outside, which is exactly when nobody does it.
//
// It reuses the loaded config rather than taking an address of its own, so the
// probe cannot drift from the port the gate actually binds. A wildcard or
// unspecified host becomes loopback: the check is deliberately local, and a
// container that answers on its published interface but not on 127.0.0.1 is
// misconfigured in a way this should report rather than paper over.
func healthcheck(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("healthcheck: cannot parse listen %q: %w", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + gate.HealthPath

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %s: %w", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s: status %d", url, resp.StatusCode)
	}
	return nil
}
