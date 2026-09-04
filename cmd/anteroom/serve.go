package main

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/radiustechsystems/anteroom/internal/logging"
	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	var (
		cfgPath string
		verbose bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "run the gate",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serve(cfgPath, verbose)
		},
	}
	addConfigFlag(cmd, &cfgPath)
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "log one line per request: which rung of the ladder answered, status, size, duration")
	return cmd
}

func serve(cfgPath string, verbose bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	lg := logging.New(os.Stderr, cfg.Log, verbose)
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
	// block on this channel after serve() has already returned on the other's
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

// isLoopback reports whether a listen host is unambiguously local. Empty and
// wildcard hosts are NOT loopback — ":8090" listens on every interface.
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
