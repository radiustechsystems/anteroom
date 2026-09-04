package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/radiustechsystems/anteroom/internal/gate"
	"github.com/spf13/cobra"
)

func newHealthcheckCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "probe the local gate's health endpoint and exit",
		Long:  "Probe /.anteroom/healthz on the listen address this config describes and exit 0 (healthy) or 1. The container image is shell-less and has no curl; this verb is the HEALTHCHECK.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			return healthcheck(cfg.Listen)
		},
	}
	addConfigFlag(cmd, &cfgPath)
	return cmd
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
