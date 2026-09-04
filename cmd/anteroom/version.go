package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/radiustechsystems/anteroom/internal/metrics"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print build version and revision",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return printVersion(os.Stdout)
		},
	}
}

func printVersion(w io.Writer) error {
	version, revision := metrics.Version, metrics.Revision
	if bi, ok := debug.ReadBuildInfo(); ok {
		if version == "" && bi.Main.Version != "" {
			version = bi.Main.Version
		}
		if revision == "" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					revision = s.Value
					break
				}
			}
		}
	}
	if version == "" {
		version = "unknown"
	}
	if revision == "" {
		fmt.Fprintf(w, "anteroom %s\n", version)
		return nil
	}
	fmt.Fprintf(w, "anteroom %s revision=%s\n", version, revision)
	return nil
}
