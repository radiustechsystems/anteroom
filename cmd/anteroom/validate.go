package main

import (
	"fmt"
	"os"

	"github.com/radiustechsystems/anteroom/internal/config"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "load and validate config, then exit; does not bind a port",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := config.Load(cfgPath); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "anteroom: %s: ok\n", cfgPath)
			return nil
		},
	}
	addConfigFlag(cmd, &cfgPath)
	return cmd
}
