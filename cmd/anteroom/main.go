// Command anteroom runs the gate: a reverse proxy that challenges browsers
// with a quiet proof-of-work and optionally offers agents an x402 payment door.
//
//	anteroom serve --config /etc/anteroom/anteroom.toml
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "anteroom:", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	cmd := newRoot()
	cmd.SetArgs(args)
	return cmd.Execute()
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "anteroom",
		Short: "A reverse proxy that challenges browsers with a quiet proof-of-work",
		Long:  "A reverse proxy that challenges browsers with a quiet proof-of-work and optionally offers agents an x402 payment door.",
		// No Run: a missing verb is help, not serve. A typo must not bind a port.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServeCmd(),
		newHealthcheckCmd(),
		newValidateCmd(),
		newVersionCmd(),
	)
	return root
}

// addConfigFlag puts --config on commands that call config.Load. It is not a
// persistent root flag: version does not load a file, and a global --config
// would make `anteroom version --config x` look meaningful.
func addConfigFlag(cmd *cobra.Command, p *string) {
	cmd.Flags().StringVarP(p, "config", "c", "anteroom.toml", "path to anteroom.toml")
}
