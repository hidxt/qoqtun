// Command qoqtun-client is the Client CLI entry point. It contains no
// business logic: everything is delegated to internal packages.
package main

import (
	"fmt"
	"os"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/logging"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "qoqtun-client",
		Short:         "qoqtun client - high-security intranet tunneling",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newRunCmd(),
		newCheckConfigCmd(),
		newPlaceholderCmd("cert", "Manage client certificates"),
		newPlaceholderCmd("enroll", "Enroll this device with the server"),
		newPlaceholderCmd("tunnel", "Manage tunnels (list/start/stop)"),
	)
	return root
}

func newRunCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the client (placeholder until Phase 5)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadClientConfig(configPath)
			if err != nil {
				return err
			}
			logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File)
			if err != nil {
				return err
			}
			logger.Info("client run: not implemented yet (Phase 5+)",
				"server_addr", cfg.ServerAddr,
				"tunnels", len(cfg.Tunnels))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to client.toml")
	return cmd
}

func newCheckConfigCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "check-config",
		Short: "Validate the configuration and print effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return config.CheckClient(configPath, nil, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to client.toml")
	return cmd
}

// newPlaceholderCmd creates a stub subcommand that reports "not implemented
// yet". Full implementations arrive in their respective phases.
func newPlaceholderCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "%s: not implemented yet\n", use)
			return nil
		},
	}
}

func loadClientConfig(path string) (*config.ClientConfig, error) {
	var fileOverlays []config.Overlay
	var err error
	if path != "" {
		fileOverlays, err = config.LoadClientOverlays(path)
		if err != nil {
			return nil, err
		}
	}
	return config.ResolveClient(config.DefaultClientConfig(), fileOverlays, nil, nil)
}
