// Command qoqtun-server is the Server CLI entry point. It contains no
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
		Use:           "qoqtun-server",
		Short:         "qoqtun server - high-security intranet tunneling",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newRunCmd(), newCheckConfigCmd())
	return root
}

func newRunCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the server (placeholder until Phase 4)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File)
			if err != nil {
				return err
			}
			logger.Info("server run: not implemented yet (Phase 4+)",
				"state_dir", cfg.StateDir,
				"control_addr", cfg.Listen.ControlAddr)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func newCheckConfigCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "check-config",
		Short: "Validate the configuration and print effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return config.CheckServer(configPath, nil, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func loadServerConfig(path string) (*config.ServerConfig, error) {
	var fileOverlays []config.Overlay
	var err error
	if path != "" {
		fileOverlays, err = config.LoadServerOverlays(path)
		if err != nil {
			return nil, err
		}
	}
	return config.ResolveServer(config.DefaultServerConfig(), fileOverlays, nil, nil)
}
