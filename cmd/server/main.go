// Command qoqtun-server is the Server CLI entry point. It contains no
// business logic: everything is delegated to internal packages.
package main

import (
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/logging"
	"github.com/hidxt/qoqtun/internal/pki"
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
	root.AddCommand(newRunCmd(), newCheckConfigCmd(), newCACmd())
	return root
}

// newCACmd implements `server ca init`: generate the Root CA and the
// server certificate into state_dir (03-pki-enrollment.md §1). Idempotent:
// existing CA requires --force, which invalidates all existing clients.
func newCACmd() *cobra.Command {
	caCmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the server certificate authority",
	}
	var configPath string
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Root CA and server certificate in state_dir",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			return runCAInit(cmd, cfg, force)
		},
	}
	initCmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	initCmd.Flags().BoolVar(&force, "force", false,
		"overwrite an existing CA (warning: invalidates all existing client certificates)")
	caCmd.AddCommand(initCmd)
	return caCmd
}

func runCAInit(cmd *cobra.Command, cfg *config.ServerConfig, force bool) error {
	caDir := filepath.Join(cfg.StateDir, "ca")
	serverDir := filepath.Join(cfg.StateDir, "server")
	caKeyPath := filepath.Join(caDir, "ca.key")
	caCertPath := filepath.Join(caDir, "ca.crt")

	if _, err := os.Stat(caKeyPath); err == nil {
		if !force {
			return fmt.Errorf("CA already initialized at %s (use --force to overwrite; this invalidates all existing client certificates)", caKeyPath)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: overwriting existing CA at %s; all existing client certificates will become invalid\n", caKeyPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", caKeyPath, err)
	}

	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", caDir, err)
	}
	if err := os.MkdirAll(serverDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", serverDir, err)
	}

	caValidity := time.Duration(cfg.PKI.CAValidityYears) * 365 * 24 * time.Hour
	ca, err := pki.GenerateCA(caValidity)
	if err != nil {
		return err
	}
	caKeyPEM, err := pki.MarshalPrivateKey(ca.Key)
	if err != nil {
		return err
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})

	if err := os.WriteFile(caKeyPath, caKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", caKeyPath, err)
	}
	if err := os.WriteFile(caCertPath, caCertPEM, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", caCertPath, err)
	}

	// server certificate with SANs derived from control_addr
	host, _, err := net.SplitHostPort(cfg.Listen.ControlAddr)
	if err != nil {
		return fmt.Errorf("parse control_addr: %w", err)
	}
	var ips []net.IP
	var dns []string
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		dns = []string{host}
	}
	serverValidity := time.Duration(cfg.PKI.CAValidityYears) * 365 * 24 * time.Hour
	serverCertPEM, serverKeyPEM, err := pki.SignServerCertificate(
		ca, int(serverValidity.Hours()/24), ips, dns)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.key"), serverKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write server key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "server.crt"), serverCertPEM, 0o644); err != nil {
		return fmt.Errorf("write server cert: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CA initialized:\n  ca:      %s\n  ca cert: %s\n  server:  %s\n  server cert: %s\n  CA fingerprint: %s\n",
		caKeyPath, caCertPath, filepath.Join(serverDir, "server.key"), filepath.Join(serverDir, "server.crt"),
		pki.Fingerprint(ca.Cert))
	return nil
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
