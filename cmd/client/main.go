// Command qoqtun-client is the Client CLI entry point. It contains no
// business logic: everything is delegated to internal packages.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/logging"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/platform/keystore"
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
		newCertCmd(),
		newEnrollCmd(),
		newPlaceholderCmd("tunnel", "Manage tunnels (list/start/stop)"),
	)
	return root
}

// newCertCmd implements `client cert init`: generate an Ed25519 private key
// (stored in the platform keystore, never written to disk in the clear),
// derive the client id and emit a CSR for enrollment.
func newCertCmd() *cobra.Command {
	var name, note, csrOut, secretsDir, backendStr string
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage client certificates",
	}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a client key and CSR (private key never leaves this device)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			backend, err := keystore.ParseBackendPref(backendStr)
			if err != nil {
				return err
			}
			return runCertInit(cmd, name, note, csrOut, secretsDir, backend)
		},
	}
	initCmd.Flags().StringVar(&name, "name", "", "device name (default: hostname)")
	initCmd.Flags().StringVar(&note, "note", "", "optional note recorded server-side")
	initCmd.Flags().StringVar(&csrOut, "csr-out", "client.csr", "path to write the CSR (0644, non-sensitive)")
	initCmd.Flags().StringVar(&secretsDir, "secrets-dir", "", "keystore fallback directory (default: <user-config>/qoqtun/secrets)")
	initCmd.Flags().StringVar(&backendStr, "keystore-backend", "auto", "keystore backend: auto|keyring|file")
	cmd.AddCommand(initCmd, newCertStatusCmd(), newCertRenewCmd())
	return cmd
}

func runCertInit(cmd *cobra.Command, name, note, csrOut, secretsDir string, backend keystore.BackendPref) error {
	key, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	clientID, err := pki.ClientID()
	if err != nil {
		return err
	}
	if name == "" {
		name, err = os.Hostname()
		if err != nil || name == "" {
			name = "unnamed-device"
		}
	}
	_ = note // recorded server-side at enrollment (Phase 3)

	keyPEM, err := pki.MarshalPrivateKey(key)
	if err != nil {
		return err
	}
	if secretsDir == "" {
		secretsDir = defaultSecretsDir()
	}
	store, backendName, err := keystore.OpenWithPref(
		keystore.KeyringConfig{ServiceName: "qoqtun"}, secretsDir, backend,
		func(msg string) { fmt.Fprintln(cmd.ErrOrStderr(), "warning:", msg) })
	if err != nil {
		return err
	}
	if err := store.Set("client-key", keyPEM); err != nil {
		return fmt.Errorf("store private key: %w", err)
	}

	csr, err := pki.CreateCSR(key, clientID, name)
	if err != nil {
		return err
	}
	if err := os.WriteFile(csrOut, csr, 0o644); err != nil {
		return fmt.Errorf("write CSR %s: %w", csrOut, err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "client certificate identity initialized:\n"+
		"  client_id: %s\n  name:      %s\n  keystore:  %s (%s)\n"+
		"  CSR:       %s (use with `client enroll`, Phase 3)\n"+
		"  private key: stored securely, never exported\n",
		clientID, name, backendName, secretsDir, csrOut)
	return nil
}

// defaultSecretsDir returns the keystore fallback directory
// (<user-config>/qoqtun/secrets, 03-pki-enrollment.md §7).
func defaultSecretsDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	return filepath.Join(base, "qoqtun", "secrets")
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
