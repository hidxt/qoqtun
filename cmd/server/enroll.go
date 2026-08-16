package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hidxt/qoqtun/internal/auth"
	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/enroll"
	"github.com/hidxt/qoqtun/internal/logging"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/spf13/cobra"
)

// newEnrollCmds wires `server client ...`, `server cert ...` and
// `server enroll serve` subcommands.
func newEnrollCmds() []*cobra.Command {
	clientCmd := &cobra.Command{Use: "client", Short: "Manage clients and enrollment tokens"}
	clientCmd.AddCommand(
		newCreateTokenCmd(),
		newClientListCmd(),
		newRevokeTokenCmd(),
	)
	certCmd := &cobra.Command{Use: "cert", Short: "Manage issued certificates"}
	certCmd.AddCommand(newCertListCmd(), newCertRevokeCmd())

	enrollCmd := &cobra.Command{Use: "enroll", Short: "Run the enrollment listener"}
	var enrollConfig string
	enrollCmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Start the enroll/renew TLS listener (token-based issuance)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnrollServe(enrollConfig)
		},
	})
	enrollCmd.PersistentFlags().StringVar(&enrollConfig, "config", "", "path to server.toml")
	return []*cobra.Command{clientCmd, certCmd, enrollCmd}
}

func newCreateTokenCmd() *cobra.Command {
	var configPath, ttlStr, createdBy string
	cmd := &cobra.Command{
		Use:   "create-token",
		Short: "Create a one-time enrollment token (printed once)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			ttl := time.Hour
			if ttlStr != "" {
				ttl, err = time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl: %w", err)
				}
			}
			tokens, err := auth.LoadTokenStore(filepath.Join(cfg.StateDir, "tokens.json"), nil)
			if err != nil {
				return err
			}
			plain, id, _, err := auth.CreateToken()
			if err != nil {
				return err
			}
			if _, err := tokens.Create(plain, id, createdBy, ttl); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Enrollment token (use once, expires in %s):\n  %s\n", ttl, plain)
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: this token is shown only once. It is stored server-side as a SHA-256 hash.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	cmd.Flags().StringVar(&ttlStr, "ttl", "1h", "token lifetime (<=24h)")
	cmd.Flags().StringVar(&createdBy, "created-by", "", "who created this token (audit)")
	return cmd
}

func newClientListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled clients",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			reg, err := pki.LoadClientRegistry(filepath.Join(cfg.StateDir, "clients.json"))
			if err != nil {
				return err
			}
			for _, rec := range reg.All() {
				fmt.Fprintf(cmd.OutOrStdout(), "%-36s %-20s serial=%s created=%s note=%s\n",
					rec.ClientID, rec.Name, rec.CertSerial, rec.CreatedAt.Format(time.RFC3339), rec.Note)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func newRevokeTokenCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "revoke-token <token_id>",
		Short: "Revoke an enrollment token by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			tokens, err := auth.LoadTokenStore(filepath.Join(cfg.StateDir, "tokens.json"), nil)
			if err != nil {
				return err
			}
			if err := tokens.Revoke(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "token %s revoked\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func newCertListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued client certificates (from the registry)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			reg, err := pki.LoadClientRegistry(filepath.Join(cfg.StateDir, "clients.json"))
			if err != nil {
				return err
			}
			revoked, err := pki.LoadRevocationList(filepath.Join(cfg.StateDir, "revoked.json"))
			if err != nil {
				return err
			}
			for _, rec := range reg.All() {
				status := "valid"
				if revoked.IsRevoked(rec.CertSerial) {
					status = "REVOKED"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s name=%s\n", rec.CertSerial, status, rec.ClientID, rec.Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func newCertRevokeCmd() *cobra.Command {
	var configPath, reason string
	cmd := &cobra.Command{
		Use:   "revoke <serial>",
		Short: "Revoke a certificate by serial (takes effect on the next handshake)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			revoked, err := pki.LoadRevocationList(filepath.Join(cfg.StateDir, "revoked.json"))
			if err != nil {
				return err
			}
			if err := revoked.Revoke(args[0], reason); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "certificate %s revoked\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	cmd.Flags().StringVar(&reason, "reason", "", "revocation reason (audit)")
	return cmd
}

func runEnrollServe(configPath string) error {
	cfg, err := loadServerConfig(configPath)
	if err != nil {
		return err
	}
	logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File)
	if err != nil {
		return err
	}
	srv, err := loadEnrollServer(cfg, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.ListenAndServe(ctx)
}

// loadEnrollServer assembles an enroll.Server from the server state dir.
func loadEnrollServer(cfg *config.ServerConfig, logger *slog.Logger) (*enroll.Server, error) {
	if !cfg.Listen.EnrollEnabled || cfg.Listen.EnrollAddr == "" {
		return nil, fmt.Errorf("enroll listener is disabled (listen.enroll_addr / enroll_enabled)")
	}
	caCertPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "ca", "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("load CA cert (run `ca init` first): %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "ca", "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("load CA key: %w", err)
	}
	caCert, err := pki.ParseCertificate(caCertPEM)
	if err != nil {
		return nil, err
	}
	caKey, err := pki.ParsePrivateKey(caKeyPEM)
	if err != nil {
		return nil, err
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "server", "server.crt"))
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "server", "server.key"))
	if err != nil {
		return nil, fmt.Errorf("load server key: %w", err)
	}
	tokens, err := auth.LoadTokenStore(filepath.Join(cfg.StateDir, "tokens.json"), nil)
	if err != nil {
		return nil, err
	}
	registry, err := pki.LoadClientRegistry(filepath.Join(cfg.StateDir, "clients.json"))
	if err != nil {
		return nil, err
	}
	revoked, err := pki.LoadRevocationList(filepath.Join(cfg.StateDir, "revoked.json"))
	if err != nil {
		return nil, err
	}
	return &enroll.Server{
		Addr:                   cfg.Listen.EnrollAddr,
		CertPEM:                serverCertPEM,
		KeyPEM:                 serverKeyPEM,
		CA:                     &pki.CA{Cert: caCert, Key: caKey},
		Tokens:                 tokens,
		Registry:               registry,
		Revoked:                revoked,
		ClientCertValidityDays: cfg.PKI.ClientCertValidityDays,
		Limiter:                enroll.NewIPLimiter(nil),
		Log:                    logger,
	}, nil
}
