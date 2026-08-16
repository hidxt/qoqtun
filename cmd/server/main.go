// Command qoqtun-server is the Server CLI entry point. It contains no
// business logic: everything is delegated to internal packages.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/control"
	"github.com/hidxt/qoqtun/internal/logging"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/platform/atomicfile"
	"github.com/hidxt/qoqtun/internal/security"
	"github.com/hidxt/qoqtun/internal/transport"
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
	root.AddCommand(newRunCmd(), newCheckConfigCmd(), newCACmd(), newStatusCmd())
	root.AddCommand(newEnrollCmds()...)
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
	var sans []string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Root CA and server certificate in state_dir",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			return runCAInit(cmd, cfg, force, sans)
		},
	}
	initCmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	initCmd.Flags().BoolVar(&force, "force", false,
		"overwrite an existing CA (warning: invalidates all existing client certificates)")
	initCmd.Flags().StringSliceVar(&sans, "san", nil,
		"extra SAN (IP or DNS) for the server certificate; repeatable. Required when control_addr is 0.0.0.0/:: so clients can verify the connection")
	caCmd.AddCommand(initCmd)
	return caCmd
}

func runCAInit(cmd *cobra.Command, cfg *config.ServerConfig, force bool, sans []string) error {
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

	// server certificate SANs: control_addr host + explicit --san values.
	// Wildcard listen addresses (0.0.0.0/::) are not usable as SANs and are
	// skipped with a warning.
	host, _, err := net.SplitHostPort(cfg.Listen.ControlAddr)
	if err != nil {
		return fmt.Errorf("parse control_addr: %w", err)
	}
	var ips []net.IP
	var dns []string
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: control_addr host %s is a wildcard; clients cannot verify it. Add SANs with --san (e.g. --san 203.0.113.5 --san tunnel.example.com).\n", host)
		} else {
			ips = append(ips, ip)
		}
	} else if host != "" {
		dns = append(dns, host)
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, san)
		}
	}
	if len(ips) == 0 && len(dns) == 0 {
		return fmt.Errorf("no SAN for the server certificate (control_addr is a wildcard and no --san given)")
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

// writeStatusLoop snapshots the server state to status.json every 2s.
func writeStatusLoop(ctx context.Context, srv *control.Server, path string, logger *slog.Logger) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			data, err := json.MarshalIndent(srv.Status(), "", "  ")
			if err != nil {
				continue
			}
			if err := atomicfile.Write(path, data, 0o600); err != nil {
				logger.Debug("status write failed", "error", err)
			}
		}
	}
}

// newStatusCmd implements `server status`: print the local status snapshot.
func newStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the local server status snapshot",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(filepath.Join(cfg.StateDir, "status.json"))
			if err != nil {
				return fmt.Errorf("no status file yet (server run must be active): %w", err)
			}
			os.Stdout.Write(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	return cmd
}

func newRunCmd() *cobra.Command {
	var (
		configPath string
		allowRoot  bool
		allowLowFD bool
		pprofAddr  string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the server control plane (mTLS + tunnel listeners)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadServerConfig(configPath)
			if err != nil {
				return err
			}
			logger, err := logging.New(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File)
			if err != nil {
				return err
			}
			if err := applyStartupGuards(cfg, allowRoot, allowLowFD); err != nil {
				return err
			}
			return runServer(cfg, logger, pprofAddr)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to server.toml")
	cmd.Flags().BoolVar(&allowRoot, "allow-root", false, "allow running as root/administrator")
	cmd.Flags().BoolVar(&allowLowFD, "allow-low-fdlimit", false, "allow running below the recommended open-file limit")
	cmd.Flags().StringVar(&pprofAddr, "pprof", "", "pprof listen address (127.0.0.1 only, e.g. 127.0.0.1:6060)")
	return cmd
}

// applyStartupGuards enforces the resource guards (T10): root detection and
// the RLIMIT_NOFILE check. Both are injectable via the security package.
func applyStartupGuards(cfg *config.ServerConfig, allowRoot, allowLowFD bool) error {
	if security.IsRoot() && !allowRoot {
		return security.ErrRootDenied()
	}
	est := security.EstimatedFDLimit(cfg.Policy.MaxConnsPerClient, cfg.Policy.MaxConnsPerTunnel, 64)
	chk := security.CheckFDLimit(est)
	if chk.BelowLimit && !allowLowFD {
		return security.ErrInsufficientFD(chk)
	}
	return nil
}

// runServer loads the PKI materials and serves the control plane until
// interrupted.
func runServer(cfg *config.ServerConfig, logger *slog.Logger, pprofAddr string) error {
	if pprofAddr != "" {
		// pprof is off by default; when enabled it binds 127.0.0.1 only
		// (T10: diagnostics endpoint, never exposed publicly)
		host, _, err := net.SplitHostPort(pprofAddr)
		if err != nil || host != "127.0.0.1" {
			return fmt.Errorf("--pprof must bind 127.0.0.1 (got %q)", pprofAddr)
		}
		go func() {
			logger.Info("pprof listening", "addr", pprofAddr)
			_ = http.ListenAndServe(pprofAddr, nil)
		}()
	}
	caCertPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "ca", "ca.crt"))
	if err != nil {
		return fmt.Errorf("load CA cert (run `ca init` first): %w", err)
	}
	caKeyPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "ca", "ca.key"))
	if err != nil {
		return fmt.Errorf("load CA key: %w", err)
	}
	caCert, err := pki.ParseCertificate(caCertPEM)
	if err != nil {
		return err
	}
	_, err = pki.ParsePrivateKey(caKeyPEM)
	if err != nil {
		return err
	}
	serverCertPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "server", "server.crt"))
	if err != nil {
		return fmt.Errorf("load server cert: %w", err)
	}
	serverKeyPEM, err := os.ReadFile(filepath.Join(cfg.StateDir, "server", "server.key"))
	if err != nil {
		return fmt.Errorf("load server key: %w", err)
	}
	revoked, err := pki.LoadRevocationList(filepath.Join(cfg.StateDir, "revoked.json"))
	if err != nil {
		return err
	}

	raw, err := net.Listen("tcp", cfg.Listen.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen.ControlAddr, err)
	}
	ln, err := transport.Listen(raw, transport.Options{
		CAs:              []*x509.Certificate{caCert},
		Cert:             serverCertPEM,
		Key:              serverKeyPEM,
		IsRevoked:        revoked.IsRevoked,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	srv := &control.Server{
		CAs:              []*x509.Certificate{caCert},
		Cert:             serverCertPEM,
		Key:              serverKeyPEM,
		IsRevoked:        revoked.IsRevoked,
		Cfg:              cfg,
		Log:              logger,
		MaxHalfOpen:      8,
		HandshakeTimeout: 10 * time.Second,
		VhostPort:        cfg.Listen.HTTPVhostPort,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// periodic local status snapshot (V1: local query only, no remote
	// management channel); read by `server status`
	statusPath := filepath.Join(cfg.StateDir, "status.json")
	go writeStatusLoop(ctx, srv, statusPath, logger)
	// graceful shutdown: broadcast shutdown to clients, drain, then exit
	go func() {
		<-ctx.Done()
		logger.Info("server shutting down, notifying clients")
		sctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		srv.BroadcastShutdown(sctx, "server shutdown", 30*time.Second)
		_ = ln.Close()
	}()
	// second signal forces immediate exit
	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch // first signal consumed by NotifyContext
		<-ch // second: force quit
		os.Exit(130)
	}()
	logger.Info("server control plane starting", "addr", cfg.Listen.ControlAddr)
	return srv.Serve(ctx, ln)
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
