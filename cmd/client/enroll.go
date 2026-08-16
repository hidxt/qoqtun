package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hidxt/qoqtun/internal/enroll"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/platform/keystore"
	"github.com/spf13/cobra"
)

// clientState is the persisted client identity metadata (0600).
type clientState struct {
	ClientID      string `json:"client_id"`
	ServerAddr    string `json:"server_addr"`
	CAFingerprint string `json:"ca_fingerprint"`
	CertPath      string `json:"cert_path"`
	ExpiresAt     string `json:"expires_at"`
}

func defaultStatePath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	return filepath.Join(base, "qoqtun", "state.json")
}

func loadClientState(path string) (*clientState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client state %s: %w", path, err)
	}
	var st clientState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse client state: %w", err)
	}
	return &st, nil
}

// newEnrollCmd implements `client enroll`: send the CSR with a one-time
// token, verify the returned chain and persist the identity.
func newEnrollCmd() *cobra.Command {
	var token, serverAddr, csrPath, caFingerprint, certOut, caOut, statePath, secretsDir, backendStr string
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device with the server using a one-time token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if token == "" {
				// prefer stdin to keep the token out of shell history
				fmt.Fprint(cmd.ErrOrStderr(), "token: ")
				if _, err := fmt.Fscanln(cmd.InOrStdin(), &token); err != nil {
					return fmt.Errorf("no token provided (use --token or stdin)")
				}
			}
			csr, err := os.ReadFile(csrPath)
			if err != nil {
				return fmt.Errorf("read CSR %s (run `client cert init` first): %w", csrPath, err)
			}
			backend, err := keystore.ParseBackendPref(backendStr)
			if err != nil {
				return err
			}
			keyPEM, err := loadClientKey(secretsDir, backend)
			if err != nil {
				return err
			}
			key, err := pki.ParsePrivateKey(keyPEM)
			if err != nil {
				return err
			}
			host, _, err := splitServerAddr(serverAddr)
			if err != nil {
				return err
			}
			_ = host
			client := &enroll.Client{ServerAddr: serverAddr}
			res, err := client.Enroll(context.Background(), enroll.EnrollOptions{
				Token:         token,
				CSR:           csr,
				Meta:          enroll.Meta{Name: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH},
				CAFingerprint: caFingerprint,
				ClientKey:     key,
			})
			if err != nil {
				return err
			}
			st := &clientState{
				ClientID:      res.ClientID,
				ServerAddr:    serverAddr,
				CAFingerprint: res.CAFingerprint,
				CertPath:      certOut,
				ExpiresAt:     res.ExpiresAt.UTC().Format(time.RFC3339),
			}
			if err := res.Save(res.ClientCertPEM, res.CACertPEM, certOut, caOut, statePath, st); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "enrolled as %s (expires %s)\n  cert: %s\n  ca:   %s\n  CA fingerprint: %s\n",
				res.ClientID, res.ExpiresAt.UTC().Format(time.RFC3339), certOut, caOut, res.CAFingerprint)
			if caFingerprint == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "NOTE: no --ca-fingerprint given; the CA fingerprint above was accepted on first use (pin it on next enroll).")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "one-time enrollment token (prefer stdin)")
	cmd.Flags().StringVar(&serverAddr, "server", "", "server address host:port (required)")
	cmd.Flags().StringVar(&csrPath, "csr", "client.csr", "path to the CSR from `cert init`")
	cmd.Flags().StringVar(&caFingerprint, "ca-fingerprint", "", "pin the server CA fingerprint (64 hex chars)")
	cmd.Flags().StringVar(&certOut, "cert-out", "client.crt", "path to write the issued certificate")
	cmd.Flags().StringVar(&caOut, "ca-out", "ca.crt", "path to write the server CA certificate")
	cmd.Flags().StringVar(&statePath, "state-out", "", "path to the identity state file (default: <user-config>/qoqtun/state.json)")
	cmd.Flags().StringVar(&secretsDir, "secrets-dir", "", "keystore fallback directory")
	cmd.Flags().StringVar(&backendStr, "keystore-backend", "auto", "keystore backend: auto|keyring|file")
	cmd.MarkFlagRequired("server")
	return cmd
}

// newCertStatusCmd implements `client cert status`.
func newCertStatusCmd() *cobra.Command {
	var statePath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the enrolled identity status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if statePath == "" {
				statePath = defaultStatePath()
			}
			st, err := loadClientState(statePath)
			if err != nil {
				return err
			}
			certPEM, err := os.ReadFile(st.CertPath)
			if err != nil {
				return fmt.Errorf("read cert: %w", err)
			}
			cert, err := pki.ParseCertificate(certPEM)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "client_id: %s\nserver:    %s\nCA fp:     %s\nexpires:   %s (%s)\n",
				st.ClientID, st.ServerAddr, st.CAFingerprint, st.ExpiresAt,
				time.Until(cert.NotAfter).Round(time.Hour))
			if pki.IsExpired(cert) {
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: certificate is expired; re-enroll with a new token")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&statePath, "state", "", "path to the identity state file")
	return cmd
}

// newCertRenewCmd implements `client cert renew` over mTLS.
func newCertRenewCmd() *cobra.Command {
	var serverAddr, csrPath, certOut, caOut, statePath, secretsDir, backendStr string
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew the client certificate over the authenticated mTLS channel",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if statePath == "" {
				statePath = defaultStatePath()
			}
			st, err := loadClientState(statePath)
			if err != nil {
				return err
			}
			if serverAddr == "" {
				serverAddr = st.ServerAddr
			}
			if certOut == "" {
				certOut = st.CertPath
			}
			csr, err := os.ReadFile(csrPath)
			if err != nil {
				return fmt.Errorf("read CSR: %w", err)
			}
			backend, err := keystore.ParseBackendPref(backendStr)
			if err != nil {
				return err
			}
			keyPEM, err := loadClientKey(secretsDir, backend)
			if err != nil {
				return err
			}
			key, err := pki.ParsePrivateKey(keyPEM)
			if err != nil {
				return err
			}
			oldCert, err := os.ReadFile(st.CertPath)
			if err != nil {
				return fmt.Errorf("read current cert: %w", err)
			}
			client := &enroll.Client{ServerAddr: serverAddr}
			res, err := client.Enroll(context.Background(), enroll.EnrollOptions{
				CSR:           csr,
				ClientCert:    oldCert,
				ClientKey:     key,
				CAFingerprint: st.CAFingerprint,
			})
			if err != nil {
				return err
			}
			st.ExpiresAt = res.ExpiresAt.UTC().Format(time.RFC3339)
			if err := res.Save(res.ClientCertPEM, res.CACertPEM, certOut, caOut, statePath, st); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "certificate renewed (new serial, expires %s)\n", st.ExpiresAt)
			return nil
		},
	}
	cmd.Flags().StringVar(&serverAddr, "server", "", "server address (default: from state)")
	cmd.Flags().StringVar(&csrPath, "csr", "client.csr", "path to the CSR")
	cmd.Flags().StringVar(&certOut, "cert-out", "", "certificate output path (default: current)")
	cmd.Flags().StringVar(&caOut, "ca-out", "ca.crt", "path to write the server CA certificate")
	cmd.Flags().StringVar(&statePath, "state", "", "path to the identity state file")
	cmd.Flags().StringVar(&secretsDir, "secrets-dir", "", "keystore fallback directory")
	cmd.Flags().StringVar(&backendStr, "keystore-backend", "auto", "keystore backend: auto|keyring|file")
	return cmd
}

// loadClientKey reads the private key from the keystore.
func loadClientKey(secretsDir string, backend keystore.BackendPref) ([]byte, error) {
	if secretsDir == "" {
		secretsDir = defaultSecretsDir()
	}
	store, _, err := keystore.OpenWithPref(keystore.KeyringConfig{ServiceName: "qoqtun"}, secretsDir, backend, nil)
	if err != nil {
		return nil, err
	}
	keyPEM, err := store.Get("client-key")
	if err != nil {
		return nil, fmt.Errorf("read client private key (run `client cert init` first): %w", err)
	}
	return keyPEM, nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unnamed-device"
	}
	return h
}

func splitServerAddr(addr string) (string, string, error) {
	// naive split used for metadata only; full validation is done by config
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("invalid server address %q (want host:port)", addr)
}
