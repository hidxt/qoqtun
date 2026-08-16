// Package coreapi is the Desktop's only entry point (01-architecture §4):
// a narrow, validated facade over the Go core. The GUI is a thin shell —
// every network/TLS/PKI/security/statistics operation delegates to the
// existing internal packages. Nothing returned here ever contains private
// keys, certificate PEMs or tokens.
package coreapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hidxt/qoqtun/internal/clientcore"
	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/enroll"
	"github.com/hidxt/qoqtun/internal/metrics"
	"github.com/hidxt/qoqtun/internal/pki"
	"github.com/hidxt/qoqtun/internal/platform/atomicfile"
	"github.com/hidxt/qoqtun/internal/platform/keystore"
	"github.com/pelletier/go-toml/v2"
)

// API is the Desktop-facing facade. All methods validate their inputs
// (same source as config validation) and return metadata only.
type API struct {
	mu sync.Mutex

	configPath string // client.toml
	statePath  string // state.json
	secretsDir string
	backend    keystore.BackendPref

	logger *slog.Logger
	cfg    *config.ClientConfig

	// runtime client (nil while stopped)
	client *clientcore.Client
	cancel context.CancelFunc
	runErr chan error

	events chan Event
}

// Event is a typed notification for the GUI (Wails Events bridge).
type Event struct {
	Type string // state | stats | tunnel | log
	Data any
}

// Status mirrors the connection state machine for the UI.
type Status struct {
	Running    bool   `json:"running"`
	State      string `json:"state"` // stopped|connecting|online
	ClientID   string `json:"client_id,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
}

// IdentityInfo is the enrolled identity metadata (no secrets).
type IdentityInfo struct {
	ClientID   string `json:"client_id"`
	Name       string `json:"name"`
	ServerAddr string `json:"server_addr"`
	ExpiresAt  string `json:"expires_at"`
	Keystore   string `json:"keystore"`
	Enrolled   bool   `json:"enrolled"`
}

// Options configures the API.
type Options struct {
	ConfigPath string
	StatePath  string
	SecretsDir string
	Backend    keystore.BackendPref
	Log        *slog.Logger
}

// New builds the facade. It does not start the tunnel client.
func New(o Options) (*API, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	a := &API{
		configPath: o.ConfigPath,
		statePath:  o.StatePath,
		secretsDir: o.SecretsDir,
		backend:    o.Backend,
		logger:     o.Log,
		events:     make(chan Event, 128),
		runErr:     make(chan error, 1),
	}
	if err := a.loadConfig(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *API) loadConfig() error {
	cfg, err := config.LoadClient(a.configPath)
	if err != nil {
		return fmt.Errorf("coreapi: load config: %w", err)
	}
	if err := config.ValidateClient(cfg); err != nil {
		return fmt.Errorf("coreapi: invalid config: %w", err)
	}
	a.cfg = cfg
	return nil
}

// ---- lifecycle ----

// Start loads the identity, builds the tunnel client and runs it until
// Stop is called. profile is reserved for multiple config profiles (V1:
// "" = default config).
func (a *API) Start(profile string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return fmt.Errorf("coreapi: already running")
	}
	// identity from state file
	st, err := loadState(a.statePath)
	if err != nil {
		return fmt.Errorf("coreapi: identity: %w", err)
	}
	caCert, err := loadCA(a.statePath, st)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(st.CertPath)
	if err != nil {
		return fmt.Errorf("coreapi: read client cert: %w", err)
	}
	keyPEM, err := loadKey(a.secretsDir, a.backend)
	if err != nil {
		return err
	}
	if _, err := pki.ParsePrivateKey(keyPEM); err != nil {
		return fmt.Errorf("coreapi: parse key: %w", err)
	}

	serverAddr := a.cfg.ServerAddr
	if serverAddr == "" {
		serverAddr = st.ServerAddr
	}
	client := &clientcore.Client{
		ServerAddr: serverAddr,
		CAs:        []*x509.Certificate{caCert},
		Cert:       certPEM,
		Key:        keyPEM,
		ClientID:   st.ClientID,
		Name:       st.Name,
		Log:        a.logger,
		Tunnels:    tunnelsToSpecs(a.cfg.Tunnels),
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.client = client
	a.cancel = cancel
	a.emit(Event{Type: "state", Data: Status{Running: true, State: "connecting", ClientID: st.ClientID, ServerAddr: serverAddr}})
	go func() {
		err := client.Run(ctx)
		if err != nil && err != clientcore.ErrGracefulShutdown {
			a.logger.Error("coreapi: client stopped", "error", err)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.client = nil
		a.cancel = nil
		a.emit(Event{Type: "state", Data: Status{Running: false, State: "stopped"}})
		select {
		case a.runErr <- err:
		default:
		}
	}()
	return nil
}

// Stop gracefully stops the tunnel client (ctx-cancel; the client sends
// shutdown to the server and drains).
func (a *API) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return nil
	}
	if a.cancel != nil {
		a.cancel()
	}
	a.client = nil
	a.cancel = nil
	return nil
}

// Status returns the current lifecycle state.
func (a *API) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return Status{Running: false, State: "stopped"}
	}
	return Status{Running: true, State: "online", ClientID: a.client.ClientID, ServerAddr: a.client.ServerAddr}
}

// ---- tunnels (runtime) ----

// ListTunnels returns the runtime tunnel states.
func (a *API) ListTunnels() []clientcore.TunnelInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return nil
	}
	return a.client.TunnelList()
}

// StartTunnel starts a configured tunnel at runtime (not persisted).
func (a *API) StartTunnel(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return fmt.Errorf("coreapi: client not running")
	}
	spec, ok := tunnelSpecByName(a.cfg.Tunnels, name)
	if !ok {
		return fmt.Errorf("coreapi: tunnel %q not in config", name)
	}
	spec.Enabled = true
	return a.client.RegisterTunnel(context.Background(), spec)
}

// StopTunnel stops a running tunnel (runtime only).
func (a *API) StopTunnel(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return fmt.Errorf("coreapi: client not running")
	}
	return a.client.UnregisterTunnel(context.Background(), name)
}

// ---- config ----

// GetConfig returns the effective config (metadata; no secrets).
func (a *API) GetConfig() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]any{
		"server_addr": a.cfg.ServerAddr,
	}
	tunnels := make([]map[string]any, 0, len(a.cfg.Tunnels))
	for _, t := range a.cfg.Tunnels {
		tunnels = append(tunnels, map[string]any{
			"name": t.Name, "type": t.Type, "remote_port": t.RemotePort,
			"local_ip": t.LocalIP, "local_port": t.LocalPort,
			"http_host": t.HTTPHost, "enabled": t.Enabled,
		})
	}
	out["tunnels"] = tunnels
	return out
}

// UpdateConfig merges partial settings (server_addr / tunnels), validates,
// persists to client.toml and returns the effective config.
func (a *API) UpdateConfig(partial map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := applyPartial(a.cfg, partial); err != nil {
		return err
	}
	if err := config.ValidateClient(a.cfg); err != nil {
		return fmt.Errorf("coreapi: invalid config: %w", err)
	}
	return a.persistConfig()
}

// UpsertTunnel adds or replaces a tunnel in client.toml (persisted; takes
// effect on next start, or immediately if running and already registered).
func (a *API) UpsertTunnel(t config.TunnelConfig) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := validateTunnel(a.cfg, t); err != nil {
		return err
	}
	replaced := false
	for i := range a.cfg.Tunnels {
		if a.cfg.Tunnels[i].Name == t.Name {
			a.cfg.Tunnels[i] = t
			replaced = true
			break
		}
	}
	if !replaced {
		a.cfg.Tunnels = append(a.cfg.Tunnels, t)
	}
	if err := config.ValidateClient(a.cfg); err != nil {
		return fmt.Errorf("coreapi: invalid config: %w", err)
	}
	if err := a.persistConfig(); err != nil {
		return err
	}
	a.emit(Event{Type: "tunnel", Data: t.Name})
	return nil
}

// DeleteTunnel removes a tunnel from client.toml.
func (a *API) DeleteTunnel(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.cfg.Tunnels[:0]
	found := false
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		return fmt.Errorf("coreapi: tunnel %q not found", name)
	}
	a.cfg.Tunnels = out
	if err := a.persistConfig(); err != nil {
		return err
	}
	a.emit(Event{Type: "tunnel", Data: name})
	return nil
}

func (a *API) persistConfig() error {
	data, err := toml.Marshal(a.cfg)
	if err != nil {
		return fmt.Errorf("coreapi: marshal config: %w", err)
	}
	if err := atomicfile.Write(a.configPath, data, 0o600); err != nil {
		return fmt.Errorf("coreapi: persist config: %w", err)
	}
	return nil
}

// ---- identity ----

// GetIdentity returns enrolled identity metadata (never secrets).
func (a *API) GetIdentity() IdentityInfo {
	st, err := loadState(a.statePath)
	if err != nil {
		return IdentityInfo{Enrolled: false, Keystore: a.backend.String()}
	}
	info := IdentityInfo{
		ClientID:   st.ClientID,
		ServerAddr: st.ServerAddr,
		ExpiresAt:  st.ExpiresAt,
		Keystore:   a.backend.String(),
		Enrolled:   true,
	}
	if certPEM, err := os.ReadFile(st.CertPath); err == nil {
		if cert, err := pki.ParseCertificate(certPEM); err == nil {
			info.ExpiresAt = cert.NotAfter.Format(time.RFC3339)
			if len(cert.Subject.Organization) > 0 {
				info.Name = cert.Subject.Organization[0]
			}
		}
	}
	return info
}

// EnrollOptions mirrors the CLI enroll inputs (token travels in memory
// only; it is never persisted or logged).
type EnrollOptions struct {
	Token      string `json:"token"`
	ServerAddr string `json:"server_addr"`
	Name       string `json:"name"`
}

// Enroll provisions the device identity: generates the key (into the
// keystore), sends the CSR with the one-time token, persists the issued
// certificate and the state file.
func (a *API) Enroll(o EnrollOptions) (IdentityInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if o.Token == "" {
		return IdentityInfo{}, fmt.Errorf("coreapi: token required")
	}
	if o.ServerAddr == "" {
		return IdentityInfo{}, fmt.Errorf("coreapi: server_addr required")
	}
	dir := filepath.Dir(a.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return IdentityInfo{}, err
	}
	store, _, err := keystore.OpenWithPref(keystore.KeyringConfig{ServiceName: "qoqtun"}, a.secretsDir, a.backend, nil)
	if err != nil {
		return IdentityInfo{}, fmt.Errorf("coreapi: keystore: %w", err)
	}
	key, err := pki.GenerateKey()
	if err != nil {
		return IdentityInfo{}, err
	}
	id, err := pki.ClientID()
	if err != nil {
		return IdentityInfo{}, err
	}
	csr, err := pki.CreateCSR(key, id, o.Name)
	if err != nil {
		return IdentityInfo{}, err
	}
	client := &enroll.Client{ServerAddr: o.ServerAddr}
	res, err := client.Enroll(context.Background(), enroll.EnrollOptions{
		Token: o.Token,
		CSR:   csr,
		Meta:  enroll.Meta{Name: o.Name},
	})
	if err != nil {
		return IdentityInfo{}, fmt.Errorf("coreapi: enroll: %w", err)
	}
	keyPEM, err := pki.MarshalPrivateKey(key)
	if err != nil {
		return IdentityInfo{}, err
	}
	if err := store.Set("client-key", keyPEM); err != nil {
		return IdentityInfo{}, err
	}
	certPath := filepath.Join(dir, "client.crt")
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, res.ClientCertPEM, 0o600); err != nil {
		return IdentityInfo{}, err
	}
	if err := os.WriteFile(caPath, res.CACertPEM, 0o600); err != nil {
		return IdentityInfo{}, err
	}
	st := map[string]string{
		"client_id":      res.ClientID,
		"server_addr":    o.ServerAddr,
		"ca_fingerprint": res.CAFingerprint,
		"cert_path":      certPath,
		"expires_at":     res.ExpiresAt.Format(time.RFC3339),
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return IdentityInfo{}, err
	}
	if err := atomicfile.Write(a.statePath, data, 0o600); err != nil {
		return IdentityInfo{}, err
	}
	return a.GetIdentity(), nil
}

// ---- stats ----

// GetStats returns the traffic snapshot (client-side counters).
func (a *API) GetStats() metrics.Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client == nil {
		return metrics.Snapshot{}
	}
	return a.client.Status()
}

// ---- events ----

// Events returns the shared event stream (the Wails bridge consumes it;
// events are dropped when nobody reads, no subscription leak).
func (a *API) Events() <-chan Event { return a.events }

func (a *API) emit(e Event) {
	select {
	case a.events <- e:
	default:
	}
}

// ---- helpers ----

func tunnelsToSpecs(tunnels []config.TunnelConfig) []clientcore.TunnelSpec {
	out := make([]clientcore.TunnelSpec, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, clientcore.TunnelSpec{
			Name: t.Name, Type: t.Type, RemotePort: t.RemotePort,
			LocalIP: t.LocalIP, LocalPort: t.LocalPort, HTTPHost: t.HTTPHost,
			Enabled: t.Enabled,
		})
	}
	return out
}

func tunnelSpecByName(tunnels []config.TunnelConfig, name string) (clientcore.TunnelSpec, bool) {
	for _, t := range tunnels {
		if t.Name == name {
			return clientcore.TunnelSpec{
				Name: t.Name, Type: t.Type, RemotePort: t.RemotePort,
				LocalIP: t.LocalIP, LocalPort: t.LocalPort, HTTPHost: t.HTTPHost,
				Enabled: t.Enabled,
			}, true
		}
	}
	return clientcore.TunnelSpec{}, false
}

func validateTunnel(cfg *config.ClientConfig, t config.TunnelConfig) error {
	if t.Name == "" {
		return fmt.Errorf("coreapi: tunnel name required")
	}
	tmp := *cfg // shallow copy; the tunnel list is replaced for validation
	tmp.Tunnels = []config.TunnelConfig{t}
	return config.ValidateClient(&tmp)
}

func applyPartial(cfg *config.ClientConfig, partial map[string]any) error {
	if v, ok := partial["server_addr"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("coreapi: server_addr must be a string")
		}
		cfg.ServerAddr = s
	}
	if v, ok := partial["tunnels"]; ok {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var ts []config.TunnelConfig
		if err := json.Unmarshal(data, &ts); err != nil {
			return fmt.Errorf("coreapi: tunnels payload invalid: %w", err)
		}
		cfg.Tunnels = ts
	}
	return nil
}

// ---- state helpers (duplicated small loaders so coreapi stays standalone) ----

type stateFile struct {
	ClientID   string `json:"client_id"`
	ServerAddr string `json:"server_addr"`
	Name       string `json:"name,omitempty"`
	CertPath   string `json:"cert_path"`
	ExpiresAt  string `json:"expires_at"`
}

func loadState(path string) (*stateFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state %s (enroll first): %w", path, err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if st.ClientID == "" || st.CertPath == "" {
		return nil, fmt.Errorf("state incomplete (enroll first)")
	}
	return &st, nil
}

func loadCA(statePath string, st *stateFile) (*x509.Certificate, error) {
	caPath := filepath.Join(filepath.Dir(statePath), "ca.crt")
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	cert, err := pki.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}
	return cert, nil
}

func loadKey(secretsDir string, backend keystore.BackendPref) ([]byte, error) {
	store, _, err := keystore.OpenWithPref(keystore.KeyringConfig{ServiceName: "qoqtun"}, secretsDir, backend, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	key, err := store.Get("client-key")
	if err != nil {
		return nil, fmt.Errorf("read client key (keystore %s): %w", backend, err)
	}
	return key, nil
}
