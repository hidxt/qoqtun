// Command qoqtun-desktop is the Wails v2 shell for the Desktop client.
// The GUI is a thin shell: every network/TLS/PKI/security/statistics
// operation delegates to the internal Go core via coreapi. The frontend
// never touches certificates, keys or tokens.
package main

import (
	"embed"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/hidxt/qoqtun/internal/config"
	"github.com/hidxt/qoqtun/internal/coreapi"
	"github.com/hidxt/qoqtun/internal/platform/atomicfile"
	"github.com/hidxt/qoqtun/internal/platform/keystore"
	"github.com/pelletier/go-toml/v2"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	dir := filepath.Join(base, "qoqtun")
	_ = os.MkdirAll(dir, 0o700)
	_ = os.MkdirAll(filepath.Join(dir, "secrets"), 0o700)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	backend, err := keystore.ParseBackendPref("auto")
	if err != nil {
		logger.Error("keystore backend", "error", err)
		os.Exit(1)
	}
	cfgPath := filepath.Join(dir, "client.toml")
	if _, err := os.Stat(cfgPath); err != nil {
		// first run: write a default config
		cfg := config.DefaultClientConfig()
		data, err := toml.Marshal(cfg)
		if err == nil {
			_ = atomicfile.Write(cfgPath, data, 0o600)
		}
	}
	api, err := coreapi.New(coreapi.Options{
		ConfigPath: cfgPath,
		StatePath:  filepath.Join(dir, "state.json"),
		SecretsDir: filepath.Join(dir, "secrets"),
		Backend:    backend,
		Log:        logger,
	})
	if err != nil {
		logger.Error("coreapi init", "error", err)
		os.Exit(1)
	}

	wails.Run(&options.App{
		Title:     "qoqtun",
		Width:     1024,
		Height:    720,
		MinWidth:  800,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Bind: []any{api},
	})
}
