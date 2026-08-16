//go:build linux || darwin

package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/hidxt/qoqtun/internal/platform/atomicfile"
)

// linux: XDG autostart entry; darwin: launchd LaunchAgent.

func autostartPath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(base, "Library", "LaunchAgents", "com.qoqtun.desktop.plist")
	}
	return filepath.Join(base, "autostart", "qoqtun-desktop.desktop")
}

func autostartInstall(a Autostart) error {
	if runtime.GOOS == "darwin" {
		args := ""
		for _, c := range a.Command {
			args += "      <string>" + c + "</string>\n"
		}
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.qoqtun.desktop</string>
  <key>ProgramArguments</key>
  <array>
` + args + `  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
`
		return atomicfile.Write(autostartPath(), []byte(plist), 0o600)
	}
	entry := "[Desktop Entry]\nType=Application\nName=qoqtun\nExec=" + commandString(a.Command) + "\nX-GNOME-Autostart-enabled=true\n"
	return atomicfile.Write(autostartPath(), []byte(entry), 0o600)
}

func autostartRemove(a Autostart) error {
	if err := os.Remove(autostartPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("desktop: remove autostart: %w", err)
	}
	return nil
}

func autostartEnabled(a Autostart) (bool, error) {
	_, err := os.Stat(autostartPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
