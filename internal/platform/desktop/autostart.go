package desktop

import (
	"fmt"
)

// Autostart registers or removes the app from the OS auto-start
// (explicit opt-in only, V1):
//
//	windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//	darwin:  ~/Library/LaunchAgents/com.qoqtun.desktop.plist
//	linux:   ~/.config/autostart/qoqtun-desktop.desktop
type Autostart struct {
	// AppName is the registry/plist/desktop entry name.
	AppName string
	// Command is the absolute path + args to launch.
	Command []string
}

// Install registers the auto-start entry.
func (a Autostart) Install() error {
	if a.AppName == "" || len(a.Command) == 0 {
		return fmt.Errorf("desktop: autostart needs AppName and Command")
	}
	return autostartInstall(a)
}

// Remove deletes the auto-start entry.
func (a Autostart) Remove() error {
	return autostartRemove(a)
}

// Enabled reports whether the auto-start entry exists.
func (a Autostart) Enabled() (bool, error) {
	return autostartEnabled(a)
}

func commandString(cmd []string) string {
	out := ""
	for i, c := range cmd {
		if i > 0 {
			out += " "
		}
		if containsSpace(c) {
			out += `"` + c + `"`
		} else {
			out += c
		}
	}
	return out
}

func containsSpace(s string) bool {
	for _, r := range s {
		if r == ' ' {
			return true
		}
	}
	return false
}
