//go:build windows

package desktop

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func windowsAutostartKey() (registry.Key, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return 0, fmt.Errorf("desktop: open Run key: %w", err)
	}
	return k, nil
}

func autostartInstall(a Autostart) error {
	k, err := windowsAutostartKey()
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue(a.AppName, commandString(a.Command)); err != nil {
		return fmt.Errorf("desktop: set Run value: %w", err)
	}
	return nil
}

func autostartRemove(a Autostart) error {
	k, err := windowsAutostartKey()
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(a.AppName); err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("desktop: delete Run value: %w", err)
	}
	return nil
}

func autostartEnabled(a Autostart) (bool, error) {
	k, err := windowsAutostartKey()
	if err != nil {
		return false, err
	}
	defer k.Close()
	_, _, err = k.GetStringValue(a.AppName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("desktop: query Run value: %w", err)
	}
	return true, nil
}
