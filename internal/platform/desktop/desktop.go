// Package desktop provides optional desktop integrations for the GUI shell
// (tray, autostart, notifications). Every integration is explicitly
// opt-in; unsupported platforms return a clear ErrUnsupported.
package desktop

import "errors"

// ErrUnsupported is returned by features not implemented on the platform.
var ErrUnsupported = errors.New("desktop: feature not supported on this platform")

// Notifier posts a desktop notification (best-effort; never blocks).
type Notifier interface {
	Notify(title, body string) error
}

// Tray manages a status-icon tray (state toggles). Not implemented in V1:
// returns ErrUnsupported on every platform (UI design lands in Phase 13).
type Tray interface {
	Run() error
	SetState(state string)
	Stop()
}

// NewTray returns an explicit not-supported tray.
func NewTray() Tray { return unsupportedTray{} }

type unsupportedTray struct{}

func (unsupportedTray) Run() error      { return ErrUnsupported }
func (unsupportedTray) SetState(string) {}
func (unsupportedTray) Stop()           {}

// NewNotifier returns the platform notifier or ErrUnsupported.
func NewNotifier() (Notifier, error) { return newNotifier() }
