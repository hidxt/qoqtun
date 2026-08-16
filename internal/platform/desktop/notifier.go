package desktop

import "fmt"

// V1 deliberately ships no native notification implementation: desktop
// notifications require platform shelling out (os/exec is banned in
// production code) or a third-party dependency outside the whitelist.
// The GUI shows in-app notifications instead; native toasts land with the
// Phase 13 UI work.
func newNotifier() (Notifier, error) {
	return nil, fmt.Errorf("desktop: notifications not implemented in V1: %w", ErrUnsupported)
}
