package desktop

import (
	"errors"
	"testing"
)

func TestTrayUnsupported(t *testing.T) {
	tr := NewTray()
	if err := tr.Run(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("tray must be not-supported in V1, got %v", err)
	}
}

func TestNotifierUnsupported(t *testing.T) {
	if _, err := NewNotifier(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("notifier must be not-supported in V1, got %v", err)
	}
}

func TestAutostartValidation(t *testing.T) {
	a := Autostart{}
	if err := a.Install(); err == nil {
		t.Fatal("empty autostart must fail validation")
	}
}

func TestCommandString(t *testing.T) {
	got := commandString([]string{`C:\Program Files\qoqtun\app.exe`, "--config", `C:\qoqtun\c.toml`})
	want := `"C:\Program Files\qoqtun\app.exe" --config C:\qoqtun\c.toml`
	if got != want {
		t.Fatalf("command string = %q, want %q", got, want)
	}
}
