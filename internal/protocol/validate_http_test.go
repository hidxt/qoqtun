package protocol

import "testing"

func TestValidateRegisterHTTPSRequiresPort(t *testing.T) {
	r := &RegisterTunnel{Name: "t", Type: "https", RemotePort: 0,
		Local: LocalTarget{IP: "127.0.0.1", Port: 80}}
	if err := ValidateRegisterTunnel(r); err == nil {
		t.Fatal("https with remote_port=0 must be rejected (L4 passthrough needs a port)")
	}
	r.RemotePort = 443
	if err := ValidateRegisterTunnel(r); err != nil {
		t.Fatalf("https with remote_port must pass: %v", err)
	}
}

func TestValidateRegisterHTTPVhost(t *testing.T) {
	// vhost mode requires http.host
	r := &RegisterTunnel{Name: "t", Type: "http", RemotePort: 0,
		Local: LocalTarget{IP: "127.0.0.1", Port: 80}}
	if err := ValidateRegisterTunnel(r); err == nil {
		t.Fatal("http with remote_port=0 and no host must be rejected")
	}
	r.HTTP = &HTTPConfig{Host: "example.com"}
	if err := ValidateRegisterTunnel(r); err != nil {
		t.Fatalf("http vhost must pass: %v", err)
	}
}
