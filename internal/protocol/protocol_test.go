package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	hello := &ClientHello{
		ClientID:        "cl_abcdefghijklmnopqrstuvwxyz234567",
		ProtocolVersion: 1,
		Name:            "nas",
	}
	frame, err := Encode(MsgClientHello, 1, hello)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != MsgClientHello || env.Seq != 1 || env.Version != 1 {
		t.Fatalf("envelope mismatch: %+v", env)
	}
	var back ClientHello
	if err := env.DecodePayload(&back); err != nil {
		t.Fatal(err)
	}
	if back.ClientID != hello.ClientID || back.Name != "nas" || back.ProtocolVersion != 1 {
		t.Fatalf("payload mismatch: %+v", back)
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"empty", nil},
		{"short", []byte{0, 0}},
		{"zero-size", []byte{0, 0, 0, 0, '{'}},
		{"oversize-header", []byte{0xff, 0xff, 0xff, 0xff}},
		{"length-mismatch", []byte{0, 0, 0, 5, '{', '}'}},
		{"bad-json", []byte{0, 0, 0, 5, 'n', 'o', 't', 'j', 's'}},
		{"missing-type", []byte{0, 0, 0, 11, '{', '"', 's', 'e', 'q', '"', ':', '1', '}'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode(tc.frame); err == nil {
				t.Fatalf("must reject %s", tc.name)
			}
		})
	}
}

func TestFrameSizeLimit(t *testing.T) {
	big := make([]byte, MaxFrameSize+10)
	payload := struct{ Data []byte }{Data: big}
	if _, err := Encode(MsgError, 1, payload); err == nil {
		t.Fatal("oversized frame must be rejected at encode")
	}
}

func TestValidateClientHello(t *testing.T) {
	ok := &ClientHello{ClientID: "cl_x", ProtocolVersion: 1, Name: "dev"}
	if err := ValidateClientHello(ok); err != nil {
		t.Fatalf("valid hello rejected: %v", err)
	}
	bad := []*ClientHello{
		nil,
		{ProtocolVersion: 1},
		{ClientID: "cl_x", ProtocolVersion: 2},
		{ClientID: "cl_x", ProtocolVersion: 1, Name: string(make([]byte, 65))},
	}
	for i, h := range bad {
		if err := ValidateClientHello(h); err == nil {
			t.Fatalf("bad hello #%d accepted", i)
		}
	}
}

func TestValidateRegisterTunnel(t *testing.T) {
	ok := []*RegisterTunnel{
		{Name: "ssh", Type: "tcp", RemotePort: 22000, Local: LocalTarget{IP: "127.0.0.1", Port: 22}},
		{Name: "web", Type: "http", RemotePort: 0, Local: LocalTarget{IP: "127.0.0.1", Port: 8080}, HTTP: &HTTPConfig{Host: "blog.example.com"}},
	}
	for i, r := range ok {
		if err := ValidateRegisterTunnel(r); err != nil {
			t.Fatalf("valid register #%d rejected: %v", i, err)
		}
	}
	bad := []*RegisterTunnel{
		nil,
		{Name: "bad name!", Type: "tcp", RemotePort: 1, Local: LocalTarget{IP: "127.0.0.1", Port: 1}},
		{Name: "x", Type: "quic", RemotePort: 1, Local: LocalTarget{IP: "127.0.0.1", Port: 1}},
		{Name: "x", Type: "tcp", RemotePort: 70000, Local: LocalTarget{IP: "127.0.0.1", Port: 1}},
		{Name: "x", Type: "tcp", RemotePort: 1, Local: LocalTarget{IP: "0.0.0.0", Port: 1}},
		{Name: "x", Type: "tcp", RemotePort: 1, Local: LocalTarget{IP: "127.0.0.1", Port: 0}},
		{Name: "x", Type: "http", RemotePort: 0, Local: LocalTarget{IP: "127.0.0.1", Port: 1}},
	}
	for i, r := range bad {
		if err := ValidateRegisterTunnel(r); err == nil {
			t.Fatalf("bad register #%d accepted", i)
		}
	}
}

func TestValidatePolicy(t *testing.T) {
	ok := &Policy{
		AllowedPorts:   []string{"20000-29999"},
		MaxTunnels:     16,
		MaxConns:       256,
		UDP:            UDPPolicy{MaxSessions: 256, MaxPacket: 1500, SessionIdleTimeout: "60s"},
		AllowedTargets: []string{"10.0.0.0/8:*", "192.168.0.0/16:8080-8090"},
	}
	if err := ValidatePolicy(ok); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	bad := []*Policy{
		{MaxTunnels: 0, MaxConns: 1},
		{MaxTunnels: 2048, MaxConns: 1},
		{MaxTunnels: 1, MaxConns: 0},
		{MaxTunnels: 1, MaxConns: 1, UDP: UDPPolicy{MaxPacket: 70000}},
		{MaxTunnels: 1, MaxConns: 1, AllowedTargets: []string{"10.0.0.0/8"}},
	}
	for i, p := range bad {
		if err := ValidatePolicy(p); err == nil {
			t.Fatalf("bad policy #%d accepted", i)
		}
	}
}

func TestReadWriteFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, MsgPing, 7, &Ping{Echo: "x"}); err != nil {
		t.Fatal(err)
	}
	env, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var p Ping
	if err := env.DecodePayload(&p); err != nil || p.Echo != "x" {
		t.Fatalf("ping round trip failed: %+v %v", p, err)
	}
}

func TestParsePortRange(t *testing.T) {
	for _, good := range []string{"1", "65535", "1000-2000", "80"} {
		lo, hi, err := ParsePortRange(good)
		if err != nil || lo > hi || lo < 1 || hi > 65535 {
			t.Fatalf("range %q rejected: %v", good, err)
		}
	}
	for _, bad := range []string{"0", "65536", "abc", "5-1", "1-70000", "-1", ""} {
		if _, _, err := ParsePortRange(bad); err == nil {
			t.Fatalf("bad range %q accepted", bad)
		}
	}
}
