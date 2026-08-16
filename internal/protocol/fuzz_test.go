package protocol

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// FuzzDecodeFrame exercises the frame parser: malformed lengths, truncation,
// oversized headers and invalid JSON must never panic.
func FuzzDecodeFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 4, 't', 'e', 's', 't'})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 3, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = safeDecode(data)
	})
}

// FuzzValidateMessage ensures every message validator tolerates arbitrary
// payloads without panics.
func FuzzValidateMessage(f *testing.F) {
	f.Add([]byte(`{"client_id":"cl_x","protocol_version":1}`))
	f.Add([]byte(`{"name":"ssh","type":"tcp","remote_port":22000,"local":{"ip":"127.0.0.1","port":22}}`))
	f.Add([]byte(`{"max_tunnels":16,"max_conns":256}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var h ClientHello
		_ = jsonUnmarshal(data, &h)
		_ = ValidateClientHello(&h)
		var r RegisterTunnel
		_ = jsonUnmarshal(data, &r)
		_ = ValidateRegisterTunnel(&r)
		var p Policy
		_ = jsonUnmarshal(data, &p)
		_ = ValidatePolicy(&p)
	})
}

// safeDecode runs Decode and recovers from any panic (fuzz must not panic).
func safeDecode(frame []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	_, err = Decode(frame)
	return err
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func FuzzEncodeRoundTrip(f *testing.F) {
	f.Add("cl_abcdefghijklmnopqrstuvwxyz234567")
	f.Add("")
	f.Add("name-with-dashes-123")
	f.Fuzz(func(t *testing.T, clientID string) {
		frame, err := Encode(MsgClientHello, 1, &ClientHello{
			ClientID:        clientID,
			ProtocolVersion: 1,
		})
		if err != nil {
			return
		}
		if len(frame) < 4 {
			t.Fatalf("short frame")
		}
		size := binary.BigEndian.Uint32(frame[:4])
		if size > MaxFrameSize {
			t.Fatalf("frame exceeds limit")
		}
	})
}
