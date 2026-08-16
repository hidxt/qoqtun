// Package protocol implements qoqtun Protocol v1 (docs/plan/04-protocol-v1.md):
// control-plane framing (4-byte big-endian length + JSON, ≤64KiB), the
// message directory, per-field validation and error codes. It has no
// dependencies on tunnel/control so it can be fuzzed standalone.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// MaxFrameSize caps control frames (04-protocol-v1.md §0): oversized frames
// close the connection immediately.
const MaxFrameSize = 64 * 1024

// ProtocolVersion is the current control protocol version.
const ProtocolVersion = 1

// Envelope is the common message envelope (§2).
type Envelope struct {
	Version int             `json:"version"`
	Type    string          `json:"type"`
	Seq     uint64          `json:"seq"`
	Nonce   string          `json:"nonce"`             // 16B hex, random per message
	TS      int64           `json:"ts"`                // unix milliseconds
	Payload json.RawMessage `json:"payload,omitempty"` // typed per message
}

// Control message types (§2 + data-plane first frame).
const (
	MsgClientHello        = "client_hello"
	MsgServerHello        = "server_hello"
	MsgRegisterTunnel     = "register_tunnel"
	MsgRegisterTunnelResp = "register_tunnel_resp"
	MsgUnregisterTunnel   = "unregister_tunnel"
	MsgOpenConnection     = "open_connection"
	MsgCloseConnection    = "close_connection"
	MsgPing               = "ping"
	MsgPong               = "pong"
	MsgPolicyUpdate       = "policy_update"
	MsgShutdown           = "shutdown"
	MsgError              = "error"
	MsgOpenData           = "open_data"
)

// Encode builds a frame (4B length prefix + JSON envelope). payload is
// marshaled into the envelope's payload field. The nonce (16 random bytes,
// hex) and ts (unix ms) are filled automatically (§2).
func Encode(msgType string, seq uint64, payload any) ([]byte, error) {
	var raw json.RawMessage
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("protocol: marshal %s payload: %w", msgType, err)
		}
		raw = data
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	env := Envelope{
		Version: ProtocolVersion,
		Type:    msgType,
		Seq:     seq,
		Nonce:   nonce,
		TS:      time.Now().UnixMilli(),
		Payload: raw,
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal envelope: %w", err)
	}
	if len(data) > MaxFrameSize {
		return nil, fmt.Errorf("protocol: frame too large (%d > %d)", len(data), MaxFrameSize)
	}
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out, nil
}

// randomNonce returns 16 random bytes as hex (32 chars).
func randomNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("protocol: nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Decode parses a full frame (length prefix + JSON).
func Decode(frame []byte) (*Envelope, error) {
	if len(frame) < 4 {
		return nil, fmt.Errorf("protocol: frame too short (%d bytes)", len(frame))
	}
	size := binary.BigEndian.Uint32(frame[:4])
	if size == 0 || size > MaxFrameSize {
		return nil, fmt.Errorf("protocol: invalid frame size %d", size)
	}
	if len(frame) != int(size)+4 {
		return nil, fmt.Errorf("protocol: frame length mismatch (header %d, actual %d)", size, len(frame)-4)
	}
	var env Envelope
	if err := json.Unmarshal(frame[4:], &env); err != nil {
		return nil, fmt.Errorf("protocol: parse envelope: %w", err)
	}
	if env.Type == "" {
		return nil, fmt.Errorf("protocol: envelope missing type")
	}
	return &env, nil
}

// ReadFrame reads one length-prefixed frame from r.
func ReadFrame(r io.Reader) (*Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > MaxFrameSize {
		return nil, fmt.Errorf("protocol: invalid frame size %d", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return Decode(append(hdr[:], body...))
}

// WriteFrame encodes and writes one frame.
func WriteFrame(w io.Writer, msgType string, seq uint64, payload any) error {
	frame, err := Encode(msgType, seq, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

// DecodePayload unmarshals the envelope payload into v.
func (e *Envelope) DecodePayload(v any) error {
	if e.Payload == nil {
		return fmt.Errorf("protocol: %s has no payload", e.Type)
	}
	if err := json.Unmarshal(e.Payload, v); err != nil {
		return fmt.Errorf("protocol: parse %s payload: %w", e.Type, err)
	}
	return nil
}
