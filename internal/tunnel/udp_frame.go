package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// udpMaxPacket is the hard cap for a single UDP payload inside a channel
// frame (04-protocol-v1.md §6; policy default 1500).
const udpMaxPacket = 65507

// sessionIDLen is the fixed 16-byte session identifier.
const sessionIDLen = 16

// NewSessionID generates a CSPRNG 16-byte session id.
func NewSessionID() ([]byte, error) {
	buf := make([]byte, sessionIDLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("tunnel: session id: %w", err)
	}
	return buf, nil
}

// udpFrame is one datagram on the mTLS UDP data channel:
//
//	[4B big-endian length][16B session_id][payload]
func udpFrame(sessionID, payload []byte) ([]byte, error) {
	if len(payload) > udpMaxPacket {
		return nil, fmt.Errorf("tunnel: udp payload too large (%d > %d)", len(payload), udpMaxPacket)
	}
	if len(sessionID) != sessionIDLen {
		return nil, fmt.Errorf("tunnel: bad session id length %d", len(sessionID))
	}
	size := sessionIDLen + len(payload)
	frame := make([]byte, 4+size)
	binary.BigEndian.PutUint32(frame[:4], uint32(size))
	copy(frame[4:], sessionID)
	copy(frame[4+sessionIDLen:], payload)
	return frame, nil
}

// readUDPFrame reads one frame from the channel, returning the session id
// and payload. maxPacket caps the payload (policy); oversized frames are
// rejected (caller drops and counts).
func readUDPFrame(r io.Reader, maxPacket int) (sessionID, payload []byte, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size < sessionIDLen || int(size) > sessionIDLen+maxPacket {
		return nil, nil, fmt.Errorf("tunnel: invalid udp frame size %d", size)
	}
	body := make([]byte, size)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	return body[:sessionIDLen], body[sessionIDLen:], nil
}
