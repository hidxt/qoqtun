package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// HTTP vhost sniffing limits (04 §7): read only the request head, at most
// 8 KiB, within 5 s. Everything after the Host header is left untouched and
// replayed verbatim (pure byte passthrough afterwards).
const (
	MaxSniffBytes = 8 * 1024
	SniffTimeout  = 5 * time.Second
)

var (
	ErrSniffTooLarge  = errors.New("http: request head exceeds 8KiB sniff limit")
	ErrSniffNoHost    = errors.New("http: request has no usable Host")
	ErrSniffBadHost   = errors.New("http: invalid Host value")
	ErrSniffMalformed = errors.New("http: malformed request head")
	ErrSniffClosed    = errors.New("http: connection closed during sniff")
	ErrNameConflict   = errors.New("http: host already registered")
)

// SniffResult is the outcome of a Host sniff: the normalized routing key,
// the exact bytes consumed so far, and the reader for the unread remainder.
type SniffResult struct {
	Host   string    // normalized routing key (lowercase, no port, no trailing dot)
	Prefix []byte    // request line + headers through the Host header (verbatim)
	Rest   io.Reader // unread remainder (same stream; replay after Prefix)
}

// SniffHost reads the request head from r (the caller must bound it with a
// deadline) and returns the normalized Host. Parsing is deliberately
// conservative: anything unusual (folded headers, oversized lines, garbage)
// is rejected rather than guessed (fail-closed, §7).
func SniffHost(r io.Reader, maxBytes int) (*SniffResult, error) {
	if maxBytes <= 0 {
		maxBytes = MaxSniffBytes
	}
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, maxBytes+1)
	}
	res := &SniffResult{Rest: br}
	host := ""

	// request line: METHOD SP request-target SP HTTP/x.y
	line, err := readSniffLine(br, &res.Prefix, maxBytes)
	if err != nil {
		return nil, err
	}
	host = hostFromRequestLine(line)

	// headers until an empty line; stop at the Host header (04 §7: read
	// only the necessary head).
	for {
		line, err := readSniffLine(br, &res.Prefix, maxBytes)
		if err != nil {
			return nil, err
		}
		if len(line) == 0 {
			break // end of headers
		}
		if line[0] == ' ' || line[0] == '\t' {
			// obs-fold: deprecated and ambiguous; reject conservatively
			return nil, ErrSniffMalformed
		}
		key, value := splitHeader(line)
		if key == "" {
			return nil, ErrSniffMalformed
		}
		if strings.EqualFold(key, "Host") {
			host = value
			break // got what we need; the rest replays verbatim
		}
	}

	if host == "" {
		return nil, ErrSniffNoHost
	}
	norm, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	res.Host = norm
	return res, nil
}

// readSniffLine reads one CRLF-terminated line, appending the raw bytes
// (with terminator) to prefix. The cumulative and per-line sizes are capped
// by maxBytes so a hostile client cannot force unbounded buffering.
func readSniffLine(br *bufio.Reader, prefix *[]byte, maxBytes int) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		switch err {
		case bufio.ErrBufferFull:
			return nil, ErrSniffTooLarge
		case io.EOF:
			if len(line) == 0 {
				return nil, ErrSniffClosed
			}
			// unterminated last line: malformed head
			return nil, ErrSniffMalformed
		default:
			return nil, err
		}
	}
	if len(*prefix)+len(line) > maxBytes {
		return nil, ErrSniffTooLarge
	}
	*prefix = append(*prefix, line...)
	// strip CRLF for parsing (the raw bytes stay in prefix for replay)
	trimmed := bytes.TrimSuffix(line, []byte("\n"))
	trimmed = bytes.TrimSuffix(trimmed, []byte("\r"))
	return trimmed, nil
}

// splitHeader splits "Key: Value" at the first colon; returns "" key for
// malformed lines.
func splitHeader(line []byte) (string, string) {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return "", ""
	}
	key := string(line[:i])
	val := strings.TrimSpace(string(line[i+1:]))
	return key, val
}

// hostFromRequestLine extracts the authority from an absolute-form request
// target (e.g. "GET http://example.com/x HTTP/1.1"); returns "" for
// origin-form targets (the Host header decides).
func hostFromRequestLine(line []byte) string {
	parts := bytes.Fields(line)
	if len(parts) < 3 {
		return ""
	}
	target := string(parts[1])
	if !strings.HasPrefix(strings.ToLower(target), "http://") {
		return ""
	}
	rest := target[len("http://"):]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// normalizeHost lowercases, strips an optional numeric port and a trailing
// dot, then validates the hostname (RFC 1123 labels). IPv6 literals are
// rejected (vhost routing keys are hostnames only; documented).
func normalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", ErrSniffNoHost
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i] // strip ":port"
		}
	}
	h = strings.ToLower(h)
	h = strings.TrimSuffix(h, ".")
	if !validHostname(h) {
		return "", ErrSniffBadHost
	}
	return h, nil
}

// NormalizeHostName exports host normalization for registration-time
// validation (server-side, before a host enters the routing table).
func NormalizeHostName(h string) (string, error) {
	return normalizeHost(h)
}

// validHostname validates RFC 1123 hostname labels (a-z0-9 and '-', no
// leading/trailing '-', max 63 per label, 253 total).
func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ReplayConn is a net.Conn whose read stream is the consumed prefix followed
// by the unread remainder — the exact bytes the client sent are replayed
// verbatim before pure passthrough (04 §7).
type ReplayConn struct {
	net.Conn
	r io.Reader
}

// NewReplayConn wraps c so reads yield prefix first, then rest.
func NewReplayConn(c net.Conn, prefix []byte, rest io.Reader) *ReplayConn {
	return &ReplayConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), rest)}
}

func (c *ReplayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// WriteHTTPError writes a minimal HTTP/1.1 error response and flushes the
// deadline reset so the peer can read it before close.
func WriteHTTPError(w io.Writer, status int, reason string) {
	body := fmt.Sprintf("%d %s\n", status, reason)
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, reason, len(body), body)
}
