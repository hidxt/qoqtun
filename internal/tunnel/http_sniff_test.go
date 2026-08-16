package tunnel

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func sniffOK(t *testing.T, head string) *SniffResult {
	t.Helper()
	res, err := SniffHost(strings.NewReader(head), 0)
	if err != nil {
		t.Fatalf("SniffHost(%q): %v", head, err)
	}
	return res
}

func sniffErr(t *testing.T, head string) error {
	t.Helper()
	_, err := SniffHost(strings.NewReader(head), 0)
	if err == nil {
		t.Fatalf("SniffHost(%q): expected error", head)
	}
	return err
}

func TestSniffHostBasic(t *testing.T) {
	head := "GET /index.html HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: t\r\n\r\n"
	res := sniffOK(t, head)
	if res.Host != "example.com" {
		t.Fatalf("host = %q, want example.com", res.Host)
	}
	// prefix must contain the exact bytes through the Host line
	if !bytes.Contains(res.Prefix, []byte("Host: Example.COM")) {
		t.Fatalf("prefix lost the original Host casing: %q", res.Prefix)
	}
	// remaining bytes after sniff must replay the tail
	rest, err := io.ReadAll(res.Rest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rest, []byte("User-Agent: t")) {
		t.Fatalf("rest lost the tail: %q", rest)
	}
}

func TestSniffHostNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"Example.COM:8080", "example.com"},
		{"example.com.", "example.com"},
		{"WWW.Example.Com.:443", "www.example.com"},
		{"xn--fiqs8s.cn", "xn--fiqs8s.cn"},
		{"a-b.c-d.e", "a-b.c-d.e"},
	}
	for _, c := range cases {
		res := sniffOK(t, "GET / HTTP/1.1\r\nHost: "+c.in+"\r\n\r\n")
		if res.Host != c.want {
			t.Errorf("Host %q -> %q, want %q", c.in, res.Host, c.want)
		}
	}
}

func TestSniffHostAbsoluteURI(t *testing.T) {
	// proxy-style absolute-form request target
	head := "GET http://api.example.com/v1/data HTTP/1.1\r\nAccept: */*\r\n\r\n"
	res := sniffOK(t, head)
	if res.Host != "api.example.com" {
		t.Fatalf("absolute URI host = %q, want api.example.com", res.Host)
	}
}

func TestSniffHostRejections(t *testing.T) {
	cases := []struct {
		name string
		head string
		want error
	}{
		{"no host header", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", ErrSniffNoHost},
		{"empty host", "GET / HTTP/1.1\r\nHost:\r\n\r\n", ErrSniffNoHost},
		{"bad label chars", "GET / HTTP/1.1\r\nHost: exa_mple.com\r\n\r\n", ErrSniffBadHost},
		{"leading dash", "GET / HTTP/1.1\r\nHost: -bad.com\r\n\r\n", ErrSniffBadHost},
		{"trailing dash", "GET / HTTP/1.1\r\nHost: bad-.com\r\n\r\n", ErrSniffBadHost},
		{"label too long", "GET / HTTP/1.1\r\nHost: " + strings.Repeat("a", 64) + ".com\r\n\r\n", ErrSniffBadHost},
		{"ipv6 literal", "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", ErrSniffBadHost},
		{"folded header", "GET / HTTP/1.1\r\nUser-Agent: foo\r\n bar\r\nHost: x.com\r\n\r\n", ErrSniffMalformed},
		{"no crlf line", "GET / HTTP/1.1", ErrSniffMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := sniffErr(t, c.head); err != c.want {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestSniffHostTooLarge(t *testing.T) {
	// request line alone exceeds 8 KiB
	big := "GET /" + strings.Repeat("a", 9*1024) + " HTTP/1.1\r\nHost: x.com\r\n\r\n"
	if err := sniffErr(t, big); err != ErrSniffTooLarge {
		t.Fatalf("got %v, want ErrSniffTooLarge", err)
	}
	// cumulative headers exceed 8 KiB
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 200; i++ {
		b.WriteString("X-Pad: " + strings.Repeat("z", 64) + "\r\n")
	}
	b.WriteString("Host: x.com\r\n\r\n")
	if err := sniffErr(t, b.String()); err != ErrSniffTooLarge {
		t.Fatalf("got %v, want ErrSniffTooLarge", err)
	}
}

func TestSniffHostStopsAtHostHeader(t *testing.T) {
	// the Host header appears early; the sniff must not consume body bytes
	body := "GET / HTTP/1.1\r\nHost: x.com\r\nConnection: keep-alive\r\n\r\nPAYLOAD"
	res := sniffOK(t, body)
	rest, _ := io.ReadAll(res.Rest)
	if !strings.Contains(string(rest), "PAYLOAD") {
		t.Fatalf("body leaked into sniff: rest=%q", rest)
	}
}

func TestNormalizeHostName(t *testing.T) {
	if h, err := NormalizeHostName("API.Example.COM."); err != nil || h != "api.example.com" {
		t.Fatalf("got %q %v", h, err)
	}
	if _, err := NormalizeHostName("not a host!"); err == nil {
		t.Fatal("expected error")
	}
}

// ---- vhost table ----

func TestVhostTable(t *testing.T) {
	vt := NewVhostTable()
	if err := vt.Register("example.com", "t1", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := vt.Register("example.com", "t2", "c2"); err != ErrNameConflict {
		t.Fatalf("duplicate host: got %v, want ErrNameConflict", err)
	}
	if err := vt.Register("sub.example.com", "t3", "c3"); err != nil {
		t.Fatal(err)
	}

	// exact match
	id, cid, ok := vt.Lookup("example.com")
	if !ok || id != "t1" || cid != "c1" {
		t.Fatalf("exact: %s %s %v", id, cid, ok)
	}
	// suffix match
	id, cid, ok = vt.Lookup("www.example.com")
	if !ok || id != "t1" {
		t.Fatalf("suffix: %s %v", id, ok)
	}
	// longer suffix wins over the shorter rule
	id, _, _ = vt.Lookup("deep.sub.example.com")
	if id != "t3" {
		t.Fatalf("longest suffix: got %s, want t3", id)
	}
	// unrelated host misses
	if _, _, ok := vt.Lookup("example.org"); ok {
		t.Fatal("example.org must miss")
	}
	// badexample.com must NOT match the suffix rule example.com
	if _, _, ok := vt.Lookup("badexample.com"); ok {
		t.Fatal("badexample.com must miss (suffix requires a dot boundary)")
	}

	// unregister by tunnel
	vt.UnregisterTunnel("t1")
	if _, _, ok := vt.Lookup("example.com"); ok {
		t.Fatal("host should be gone after unregister")
	}
	if vt.Count() != 1 {
		t.Fatalf("count = %d, want 1", vt.Count())
	}
}

// ---- ReplayConn ----

func TestReplayConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	prefix := []byte("GET / HTTP/1.1\r\nHost: x\r\n")
	tail := strings.NewReader("\r\nbody")
	rc := NewReplayConn(server, prefix, tail)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	want := string(prefix) + "\r\nbody"
	if string(got) != want {
		t.Fatalf("replay = %q, want %q", got, want)
	}
}

var _ = time.Second // keep time import for future deadline helpers
