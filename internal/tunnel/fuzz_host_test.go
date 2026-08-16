package tunnel

import (
	"strings"
	"testing"
)

// FuzzHostSniff exercises the conservative request-head parser: it must
// never panic and never return a non-normalized host.
func FuzzHostSniff(f *testing.F) {
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"GET http://api.x.com/ HTTP/1.1\r\n\r\n",
		"POST /a HTTP/1.1\r\nhost: UP.X.com.:443\r\nX: 1\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: exa_mple.com\r\n\r\n",
		strings.Repeat("GET / HTTP/1.1\r\nX: y\r\n", 50),
		"GET /\xff\xfe HTTP/1.1\r\nHost: x.com\r\n\r\n",
		"G",
		"",
		"\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x.com\r\nHost: y.com\r\n\r\n",
		"GET / HTTP/1.1\nHost: x.com\n\n",
		"HEAD / HTTP/1.1\r\nHost: a-b.c-d.e\r\nConnection: close\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := SniffHost(strings.NewReader(string(data)), 0)
		if err != nil {
			return
		}
		// any accepted host must survive re-normalization unchanged
		norm, nerr := NormalizeHostName(res.Host)
		if nerr != nil || norm != res.Host {
			t.Fatalf("un-normalized host accepted: %q (renorm %q err %v)", res.Host, norm, nerr)
		}
		if len(res.Host) > 253 {
			t.Fatalf("host too long: %d", len(res.Host))
		}
	})
}
