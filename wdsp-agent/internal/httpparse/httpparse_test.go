package httpparse

import (
	"strings"
	"testing"
)

func feedAll(t *testing.T, s *Sniffer, chunks ...string) Result {
	t.Helper()
	for _, c := range chunks {
		if s.Feed([]byte(c)) {
			return s.Result()
		}
	}
	return s.Result()
}

func TestGETRequest(t *testing.T) {
	s := NewSniffer(0)
	res := feedAll(t, s, "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n")
	if res.Visibility != Plaintext {
		t.Fatalf("visibility=%s", res.Visibility)
	}
	if res.Method != "GET" || res.Host != "example.com" || res.URI != "/index.html" {
		t.Fatalf("got %+v", res)
	}
}

func TestPOSTRequestLowercaseHostHeader(t *testing.T) {
	s := NewSniffer(0)
	res := feedAll(t, s, "POST /api/login HTTP/1.1\r\nhost: api.example.com:8080\r\nContent-Length: 12\r\n\r\n")
	if res.Visibility != Plaintext || res.Method != "POST" || res.URI != "/api/login" {
		t.Fatalf("got %+v", res)
	}
	if res.Host != "api.example.com:8080" {
		t.Fatalf("host=%q", res.Host)
	}
}

func TestFragmentedRequest(t *testing.T) {
	s := NewSniffer(0)
	if s.Feed([]byte("GET /api")) {
		t.Fatal("分片未到请求行结束不应决定")
	}
	if s.Feed([]byte("/v1 HT")) {
		t.Fatal("请求行未完整不应决定")
	}
	res := feedAll(t, s, "TP/1.1\r\nHo", "st: frag.example\r\n\r\n")
	if res.Visibility != Plaintext || res.Method != "GET" || res.URI != "/api/v1" || res.Host != "frag.example" {
		t.Fatalf("got %+v", res)
	}
}

func TestRequestLineOnlyNoHostYet(t *testing.T) {
	s := NewSniffer(0)
	if s.Feed([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("头部未结束且无 Host，应继续等待")
	}
	res := feedAll(t, s, "\r\n") // 头部结束仍无 Host → PLAINTEXT，Host 空
	if res.Visibility != Plaintext || res.Host != "" {
		t.Fatalf("got %+v", res)
	}
}

func TestTLSClientHello(t *testing.T) {
	s := NewSniffer(0)
	// TLS handshake record: 0x16 0x03 0x01 ...
	res := feedAll(t, s, string([]byte{0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00}))
	if res.Visibility != Encrypted {
		t.Fatalf("visibility=%s", res.Visibility)
	}
}

func TestTLSClientHelloFragmented(t *testing.T) {
	s := NewSniffer(0)
	if s.Feed([]byte{0x16, 0x03}) {
		t.Fatal("TLS 记录头未完整不应决定")
	}
	res := feedAll(t, s, string([]byte{0x03}))
	if res.Visibility != Encrypted {
		t.Fatalf("visibility=%s", res.Visibility)
	}
}

func TestNonHTTPUnknown(t *testing.T) {
	cases := map[string]string{
		"binary-ssh":  "SSH-2.0-OpenSSH_9.6\r\n",
		"lowercase":   "get / HTTP/1.1\r\n\r\n", // 小写方法非合法 HTTP/1.x
		"bad-version": "GET / HTTP/2.0\r\n\r\n",
		"no-uri":      "GET\r\n\r\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewSniffer(0)
			res := feedAll(t, s, data)
			if res.Visibility != Unknown {
				t.Fatalf("visibility=%s, want UNKNOWN", res.Visibility)
			}
		})
	}
}

func TestBinaryFirstByteUnknown(t *testing.T) {
	s := NewSniffer(0)
	res := feedAll(t, s, string([]byte{0x00, 0x01, 0x02}))
	if res.Visibility != Unknown {
		t.Fatalf("visibility=%s", res.Visibility)
	}
}

func TestMaxBytesCapUnknown(t *testing.T) {
	s := NewSniffer(64)
	// 超长请求行，缓冲满仍无 \r\n → UNKNOWN
	res := feedAll(t, s, strings.Repeat("A", 64))
	if res.Visibility != Unknown {
		t.Fatalf("visibility=%s", res.Visibility)
	}
}

func TestDecidedLatches(t *testing.T) {
	s := NewSniffer(0)
	feedAll(t, s, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	if !s.Feed([]byte("GARBAGE")) || s.Result().Visibility != Plaintext {
		t.Fatal("决定后应保持结论")
	}
}
