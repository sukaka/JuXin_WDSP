package tlsmux

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// TestWriteHTTP10RequestRejectsOversizeBody 验证 HTTP/1.0 回源体超过 32 MiB 硬上限时显式报错，
// 防止无界 io.ReadAll 导致内存暴涨 OOM。
func TestWriteHTTP10RequestRejectsOversizeBody(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "http", Host: "127.0.0.1:8080", Path: "/upload"},
		Host:   "127.0.0.1:8080",
		Header: make(http.Header),
		Body:   io.NopCloser(io.LimitReader(zeroReader{}, maxHTTP10RequestBodyBytes+1)),
	}
	var out bytes.Buffer
	err := writeHTTP10Request(&out, req)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("writeHTTP10Request(>32 MiB) err = %v, want explicit size limit error", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestMuxListenerCloseAndDeliverReadyRaceSafe 验证 Close() 与并发 deliverReady() 在 -race 下无竞态、
// 且关闭后不会遗留未关闭的连接在 readyCh 中导致 fd 泄漏。
func TestMuxListenerCloseAndDeliverReadyRaceSafe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	mux := &ListenerMux{}
	wrapped := mux.WrapListener(ln).(*muxListener)

	var wg sync.WaitGroup
	var peers []net.Conn
	for i := 0; i < 16; i++ {
		c1, c2 := net.Pipe()
		peers = append(peers, c2)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			wrapped.deliverReady(c)
		}(c1)
	}
	if err := mux.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	wg.Wait()
	for _, p := range peers {
		_ = p.Close()
	}
	select {
	case leaked := <-wrapped.readyCh:
		_ = leaked.Close()
		t.Fatal("connection leaked in readyCh after Close/Cleanup")
	default:
	}
}
