//go:build darwin

package capture

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// TestDarwinBPFLoopbackLiveSmoke 若当前 macOS 用户具备 /dev/bpf 读权限（如 root 或 access_bpf 组），
// 在 lo0 上执行真实 BPF 旁路只读抓包冒烟，验证能真实捕获 HTTP 请求并迅速优雅关闭。
func TestDarwinBPFLoopbackLiveSmoke(t *testing.T) {
	fd, err := openFreeBPFDevice()
	if err != nil {
		t.Skipf("当前环境无 /dev/bpf 权限，跳过真实 BPF 冒烟: %v", err)
	}
	_ = closeFD(fd)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	var mu sync.Mutex
	var matched bool
	hitCh := make(chan struct{}, 1)

	cfg := BackendConfig{
		Ifaces: []string{"lo0"},
		Filter: filter.New([]uint16{port}, filter.Both),
		Consumer: func(p Packet) {
			if bytes.Contains(p.Payload, []byte("GET /wdsp-bpf-smoke")) {
				mu.Lock()
				if !matched {
					matched = true
					close(hitCh)
				}
				mu.Unlock()
			}
		},
		Stats: &Stats{},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	sel, err := StartBackend(BackendBPF, cfg)
	if err != nil {
		t.Skipf("无法绑定 lo0 BPF，跳过: %v", err)
	}

	resp, err := http.Get("http://" + ln.Addr().String() + "/wdsp-bpf-smoke")
	if err != nil {
		_ = sel.Backend.Close()
		t.Fatalf("HTTP 冒烟请求失败: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	select {
	case <-hitCh:
	case <-time.After(3 * time.Second):
		_ = sel.Backend.Close()
		t.Fatal("未在 3s 内通过 macOS BPF 捕获到 lo0 HTTP 请求报文")
	}

	// 验证 KernelStats 可读且 Close 在 500ms 内迅速返回
	if _, _, err := sel.Backend.KernelStats(); err != nil {
		t.Fatalf("BIOCGSTATS 失败: %v", err)
	}
	startClose := time.Now()
	if err := sel.Backend.Close(); err != nil {
		t.Fatalf("BPF Close 失败: %v", err)
	}
	if dur := time.Since(startClose); dur > 500*time.Millisecond {
		t.Fatalf("BPF Close 耗时过长: %v", dur)
	}
}

func closeFD(fd int) error {
	h := &bpfHandle{fd: fd, wakeR: -1, wakeW: -1, stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	close(h.doneCh)
	return h.close()
}
