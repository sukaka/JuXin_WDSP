// dial_guard_test.go 拨号复检单测：快照解析、重解析比对（DNS 重绑定拒绝）、
// 快照内地址放行（真实拨号 httptest 靶标）。
package apiscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestResolveHostSnapshotLiteralIP 字面 IP 主机直接收录快照（不经 DNS）。
func TestResolveHostSnapshotLiteralIP(t *testing.T) {
	ips, err := resolveHostSnapshot(context.Background(), "http://127.0.0.1:8080")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("snapshot=%v err=%v", ips, err)
	}
	// IPv4 映射 IPv6 归一：与字面 IPv4 视为同一地址
	ips, err = resolveHostSnapshot(context.Background(), "http://[::ffff:127.0.0.1]:8080")
	if err != nil || len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("mapped snapshot=%v err=%v", ips, err)
	}
	if _, err := resolveHostSnapshot(context.Background(), "://bad"); err == nil {
		t.Fatal("非法 base_url 应返回错误")
	}
}

// TestPinnedDialRejectsReboundIP 拨号重解析出现授权快照外地址：拒绝拨号（DNS 重绑定防护）。
func TestPinnedDialRejectsReboundIP(t *testing.T) {
	snapshot := []net.IP{net.ParseIP("93.184.216.34")}
	tr := pinnedTransport(snapshot, func(context.Context, string) ([]net.IP, error) {
		// 重解析被「重绑定」到内网地址
		return []net.IP{net.ParseIP("10.0.0.8")}, nil
	})
	_, err := tr.DialContext(context.Background(), "tcp", "api.example.com:443")
	if err == nil || !strings.Contains(err.Error(), "快照外地址") {
		t.Fatalf("重绑定拨号应被拒绝, err=%v", err)
	}
	// 部分命中部分越界同样拒绝（任一快照外地址即拒绝）
	tr2 := pinnedTransport(snapshot, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.1")}, nil
	})
	if _, err := tr2.DialContext(context.Background(), "tcp", "api.example.com:443"); err == nil {
		t.Fatal("混合解析结果含快照外地址应被拒绝")
	}
}

// TestPinnedDialAllowsSnapshotIP 快照内地址放行并真实连通（httptest 靶标）。
func TestPinnedDialAllowsSnapshotIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	snapshot, err := resolveHostSnapshot(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: pinnedTransport(snapshot, nil), Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("快照内地址拨号应放行: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

// TestWorkerExecuteInjectsPinnedClient 执行路径端到端：worker 装配的探测客户端
// 带拨号复检（httptest 字面 IP 靶标在快照内，任务正常完成）。
func TestWorkerExecuteInjectsPinnedClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	store := NewMemStore()
	_, _, jobID := seedJob(t, store, srv.URL, []string{"/open"}, nil)
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Completed != 1 {
		t.Fatalf("stats=%+v, 拨号复检客户端不应阻断快照内目标", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusCompleted || job.Progress.Findings != 1 {
		t.Fatalf("job=%+v", job)
	}
}

// TestWorkerUnresolvableHostFails 目标主机解析失败：任务 FAILED（fail-closed，不拨号）。
func TestWorkerUnresolvableHostFails(t *testing.T) {
	// 环境性前置检查：本用例依赖 RFC2606 保留域不可解析；本机/上游 DNS 若把
	// nonexistent.invalid.jiuzhang 解析为真实 IP（如实验网通配解析），则前提不成立，
	// 如实跳过而非误判 fail-closed 语义。
	if ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", "nonexistent.invalid.jiuzhang"); err == nil && len(ips) > 0 {
		t.Skipf("本机 DNS 将保留域解析为真实 IP（%v，环境性），跳过", ips)
	}
	store := NewMemStore()
	_, _, jobID := seedJob(t, store, "http://nonexistent.invalid.jiuzhang", []string{"/a"}, func(a *Authorization) {
		a.Allowlist = []string{"nonexistent.invalid.jiuzhang"}
	})
	worker, _ := newTestWorker(store, fakeSettings{enabled: true})

	stats, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	job, _ := store.GetJob(context.Background(), jobID)
	if job.Status != JobStatusFailed || !strings.Contains(job.Progress.LastError, "解析失败") {
		t.Fatalf("job=%+v", job)
	}
}
