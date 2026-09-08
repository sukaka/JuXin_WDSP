// mirrorsrc 单元测试：规范化、脱敏复用、伪造头防护、资源边界、监听隔离。
package mirrorsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

type collector struct {
	mu   sync.Mutex
	recs []events.HTTPRecordV2
}

func (c *collector) add(rec events.HTTPRecordV2) {
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
}

func (c *collector) all() []events.HTTPRecordV2 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]events.HTTPRecordV2(nil), c.recs...)
}

func newTestReceiver(t *testing.T, cfg Config) (*Receiver, *collector, string) {
	t.Helper()
	if cfg.SourceInstance == "" {
		cfg.SourceInstance = "nginx-a"
	}
	if cfg.InstanceToken == "" {
		cfg.InstanceToken = "tok-test-123"
	}
	if cfg.SocketPath == "" && cfg.ListenAddr == "" {
		cfg.SocketPath = filepath.Join(t.TempDir(), "m.sock") // 短名：macOS unix socket 路径 104 字符上限
	}
	coll := &collector{}
	r, err := New("agent-1", cfg, coll.add, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { r.Shutdown(context.Background()) })
	addr := ""
	if cfg.SocketPath != "" {
		addr = cfg.SocketPath
	} else {
		addr = r.ln.Addr().String()
	}
	return r, coll, addr
}

func dialerFor(socketPath string) (*http.Client, string) {
	if socketPath != "" && strings.HasSuffix(socketPath, ".sock") {
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		}
		return &http.Client{Transport: tr, Timeout: 5 * time.Second}, "http://unix"
	}
	return &http.Client{Timeout: 5 * time.Second}, "http://" + socketPath
}

func doReq(t *testing.T, client *http.Client, base, method, path string, headers map[string]string, body string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func authed(h map[string]string) map[string]string {
	if h == nil {
		h = map[string]string{}
	}
	h[HeaderInstance] = "tok-test-123"
	return h
}

// 正常 GET：方法/Host/路径/Header 采集与 v2 单向源口径（response 恒 null）。
func TestNormalizeGET(t *testing.T) {
	r, coll, addr := newTestReceiver(t, Config{TLSTerminated: true})
	client, base := dialerFor(addr)
	resp := doReq(t, client, base, "GET", "/api/orders?id=1&token=plain-secret", authed(map[string]string{
		"Authorization": "Bearer abc.def",
		"X-Request-Id":  "rid-9",
	}), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	recs := coll.all()
	if len(recs) != 1 {
		t.Fatalf("records=%d", len(recs))
	}
	rec := recs[0]
	if rec.SourceType != events.SourceNginxMirror || rec.SourceInstance != "nginx-a" {
		t.Fatalf("source: %s/%s", rec.SourceType, rec.SourceInstance)
	}
	if rec.SourceEpoch <= 0 || rec.SourceCapabilitiesVersion != CapabilitiesVersion {
		t.Fatalf("epoch/cap: %d/%q", rec.SourceEpoch, rec.SourceCapabilitiesVersion)
	}
	if rec.AssociationState != events.AssocRequestOnly ||
		rec.AssociationReason != events.AssocReasonSourceRequestOnly {
		t.Fatalf("association: %s/%s", rec.AssociationState, rec.AssociationReason)
	}
	// 单向源口径：响应/响应时间/延迟恒 null
	if rec.Response != nil || rec.ResponseTS != nil || rec.LatencyMS != nil {
		t.Fatalf("响应必须恒 null: %+v", rec.Response)
	}
	if rec.TLSVisibility != "DECRYPTED" {
		t.Fatalf("tls_visibility=%q", rec.TLSVisibility)
	}
	if rec.ObservedHTTPVersion != "1.1" || rec.OriginalHTTPVersion != nil {
		t.Fatalf("proto: %q/%v", rec.ObservedHTTPVersion, rec.OriginalHTTPVersion)
	}
	if rec.EventID == "" || !strings.HasPrefix(rec.EventID, "ev-") {
		t.Fatalf("event_id: %q", rec.EventID)
	}
	q := rec.Request
	if q.Method != "GET" || q.URI != "/api/orders?id=1&token=********" {
		t.Fatalf("request: %+v", q)
	}
	if q.Host != "unix" {
		t.Fatalf("host=%q", q.Host)
	}
	if vs := q.Headers["authorization"]; len(vs) != 1 || vs[0] != "********" {
		t.Fatalf("authorization 未脱敏: %q", q.Headers["authorization"])
	}
	if vs := q.Headers["x-request-id"]; len(vs) != 1 || vs[0] != "rid-9" {
		t.Fatalf("普通头丢失: %v", q.Headers)
	}
	if _, ok := q.Headers[strings.ToLower(HeaderInstance)]; ok {
		t.Fatal("控制头不得入记录")
	}
	if r.MaskedFieldCount() == 0 {
		t.Fatal("masked 指标应为正")
	}
}

// 伪造写入方：缺/错/多实例标识一律 403，不产生记录。
func TestForgeRejected(t *testing.T) {
	r, coll, addr := newTestReceiver(t, Config{})
	client, base := dialerFor(addr)
	for _, tc := range []struct {
		name  string
		token []string
	}{
		{"missing", nil},
		{"wrong", []string{"tok-evil"}},
		{"multi", []string{"tok-test-123", "tok-test-123"}},
	} {
		req, err := http.NewRequest("GET", base+"/api/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tok := range tc.token {
			req.Header.Add(HeaderInstance, tok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: status=%d", tc.name, resp.StatusCode)
		}
	}
	if len(coll.all()) != 0 {
		t.Fatal("伪造请求不得产生记录")
	}
	if r.Stats.Forbidden.Load() != 3 {
		t.Fatalf("forbidden=%d", r.Stats.Forbidden.Load())
	}
}

// 伪造来源头：X-Forwarded-For/X-Real-IP 仅作数据采集，五元组取真实对端；
// 客户端伪造的 x-wdsp-* 控制头整体剥离。
func TestSpoofedHeadersNotTrusted(t *testing.T) {
	_, coll, addr := newTestReceiver(t, Config{ListenAddr: "127.0.0.1:0"})
	client, base := dialerFor(addr)
	resp := doReq(t, client, base, "GET", "/p", authed(map[string]string{
		"X-Forwarded-For": "9.9.9.9",
		"X-Real-Ip":       "8.8.8.8",
		"X-Wdsp-Evil":     "inject",
	}), "")
	resp.Body.Close()
	rec := coll.all()[0]
	if rec.SrcIP == "9.9.9.9" || rec.SrcIP == "8.8.8.8" {
		t.Fatalf("五元组被外部头污染: %s", rec.SrcIP)
	}
	if rec.SrcIP != "127.0.0.1" {
		t.Fatalf("真实对端应为回环: %s", rec.SrcIP)
	}
	if vs := rec.Request.Headers["x-forwarded-for"]; len(vs) != 1 || vs[0] != "9.9.9.9" {
		t.Fatal("X-Forwarded-For 应作为普通数据头保留（脱敏规则照常适用）")
	}
	if _, ok := rec.Request.Headers["x-wdsp-evil"]; ok {
		t.Fatal("伪造控制头必须剥离")
	}
}

// 正文采集：默认仅元数据；L2+BodyEnabled 采集并脱敏；content_type 白名单外跳过。
func TestBodyGating(t *testing.T) {
	r, coll, addr := newTestReceiver(t, Config{BodyEnabled: true})
	r.UpdatePolicy(config.LevelL2, 4096, config.DefaultMasking())
	client, base := dialerFor(addr)

	// L2 + BodyEnabled：JSON 一级字段脱敏
	resp := doReq(t, client, base, "POST", "/login", authed(map[string]string{
		"Content-Type": "application/json",
	}), `{"user":"u","password":"plain-secret"}`)
	resp.Body.Close()
	rec := coll.all()[0]
	if rec.Request.Body != `{"password":"********","user":"u"}` {
		t.Fatalf("body=%q", rec.Request.Body)
	}
	if rec.Request.BodyQuality.OriginalTotalSize == nil ||
		*rec.Request.BodyQuality.OriginalTotalSize != int64(len(`{"user":"u","password":"plain-secret"}`)) {
		t.Fatalf("body_quality: %+v", rec.Request.BodyQuality)
	}

	// 白名单外 content_type 跳过
	resp = doReq(t, client, base, "POST", "/bin", authed(map[string]string{
		"Content-Type": "application/octet-stream",
	}), "raw-bytes")
	resp.Body.Close()
	rec = coll.all()[1]
	if rec.Request.Body != "" || rec.Request.BodyQuality.SkippedReason != "content_type" {
		t.Fatalf("skip: %q/%q", rec.Request.Body, rec.Request.BodyQuality.SkippedReason)
	}
}

// 默认（BodyEnabled=false）仅元数据：正文不驻留，original_body_size 照记。
func TestBodyDisabledByDefault(t *testing.T) {
	_, coll, addr := newTestReceiver(t, Config{})
	client, base := dialerFor(addr)
	resp := doReq(t, client, base, "POST", "/u", authed(map[string]string{
		"Content-Type": "application/json",
	}), `{"password":"plain-secret"}`)
	resp.Body.Close()
	rec := coll.all()[0]
	if rec.Request.Body != "" {
		t.Fatalf("默认不采正文: %q", rec.Request.Body)
	}
	if rec.Request.BodyQuality.OriginalTotalSize == nil ||
		*rec.Request.BodyQuality.OriginalTotalSize != int64(len(`{"password":"plain-secret"}`)) {
		t.Fatalf("original_total_size=%v", rec.Request.BodyQuality.OriginalTotalSize)
	}
}

// 大正文截断：捕获 ≤ 上限、truncated=true、原始总大小=Content-Length。
func TestBodyTruncation(t *testing.T) {
	r, coll, addr := newTestReceiver(t, Config{BodyEnabled: true, MaxBodyBytes: 16})
	r.UpdatePolicy(config.LevelL2, 4096, config.DefaultMasking())
	client, base := dialerFor(addr)
	body := strings.Repeat("a", 4096)
	resp := doReq(t, client, base, "POST", "/big", authed(map[string]string{
		"Content-Type": "text/plain",
	}), body)
	resp.Body.Close()
	rec := coll.all()[0]
	if len(rec.Request.Body) != 16 || !rec.Request.BodyQuality.Truncated {
		t.Fatalf("truncation: len=%d truncated=%v", len(rec.Request.Body), rec.Request.BodyQuality.Truncated)
	}
	if rec.Request.BodyQuality.OriginalTotalSize == nil ||
		*rec.Request.BodyQuality.OriginalTotalSize != 4096 || rec.Request.BodyQuality.CapturedBytes != 16 {
		t.Fatalf("body_quality: %+v", rec.Request.BodyQuality)
	}
}

// chunked 且未读尽：原始总大小不可确认 → body_quality.original_total_size 为 null（不填 0）。
func TestChunkedUnknownTotal(t *testing.T) {
	r, coll, addr := newTestReceiver(t, Config{BodyEnabled: true, MaxBodyBytes: 16})
	r.UpdatePolicy(config.LevelL2, 4096, config.DefaultMasking())
	_, base := dialerFor(addr)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, err := http.NewRequest("POST", base+"/stream", io.NopCloser(strings.NewReader(strings.Repeat("b", 4096))))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderInstance, "tok-test-123")
	req.Header.Set("Content-Type", "text/plain")
	req.TransferEncoding = []string{"chunked"}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rec := coll.all()[0]
	if rec.Request.BodyQuality.OriginalTotalSize != nil {
		t.Fatalf("未知总大小必须为 null: %+v", rec.Request.BodyQuality)
	}
	// 契约 §2.1 一致性：truncated=true 要求总大小非 null——未知总大小时不能
	// 声明截断，已捕获字节数如实保留
	if rec.Request.BodyQuality.Truncated {
		t.Fatal("未知总大小不得声明 truncated")
	}
	if rec.Request.BodyQuality.CapturedBytes != 16 {
		t.Fatalf("已捕获字节应照记: %d", rec.Request.BodyQuality.CapturedBytes)
	}
}

// 元数据镜像：子请求无 Content-Length 时，原始正文大小取可信控制头
// （控制头剥离不入记录）；正文镜像路径（CL 已知）忽略控制头。
func TestOriginalBodySizeControlHeader(t *testing.T) {
	_, coll, addr := newTestReceiver(t, Config{})
	client, base := dialerFor(addr)

	// 元数据路径：无 CL + 控制头 29 → original_total_size=29，控制头不入记录
	req, err := http.NewRequest("POST", base+"/form", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderInstance, "tok-test-123")
	req.Header.Set(HeaderOriginalBodySize, "29")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rec := coll.all()[0]
	if rec.Request.BodyQuality.OriginalTotalSize == nil ||
		*rec.Request.BodyQuality.OriginalTotalSize != 29 {
		t.Fatalf("控制头原始大小未生效: %+v", rec.Request.BodyQuality)
	}
	if _, ok := rec.Request.Headers[strings.ToLower(HeaderOriginalBodySize)]; ok {
		t.Fatal("控制头必须剥离")
	}

	// 正文路径：CL=5 优先于控制头 9999
	resp = doReq(t, client, base, "POST", "/body", authed(map[string]string{
		"Content-Type":         "text/plain",
		HeaderOriginalBodySize: "9999",
	}), "hello")
	resp.Body.Close()
	rec = coll.all()[1]
	if rec.Request.BodyQuality.OriginalTotalSize == nil ||
		*rec.Request.BodyQuality.OriginalTotalSize != 5 {
		t.Fatalf("CL 已知时控制头不得覆盖: %+v", rec.Request.BodyQuality)
	}
}

// Unix Socket 权限与陈旧文件处置：0600 落盘；非 socket 占位拒绝覆盖。
func TestUnixSocketPerms(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "m.sock")
	r, _, _ := newTestReceiver(t, Config{SocketPath: sock})
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket 权限 %v", fi.Mode().Perm())
	}
	r.Shutdown(context.Background())
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("停机后 socket 应清理")
	}

	// 非 socket 占位：拒绝覆盖
	blocker := filepath.Join(dir, "blocked.sock")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("a", Config{
		SocketPath: blocker, SourceInstance: "i", InstanceToken: "t",
	}, nil, nil); err != nil {
		t.Fatalf("New 不应触碰文件: %v", err)
	}
	rc, err := New("a", Config{
		SocketPath: blocker, SourceInstance: "i", InstanceToken: "t",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Start(); err == nil {
		t.Fatal("非 socket 占位必须拒绝")
	}
	if _, err := os.Stat(blocker); err != nil {
		t.Fatal("占位文件不得被删除")
	}
}

// 监听隔离：非回环 TCP 一律拒绝（wildcard/公网地址）。
func TestLoopbackEnforced(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:9080", ":9080", "192.168.1.10:9080", "[::]:9080", "bad"} {
		_, err := New("a", Config{
			ListenAddr: addr, SourceInstance: "i", InstanceToken: "t",
		}, nil, nil)
		if err == nil {
			t.Fatalf("%s 必须拒绝", addr)
		}
	}
	if _, err := New("a", Config{
		ListenAddr: "127.0.0.1:0", SourceInstance: "i", InstanceToken: "t",
	}, nil, nil); err != nil {
		t.Fatalf("回环应允许: %v", err)
	}
	if _, err := New("a", Config{
		ListenAddr: "localhost:0", SourceInstance: "i", InstanceToken: "t",
	}, nil, nil); err != nil {
		t.Fatalf("localhost 应允许: %v", err)
	}
}

// 配置校验：source_instance/instance_token 必填；双监听互斥。
func TestConfigValidation(t *testing.T) {
	if _, err := New("a", Config{InstanceToken: "t", SocketPath: filepath.Join(t.TempDir(), "s.sock")}, nil, nil); err == nil {
		t.Fatal("缺 source_instance 必须拒绝")
	}
	if _, err := New("a", Config{SourceInstance: "i", SocketPath: filepath.Join(t.TempDir(), "s.sock")}, nil, nil); err == nil {
		t.Fatal("缺 instance_token 必须拒绝")
	}
	if _, err := New("a", Config{
		SourceInstance: "i", InstanceToken: "t",
		SocketPath: filepath.Join(t.TempDir(), "s.sock"), ListenAddr: "127.0.0.1:0",
	}, nil, nil); err == nil {
		t.Fatal("双监听配置必须拒绝")
	}
}

// 连接数上限：慢请求占满信号量后新请求 503，进程不 hang。
func TestMaxConnsBounded(t *testing.T) {
	r, _, addr := newTestReceiver(t, Config{MaxConns: 2, BodyEnabled: true})
	r.UpdatePolicy(config.LevelL2, 1<<20, config.DefaultMasking())
	_, base := dialerFor(addr)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// 两个永不结束的正文流占满信号量
	hold := make(chan struct{})
	for i := 0; i < 2; i++ {
		pr, pw := io.Pipe()
		req, err := http.NewRequest("POST", base+"/hold", pr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(HeaderInstance, "tok-test-123")
		req.Header.Set("Content-Type", "text/plain")
		go func() {
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
		defer pw.Close()
		_ = pw
	}
	// 等两个 hold 请求进入 handler
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Stats.Received.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.Stats.Received.Load() < 2 {
		t.Fatalf("hold 请求未到达: %d", r.Stats.Received.Load())
	}
	// 第三个请求：信号量满 → 503（有界拒绝，不阻塞）
	resp := doReq(t, client, base, "GET", "/third", authed(nil), "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("超限连接应 503: %d", resp.StatusCode)
	}
	if r.Stats.ConnsRejected.Load() != 1 {
		t.Fatalf("conns_rejected=%d", r.Stats.ConnsRejected.Load())
	}
	close(hold)
}

// 序列化红线：记录 JSON 不出现明文敏感值（脱敏在构造出口完成）。
func TestNoPlaintextLeak(t *testing.T) {
	_, coll, addr := newTestReceiver(t, Config{BodyEnabled: true})
	client, base := dialerFor(addr)
	resp := doReq(t, client, base, "POST", "/api?access_token=tok-plain", authed(map[string]string{
		"Authorization": "Bearer plain-secret",
		"Cookie":        "sid=plain-cookie",
		"Content-Type":  "application/x-www-form-urlencoded",
	}), "password=plain-secret&ok=1")
	resp.Body.Close()
	for _, rec := range coll.all() {
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		for _, plain := range []string{"plain-secret", "plain-cookie", "tok-plain"} {
			if bytes.Contains(data, []byte(plain)) {
				t.Fatalf("记录泄漏明文 %q: %s", plain, data)
			}
		}
	}
}

// event_id 与 flow_id 稳定性：同一接收器内唯一，含来源实例标识。
func TestFlowIDForm(t *testing.T) {
	_, coll, addr := newTestReceiver(t, Config{})
	client, base := dialerFor(addr)
	for i := 0; i < 2; i++ {
		resp := doReq(t, client, base, "GET", fmt.Sprintf("/r%d", i), authed(nil), "")
		resp.Body.Close()
	}
	recs := coll.all()
	if recs[0].FlowID == recs[1].FlowID || recs[0].EventID == recs[1].EventID {
		t.Fatal("flow_id/event_id 必须唯一")
	}
	if !strings.Contains(recs[0].FlowID, "mirror-nginx-a") {
		t.Fatalf("flow_id 应含来源实例标识: %q", recs[0].FlowID)
	}
}
