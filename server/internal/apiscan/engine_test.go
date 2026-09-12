// engine_test.go 内置探针引擎单测（httptest 靶标）：
// 六探针集判定逻辑、隔离签名头携带、限速/并发参数生效、Guard 中止、
// 高风险方法零主动发送、脱敏样本回归。
package apiscan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// collectEmitter 收集引擎产出的发现。
type collectEmitter struct {
	mu   sync.Mutex
	list []*ProbeResult
	err  error
}

func (c *collectEmitter) emit(r *ProbeResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = append(c.list, r)
	return c.err
}

func (c *collectEmitter) findings() []*ProbeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*ProbeResult(nil), c.list...)
}

// runTask 便捷执行：单端点单/多探针集。
func runTask(t *testing.T, baseURL string, paths, sets []string, mutate func(*ProbeTask)) (RunSummary, *collectEmitter, error) {
	t.Helper()
	signer, err := NewSigner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	task := &ProbeTask{
		JobID:          uuid.New(),
		BaseURL:        baseURL,
		Paths:          paths,
		ProbeSets:      sets,
		MaxQPS:         1000,
		MaxConcurrency: 1,
		Signer:         signer,
	}
	if mutate != nil {
		mutate(task)
	}
	em := &collectEmitter{}
	summary, err := NewBuiltinEngine(nil).Run(context.Background(), task, em.emit)
	return summary, em, err
}

// TestProbeAuthRequired AUTH_REQUIRED：2xx 命中（HIGH/AUTHN），401/403 负结果。
func TestProbeAuthRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/open") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/open/api", "/protected/api"}, []string{ProbeAuthRequired}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 1 {
		t.Fatalf("findings=%d, want 1", len(fs))
	}
	f := fs[0]
	if f.Template != ProbeAuthRequired || f.Category != CategoryAuthn || f.Severity != SeverityHigh {
		t.Fatalf("finding=%+v", f)
	}
	if f.EndpointKey != "GET /open/api" {
		t.Fatalf("endpoint_key=%q", f.EndpointKey)
	}
	// 脱敏回归：签名头值不落请求样本（头值替换 [redacted]）
	if !strings.Contains(f.RequestSample, Redacted) {
		t.Fatalf("request sample should redact scan signature header: %s", f.RequestSample)
	}
	if strings.Contains(f.RequestSample, "X-Jiuzhang-Scan: ") && !strings.Contains(f.RequestSample, "X-Jiuzhang-Scan: "+Redacted) {
		t.Fatalf("scan signature value leaked in request sample: %s", f.RequestSample)
	}
}

// TestProbeDeprecatedAlive DEPRECATED_ALIVE：2xx/3xx 命中，404/410 负结果。
func TestProbeDeprecatedAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alive":
			w.WriteHeader(http.StatusOK)
		case "/redirect":
			w.WriteHeader(http.StatusFound)
		case "/gone":
			w.WriteHeader(http.StatusGone)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/alive", "/redirect", "/gone", "/dead"}, []string{ProbeDeprecatedAlive}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 2 {
		t.Fatalf("findings=%d, want 2 (alive+redirect): %+v", len(fs), fs)
	}
}

// TestProbeSensitiveExposure SENSITIVE_EXPOSURE：命中只落字段名不落原文（脱敏红线）。
func TestProbeSensitiveExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/leak" {
			_, _ = w.Write([]byte(`{"user":"zhangsan","password":"p@ssw0rd-secret","phone":"13800001111"}`))
			return
		}
		_, _ = w.Write([]byte(`{"user":"zhangsan","role":"admin"}`))
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/leak", "/clean"}, []string{ProbeSensitiveExposure}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 1 {
		t.Fatalf("findings=%d, want 1", len(fs))
	}
	f := fs[0]
	if f.ResponseSample != "" {
		t.Fatalf("sensitive probe must not store response body: %q", f.ResponseSample)
	}
	fields, _ := f.Evidence["sensitive_fields"].([]string)
	if len(fields) != 2 {
		t.Fatalf("evidence fields=%v", f.Evidence)
	}
	// 响应原文值不得出现在任何落库字段
	blob := fmt.Sprintf("%+v %s %s", f.Evidence, f.RequestSample, f.ResponseSample)
	for _, leaked := range []string{"p@ssw0rd-secret", "13800001111"} {
		if strings.Contains(blob, leaked) {
			t.Fatalf("finding leaks sensitive value %q", leaked)
		}
	}
}

// TestProbeSchemaConform SCHEMA_CONFORM：边界参数被接受命中（低置信），400 负结果，基线非 2xx 跳过。
func TestProbeSchemaConform(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/strict":
			if r.URL.Query().Get("jz_boundary") != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/lax":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/lax", "/strict", "/missing"}, []string{ProbeSchemaConform}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 1 || fs[0].EndpointKey != "GET /lax" {
		t.Fatalf("findings=%+v", fs)
	}
	if fs[0].Confidence >= 0.5 {
		t.Fatal("schema conform finding should be low confidence")
	}
}

// TestProbeBolaCompare BOLA_COMPARE：相邻 id 均 2xx 且体不同命中（仅 OBSERVE 证据）；
// 非数字尾段跳过；体一致不命中。
func TestProbeBolaCompare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orders/100":
			_, _ = w.Write([]byte(`{"order":100,"amount":88}`))
		case "/orders/101":
			_, _ = w.Write([]byte(`{"order":101,"amount":99}`))
		case "/same/1", "/same/2":
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/orders/100", "/same/1", "/users/profile"}, []string{ProbeBolaCompare}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 1 {
		t.Fatalf("findings=%d, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Evidence["observe_only"] != true {
		t.Fatal("bola finding must be observe-only evidence")
	}
	if f.ResponseSample != "" {
		t.Fatal("bola probe must not store response body")
	}
	if f.Evidence["other_path"] != "/orders/101" {
		t.Fatalf("evidence=%v", f.Evidence)
	}
}

// TestProbeMethodEnum METHOD_ENUM：Allow 宣告高风险方法命中；只发 OPTIONS，
// 高风险方法一律不主动发送（安全红线回归）。
func TestProbeMethodEnum(t *testing.T) {
	var gotMethods sync.Map // method → count
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethods.Store(r.Method, true)
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, POST, DELETE, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, em, err := runTask(t, srv.URL, []string{"/resource"}, []string{ProbeMethodEnum}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := em.findings()
	if len(fs) != 1 {
		t.Fatalf("findings=%d, want 1", len(fs))
	}
	dangerous, _ := fs[0].Evidence["dangerous_methods"].([]string)
	if len(dangerous) != 1 || dangerous[0] != "DELETE" {
		t.Fatalf("evidence=%v", fs[0].Evidence)
	}
	// 红线：引擎只发了 OPTIONS
	for m := range dangerousMethods {
		if _, sent := gotMethods.Load(m); sent {
			t.Fatalf("dangerous method %s was actively sent", m)
		}
	}
	if _, sent := gotMethods.Load(http.MethodOptions); !sent {
		t.Fatal("OPTIONS not sent")
	}
}

// TestEngineSignatureHeader 隔离签名头：探针请求携带 X-JiuZhang-Scan 且签名可校验。
func TestEngineSignatureHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(ScanHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	signer, _ := NewSigner(make([]byte, 32))
	var jobID uuid.UUID
	_, _, err := runTask(t, srv.URL, []string{"/a"}, []string{ProbeAuthRequired}, func(task *ProbeTask) {
		jobID = task.JobID
		task.Signer = signer
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotHeader == "" {
		t.Fatal("scan header missing")
	}
	id, ok := signer.Verify(gotHeader)
	if !ok || id != jobID {
		t.Fatalf("signature verify failed: %q", gotHeader)
	}
}

// TestEngineRateLimit 限速参数生效：低 QPS 下 N 个请求的耗时下限。
func TestEngineRateLimit(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	start := time.Now()
	summary, _, err := runTask(t, srv.URL, []string{"/a", "/b", "/c"}, []string{ProbeAuthRequired}, func(task *ProbeTask) {
		task.MaxQPS = 20 // 50ms/请求
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Requests != 3 {
		t.Fatalf("requests=%d, want 3", summary.Requests)
	}
	// 3 请求 × 50ms 间隔 ≈ 150ms 下限（留 30% 抖动余量）
	if elapsed < 100*time.Millisecond {
		t.Fatalf("rate limit not effective: 3 requests in %v", elapsed)
	}
}

// TestEngineConcurrencyLimit 并发参数生效：max_concurrency=2 时在飞请求数不超过 2。
func TestEngineConcurrencyLimit(t *testing.T) {
	var inflight, maxInflight int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt64(&inflight, 1)
		for {
			old := atomic.LoadInt64(&maxInflight)
			if cur <= old || atomic.CompareAndSwapInt64(&maxInflight, old, cur) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt64(&inflight, -1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	paths := []string{"/a", "/b", "/c", "/d", "/e", "/f"}
	_, _, err := runTask(t, srv.URL, paths, []string{ProbeAuthRequired}, func(task *ProbeTask) {
		task.MaxConcurrency = 2
		task.MaxQPS = 1000
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&maxInflight); got > 2 {
		t.Fatalf("max inflight=%d, want <=2", got)
	}

	// 并发=1 时在飞不超过 1
	atomic.StoreInt64(&inflight, 0)
	atomic.StoreInt64(&maxInflight, 0)
	_, _, err = runTask(t, srv.URL, paths, []string{ProbeAuthRequired}, func(task *ProbeTask) {
		task.MaxConcurrency = 1
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&maxInflight); got != 1 {
		t.Fatalf("serial run max inflight=%d, want 1", got)
	}
}

// TestEngineGuardAbort Guard 中止：第二批起返回错误，任务提前终止且错误向上返回
// （吊销即停/停止即停的执行侧语义）。
func TestEngineGuardAbort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var calls int64
	guardErr := fmt.Errorf("授权已撤销")
	summary, _, err := runTask(t, srv.URL,
		[]string{"/a", "/b", "/c", "/d"}, []string{ProbeAuthRequired}, func(task *ProbeTask) {
			task.MaxQPS = 100 // 放慢便于观察早退
			task.Guard = func(context.Context) error {
				if atomic.AddInt64(&calls, 1) > 1 {
					return guardErr
				}
				return nil
			}
		})
	if err == nil || !strings.Contains(err.Error(), "授权已撤销") {
		t.Fatalf("guard error not propagated: %v", err)
	}
	if summary.EndpointsDone >= 4 {
		t.Fatalf("job should abort early, done=%d", summary.EndpointsDone)
	}
}

// TestEngineRejectsUnknownProbeSet 词表外探针集拒绝（白名单制红线）。
func TestEngineRejectsUnknownProbeSet(t *testing.T) {
	_, _, err := runTask(t, "http://127.0.0.1:1", []string{"/a"}, []string{"SQLI_FUZZ"}, nil)
	if err == nil || !strings.Contains(err.Error(), "词表外") {
		t.Fatalf("unknown probe set should be rejected: %v", err)
	}
}

// TestEngineEmitErrorAborts 发现落库失败不静默：任务中止并计错误。
func TestEngineEmitErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em := &collectEmitter{err: fmt.Errorf("db down")}
	signer, _ := NewSigner(make([]byte, 32))
	task := &ProbeTask{
		JobID: uuid.New(), BaseURL: srv.URL, Paths: []string{"/a"},
		ProbeSets: []string{ProbeAuthRequired}, MaxQPS: 1000, MaxConcurrency: 1, Signer: signer,
	}
	summary, err := NewBuiltinEngine(nil).Run(context.Background(), task, em.emit)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Errors == 0 || !strings.Contains(summary.LastError, "db down") {
		t.Fatalf("emit error not surfaced: %+v", summary)
	}
}

// TestEngineEndpointErrorDoesNotBlock 单端点错误不阻断任务（连接失败计错误继续）。
func TestEngineEndpointErrorDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close() // 立即关闭：连接失败

	summary, _, err := runTask(t, srv.URL, []string{"/a", "/b"}, []string{ProbeAuthRequired}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Errors != 2 || summary.LastError == "" {
		t.Fatalf("endpoint errors not counted: %+v", summary)
	}
}
