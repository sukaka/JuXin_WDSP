// client_test.go Unix Socket 客户端测试：真实 socket 上的 fake sidecar 往返、
// 结构化错误解析、不可用映射。
package containerops

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shortTempDir 返回短路径临时目录（macOS t.TempDir 路径过长会超 Unix Socket 地址上限）。
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cc")
	if err != nil {
		t.Fatalf("创建临时目录: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeSidecar 启动 fake containeropsd（Unix Socket HTTP），返回客户端与请求记录。
func fakeSidecar(t *testing.T, handler http.Handler) *Client {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "containerops.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听 socket: %v", err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return NewClient(sock)
}

func TestClientUnavailableWhenEmpty(t *testing.T) {
	c := NewClient("")
	if c.Available() {
		t.Fatal("空 socket 路径应不可用")
	}
	for _, err := range []error{
		func() error { _, e := c.ListContainers(context.Background()); return e }(),
		func() error { _, e := c.ContainerLogs(context.Background(), "web", 10, 0); return e }(),
		func() error { _, e := c.SubmitAction(context.Background(), "web", "start", 0); return e }(),
		func() error {
			_, e := c.ActionStatus(context.Background(), "0123456789abcdef0123456789abcdef")
			return e
		}(),
	} {
		if !IsUnavailable(err) {
			t.Fatalf("空配置应返回 KindUnavailable: %v", err)
		}
	}
}

func TestClientConnectionRefused(t *testing.T) {
	c := NewClient(filepath.Join(shortTempDir(t), "gone.sock"))
	if !c.Available() {
		t.Fatal("配置了路径应视为可用（连接期才暴露故障）")
	}
	_, err := c.ListContainers(context.Background())
	if !IsUnavailable(err) {
		t.Fatalf("socket 不存在应映射 KindUnavailable: %v", err)
	}
}

func TestClientListAndLogsRoundTrip(t *testing.T) {
	var gotQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/containers", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"containers": []map[string]interface{}{{"service": "web", "running": true, "health": "healthy"}},
		})
	})
	mux.HandleFunc("GET /v1/containers/{service}/logs", func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":    r.PathValue("service"),
			"lines":      []map[string]string{{"timestamp": "2026-10-19T01:02:03Z", "stream": "stdout", "message": "ok"}},
			"truncated":  false,
			"next_since": 123456,
		})
	})
	c := fakeSidecar(t, mux)

	containers, err := c.ListContainers(context.Background())
	if err != nil || len(containers) != 1 || containers[0].Service != "web" || !containers[0].Running {
		t.Fatalf("列表往返错误: containers=%+v err=%v", containers, err)
	}
	logs, err := c.ContainerLogs(context.Background(), "web", 500, 1699999999)
	if err != nil {
		t.Fatalf("日志调用: %v", err)
	}
	if gotQuery != "since=1699999999&tail=500" {
		t.Fatalf("查询参数错误: %q", gotQuery)
	}
	if logs.Service != "web" || logs.NextSince != 123456 || len(logs.Lines) != 1 {
		t.Fatalf("日志解析错误: %+v", logs)
	}
}

func TestClientSubmitActionAndStatus(t *testing.T) {
	var gotBody map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/containers/{service}/actions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"job_id": "0123456789abcdef0123456789abcdef", "status": "ACCEPTED"})
	})
	mux.HandleFunc("GET /v1/actions/{job_id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id": r.PathValue("job_id"), "service": "web", "action": "restart",
			"status": "SUCCESS", "message": "执行成功",
		})
	})
	c := fakeSidecar(t, mux)

	job, err := c.SubmitAction(context.Background(), "web", "restart", 5)
	if err != nil || job.JobID == "" || job.Status != "ACCEPTED" {
		t.Fatalf("受理往返错误: job=%+v err=%v", job, err)
	}
	if gotBody["action"] != "restart" || gotBody["delay_seconds"].(float64) != 5 {
		t.Fatalf("请求体错误: %v", gotBody)
	}
	status, err := c.ActionStatus(context.Background(), job.JobID)
	if err != nil || status.Status != "SUCCESS" || status.Action != "restart" {
		t.Fatalf("状态往返错误: status=%+v err=%v", status, err)
	}
}

func TestClientUpstreamError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/containers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{"code": "PROJECT_NOT_CONFIGURED", "message": "未配置项目"},
		})
	})
	c := fakeSidecar(t, mux)
	_, err := c.ListContainers(context.Background())
	var ce *Error
	if !errors.As(err, &ce) || ce.Kind != KindUpstream || ce.Status != http.StatusServiceUnavailable ||
		ce.Code != "PROJECT_NOT_CONFIGURED" || ce.Message != "未配置项目" {
		t.Fatalf("上游结构化错误解析失败: %v", err)
	}
	if IsUnavailable(err) {
		t.Fatal("上游错误不应判为不可用")
	}
}
