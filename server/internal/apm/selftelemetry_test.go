package apm

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type noopHTTPHandler struct{}

func (noopHTTPHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestInitSelfTelemetryInvalidAddrDegrades(t *testing.T) {
	// 无效 OTLP 地址：不得 panic，降级为空句柄（provider nil），行为等同关闭
	s := InitSelfTelemetry(context.Background(), "://invalid-addr")
	if s == nil {
		t.Fatal("InitSelfTelemetry returned nil handle")
	}
	if s.provider != nil {
		t.Error("degraded handle should have nil provider")
	}
	if s.meterProvider != nil {
		t.Error("degraded handle should have nil meterProvider")
	}
	h := noopHTTPHandler{}
	if got := s.WrapHTTP(h); got != h {
		t.Error("degraded WrapHTTP should return the original handler unchanged")
	}
	// 降级态 Shutdown：立即返回、不 panic
	s.Shutdown(context.Background())
}

func TestInitSelfTelemetryEnabled(t *testing.T) {
	// 合法地址（对端无需真实存在：OTLP/HTTP exporter 惰性连接）
	s := InitSelfTelemetry(context.Background(), "http://127.0.0.1:4318")
	if s.provider == nil {
		t.Fatal("enabled self telemetry should have non-nil provider")
	}
	if s.meterProvider == nil {
		t.Fatal("enabled self telemetry should have non-nil meterProvider（阶段3 runtime 指标）")
	}
	h := noopHTTPHandler{}
	if got := s.WrapHTTP(h); got == h {
		t.Error("enabled WrapHTTP should wrap the handler with otelhttp")
	}
	// Shutdown 不 panic 且不超期（无积压 span/指标时导出 flush 为空操作，不依赖 Collector 可达）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)
	if err := ctx.Err(); err != nil {
		t.Fatalf("Shutdown exceeded context: %v", err)
	}
}

func TestSelfInstanceID(t *testing.T) {
	// 实例标识必须非空且含 PID 后缀（主机名缺失时回退 unknown-host）
	id := selfInstanceID()
	if id == "" {
		t.Fatal("selfInstanceID() should never be empty")
	}
	if got := selfInstanceID(); got != id {
		t.Errorf("selfInstanceID() not stable within process: %q vs %q", got, id)
	}
}

func TestDeployEnv(t *testing.T) {
	if got := deployEnv(); got != "prod" {
		t.Errorf("deployEnv() default = %q, want prod", got)
	}
	t.Setenv("DEPLOY_ENV", "staging")
	if got := deployEnv(); got != "staging" {
		t.Errorf("deployEnv() = %q, want staging", got)
	}
}

func TestBuildVersionFallback(t *testing.T) {
	// 测试进程无有效主模块版本，应回退 unknown（不 panic、非空）
	if got := buildVersion(); got == "" {
		t.Error("buildVersion() should never be empty")
	}
}
