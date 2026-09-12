// selftelemetry.go APM 阶段2 收尾 + 阶段3 运行时指标：管理后端自埋点（默认关）。
// traces：仅包裹管理 API 的 HTTP Handler（otelhttp），与网关数据面（Caddy 原生
// tracing，GATEWAY_TRACING_ENABLED）相互独立。
// metrics（阶段3）：MeterProvider + OTLP/HTTP 周期导出（30s）+ contrib
// instrumentation/runtime 发射 Go runtime 指标（goroutine/heap/GC/调度器，
// 指标名见包文档与 docs/DEPENDENCIES.md），与 traces 同一 OTLP 地址、同一开关总控。
// fail-open 纪律（设计 §19.4/§20）：exporter 初始化失败仅 Warn 降级为空句柄，
// 绝不 panic、不阻断管理服务启动。
package apm

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	contribruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// 自埋点批量导出有界参数（设计 §13.3 基数/背压纪律：队列有界、超时有限，
// 管理面 trace 量极低，参数取 SDK 默认量级即可，不追求吞吐）
const (
	selfTelemetrySpanName    = "jiuzhang-server.admin-api"
	selfTelemetryServiceName = "jiuzhang-server"
	selfTelemetryMaxQueue    = 2048 // BatchSpanProcessor 有界队列上限
	selfTelemetryMaxBatch    = 512
	selfTelemetryBatchWait   = 5 * time.Second
	selfTelemetryExportTO    = 10 * time.Second // 单次导出超时（含 exporter client 超时）
	// selfTelemetryMetricInterval 指标周期导出间隔（阶段3；30s 与采集侧口径对齐，
	// runtime 指标为低开销计数/读值，该频率足够发现 goroutine 堆积与 GC 异常）
	selfTelemetryMetricInterval = 30 * time.Second
)

// SelfTelemetry 管理后端自埋点句柄。provider/meterProvider 为 nil 是降级态
// （exporter 初始化失败）：WrapHTTP 原样透传、Shutdown 立即返回——行为等同关闭。
// 两者降级相互独立（metrics 失败不影响 traces，反之亦然）。
type SelfTelemetry struct {
	provider      *sdktrace.TracerProvider
	meterProvider *sdkmetric.MeterProvider
}

// InitSelfTelemetry 初始化 OTel TracerProvider（OTLP/HTTP exporter + 有界批量队列）并
// 安装为全局 provider 与 W3C TraceContext propagator。任何失败仅 Warn 降级，
// 返回的句柄始终非 nil 且可安全 Shutdown。
func InitSelfTelemetry(ctx context.Context, otlpAddr string) *SelfTelemetry {
	// 先自查地址合法性：otlptracehttp 对非法 URL 仅内部记日志不返回错误
	// （导出时才失败），此处显式校验使降级路径确定、可测
	if u, err := url.Parse(otlpAddr); err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		slog.Warn("apm self telemetry invalid otlp addr, degrade to disabled", "otlp_addr", otlpAddr)
		return &SelfTelemetry{}
	}
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(otlpAddr),
		otlptracehttp.WithTimeout(selfTelemetryExportTO),
	)
	if err != nil {
		slog.Warn("apm self telemetry exporter init failed, degrade to disabled",
			"otlp_addr", otlpAddr, "error", err)
		return &SelfTelemetry{}
	}
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(selfTelemetryServiceName),
		semconv.ServiceVersion(buildVersion()),
		// service.instance.id：运行时指标（阶段3）按实例分组的唯一标识
		semconv.ServiceInstanceID(selfInstanceID()),
		attribute.String("deployment.environment.name", deployEnv()),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxQueueSize(selfTelemetryMaxQueue),
			sdktrace.WithMaxExportBatchSize(selfTelemetryMaxBatch),
			sdktrace.WithBatchTimeout(selfTelemetryBatchWait),
			sdktrace.WithExportTimeout(selfTelemetryExportTO),
		),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	slog.Info("apm self telemetry enabled", "otlp_addr", otlpAddr, "deploy_env", deployEnv())
	return &SelfTelemetry{provider: tp, meterProvider: initSelfMetrics(ctx, otlpAddr, res)}
}

// initSelfMetrics 初始化 MeterProvider（OTLP/HTTP exporter + 30s 周期导出）并启动
// Go runtime 指标采集（contrib instrumentation/runtime：go.goroutine.count、
// go.memory.used/allocated/limit/gc.goal、go.memory.allocations、go.processor.limit、
// go.config.gogc；经 WithProducer 附带 go.schedule.duration 调度延迟直方图）。
// 任何失败仅 Warn 返回 nil（指标降级不影响 traces 与管理服务启动）。
// 注意不调用 otel.SetMeterProvider：指标仅走本 provider，避免 otelhttp 等
// 既有埋点意外开始发射指标（本阶段只承诺 Go runtime 指标集）。
func initSelfMetrics(ctx context.Context, otlpAddr string, res *resource.Resource) *sdkmetric.MeterProvider {
	exp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpointURL(otlpAddr),
		otlpmetrichttp.WithTimeout(selfTelemetryExportTO),
	)
	if err != nil {
		slog.Warn("apm self telemetry metric exporter init failed, metrics degraded",
			"otlp_addr", otlpAddr, "error", err)
		return nil
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
			sdkmetric.WithInterval(selfTelemetryMetricInterval),
			sdkmetric.WithTimeout(selfTelemetryExportTO),
			sdkmetric.WithProducer(contribruntime.NewProducer()),
		)),
	)
	if err := contribruntime.Start(contribruntime.WithMeterProvider(mp)); err != nil {
		slog.Warn("apm self telemetry runtime metrics start failed, metrics degraded", "error", err)
		// 显式关闭已建 provider（含 reader/exporter），避免泄漏后台协程
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mp.Shutdown(shutdownCtx); err != nil {
			slog.Warn("apm self telemetry meter provider cleanup degraded", "error", err)
		}
		return nil
	}
	return mp
}

// WrapHTTP 用 otelhttp 包裹管理 API Handler（每请求一个 server span）。
// 降级态/零值原样返回，零开销零行为变化。
func (s *SelfTelemetry) WrapHTTP(h http.Handler) http.Handler {
	if s == nil || s.provider == nil {
		return h
	}
	return otelhttp.NewHandler(h, selfTelemetrySpanName)
}

// Shutdown 优雅停机：flush 并关闭 metrics/traces 两个 provider。失败仅 Warn
// （遥测 fail-open，不阻断进程退出）；降级态/零值直接返回。不 panic。
func (s *SelfTelemetry) Shutdown(ctx context.Context) {
	if s == nil {
		return
	}
	if s.meterProvider != nil {
		if err := s.meterProvider.Shutdown(ctx); err != nil {
			slog.Warn("apm self telemetry metrics shutdown degraded", "error", err)
		}
	}
	if s.provider == nil {
		return
	}
	if err := s.provider.Shutdown(ctx); err != nil {
		slog.Warn("apm self telemetry shutdown degraded", "error", err)
	}
}

// selfInstanceID 实例标识（resource service.instance.id）：主机名+PID，
// 单机多进程与多副本均可区分；主机名缺失回退 pid-only，保证非空。
func selfInstanceID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

// deployEnv 部署环境名（resource deployment.environment.name）；
// 环境变量 DEPLOY_ENV，默认 prod。
func deployEnv() string {
	if v := os.Getenv("DEPLOY_ENV"); v != "" {
		return v
	}
	return "prod"
}

// buildVersion 服务版本：仓库无版本常量/ldflags 注入，取 Go build info
// 主模块版本；本地开发构建（(devel)）与缺失时如实标注 unknown。
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "unknown"
}
