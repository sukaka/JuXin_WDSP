// demootel P1-01 A1 演示合成业务的 OTel TracerProvider 初始化。
// 纪律与产品自埋点一致（server/internal/apm/selftelemetry.go）：
//   - fail-open：exporter 初始化失败返回 error，由调用方 Warn 降级为无遥测运行，
//     绝不 panic、不阻断服务启动；
//   - 有界批量导出（队列 2048 / 批 512 / 超时 10s）；
//   - 头采 parentbased_always_on（100%）：采样保留决策集中在 Collector 尾采样，
//     业务侧不做概率裁剪（丢弃不可恢复）；
//   - 传播协议 W3C Trace Context（traceparent；不读/不传 tracestate 之外的厂商段）。
package demootel

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"jiuzhang-wdsp/test/security-apm-demo/services/internal/democommon"
)

const (
	maxQueue      = 2048
	maxBatch      = 512
	batchWait     = 5 * time.Second
	exportTimeout = 10 * time.Second
)

// InitProvider 初始化 TracerProvider（OTLP/HTTP exporter）并安装为全局 provider 与
// W3C TraceContext propagator。otlpEndpoint 非法或 exporter 初始化失败返回 error
//（调用方降级处理）；成功时返回的 provider 非 nil，Shutdown 用于退出前冲刷。
func InitProvider(ctx context.Context, serviceName, otlpEndpoint, deployEnv string) (*sdktrace.TracerProvider, error) {
	// OTEL_SDK_DISABLED=true（A4「仅网关观测」场景）：业务照常运行但不装 provider，
	// 返回 (nil, nil)——调用方 tp==nil 即无遥测路径，与初始化失败的 fail-open 同形。
	if democommon.TelemetryDisabled(os.Getenv) {
		slog.Warn("OTEL_SDK_DISABLED=true：应用遥测已关闭（仅网关观测场景），不产生任何 Span",
			"service", serviceName)
		return nil, nil
	}
	if u, err := url.Parse(otlpEndpoint); err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("OTLP 端点非法（需 http/https URL）: %q", otlpEndpoint)
	}
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(otlpEndpoint),
		otlptracehttp.WithTimeout(exportTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("OTLP exporter 初始化失败: %w", err)
	}
	host, _ := os.Hostname()
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion("0.1.0-demo"),
		semconv.ServiceInstanceID(fmt.Sprintf("%s-%d", host, os.Getpid())),
		attribute.String("deployment.environment.name", deployEnv),
	)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		// 头采 100%：保留决策集中在 Collector 尾采样（见 collector/ 双配置）
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxQueueSize(maxQueue),
			sdktrace.WithMaxExportBatchSize(maxBatch),
			sdktrace.WithBatchTimeout(batchWait),
			sdktrace.WithExportTimeout(exportTimeout),
		),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return tp, nil
}
