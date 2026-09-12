// service-a P1-01 A1 演示合成业务入口服务：HTTP 入口 → 调用服务 B。
//   - otelhttp 包裹 Handler/Transport：产生真实 Server/Client span，
//     提取上游（网关或造流脚本）注入的 traceparent，并向服务 B 续传 W3C traceparent；
//   - 场景开关默认关闭（DEMO_SCENARIOS_ENABLED），仅转发白名单场景头；
//   - 服务 B 地址来自环境变量 SERVICE_B_URL（compose 内网固定值），不取自请求输入；
//   - 响应头 X-Demo-Trace-Id 输出本服务 span 的 trace ID，供断言精确对账。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"jiuzhang-wdsp/test/security-apm-demo/services/internal/democommon"
	"jiuzhang-wdsp/test/security-apm-demo/services/internal/demootel"
)

const maxProxyBodyBytes = 64 << 10 // 转发服务 B 响应的有界上限（64KiB）

type config struct {
	port             string
	serviceBURL      string
	otlpEndpoint     string
	deployEnv        string
	scenarioEnabled  bool
	shutdownGraceSec int
}

func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		port:             getenv("PORT"),
		serviceBURL:      getenv("SERVICE_B_URL"),
		otlpEndpoint:     getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		deployEnv:        getenv("DEMO_ENV"),
		scenarioEnabled:  democommon.ScenariosEnabled(getenv),
		shutdownGraceSec: 5,
	}
	if cfg.port == "" {
		cfg.port = "8080"
	}
	if cfg.otlpEndpoint == "" {
		cfg.otlpEndpoint = "http://127.0.0.1:4318"
	}
	if cfg.deployEnv == "" {
		cfg.deployEnv = "security-apm-demo"
	}
	if cfg.serviceBURL == "" {
		return cfg, errors.New("缺少 SERVICE_B_URL（compose 内网固定地址，不接受运行时请求输入）")
	}
	return cfg, nil
}

type server struct {
	cfg    config
	client *http.Client
	// orderRequests /demo/order 入口累计调用计数（场景 3「网关阻断」源站计数证据：
	// 阻断波次前后读数不变 = 请求未到达源站的业务侧直接证据）
	orderRequests atomic.Int64
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("配置加载失败", "error", err)
		os.Exit(1)
	}
	ctx := context.Background()
	tp, err := demootel.InitProvider(ctx, "demo-service-a", cfg.otlpEndpoint, cfg.deployEnv)
	if err != nil {
		// fail-open：遥测降级不影响业务服务（断言阶段会如实 FAIL，不伪造 Trace）
		slog.Warn("OTel 初始化失败，降级为无遥测运行", "error", err)
	}
	srv := &server{
		cfg: cfg,
		client: &http.Client{
			Transport: otelhttp.NewTransport(http.DefaultTransport),
			Timeout:   15 * time.Second,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	// 计数端点不包 otelhttp：读数操作本身不产生 Span，避免污染对账证据
	mux.HandleFunc("GET /demo/stats", srv.handleStats)
	// Go 1.22 方法模式注册：otelhttp v0.69.0 从 req.Pattern 提取 http.route
	mux.Handle("GET /demo/order",
		otelhttp.NewHandler(http.HandlerFunc(srv.handleOrder), "GET /demo/order"))

	httpSrv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		shCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.shutdownGraceSec)*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
		if tp != nil {
			_ = tp.Shutdown(shCtx) // 退出前冲刷有界队列中的 span
		}
	}()
	slog.Info("service-a 启动", "port", cfg.port, "service_b", cfg.serviceBURL,
		"scenarios_enabled", cfg.scenarioEnabled, "otlp", cfg.otlpEndpoint)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP 服务退出", "error", err)
		os.Exit(1)
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleStats GET /demo/stats：返回 /demo/order 累计调用计数（合成业务内计数器，
// 无任何外部输入；供「网关阻断波次源站计数不变」断言读取）。
func (s *server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK,
		map[string]string{"order_requests_total": strconv.FormatInt(s.orderRequests.Load(), 10)})
}

// handleOrder GET /demo/order?id=1..100 → 调用服务 B /items，透传场景与演示请求 ID。
func (s *server) handleOrder(w http.ResponseWriter, r *http.Request) {
	s.orderRequests.Add(1)
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	id, ok := democommon.ParseItemID(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id（允许 1..100）"})
		return
	}
	scenario, ok := democommon.ParseScenario(s.cfg.scenarioEnabled, r.Header.Get(democommon.HeaderScenario))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown scenario（白名单：slow-sql|exception）"})
		return
	}
	// otelhttp v0.69.0 走新 semconv（http.request.method）；产品端点分钟聚合仍读
	// 旧键 http.method（deployment/apm/clickhouse/002_aggregates.sql apm_endpoint_minutes_mv），
	// 此处补写一次保持聚合键可用（合成常量，非用户输入）
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("http.method", r.Method))
	if reqID := r.Header.Get(democommon.HeaderDemoRequestID); reqID != "" {
		if !democommon.ValidDemoRequestID(reqID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid demo request id 形态"})
			return
		}
		// 合成属性：供 ClickHouse 侧按演示请求 ID 精确对账（非内部 request_id）
		trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("demo.request_id", reqID))
	}

	upURL := s.cfg.serviceBURL + "/items?id=" + strconv.Itoa(id)
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, upURL, nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "build upstream request failed"})
		return
	}
	upReq.Header.Set(democommon.HeaderScenario, scenario)
	if reqID := r.Header.Get(democommon.HeaderDemoRequestID); reqID != "" {
		upReq.Header.Set(democommon.HeaderDemoRequestID, reqID)
	}
	resp, err := s.client.Do(upReq)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream service-b unreachable"})
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "read upstream body failed"})
		return
	}

	// 响应头：本服务 span 的 trace ID（遥测降级/未开启时为无效 ID，不输出）
	if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() && sc.TraceID().IsValid() {
		w.Header().Set(democommon.HeaderTraceID, sc.TraceID().String())
	}
	w.Header().Set(democommon.HeaderScenarioApplied, scenario)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v map[string]string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// healthcheck 容器健康检查子命令：GET 本机 /healthz，200 退出 0。
func healthcheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
