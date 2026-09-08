// service-b P1-01 A1 演示合成业务数据服务：HTTP 入口 → 查询独立测试库。
//   - otelhttp 包裹 Handler 产生 Server span；DB 调用用 OTel SDK 显式埋点产生
//     Client kind 的 DB span（db.system / db.statement 常量语句，绑定值绝不入属性）；
//   - SQL 语句全部为代码内常量，经 database/sql 参数化传值；不接受任何外部 SQL、
//     命令或 URL 输入；
//   - 慢查询/异常由测试库内预定义的有界函数执行（demo_sleep_bounded 上限 3s、
//     demo_raise_synthetic_error 固定合成错误），场景开关默认关闭；
//   - 异常对客户端只返回通用摘要，不回显 SQL/DSN/驱动错误原文。
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"jiuzhang-wdsp/test/security-apm-demo/services/internal/democommon"
	"jiuzhang-wdsp/test/security-apm-demo/services/internal/demootel"
)

type config struct {
	port            string
	databaseDSN     string
	otlpEndpoint    string
	deployEnv       string
	scenarioEnabled bool
}

func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		port:            getenv("PORT"),
		databaseDSN:     getenv("DATABASE_DSN"),
		otlpEndpoint:    getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		deployEnv:       getenv("DEMO_ENV"),
		scenarioEnabled: democommon.ScenariosEnabled(getenv),
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
	if cfg.databaseDSN == "" {
		return cfg, errors.New("缺少 DATABASE_DSN（由 compose 经运行时环境注入）")
	}
	return cfg, nil
}

type server struct {
	cfg config
	db  *sql.DB
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
	tp, err := demootel.InitProvider(ctx, "demo-service-b", cfg.otlpEndpoint, cfg.deployEnv)
	if err != nil {
		slog.Warn("OTel 初始化失败，降级为无遥测运行", "error", err)
	}
	db, err := openDemoDB(cfg.databaseDSN)
	if err != nil {
		// DSN 含凭据，日志只记错误类型不回显 DSN
		slog.Error("测试库连接初始化失败", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	srv := &server{cfg: cfg, db: db}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	// Go 1.22 方法模式注册：otelhttp v0.69.0 从 req.Pattern 提取 http.route
	mux.Handle("GET /items",
		otelhttp.NewHandler(http.HandlerFunc(srv.handleItems), "GET /items"))

	httpSrv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
		if tp != nil {
			_ = tp.Shutdown(shCtx)
		}
	}()
	slog.Info("service-b 启动", "port", cfg.port,
		"scenarios_enabled", cfg.scenarioEnabled, "otlp", cfg.otlpEndpoint)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP 服务退出", "error", err)
		os.Exit(1)
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleItems GET /items?id=1..100：按场景执行正常/慢 SQL/已知异常三类固定路径。
func (s *server) handleItems(w http.ResponseWriter, r *http.Request) {
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
		trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("demo.request_id", reqID))
	}

	// 全部 DB 操作共享一个有界超时上下文（慢查询上限 3s + 余量）
	dbCtx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	switch scenario {
	case democommon.ScenarioSlowSQL:
		// 慢 SQL：测试库内预定义有界延迟函数（db-init/001_demo_schema.sql，
		// clamp 上限 3.0s）；随后照常执行商品查询
		if err := execBoundedDelay(dbCtx, s.db, 2.5); err != nil {
			slog.Warn("有界延迟执行失败", "error", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bounded delay failed (synthetic)"})
			return
		}
	case democommon.ScenarioException:
		// 应用异常：测试库内预定义函数抛出固定合成错误（真实 DB 错误路径）
		if err := execSyntheticError(dbCtx, s.db); err != nil {
			trace.SpanFromContext(r.Context()).RecordError(err)
			writeJSON(w, http.StatusInternalServerError,
				map[string]string{"error": "inventory query failed (synthetic)"})
			return
		}
	}

	item, err := queryItem(dbCtx, s.db, id)
	if err != nil {
		trace.SpanFromContext(r.Context()).RecordError(err)
		slog.Warn("商品查询失败", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "item query failed (synthetic)"})
		return
	}
	w.Header().Set(democommon.HeaderScenarioApplied, scenario)
	writeJSON(w, http.StatusOK, item)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
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
