// 九章管理后端 API 服务
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/app"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/guardjanitor"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/securityevents"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
	"github.com/jiuzhang-waf/server/internal/users"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 结构化日志
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx := context.Background()

	// 数据库迁移
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		return runMigrate(ctx, cfg, os.Args[2:])
	}

	// 连接数据库
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer db.Close()

	// 连接 Valkey
	cacheClient, err := cache.New(ctx, cfg.Cache)
	if err != nil {
		return fmt.Errorf("connect valkey: %w", err)
	}
	defer cacheClient.Close()

	// 初始化管理员（首次启动）
	if err := ensureInitialAdmin(ctx, db, cfg); err != nil {
		return fmt.Errorf("ensure initial admin: %w", err)
	}

	// 装配应用
	application, err := app.New(cfg, db, cacheClient)
	if err != nil {
		return fmt.Errorf("initialize application: %w", err)
	}

	// syslog 外发（三期）：后台发送循环 + spool 重放，采集器入库成功后 fan-out 投递
	collectorCtx, collectorCancel := context.WithCancel(context.Background())
	defer collectorCancel()
	syslogFw := application.SyslogForwarder()
	go syslogFw.Run(collectorCtx)

	// 阶段4：启动安全事件采集器（后台 goroutine）
	eventCollector := securityevents.NewCollector(db, "collector-01", cfg.WAF.AuditLogPath, cfg.WAF.GatewayNodeName)
	eventCollector.SetSyslogForwarder(syslogFw)
	go eventCollector.Run(collectorCtx, 2*time.Second)

	// 阶段5：启动访问控制/CC 事件采集器（断点续传，封禁与命中联动）
	// 注意：checkpoint 必须落在可写数据目录（日志卷以只读方式挂载，不能存放断点）
	acEventStore := accesscontrolevents.NewStore(db)
	acTempBlocks := temporaryblocks.NewStore(db, cacheClient)
	acRules := accessrules.NewStore(db)
	acCollector := accesscontrolevents.NewCollector(acEventStore, "ac-collector-01",
		cfg.WAF.GuardEventsLog, filepath.Join(cfg.Gateway.DataDir, "guard-events.checkpoint"), cfg.WAF.GatewayNodeName)
	acCollector.SetBlockUpserter(acTempBlocks)
	acCollector.SetHitRecorder(acRules)
	acCollector.SetSyslogForwarder(syslogFw)
	go acCollector.Run(collectorCtx, 2*time.Second)

	// 阶段5：到期自动失效调度（临时规则/临时封禁/临时例外标记 EXPIRED + 系统审计）
	auditSvcForJanitor := audits.NewService(db)
	exceptionStoreForJanitor := exceptions.NewStore(db)
	go guardjanitor.RunFull(collectorCtx, time.Minute, acRules, acTempBlocks, exceptionStoreForJanitor, auditSvcForJanitor, acEventStore)

	// 阶段6：访问日志采集器与数据聚合任务
	aggStore := aggregations.NewStore(db)
	accessCollector := aggregations.NewAccessLogCollector(aggStore,
		cfg.WAF.AccessLogPath, filepath.Join(cfg.Gateway.DataDir, "access-log.checkpoint"))
	go accessCollector.Run(collectorCtx, 2*time.Second)
	aggJobs := aggregations.NewJobs(aggStore)
	go aggJobs.Run(collectorCtx)

	// 全量访问日志（二期）：JSON Lines 采集器 + 留存清理（开关默认关闭，无日志文件时采集器空转）
	accessFullCollector := accesslogs.NewCollector(db, "accesslog-01", cfg.WAF.AccessFullLog)
	accessFullCollector.SetSyslogForwarder(syslogFw)
	go accessFullCollector.Run(collectorCtx, 2*time.Second)
	go accesslogs.NewRetentionCleaner(db, settings.NewService(db)).Run(collectorCtx, 10*time.Minute)

	// 阶段8 / WDSP：API 运行时事件采集器（仅 WDSP 且开关开启时启动；
	// checkpoint 落在可写数据目录，日志卷只读挂载）
	if cfg.Product.APIDynamicProtectionEnabled() {
		apiRuntimeStore := apiruntime.NewStore(db)
		apiAssetStore := apiassets.NewStore(db)
		apiCollector := apiruntime.NewCollector(apiRuntimeStore, "api-collector-01",
			cfg.WAF.APIEventsLog, filepath.Join(cfg.Gateway.DataDir, "api-runtime-events.checkpoint"), cfg.WAF.GatewayNodeName)
		apiCollector.SetDiscoveryUpserter(apiAssetStore)
		// 端点归属解析：app_code → application_id，host → domain_id
		apiCollector.SetResolver(apiruntime.NewAppResolver(applications.NewStore(db)))
		go apiCollector.Run(collectorCtx, 2*time.Second)
	}

	// 阶段6：报告/备份/健康采集/告警评估后台工人
	application.StartStage6Workers(collectorCtx)

	srv := &http.Server{
		Addr:         cfg.HTTP.HTTPAddr(),
		Handler:      application.Handler,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("jiuzhang api server started", "addr", cfg.HTTP.HTTPAddr(), "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigCh:
		slog.Info("shutting down", "signal", sig.String())
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func runMigrate(ctx context.Context, cfg *config.Config, args []string) error {
	direction := "up"
	if len(args) > 0 {
		direction = args[0]
	}
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		return err
	}
	defer db.Close()
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	return database.Migrate(ctx, db, migrationsDir, direction)
}

// ensureInitialAdmin 首次启动时创建初始管理员。
// 密码优先级：环境变量注入 > 生成一次性随机密码（仅打印一次到 stdout）。
// 临时密码必须首次登录修改，不写入任何日志文件。
func ensureInitialAdmin(ctx context.Context, db *pgxpool.Pool, cfg *config.Config) error {
	store := users.NewStore(db)
	has, err := store.HasUsers(ctx)
	if err != nil {
		return err
	}
	if has {
		return nil
	}

	username := cfg.Security.InitialAdminUsername
	password := cfg.Security.InitialAdminPassword
	generated := false
	if password == "" {
		password, err = security.GenerateTemporaryPassword(16)
		if err != nil {
			return err
		}
		generated = true
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now()
	user := &users.User{
		Username:           username,
		DisplayName:        "系统管理员",
		PasswordHash:       hash,
		Status:             users.StatusActive,
		MustChangePassword: true,
		PasswordChangedAt:  &now,
	}
	if err := store.Create(ctx, user); err != nil {
		return err
	}
	roleID, err := store.GetRoleIDByCode(ctx, "SYSTEM_ADMIN")
	if err != nil {
		return err
	}
	if err := store.AssignRole(ctx, user.ID, roleID, user.ID); err != nil {
		return err
	}

	if generated {
		// 仅打印一次到 stdout，不写入日志文件，首次登录必须修改
		fmt.Fprintf(os.Stdout, "\n")
		fmt.Fprintf(os.Stdout, "╔══════════════════════════════════════════════════════════════╗\n")
		fmt.Fprintf(os.Stdout, "║  九章WAF 初始管理员已创建（仅此一次显示，请立即记录）          ║\n")
		fmt.Fprintf(os.Stdout, "╠══════════════════════════════════════════════════════════════╣\n")
		fmt.Fprintf(os.Stdout, "║  用户名: %-51s ║\n", username)
		fmt.Fprintf(os.Stdout, "║  临时密码: %-49s ║\n", password)
		fmt.Fprintf(os.Stdout, "║  首次登录必须修改密码                                          ║\n")
		fmt.Fprintf(os.Stdout, "╚══════════════════════════════════════════════════════════════╝\n\n")
	} else {
		slog.Info("initial admin created from environment variable", "username", username)
	}
	return nil
}
