// 九章管理后端 API 服务
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/app"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/securityevents"
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
	application := app.New(cfg, db, cacheClient)

	// 阶段4：启动安全事件采集器（后台 goroutine）
	collectorCtx, collectorCancel := context.WithCancel(context.Background())
	defer collectorCancel()
	eventCollector := securityevents.NewCollector(db, "collector-01", cfg.WAF.AuditLogPath, cfg.WAF.GatewayNodeName)
	go eventCollector.Run(collectorCtx, 2*time.Second)

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
