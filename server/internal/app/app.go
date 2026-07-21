// Package app 装配管理后端应用（依赖注入与路由注册）。
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/auth"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/roles"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/upstreams"
	"github.com/jiuzhang-waf/server/internal/users"
)

// App 是管理后端应用。
type App struct {
	cfg      *config.Config
	db       *pgxpool.Pool
	cache    *cache.Client
	Handler  http.Handler
	users    *users.Store
	sessions *sessions.Service
	settings *settings.Service
	authSvc  *auth.Service
}

// New 装配应用。
func New(cfg *config.Config, db *pgxpool.Pool, c *cache.Client) *App {
	// 仓储与服务
	userStore := users.NewStore(db)
	sessSvc := sessions.NewService(c, db)
	settingsSvc := settings.NewService(db)
	logSvc := loginlogs.NewService(db)
	auditSvc := audits.NewService(db)
	captchaSvc := security.NewCaptchaService(c)
	authSvc := auth.NewService(userStore, sessSvc, settingsSvc, logSvc, auditSvc, captchaSvc, c)

	// 阶段3：加密服务（主密钥）
	encSvc, err := initEncryption(cfg)
	if err != nil {
		slog.Warn("encryption service not configured, certificate features disabled", "error", err)
	}

	// 阶段3：应用/证书/网关服务
	var appStore *applications.Store
	var certStore *certificates.Store
	var publisher *gatewayconfig.Publisher
	var appHandler *applications.Handler
	var certHandler *certificates.Handler
	var upstreamTestHandler *upstreams.TestHandler
	var gatewayHandler *gatewayconfig.Handler
	if encSvc != nil {
		appStore = applications.NewStore(db)
		certStore = certificates.NewStore(db, encSvc)
		publisher = gatewayconfig.NewPublisher(db, c, appStore, certStore,
			cfg.Gateway.AdminSocket, cfg.Gateway.DataDir)
		appHandler = applications.NewHandler(appStore, auditSvc, certStore)
		certHandler = certificates.NewHandler(certStore, auditSvc)
		upstreamTestHandler = upstreams.NewTestHandler(auditSvc)
		gatewayHandler = gatewayconfig.NewHandler(publisher, appStore, auditSvc)
	}

	// 处理器
	authHandler := auth.NewHandler(authSvc, sessSvc, userStore, captchaSvc, cfg.Security.CookieSecure)
	userHandler := users.NewHandler(userStore, sessSvc, settingsSvc, auditSvc)
	roleHandler := roles.NewHandler(db)
	logHandler := loginlogs.NewHandler(logSvc)
	auditHandler := audits.NewHandler(auditSvc)
	settingHandler := settings.NewHandler(settingsSvc, auditSvc)
	profileHandler := users.NewProfileHandler(userStore, logSvc)

	a := &App{
		cfg: cfg, db: db, cache: c,
		users: userStore, sessions: sessSvc, settings: settingsSvc, authSvc: authSvc,
	}

	// 路由
	mux := http.NewServeMux()

	// 限速器（登录/验证码限速动态读取系统设置，支持配置热更新；其余为固定值）
	rl := middleware.NewRateLimiter(c)
	dynamicLoginRate := func(ctx context.Context) int {
		return settingsSvc.LoginPolicy(ctx).RateLimitPerMinute
	}
	loginRate := rl.LimitDynamic("login", dynamicLoginRate, time.Minute, middleware.IPKey)
	captchaRate := rl.LimitDynamic("captcha", dynamicLoginRate, time.Minute, middleware.IPKey)
	sensitiveRate := rl.Limit("sensitive", 10, time.Minute, middleware.IPKey)
	exportRate := rl.Limit("export", 5, time.Minute, middleware.IPKey)

	// ---- 公开接口（无需认证） ----
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.Handle("GET /api/v1/auth/captcha", captchaRate(http.HandlerFunc(authHandler.Captcha)))
	mux.Handle("POST /api/v1/auth/login", loginRate(http.HandlerFunc(authHandler.Login)))

	// ---- 认证接口 ----
	authz := a.authChain()
	mux.Handle("POST /api/v1/auth/logout", authz(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("GET /api/v1/auth/me", authz(http.HandlerFunc(authHandler.Me)))
	mux.Handle("POST /api/v1/auth/change-password", authz(sensitiveRate(http.HandlerFunc(authHandler.ChangePassword))))
	mux.Handle("GET /api/v1/auth/sessions", authz(http.HandlerFunc(authHandler.Sessions)))
	mux.Handle("DELETE /api/v1/auth/sessions/{id}", authz(http.HandlerFunc(authHandler.RevokeSession)))

	// ---- 个人中心 ----
	mux.Handle("GET /api/v1/profile", authz(http.HandlerFunc(profileHandler.Get)))
	mux.Handle("PUT /api/v1/profile", authz(http.HandlerFunc(profileHandler.Update)))
	mux.Handle("GET /api/v1/profile/login-logs", authz(http.HandlerFunc(profileHandler.LoginLogs)))

	// ---- 用户管理（系统管理员） ----
	mux.Handle("GET /api/v1/users", authz(middleware.RequirePermission("users.read")(http.HandlerFunc(userHandler.List))))
	mux.Handle("POST /api/v1/users", authz(middleware.RequirePermission("users.create")(http.HandlerFunc(userHandler.Create))))
	mux.Handle("GET /api/v1/users/{id}", authz(middleware.RequirePermission("users.read")(http.HandlerFunc(userHandler.Get))))
	mux.Handle("PUT /api/v1/users/{id}", authz(middleware.RequirePermission("users.update")(http.HandlerFunc(userHandler.Update))))
	mux.Handle("DELETE /api/v1/users/{id}", authz(middleware.RequirePermission("users.update")(http.HandlerFunc(userHandler.Delete))))
	mux.Handle("POST /api/v1/users/{id}/enable", authz(middleware.RequirePermission("users.disable")(http.HandlerFunc(userHandler.Enable))))
	mux.Handle("POST /api/v1/users/{id}/disable", authz(middleware.RequirePermission("users.disable")(http.HandlerFunc(userHandler.Disable))))
	mux.Handle("POST /api/v1/users/{id}/unlock", authz(middleware.RequirePermission("users.unlock")(http.HandlerFunc(userHandler.Unlock))))
	mux.Handle("POST /api/v1/users/{id}/reset-password", authz(middleware.RequirePermission("users.reset_password")(sensitiveRate(http.HandlerFunc(userHandler.ResetPassword)))))
	mux.Handle("DELETE /api/v1/users/{id}/sessions", authz(middleware.RequirePermission("users.force_logout")(http.HandlerFunc(userHandler.ForceLogout))))

	// ---- 角色权限查询 ----
	mux.Handle("GET /api/v1/roles", authz(middleware.RequirePermission("roles.read")(http.HandlerFunc(roleHandler.ListRoles))))
	mux.Handle("GET /api/v1/roles/{id}", authz(middleware.RequirePermission("roles.read")(http.HandlerFunc(roleHandler.GetRole))))
	mux.Handle("GET /api/v1/roles/{id}/permissions", authz(middleware.RequirePermission("roles.read")(http.HandlerFunc(roleHandler.RolePermissions))))
	mux.Handle("GET /api/v1/permissions", authz(middleware.RequirePermission("permissions.read")(http.HandlerFunc(roleHandler.ListPermissions))))

	// ---- 登录日志 ----
	mux.Handle("GET /api/v1/login-logs", authz(http.HandlerFunc(logHandler.List)))
	mux.Handle("GET /api/v1/login-logs/export", authz(middleware.RequirePermission("login_logs.export")(exportRate(http.HandlerFunc(logHandler.Export)))))

	// ---- 操作审计 ----
	mux.Handle("GET /api/v1/audits", authz(middleware.RequirePermission("audits.read")(http.HandlerFunc(auditHandler.List))))
	mux.Handle("GET /api/v1/audits/{id}", authz(middleware.RequirePermission("audits.read")(http.HandlerFunc(auditHandler.Get))))
	mux.Handle("GET /api/v1/audits/export", authz(middleware.RequirePermission("audits.export")(exportRate(http.HandlerFunc(auditHandler.Export)))))
	mux.Handle("POST /api/v1/audits/verify-chain", authz(middleware.RequirePermission("audits.read")(http.HandlerFunc(auditHandler.VerifyChain))))

	// ---- 系统设置 ----
	mux.Handle("GET /api/v1/system-settings", authz(middleware.RequirePermission("system_settings.read")(http.HandlerFunc(settingHandler.List))))
	mux.Handle("PUT /api/v1/system-settings", authz(middleware.RequirePermission("system_settings.update")(http.HandlerFunc(settingHandler.Update))))

	// ---- 阶段3：Web应用/域名/源站/证书/配置发布/版本/网关状态 ----
	if encSvc != nil {
		// Web应用
		mux.Handle("GET /api/v1/applications", authz(middleware.RequirePermission("applications.read")(http.HandlerFunc(appHandler.List))))
		mux.Handle("POST /api/v1/applications", authz(middleware.RequirePermission("applications.create")(http.HandlerFunc(appHandler.Create))))
		mux.Handle("GET /api/v1/applications/{id}", authz(middleware.RequirePermission("applications.read")(http.HandlerFunc(appHandler.Get))))
		mux.Handle("PUT /api/v1/applications/{id}", authz(middleware.RequirePermission("applications.update")(http.HandlerFunc(appHandler.Update))))
		mux.Handle("DELETE /api/v1/applications/{id}", authz(middleware.RequirePermission("applications.delete")(http.HandlerFunc(appHandler.Delete))))
		mux.Handle("POST /api/v1/applications/{id}/enable", authz(middleware.RequirePermission("applications.disable")(http.HandlerFunc(appHandler.Enable))))
		mux.Handle("POST /api/v1/applications/{id}/disable", authz(middleware.RequirePermission("applications.disable")(http.HandlerFunc(appHandler.Disable))))
		mux.Handle("POST /api/v1/applications/{id}/copy", authz(middleware.RequirePermission("applications.create")(http.HandlerFunc(appHandler.Copy))))
		mux.Handle("POST /api/v1/applications/{id}/certificate", authz(middleware.RequirePermission("certificates.bind")(http.HandlerFunc(appHandler.BindCertificate))))
		mux.Handle("DELETE /api/v1/applications/{id}/certificate", authz(middleware.RequirePermission("certificates.bind")(http.HandlerFunc(appHandler.UnbindCertificate))))

		// 域名
		mux.Handle("GET /api/v1/applications/{id}/domains", authz(middleware.RequirePermission("domains.read")(http.HandlerFunc(appHandler.ListDomains))))
		mux.Handle("POST /api/v1/applications/{id}/domains", authz(middleware.RequirePermission("domains.create")(http.HandlerFunc(appHandler.AddDomain))))
		mux.Handle("PUT /api/v1/applications/{id}/domains/{domain_id}", authz(middleware.RequirePermission("domains.update")(http.HandlerFunc(appHandler.UpdateDomain))))
		mux.Handle("DELETE /api/v1/applications/{id}/domains/{domain_id}", authz(middleware.RequirePermission("domains.delete")(http.HandlerFunc(appHandler.DeleteDomain))))

		// 源站
		mux.Handle("GET /api/v1/applications/{id}/upstreams", authz(middleware.RequirePermission("upstreams.read")(http.HandlerFunc(appHandler.ListUpstreams))))
		mux.Handle("POST /api/v1/applications/{id}/upstreams", authz(middleware.RequirePermission("upstreams.create")(http.HandlerFunc(appHandler.AddUpstream))))
		mux.Handle("PUT /api/v1/upstreams/{id}", authz(middleware.RequirePermission("upstreams.update")(http.HandlerFunc(appHandler.UpdateUpstream))))
		mux.Handle("DELETE /api/v1/upstreams/{id}", authz(middleware.RequirePermission("upstreams.delete")(http.HandlerFunc(appHandler.DeleteUpstream))))
		mux.Handle("POST /api/v1/upstreams/{id}/enable", authz(middleware.RequirePermission("upstreams.update")(http.HandlerFunc(appHandler.EnableUpstream))))
		mux.Handle("POST /api/v1/upstreams/{id}/disable", authz(middleware.RequirePermission("upstreams.update")(http.HandlerFunc(appHandler.DisableUpstream))))
		mux.Handle("POST /api/v1/upstreams/test", authz(middleware.RequirePermission("upstreams.test")(http.HandlerFunc(upstreamTestHandler.Test))))

		// 证书
		mux.Handle("GET /api/v1/certificates", authz(middleware.RequirePermission("certificates.read")(http.HandlerFunc(certHandler.List))))
		mux.Handle("POST /api/v1/certificates", authz(middleware.RequirePermission("certificates.create")(http.HandlerFunc(certHandler.Upload))))
		mux.Handle("GET /api/v1/certificates/{id}", authz(middleware.RequirePermission("certificates.read")(http.HandlerFunc(certHandler.Get))))
		mux.Handle("DELETE /api/v1/certificates/{id}", authz(middleware.RequirePermission("certificates.delete")(http.HandlerFunc(certHandler.Delete))))
		mux.Handle("GET /api/v1/certificates/{id}/applications", authz(middleware.RequirePermission("certificates.read")(http.HandlerFunc(certHandler.ListApplications))))

		// 配置发布/版本/网关状态
		mux.Handle("POST /api/v1/gateway-config/preview", authz(middleware.RequirePermission("gateway_configs.preview")(http.HandlerFunc(gatewayHandler.Preview))))
		mux.Handle("POST /api/v1/gateway-config/validate", authz(middleware.RequirePermission("gateway_configs.validate")(http.HandlerFunc(gatewayHandler.Validate))))
		mux.Handle("POST /api/v1/gateway-config/publish", authz(middleware.RequirePermission("gateway_configs.publish")(http.HandlerFunc(gatewayHandler.Publish))))
		mux.Handle("GET /api/v1/gateway-config/current", authz(middleware.RequirePermission("config_versions.read")(http.HandlerFunc(gatewayHandler.CurrentConfig))))
		mux.Handle("GET /api/v1/publish-tasks", authz(middleware.RequirePermission("publish_tasks.read")(http.HandlerFunc(gatewayHandler.ListTasks))))
		mux.Handle("GET /api/v1/publish-tasks/{id}", authz(middleware.RequirePermission("publish_tasks.read")(http.HandlerFunc(gatewayHandler.GetTask))))
		mux.Handle("GET /api/v1/config-versions", authz(middleware.RequirePermission("config_versions.read")(http.HandlerFunc(gatewayHandler.ListVersions))))
		mux.Handle("GET /api/v1/config-versions/{id}", authz(middleware.RequirePermission("config_versions.read")(http.HandlerFunc(gatewayHandler.GetVersion))))
		mux.Handle("GET /api/v1/config-versions/{id}/diff", authz(middleware.RequirePermission("config_versions.read")(http.HandlerFunc(gatewayHandler.GetVersionDiff))))
		mux.Handle("POST /api/v1/config-versions/{id}/rollback", authz(middleware.RequirePermission("gateway_configs.rollback")(http.HandlerFunc(gatewayHandler.Rollback))))
		mux.Handle("GET /api/v1/gateway/status", authz(middleware.RequirePermission("gateway_status.read")(http.HandlerFunc(gatewayHandler.GatewayStatus))))
	}

	// 全局中间件链
	var handler http.Handler = mux
	handler = middleware.RecoverPanic(handler)
	handler = middleware.AccessLog(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.CORS(cfg.Security.CORSAllowedOrigins)(handler)
	handler = middleware.RequestID(handler)

	a.Handler = handler
	return a
}

// authChain 构造认证链：会话解析 → 认证检查 → CSRF 防护。
func (a *App) authChain() func(http.Handler) http.Handler {
	// 豁免路径（must_change_password 时也可访问）
	exempt := []string{
		"POST /api/v1/auth/change-password",
		"POST /api/v1/auth/logout",
		"GET /api/v1/auth/me",
	}
	return func(next http.Handler) http.Handler {
		// 包装顺序（从外到内执行）：
		// sessionMiddleware(注入Principal) → CSRFProtect → RequireAuth → next
		h := middleware.RequireAuth(exempt...)(next)
		h = middleware.CSRFProtect(a.csrfValidator)(h)
		h = a.sessionMiddleware(h)
		return h
	}
}

// sessionMiddleware 从 Cookie 解析会话并注入 Principal。
func (a *App) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.SessionCookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		policy := a.authSvc.SessionPolicy(r.Context())
		sess, err := a.sessions.Get(r.Context(), cookie.Value, policy)
		if err != nil {
			slog.Warn("session resolve failed", "error", err, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		perms := make(map[string]bool, len(sess.Permissions))
		for _, p := range sess.Permissions {
			perms[p] = true
		}
		p := &authz.Principal{
			UserID:        sess.UserID,
			Username:      sess.Username,
			Roles:         sess.Roles,
			Permissions:   sess.Permissions,
			SessionID:     sess.ID,
			SourceIP:      sess.SourceIP,
			UserAgent:     sess.UserAgent,
			MustChangePwd: sess.MustChangePwd,
			PermsSet:      perms,
		}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

// csrfValidator 校验 CSRF Token。
func (a *App) csrfValidator(r *http.Request, token string) bool {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		return false
	}
	return a.authSvc.ValidateCSRFToken(r.Context(), p.SessionID, token)
}

// health 健康检查（含依赖状态）。
func (a *App) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	dbOK := a.db.Ping(ctx) == nil
	cacheOK := a.cache.Redis().Ping(ctx).Err() == nil
	status := "ok"
	if !dbOK || !cacheOK {
		status = "degraded"
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"%s","postgres":%t,"valkey":%t}`, status, dbOK, cacheOK)
}

// initEncryption 初始化加密服务（主密钥）。
// 开发环境未配置时生成临时密钥并打印警告（不持久化，重启后旧密文无法解密）；
// 生产环境必须配置 JIUZHANG_MASTER_KEY。
func initEncryption(cfg *config.Config) (*encryption.Service, error) {
	svc, err := encryption.NewFromEnv()
	if err == nil {
		return svc, nil
	}
	if cfg.Env == "prod" {
		return nil, fmt.Errorf("JIUZHANG_MASTER_KEY is required in prod")
	}
	// 开发环境：生成临时主密钥（仅本次进程有效，供开发测试）
	key, genErr := encryption.GenerateKey()
	if genErr != nil {
		return nil, genErr
	}
	slog.Warn("JIUZHANG_MASTER_KEY not set, using a temporary in-memory master key (dev only, encrypted data will not survive restart)")
	return encryption.NewFromString(key)
}

var _ = os.Getenv
