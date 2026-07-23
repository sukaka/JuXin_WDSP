// Package app 装配管理后端应用（依赖注入与路由注册）。
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/aiagents"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aicost"
	"github.com/jiuzhang-waf/server/internal/aihandlers"
	"github.com/jiuzhang-waf/server/internal/aimemory"
	"github.com/jiuzhang-waf/server/internal/aimodel"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aiprompts"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/analytics"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/auth"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/customrules"
	"github.com/jiuzhang-waf/server/internal/dashboards"
	"github.com/jiuzhang-waf/server/internal/delivery"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/protectionpolicies"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/reports"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/restores"
	"github.com/jiuzhang-waf/server/internal/roles"
	"github.com/jiuzhang-waf/server/internal/ruleoverrides"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/securityevents"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
	"github.com/jiuzhang-waf/server/internal/upgrades"
	"github.com/jiuzhang-waf/server/internal/upstreams"
	"github.com/jiuzhang-waf/server/internal/users"
	"github.com/jiuzhang-waf/server/internal/wafrules"
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
	// 阶段6后台工人（由 StartStage6Workers 启动）
	alertEngine     *systemalerts.Engine
	reportWorker    *reports.Handler
	backupWorker    *backups.Worker
	healthCollector *runtimehealth.Collector
}

// New 装配应用。
func New(cfg *config.Config, db *pgxpool.Pool, c *cache.Client) (*App, error) {
	// 加密能力是生产环境的启动前置条件，必须在装配其他依赖前校验。
	encSvc, err := initEncryption(cfg)
	if err != nil {
		return nil, fmt.Errorf("initialize encryption service: %w", err)
	}
	clientIPMiddleware, err := middleware.ClientIP(cfg.Security.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("initialize trusted proxies: %w", err)
	}

	// 仓储与服务
	userStore := users.NewStore(db)
	sessSvc := sessions.NewService(c, db)
	settingsSvc := settings.NewService(db)
	logSvc := loginlogs.NewService(db)
	auditSvc := audits.NewService(db)
	captchaSvc := security.NewCaptchaService(c)
	authSvc := auth.NewService(userStore, sessSvc, settingsSvc, logSvc, auditSvc, captchaSvc, c)

	// 阶段3+阶段4：应用/证书/网关/策略服务
	var appStore *applications.Store
	var certStore *certificates.Store
	var publisher *gatewayconfig.Publisher
	var appHandler *applications.Handler
	var certHandler *certificates.Handler
	var upstreamTestHandler *upstreams.TestHandler
	var gatewayHandler *gatewayconfig.Handler
	policyStore := protectionpolicies.NewStore(db)
	exceptionStore := exceptions.NewStore(db)
	if encSvc != nil {
		appStore = applications.NewStore(db)
		certStore = certificates.NewStore(db, encSvc)
		publisher = gatewayconfig.NewPublisher(db, c, appStore, certStore,
			cfg.Gateway.AdminSocket, cfg.Gateway.DataDir, policyStore, exceptionStore)
		appHandler = applications.NewHandler(appStore, auditSvc, certStore)
		certHandler = certificates.NewHandler(certStore, auditSvc)
		certHandler.SetDomainLister(appStore)
		upstreamTestHandler = upstreams.NewTestHandler(auditSvc)
		gatewayHandler = gatewayconfig.NewHandler(publisher, appStore, auditSvc)
	}

	// 阶段4：WAF策略/规则/例外/事件服务
	ruleHandler := wafrules.NewHandler(db, auditSvc, cfg.WAF.CRSDir, cfg.WAF.CRSVersion)
	customRuleStore := customrules.NewStore(db)
	ruleOverrideStore := ruleoverrides.NewStore(db)
	policyHandler := protectionpolicies.NewHandler(policyStore, auditSvc)
	customRuleHandler := customrules.NewHandler(customRuleStore, auditSvc)
	ruleOverrideHandler := ruleoverrides.NewHandler(ruleOverrideStore, auditSvc)
	exceptionHandler := exceptions.NewHandler(exceptionStore, auditSvc)
	eventStore := securityevents.NewStore(db)
	eventExceptionAdapter := &eventExceptionCreator{store: exceptionStore}
	eventHandler := securityevents.NewHandler(eventStore, auditSvc, eventExceptionAdapter)

	// 阶段5：访问控制与CC防护服务
	proxyStore := trustedproxies.NewStore(db)
	protectedStore := protectedaddresses.NewStore(db)
	accessRuleStore := accessrules.NewStore(db)
	rateLimitStore := ratelimitpolicies.NewStore(db)
	tempBlockStore := temporaryblocks.NewStore(db, c)
	tempBlockStore.SetPermanentRuleCreator(accessRuleStore)
	acEventStore := accesscontrolevents.NewStore(db)
	acVersionStore := accesscontrolversions.NewStore(db)

	proxyHandler := trustedproxies.NewHandler(proxyStore, auditSvc)
	protectedHandler := protectedaddresses.NewHandler(protectedStore, auditSvc)
	accessRuleHandler := accessrules.NewHandler(accessRuleStore, auditSvc, protectedStore)
	rateLimitHandler := ratelimitpolicies.NewHandler(rateLimitStore, auditSvc)
	tempBlockHandler := temporaryblocks.NewHandler(tempBlockStore, auditSvc)
	tempBlockHandler.SetReleaseEventEmitter(func(ctx context.Context, b *temporaryblocks.Block) {
		if b == nil {
			return
		}
		now := time.Now().UTC()
		ev := accesscontrolevents.Event{
			OccurredAt:     now,
			ApplicationID:  b.ApplicationID,
			ClientIP:       b.ClientIP,
			EventType:      accesscontrolevents.EventTypeCCTempBlockReleased,
			Action:         accesscontrolevents.ActionTempBlock,
			AccessRuleID:   b.ID.String(),
			BlockExpiresAt: &b.BlockExpiresAt,
			Message:        "临时封禁人工解封",
			GatewayNodeID:  "management-api",
		}
		if _, err := acEventStore.Insert(ctx, []accesscontrolevents.Event{ev}); err != nil {
			slog.Warn("write CC_TEMP_BLOCK_RELEASED event failed", "error", err, "block_id", b.ID)
		}
	})
	acEventHandler := accesscontrolevents.NewHandler(acEventStore, auditSvc)
	acVersionHandler := accesscontrolversions.NewHandler(acVersionStore, auditSvc, nil)

	// 阶段5：guard 配置组装与发布/回滚集成
	if publisher != nil {
		guardProvider := guardconfig.NewProvider(proxyStore, protectedStore, accessRuleStore, rateLimitStore, acVersionStore,
			guardconfig.Config{
				ValkeyAddress:  fmt.Sprintf("%s:%d", cfg.Cache.Host, cfg.Cache.Port),
				ValkeyPassword: cfg.Cache.Password,
				ValkeyDB:       cfg.Cache.DB,
				EventsLog:      cfg.WAF.GuardEventsLogGateway,
				GatewayNode:    cfg.WAF.GatewayNodeName,
				FailOpen:       cfg.WAF.GuardFailOpen,
			})
		publisher.SetGuardProvider(guardProvider)
		publisher.SetCustomRulesProvider(customRuleStore)
		publisher.SetRuleOverridesProvider(ruleOverrideStore)
		acVersionHandler.SetRollbackFunc(func(ctx context.Context, versionID uuid.UUID, requestedBy uuid.UUID, requestID string) (interface{}, error) {
			return publisher.RollbackAccessControl(ctx, versionID, requestedBy, requestID)
		})
	}

	// 阶段6：指标聚合/态势/统计/报告/监控/告警/备份恢复/升级/交付检查
	aggStore := aggregations.NewStore(db)
	dashboardHandler := dashboards.NewHandler(aggStore, db)
	analyticsHandler := analytics.NewHandler(aggStore, db)
	reportStore := reports.NewStore(db)
	if err := reportStore.EnsureBuiltinTemplate(context.Background()); err != nil {
		slog.Warn("ensure builtin report template failed", "error", err)
	}
	reportHandler := reports.NewHandler(reportStore, db, aggStore, auditSvc, cfg.Gateway.DataDir)
	healthStore := runtimehealth.NewStore(db)
	storageProbe := runtimehealth.NewStorageProbe(db, c, "/app",
		filepath.Join(cfg.Gateway.DataDir, "reports"), filepath.Join(cfg.Gateway.DataDir, "backups"))
	healthHandler := runtimehealth.NewHandler(healthStore, storageProbe)
	alertStore := systemalerts.NewStore(db)
	alertEngine := systemalerts.NewEngine(alertStore, systemalerts.EngineOptions{})
	alertHandler := systemalerts.NewHandler(alertStore, auditSvc)
	alertFn := backups.AlertFunc(func(alertType, component, title, message string) {
		// 归一化非标准类型（引擎仅接受规则矩阵内的类型）
		if alertType == "RESTORE_FAILED" {
			alertType = "RESTORE_VALIDATION_FAILED"
		}
		if _, err := alertEngine.NotifyFailure(context.Background(), alertType, component, title, message); err != nil {
			slog.Warn("raise alert failed", "type", alertType, "error", err)
		}
	})
	var backupStore *backups.Store
	var backupWorker *backups.Worker
	var restoreSvc *restores.Service
	var backupHandler *backups.Handler
	var restoreHandler *restores.Handler
	var upgradeSvc *upgrades.Service
	if encSvc != nil {
		backupStore = backups.NewStore(db)
		backupExporter := backups.NewExporter(db, encSvc, cfg.Gateway.DataDir)
		backupWorker = backups.NewWorker(backupStore, backupExporter, alertFn)
		backupHandler = backups.NewHandler(backupStore, backupWorker, cfg.Gateway.DataDir, auditSvc)
		restoreSvc = restores.NewService(db, restores.NewStore(db), backupStore, backupExporter, cfg.Gateway.DataDir, c, alertFn)
		restoreHandler = restores.NewHandler(restores.NewStore(db), restoreSvc, auditSvc)
	} else {
		slog.Warn("encryption unavailable, backup/restore/upgrade features disabled")
	}
	upgradeStore := upgrades.NewStore(db)
	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	prechecker := upgrades.NewPrechecker(db, func(ctx context.Context) error {
		return c.Redis().Ping(ctx).Err()
	}, cfg.Gateway.DataDir, migrationsDir)
	if restoreSvc != nil {
		upgradeSvc = upgrades.NewService(db, upgradeStore, backupStore, restoreSvc, prechecker, migrationsDir, alertFn)
	}
	upgradeHandler := upgrades.NewHandler(upgradeStore, upgradeSvc, auditSvc)
	deliveryStore := delivery.NewStore(db)
	deliverySvc := delivery.NewService(deliveryStore, &delivery.RunContext{
		DB: db, Health: healthStore, Audits: auditSvc, Settings: settingsSvc, Cfg: cfg,
		DataDir:  cfg.Gateway.DataDir,
		RepoRoot: "/app",
		CachePing: func(ctx context.Context) error {
			return c.Redis().Ping(ctx).Err()
		},
	})
	deliveryHandler := delivery.NewHandler(deliveryStore, deliverySvc, auditSvc)

	// 阶段7：AI 安全运营（模型网关/编排器/Tool注册中心/会话/成本/记忆/Prompt/审计）
	// 加密服务不可用时仅密钥相关操作降级（本地无密钥模型不受影响），AI 模块整体仍可启动。
	aiAuditSvc := aiaudit.NewService(db)
	aiCostRec := aicost.NewRecorder(db, aicost.DefaultQuotas())
	aiMemoryStore := aimemory.NewStore(db)
	aiPromptStore := aiprompts.NewStore(db)
	aiSessionStore := aiorchestrator.NewSessionStore(db)
	aiModelStore := aimodel.NewStore(db, encSvc)
	// 模型网关：KeyResolver 由 aimodel.Store 实现（密钥解密不出服务端）
	aiGateway := aimodel.NewGateway(aiModelStore)
	// Tool 注册中心：查询类 + 草稿类 Tool（草稿复用阶段4例外仓储与阶段5保护地址检查）
	aiRegistry := aitools.NewRegistry()
	aitools.NewEventTools(aiRegistry, db)
	aitools.NewLogTools(aiRegistry, db)
	aitools.NewAssetTools(aiRegistry, db)
	aitools.NewAccessTools(aiRegistry, db)
	aitools.NewDraftTools(aiRegistry, db, exceptionStore, protectedStore)
	// Tool 执行强制尊重 ai_tools 表启停状态
	aiRegistry.SetEnabledChecker(aihandlers.ToolEnabledChecker(db))
	// 编排器：注册 7 个专业 Agent（总调度由编排器内置承担）
	aiOrch := aiorchestrator.New(db, aiGateway, aiRegistry, aiAuditSvc, aiSessionStore, aiCostRec, aiorchestrator.DefaultLimits())
	agentCodes := map[string]bool{}
	for _, ag := range []aiorchestrator.Agent{
		aiagents.NewSecurityEventAgent(db),
		aiagents.NewLogAnalysisAgent(db),
		aiagents.NewWafPolicyAgent(db),
		aiagents.NewAssetAgent(db),
		aiagents.NewOpsDiagnosticAgent(db),
		aiagents.NewReportAgent(db),
		aiagents.NewKnowledgeAgent(db),
	} {
		aiOrch.RegisterAgent(ag)
		agentCodes[ag.Code()] = true
	}
	// Agent 调度强制尊重 ai_agents 表启停状态
	aiOrch.SetAgentEnabledChecker(aihandlers.AgentEnabledChecker(db))
	// 用户背景记忆注入回答上下文（仅 ACTIVE 的长期/项目记忆，上限 5 条；注入内容为数据非指令）
	aiOrch.SetMemoryLoader(func(ctx context.Context, userID uuid.UUID) []string {
		mems, err := aiMemoryStore.LoadForContext(ctx, userID, "", 5)
		if err != nil {
			slog.Warn("load ai memories for context failed", "error", err)
			return nil
		}
		out := make([]string, 0, len(mems))
		for _, m := range mems {
			out = append(out, m.Content)
		}
		return out
	})
	// 启动同步：代码 registry 中的 Agent/Tool upsert 到 ai_agents/ai_tools（code 唯一，保留启停状态）
	if err := aihandlers.SyncRegistry(context.Background(), db, aiRegistry); err != nil {
		slog.Warn("sync ai agent/tool registry failed", "error", err)
	}
	aiDeps := aihandlers.NewDeps(aihandlers.Deps{
		DB: db, Orch: aiOrch, Sessions: aiSessionStore, Gateway: aiGateway, Models: aiModelStore,
		Tools: aiRegistry, Drafts: aitools.NewDraftStore(db), Audit: aiAuditSvc, Cost: aiCostRec,
		Memories: aiMemoryStore, Prompts: aiPromptStore, Settings: settingsSvc, AgentCodes: agentCodes,
	})
	// 启动时加载模型路由档位（配置缺失回退默认本地模型，加载失败不致命）
	if err := aiDeps.ReloadRoutes(context.Background()); err != nil {
		slog.Warn("load ai model routes failed, AI calls will degrade", "error", err)
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
	a.alertEngine = alertEngine
	a.reportWorker = reportHandler
	a.backupWorker = backupWorker
	a.healthCollector = runtimehealth.NewCollector(db, runtimehealth.Options{
		Caddy:                 gatewayconfig.NewCaddyClient(cfg.Gateway.AdminSocket),
		Cache:                 c,
		GuardEventsLog:        cfg.WAF.GuardEventsLog,
		SecurityCollectorID:   "collector-01",
		GuardEventsCheckpoint: filepath.Join(cfg.Gateway.DataDir, "guard-events.checkpoint"),
		AccessLogCheckpoint:   filepath.Join(cfg.Gateway.DataDir, "access-log.checkpoint"),
		AccessLogPath:         cfg.WAF.AccessLogPath,
	})

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
		// 证书绑定/解绑独立接口（阶段3遗留补齐）
		mux.Handle("POST /api/v1/certificates/{id}/bind", authz(middleware.RequirePermission("certificates.bind")(http.HandlerFunc(certHandler.Bind))))
		mux.Handle("POST /api/v1/certificates/{id}/unbind", authz(middleware.RequirePermission("certificates.bind")(http.HandlerFunc(certHandler.Unbind))))

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

	// ---- 阶段4：防护策略/规则/自定义规则/例外/安全事件 ----
	// 防护策略
	mux.Handle("GET /api/v1/protection-policies", authz(middleware.RequirePermission("protection_policies.read")(http.HandlerFunc(policyHandler.List))))
	mux.Handle("POST /api/v1/protection-policies", authz(middleware.RequirePermission("protection_policies.create")(http.HandlerFunc(policyHandler.Create))))
	mux.Handle("GET /api/v1/protection-policies/{id}", authz(middleware.RequirePermission("protection_policies.read")(http.HandlerFunc(policyHandler.Get))))
	mux.Handle("PUT /api/v1/protection-policies/{id}", authz(middleware.RequirePermission("protection_policies.update")(http.HandlerFunc(policyHandler.Update))))
	mux.Handle("DELETE /api/v1/protection-policies/{id}", authz(middleware.RequirePermission("protection_policies.delete")(http.HandlerFunc(policyHandler.Delete))))
	mux.Handle("POST /api/v1/protection-policies/{id}/copy", authz(middleware.RequirePermission("protection_policies.create")(http.HandlerFunc(policyHandler.Copy))))
	mux.Handle("GET /api/v1/protection-policies/{id}/applications", authz(middleware.RequirePermission("protection_policies.read")(http.HandlerFunc(policyHandler.ListApplications))))
	mux.Handle("POST /api/v1/protection-policies/{id}/applications", authz(middleware.RequirePermission("protection_policies.update")(http.HandlerFunc(policyHandler.BindApplication))))
	mux.Handle("DELETE /api/v1/protection-policies/{id}/applications/{app_id}", authz(middleware.RequirePermission("protection_policies.update")(http.HandlerFunc(policyHandler.UnbindApplication))))

	// WAF规则
	mux.Handle("GET /api/v1/waf-rules", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(ruleHandler.List))))
	mux.Handle("GET /api/v1/waf-rules/categories", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(ruleHandler.Categories))))
	mux.Handle("GET /api/v1/waf-rules/versions", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(ruleHandler.Versions))))
	mux.Handle("GET /api/v1/waf-rules/{rule_id}", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(ruleHandler.Get))))
	mux.Handle("POST /api/v1/waf-rules/sync", authz(middleware.RequirePermission("waf_rules.sync")(http.HandlerFunc(ruleHandler.Sync))))

	// 规则覆盖
	mux.Handle("GET /api/v1/rule-overrides", authz(middleware.RequirePermission("rule_overrides.manage")(http.HandlerFunc(ruleOverrideHandler.List))))
	mux.Handle("POST /api/v1/rule-overrides", authz(middleware.RequirePermission("rule_overrides.manage")(http.HandlerFunc(ruleOverrideHandler.Create))))
	mux.Handle("GET /api/v1/rule-overrides/{id}", authz(middleware.RequirePermission("rule_overrides.manage")(http.HandlerFunc(ruleOverrideHandler.Get))))
	mux.Handle("PUT /api/v1/rule-overrides/{id}", authz(middleware.RequirePermission("rule_overrides.manage")(http.HandlerFunc(ruleOverrideHandler.Update))))
	mux.Handle("DELETE /api/v1/rule-overrides/{id}", authz(middleware.RequirePermission("rule_overrides.manage")(http.HandlerFunc(ruleOverrideHandler.Delete))))

	// 自定义规则
	mux.Handle("GET /api/v1/custom-rules", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.List))))
	mux.Handle("POST /api/v1/custom-rules", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Create))))
	mux.Handle("GET /api/v1/custom-rules/{id}", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Get))))
	mux.Handle("PUT /api/v1/custom-rules/{id}", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Update))))
	mux.Handle("DELETE /api/v1/custom-rules/{id}", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Delete))))
	mux.Handle("POST /api/v1/custom-rules/{id}/validate", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Validate))))
	mux.Handle("POST /api/v1/custom-rules/{id}/enable", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Enable))))
	mux.Handle("POST /api/v1/custom-rules/{id}/disable", authz(middleware.RequirePermission("custom_rules.manage")(http.HandlerFunc(customRuleHandler.Disable))))

	// 例外策略
	mux.Handle("GET /api/v1/exceptions", authz(middleware.RequirePermission("exceptions.read")(http.HandlerFunc(exceptionHandler.List))))
	mux.Handle("POST /api/v1/exceptions", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Create))))
	mux.Handle("GET /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.read")(http.HandlerFunc(exceptionHandler.Get))))
	mux.Handle("PUT /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Update))))
	mux.Handle("DELETE /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Delete))))
	mux.Handle("POST /api/v1/exceptions/{id}/enable", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Enable))))
	mux.Handle("POST /api/v1/exceptions/{id}/disable", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Disable))))

	// 安全事件
	mux.Handle("GET /api/v1/security-events", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.List))))
	mux.Handle("GET /api/v1/security-events/export", authz(middleware.RequirePermission("security_events.export")(http.HandlerFunc(eventHandler.Export))))
	mux.Handle("GET /api/v1/security-events/{id}", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.Get))))
	mux.Handle("GET /api/v1/security-events/{id}/related", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.Related))))
	mux.Handle("POST /api/v1/security-events/{id}/notes", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.AddNote))))
	mux.Handle("POST /api/v1/security-events/{id}/confirm-attack", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.ConfirmAttack))))
	mux.Handle("POST /api/v1/security-events/{id}/confirm-false-positive", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.ConfirmFalsePositive))))
	mux.Handle("POST /api/v1/security-events/{id}/ignore", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.Ignore))))
	mux.Handle("POST /api/v1/security-events/{id}/resolve", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.Resolve))))
	mux.Handle("POST /api/v1/security-events/{id}/mark-analyzing", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.MarkAnalyzing))))
	mux.Handle("POST /api/v1/security-events/{id}/create-exception", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(eventHandler.CreateException))))

	// ---- 阶段5：可信代理/保护地址/黑白名单/CC策略/临时封禁/访问控制事件/版本 ----
	// 可信代理
	mux.Handle("GET /api/v1/trusted-proxies", authz(middleware.RequirePermission("trusted_proxies.read")(http.HandlerFunc(proxyHandler.List))))
	mux.Handle("POST /api/v1/trusted-proxies", authz(middleware.RequirePermission("trusted_proxies.manage")(http.HandlerFunc(proxyHandler.Create))))
	mux.Handle("GET /api/v1/trusted-proxies/{id}", authz(middleware.RequirePermission("trusted_proxies.read")(http.HandlerFunc(proxyHandler.Get))))
	mux.Handle("PUT /api/v1/trusted-proxies/{id}", authz(middleware.RequirePermission("trusted_proxies.manage")(http.HandlerFunc(proxyHandler.Update))))
	mux.Handle("DELETE /api/v1/trusted-proxies/{id}", authz(middleware.RequirePermission("trusted_proxies.manage")(http.HandlerFunc(proxyHandler.Delete))))
	mux.Handle("POST /api/v1/trusted-proxies/{id}/enable", authz(middleware.RequirePermission("trusted_proxies.manage")(http.HandlerFunc(proxyHandler.Enable))))
	mux.Handle("POST /api/v1/trusted-proxies/{id}/disable", authz(middleware.RequirePermission("trusted_proxies.manage")(http.HandlerFunc(proxyHandler.Disable))))
	mux.Handle("POST /api/v1/trusted-proxies/test", authz(middleware.RequirePermission("trusted_proxies.read")(http.HandlerFunc(proxyHandler.Test))))

	// 保护地址
	mux.Handle("GET /api/v1/protected-addresses", authz(middleware.RequirePermission("protected_addresses.read")(http.HandlerFunc(protectedHandler.List))))
	mux.Handle("POST /api/v1/protected-addresses", authz(middleware.RequirePermission("protected_addresses.manage")(http.HandlerFunc(protectedHandler.Create))))
	mux.Handle("DELETE /api/v1/protected-addresses/{id}", authz(middleware.RequirePermission("protected_addresses.manage")(http.HandlerFunc(protectedHandler.Delete))))
	mux.Handle("POST /api/v1/protected-addresses/refresh", authz(middleware.RequirePermission("protected_addresses.manage")(http.HandlerFunc(protectedHandler.Refresh))))

	// IP黑白名单
	mux.Handle("GET /api/v1/access-rules", authz(middleware.RequirePermission("access_rules.read")(http.HandlerFunc(accessRuleHandler.List))))
	mux.Handle("POST /api/v1/access-rules", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Create))))
	mux.Handle("GET /api/v1/access-rules/{id}", authz(middleware.RequirePermission("access_rules.read")(http.HandlerFunc(accessRuleHandler.Get))))
	mux.Handle("PUT /api/v1/access-rules/{id}", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Update))))
	mux.Handle("DELETE /api/v1/access-rules/{id}", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Delete))))
	mux.Handle("POST /api/v1/access-rules/{id}/enable", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Enable))))
	mux.Handle("POST /api/v1/access-rules/{id}/disable", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Disable))))
	mux.Handle("POST /api/v1/access-rules/{id}/extend", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Extend))))
	mux.Handle("POST /api/v1/access-rules/{id}/release", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Release))))
	mux.Handle("POST /api/v1/access-rules/{id}/copy", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Copy))))
	mux.Handle("POST /api/v1/access-rules/import", authz(middleware.RequirePermission("access_rules.import")(http.HandlerFunc(accessRuleHandler.Import))))
	mux.Handle("GET /api/v1/access-rules/export", authz(exportRate(middleware.RequirePermission("access_rules.read")(http.HandlerFunc(accessRuleHandler.Export)))))
	mux.Handle("POST /api/v1/access-rules/validate", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.Validate))))
	if gatewayHandler != nil {
		mux.Handle("POST /api/v1/access-rules/publish", authz(middleware.RequirePermission("access_rules.publish")(http.HandlerFunc(gatewayHandler.Publish))))
		mux.Handle("POST /api/v1/rate-limit-policies/publish", authz(middleware.RequirePermission("rate_limits.publish")(http.HandlerFunc(gatewayHandler.Publish))))
	}

	// CC防护策略
	mux.Handle("GET /api/v1/rate-limit-policies", authz(middleware.RequirePermission("rate_limits.read")(http.HandlerFunc(rateLimitHandler.List))))
	mux.Handle("POST /api/v1/rate-limit-policies", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Create))))
	mux.Handle("GET /api/v1/rate-limit-policies/{id}", authz(middleware.RequirePermission("rate_limits.read")(http.HandlerFunc(rateLimitHandler.Get))))
	mux.Handle("PUT /api/v1/rate-limit-policies/{id}", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Update))))
	mux.Handle("DELETE /api/v1/rate-limit-policies/{id}", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Delete))))
	mux.Handle("POST /api/v1/rate-limit-policies/{id}/enable", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Enable))))
	mux.Handle("POST /api/v1/rate-limit-policies/{id}/disable", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Disable))))
	mux.Handle("POST /api/v1/rate-limit-policies/{id}/validate", authz(middleware.RequirePermission("rate_limits.manage")(http.HandlerFunc(rateLimitHandler.Validate))))
	mux.Handle("POST /api/v1/rate-limit-policies/{id}/test", authz(middleware.RequirePermission("rate_limits.read")(http.HandlerFunc(rateLimitHandler.Test))))

	// 临时封禁
	mux.Handle("GET /api/v1/temporary-blocks", authz(middleware.RequirePermission("temporary_blocks.read")(http.HandlerFunc(tempBlockHandler.List))))
	mux.Handle("GET /api/v1/temporary-blocks/{id}", authz(middleware.RequirePermission("temporary_blocks.read")(http.HandlerFunc(tempBlockHandler.Get))))
	mux.Handle("POST /api/v1/temporary-blocks/{id}/release", authz(middleware.RequirePermission("temporary_blocks.manage")(http.HandlerFunc(tempBlockHandler.Release))))
	mux.Handle("POST /api/v1/temporary-blocks/{id}/extend", authz(middleware.RequirePermission("temporary_blocks.manage")(http.HandlerFunc(tempBlockHandler.Extend))))
	mux.Handle("POST /api/v1/temporary-blocks/{id}/convert-to-permanent", authz(middleware.RequirePermission("temporary_blocks.manage")(http.HandlerFunc(tempBlockHandler.ConvertToPermanent))))

	// 访问控制事件
	mux.Handle("GET /api/v1/access-control-events", authz(middleware.RequirePermission("access_control_events.read")(http.HandlerFunc(acEventHandler.List))))
	mux.Handle("GET /api/v1/access-control-events/export", authz(exportRate(middleware.RequirePermission("access_control_events.export")(http.HandlerFunc(acEventHandler.Export)))))
	mux.Handle("GET /api/v1/access-control-events/{id}", authz(middleware.RequirePermission("access_control_events.read")(http.HandlerFunc(acEventHandler.Get))))

	// 访问控制配置版本
	mux.Handle("GET /api/v1/access-control/versions", authz(middleware.RequirePermission("access_control_versions.read")(http.HandlerFunc(acVersionHandler.List))))
	mux.Handle("GET /api/v1/access-control/versions/{id}", authz(middleware.RequirePermission("access_control_versions.read")(http.HandlerFunc(acVersionHandler.Get))))
	mux.Handle("GET /api/v1/access-control/versions/{id}/diff", authz(middleware.RequirePermission("access_control_versions.read")(http.HandlerFunc(acVersionHandler.Diff))))
	mux.Handle("POST /api/v1/access-control/versions/{id}/rollback", authz(middleware.RequirePermission("access_control_versions.rollback")(http.HandlerFunc(acVersionHandler.Rollback))))

	// ---- 阶段6：态势/统计/报告/监控/告警/备份恢复/升级/交付检查 ----
	// 态势首页
	mux.Handle("GET /api/v1/dashboard/security-overview", authz(middleware.RequirePermission("dashboard.security.read")(http.HandlerFunc(dashboardHandler.SecurityOverview))))
	mux.Handle("GET /api/v1/dashboard/runtime-overview", authz(middleware.RequirePermission("dashboard.runtime.read")(http.HandlerFunc(dashboardHandler.RuntimeOverview))))
	mux.Handle("GET /api/v1/dashboard/audit-overview", authz(middleware.RequirePermission("dashboard.audit.read")(http.HandlerFunc(dashboardHandler.AuditOverview))))
	// 统计分析
	analyticsSec := middleware.RequirePermission("analytics.security.read")
	mux.Handle("GET /api/v1/analytics/request-trend", authz(analyticsSec(http.HandlerFunc(analyticsHandler.RequestTrend))))
	mux.Handle("GET /api/v1/analytics/security-event-trend", authz(analyticsSec(http.HandlerFunc(analyticsHandler.SecurityEventTrend))))
	mux.Handle("GET /api/v1/analytics/risk-levels", authz(analyticsSec(http.HandlerFunc(analyticsHandler.RiskLevels))))
	mux.Handle("GET /api/v1/analytics/attack-types", authz(analyticsSec(http.HandlerFunc(analyticsHandler.AttackTypes))))
	mux.Handle("GET /api/v1/analytics/top-source-ips", authz(analyticsSec(http.HandlerFunc(analyticsHandler.TopSourceIPs))))
	mux.Handle("GET /api/v1/analytics/top-applications", authz(analyticsSec(http.HandlerFunc(analyticsHandler.TopApplications))))
	mux.Handle("GET /api/v1/analytics/top-rules", authz(analyticsSec(http.HandlerFunc(analyticsHandler.TopRules))))
	mux.Handle("GET /api/v1/analytics/top-uris", authz(analyticsSec(http.HandlerFunc(analyticsHandler.TopURIs))))
	mux.Handle("GET /api/v1/analytics/cc-overview", authz(analyticsSec(http.HandlerFunc(analyticsHandler.CCOverview))))
	mux.Handle("GET /api/v1/analytics/access-control-overview", authz(analyticsSec(http.HandlerFunc(analyticsHandler.AccessControlOverview))))
	mux.Handle("GET /api/v1/analytics/disposition-overview", authz(middleware.RequirePermission("analytics.disposition.read")(http.HandlerFunc(analyticsHandler.DispositionOverview))))
	// 报告（含模板/任务/归档，权限在 handler 路由层）
	reportHandler.RegisterRoutes(mux, authz)
	// 运行监控
	mux.Handle("GET /api/v1/system-health", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.SystemHealth))))
	mux.Handle("GET /api/v1/system-health/components", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.Components))))
	mux.Handle("GET /api/v1/system-health/storage", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.Storage))))
	// 系统告警
	alertRead := requireAnyPerm("system_alerts.read", "system_alerts.read_security", "system_alerts.read_audit")
	alertWrite := requireAnyPerm("system_alerts.acknowledge", "system_alerts.acknowledge_security")
	mux.Handle("GET /api/v1/system-alerts", authz(alertRead(http.HandlerFunc(alertHandler.List))))
	mux.Handle("GET /api/v1/system-alerts/{id}", authz(alertRead(http.HandlerFunc(alertHandler.Get))))
	mux.Handle("POST /api/v1/system-alerts/{id}/acknowledge", authz(alertWrite(http.HandlerFunc(alertHandler.Acknowledge))))
	mux.Handle("POST /api/v1/system-alerts/{id}/resolve", authz(alertWrite(http.HandlerFunc(alertHandler.Resolve))))
	mux.Handle("POST /api/v1/system-alerts/{id}/ignore", authz(alertWrite(http.HandlerFunc(alertHandler.Ignore))))
	mux.Handle("POST /api/v1/system-alerts/{id}/notes", authz(alertWrite(http.HandlerFunc(alertHandler.AddNote))))
	// 备份与恢复（加密服务可用时）
	if backupHandler != nil {
		mux.Handle("GET /api/v1/backups", authz(middleware.RequirePermission("backups.read")(http.HandlerFunc(backupHandler.List))))
		mux.Handle("POST /api/v1/backups", authz(middleware.RequirePermission("backups.create")(http.HandlerFunc(backupHandler.Create))))
		mux.Handle("GET /api/v1/backups/{id}", authz(middleware.RequirePermission("backups.read")(http.HandlerFunc(backupHandler.Get))))
		mux.Handle("POST /api/v1/backups/{id}/verify", authz(middleware.RequirePermission("backups.verify")(http.HandlerFunc(backupHandler.Verify))))
		mux.Handle("GET /api/v1/backups/{id}/download", authz(middleware.RequirePermission("backups.read")(http.HandlerFunc(backupHandler.Download))))
		mux.Handle("DELETE /api/v1/backups/{id}", authz(middleware.RequirePermission("backups.delete")(http.HandlerFunc(backupHandler.Delete))))
		mux.Handle("GET /api/v1/restores", authz(requireAnyPerm("backups.read", "restore_records.read")(http.HandlerFunc(restoreHandler.List))))
		mux.Handle("POST /api/v1/restores/validate", authz(middleware.RequirePermission("backups.restore")(http.HandlerFunc(restoreHandler.Validate))))
		mux.Handle("POST /api/v1/restores/import", authz(middleware.RequirePermission("backups.restore")(http.HandlerFunc(restoreHandler.Import))))
		mux.Handle("POST /api/v1/restores", authz(middleware.RequirePermission("backups.restore")(http.HandlerFunc(restoreHandler.Create))))
		mux.Handle("GET /api/v1/restores/{id}", authz(requireAnyPerm("backups.read", "restore_records.read")(http.HandlerFunc(restoreHandler.Get))))
		mux.Handle("POST /api/v1/restores/{id}/confirm", authz(middleware.RequirePermission("backups.restore")(http.HandlerFunc(restoreHandler.Confirm))))
		mux.Handle("POST /api/v1/restores/{id}/cancel", authz(middleware.RequirePermission("backups.restore")(http.HandlerFunc(restoreHandler.Cancel))))
	}
	// 升级与交付检查（权限在各自 handler 路由层）
	upgradeHandler.RegisterRoutes(mux, authz)
	deliveryHandler.RegisterRoutes(mux, authz)

	// ---- 阶段8 / WDSP：API 资产、模型版本、统一运行时事件 ----
	apiEndpointStore := apiassets.NewStore(db)
	apiEndpointHandler := apiassets.NewHandler(apiEndpointStore)
	apiModelStore := apimodels.NewStore(db)
	apiModelHandler := apimodels.NewHandler(apiModelStore)
	apiEventStore := apiruntime.NewStore(db)
	apiEventHandler := apiruntime.NewHandler(apiEventStore)
	mux.Handle("GET /api/v1/api-endpoints", authz(middleware.RequirePermission("api_endpoints.read")(http.HandlerFunc(apiEndpointHandler.List))))
	mux.Handle("GET /api/v1/api-endpoints/{id}", authz(middleware.RequirePermission("api_endpoints.read")(http.HandlerFunc(apiEndpointHandler.Get))))
	mux.Handle("POST /api/v1/api-endpoints/discover", authz(middleware.RequirePermission("api_endpoints.manage")(http.HandlerFunc(apiEndpointHandler.Discover))))
	mux.Handle("POST /api/v1/api-endpoints/{id}/confirm", authz(middleware.RequirePermission("api_endpoints.manage")(http.HandlerFunc(apiEndpointHandler.Confirm))))
	mux.Handle("GET /api/v1/api-model-versions", authz(middleware.RequirePermission("api_models.read")(http.HandlerFunc(apiModelHandler.List))))
	mux.Handle("POST /api/v1/api-model-versions", authz(middleware.RequirePermission("api_models.manage")(http.HandlerFunc(apiModelHandler.CreateCandidate))))
	mux.Handle("POST /api/v1/api-model-versions/{id}/confirm", authz(middleware.RequirePermission("api_models.manage")(http.HandlerFunc(apiModelHandler.Confirm))))
	mux.Handle("GET /api/v1/api-runtime-events", authz(middleware.RequirePermission("api_runtime_events.read")(http.HandlerFunc(apiEventHandler.List))))
	// 产品 edition 探测（已登录可读，供前端 WDSP 菜单）
	mux.Handle("GET /api/v1/product/edition", authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"edition":                     string(cfg.Product.Edition),
			"api_dynamic_protection":      cfg.Product.APIDynamicProtection,
			"max_body_parse_bytes":        cfg.Product.MaxBodyParseBytes,
			"max_body_sample_bytes":       cfg.Product.MaxBodySampleBytes,
		})
	})))

	// ---- 阶段7：AI 安全运营（可独立启停，关闭不影响 WAF 核心）----
	if cfg.AI.Enabled {
		aiDeps.RegisterRoutes(mux, authz)
		// 模块状态探测（任意已登录用户可查，用于前端降级提示）
		mux.Handle("GET /api/v1/ai/status", authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response.JSON(w, r, http.StatusOK, map[string]interface{}{
				"enabled": true, "degraded": false, "message": "AI 安全运营模块已启用",
			})
		})))
	} else {
		// 关闭时：统一返回 AI 不可用，避免前端 404 误判
		aiDisabled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/ai/status" {
				response.JSON(w, r, http.StatusOK, map[string]interface{}{
					"enabled": false, "degraded": true, "message": "AI 安全运营模块已关闭（AI_ENABLED=false）",
				})
				return
			}
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "AI 安全运营模块已关闭，WAF 核心防护不受影响")
		})
		mux.Handle("GET /api/v1/ai/status", authz(aiDisabled))
		mux.Handle("/api/v1/ai/", authz(aiDisabled))
	}

	// 全局中间件链
	var handler http.Handler = mux
	handler = middleware.MaintenanceGate(&maintenanceFlag{c: c})(handler)
	handler = middleware.RecoverPanic(handler)
	handler = middleware.AccessLog(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.CORS(cfg.Security.CORSAllowedOrigins)(handler)
	handler = middleware.RequestID(handler)
	handler = clientIPMiddleware(handler)

	a.Handler = handler
	return a, nil
}

// maintenanceFlag 读取恢复流程写入的 Valkey 维护标志。
type maintenanceFlag struct {
	c *cache.Client
}

func (m *maintenanceFlag) InMaintenance(ctx context.Context) (bool, error) {
	if m == nil || m.c == nil {
		return false, nil
	}
	n, err := m.c.Redis().Exists(ctx, restores.MaintenanceKey).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// requireAnyPerm 任一权限满足即放行（同一路由多角色只读场景）。
func requireAnyPerm(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			for _, perm := range perms {
				if p.HasPermission(perm) {
					next.ServeHTTP(w, r)
					return
				}
			}
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "无权执行该操作")
		})
	}
}

// StartStage6Workers 启动阶段6后台工人：报告生成、备份执行、运行健康采集与告警评估。
// 幂等（重复调用仅首次生效）。
func (a *App) StartStage6Workers(ctx context.Context) {
	if a.reportWorker != nil {
		go a.reportWorker.Run(ctx, 2*time.Second)
	}
	if a.backupWorker != nil {
		go a.backupWorker.Run(ctx)
	}
	if a.healthCollector != nil {
		go a.healthCollector.Run(ctx, 30*time.Second)
	}
	// 告警评估：每 30s 基于最新健康快照评估一次
	if a.alertEngine != nil && a.healthCollector != nil {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					snaps, err := a.healthCollector.LatestAll(ctx)
					if err != nil {
						continue
					}
					if err := a.alertEngine.Evaluate(ctx, snaps); err != nil {
						slog.Warn("alert evaluate failed", "error", err)
					}
					if err := a.alertEngine.EvaluateParseFailures(ctx); err != nil {
						slog.Warn("alert parse-failure evaluate failed", "error", err)
					}
				}
			}
		}()
	}
}

// authChain 构造认证链：会话解析 → 认证检查 → CSRF 防护。
func (a *App) authChain() func(http.Handler) http.Handler { // 豁免路径（must_change_password 时也可访问）
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
		currentUser, err := a.users.GetActiveSessionUser(
			r.Context(), sess.UserID, sessions.HashSessionID(sess.ID))
		if err != nil {
			slog.Warn("persistent session validation failed", "error", err, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		currentRoles, err := a.users.GetRoles(r.Context(), sess.UserID)
		if err != nil {
			slog.Warn("current session roles resolve failed", "error", err, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		currentPermissions, err := a.users.GetPermissions(r.Context(), sess.UserID)
		if err != nil {
			slog.Warn("current session permissions resolve failed", "error", err, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}
		roleCodes := make([]string, len(currentRoles))
		for i, role := range currentRoles {
			roleCodes[i] = role.Code
		}
		perms := make(map[string]bool, len(currentPermissions))
		for _, permission := range currentPermissions {
			perms[permission] = true
		}
		p := &authz.Principal{
			UserID:        sess.UserID,
			Username:      currentUser.Username,
			Roles:         roleCodes,
			Permissions:   currentPermissions,
			SessionID:     sess.ID,
			SourceIP:      sess.SourceIP,
			UserAgent:     sess.UserAgent,
			MustChangePwd: currentUser.MustChangePassword,
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

// eventExceptionCreator 将 securityevents.Event 适配为例外草稿创建。
type eventExceptionCreator struct {
	store *exceptions.Store
}

// CreateFromEvent 实现 securityevents.ExceptionCreator 接口。
func (e *eventExceptionCreator) CreateFromEvent(ctx context.Context, evt *securityevents.Event, createdBy uuid.UUID) (uuid.UUID, error) {
	var ruleIDs []int
	// 从事件获取规则ID（从匹配记录提取由调用方传入时为空，此处从事件的RawRef不易获取，
	// 简化：使用攻击类型与域名/路径创建精确例外）
	return e.store.CreateFromEvent(ctx, exceptions.CreateFromEventInput{
		EventID:    evt.ID,
		ClientIP:   evt.ClientIP,
		Domain:     evt.Domain,
		URI:        evt.URI,
		Path:       evt.Path,
		AttackType: evt.AttackType,
		RuleIDs:    ruleIDs,
		CreatedBy:  createdBy,
	})
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
		return nil, fmt.Errorf("JIUZHANG_MASTER_KEY is required and must be valid in prod: %w", err)
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
