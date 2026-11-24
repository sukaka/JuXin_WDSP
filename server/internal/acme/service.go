package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

const (
	appLockKeyPrefix   = "jiuzhang:acme:lock:app:"
	appLockTTL         = 5 * time.Minute
	publishRetryMax    = 4
	publishRetryDelay  = 5 * time.Second
	releaseLockLua     = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`
)

// AppRepo 是 ACME 服务依赖的应用与域名最小仓储接口。
type AppRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
	ListDomains(ctx context.Context, appID uuid.UUID) ([]applications.Domain, error)
	UpdateAutoSSLConfig(ctx context.Context, appID uuid.UUID, enabled bool, challengeType string, renewBeforeDays *int) error
	UpdateAutoSSLRuntimeState(ctx context.Context, appID uuid.UUID, lastStatus, lastError string, failCount int, nextRetryAt, lastAttemptAt *time.Time) error
	ListAutoSSLCandidates(ctx context.Context) ([]applications.Application, error)
	HasAnyAutoSSLEnabled(ctx context.Context) (bool, error)
}

// CertRepo 是 ACME 服务依赖的证书最小仓储接口。
type CertRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*certificates.Certificate, error)
	GetApplicationCertificate(ctx context.Context, appID uuid.UUID) (*certificates.Certificate, error)
	ListApplicationIDs(ctx context.Context, certID uuid.UUID) ([]uuid.UUID, error)
	CreateManagedAndBind(ctx context.Context, in certificates.ManagedIssueInput) (*certificates.Certificate, *uuid.UUID, error)
	RefreshStatus(ctx context.Context) (int, error)
}

// GatewayPublisher 是 ACME 服务触发网关配置发布与检测 HTTP-01 路由的最小接口。
type GatewayPublisher interface {
	PublishSync(ctx context.Context, in gatewayconfig.PublishInput) (*gatewayconfig.PublishTask, error)
	HasActiveACMEHTTP01Route(ctx context.Context) (bool, error)
}

// AlertSink 是证书自动续约失败告警与自愈接口（由 systemalerts.Engine 适配）。
type AlertSink interface {
	RaiseRenewalFailure(ctx context.Context, title, message string) error
	RecoverRenewalFailure(ctx context.Context) error
}

// Service 提供 ACME 配置管理、站点自动 SSL 就绪检查、异步/同步签发与到期自动续约编排。
type Service struct {
	repo      Repository
	apps      AppRepo
	certs     CertRepo
	publisher GatewayPublisher
	cache     *cache.Client
	solver    ChallengeSolver
	issuer    *Issuer
	audits    *audits.Service
	alerts    AlertSink
	nowFn     func() time.Time

	// 无 Valkey 时进程内按 appID 互斥（单测与降级兜底）
	localLockMu sync.Mutex
	localLocks  map[uuid.UUID]struct{}

	// 异步唤醒队列（可由 Worker 注入）
	notifyAppFn func(appID uuid.UUID)
	// publishRetryDelayFn 测试可缩短重试等待
	publishRetryDelay time.Duration
}

// NewService 创建 ACME 业务服务。
func NewService(
	repo Repository,
	apps AppRepo,
	certs CertRepo,
	publisher GatewayPublisher,
	cacheClient *cache.Client,
	solver ChallengeSolver,
	issuer *Issuer,
	auditSvc *audits.Service,
) *Service {
	if issuer == nil {
		issuer = NewIssuer()
	}
	return &Service{
		repo:              repo,
		apps:              apps,
		certs:             certs,
		publisher:         publisher,
		cache:             cacheClient,
		solver:            solver,
		issuer:            issuer,
		audits:            auditSvc,
		nowFn:             func() time.Time { return time.Now().UTC() },
		localLocks:        make(map[uuid.UUID]struct{}),
		publishRetryDelay: publishRetryDelay,
	}
}

// SetAlertSink 注入系统告警通知与恢复出口。
func (s *Service) SetAlertSink(sink AlertSink) {
	s.alerts = sink
}

// SetNotifyAppFunc 注入后台 Worker 唤醒回调。
func (s *Service) SetNotifyAppFunc(fn func(appID uuid.UUID)) {
	s.notifyAppFn = fn
}

// GetConfig 返回全局 ACME 配置（不含敏感明文）。
func (s *Service) GetConfig(ctx context.Context) (*Config, error) {
	return s.repo.GetConfig(ctx)
}

// UpdateConfig 校验并保存全局 ACME 配置。
func (s *Service) UpdateConfig(ctx context.Context, in ConfigUpdateInput) (*Config, error) {
	if err := ValidateProvider(in.Provider); err != nil {
		return nil, err
	}
	if in.KeyType == "" {
		in.KeyType = KeyTypeEC256
	}
	if err := ValidateKeyType(in.KeyType); err != nil {
		return nil, err
	}
	if in.RenewBeforeDays == 0 {
		in.RenewBeforeDays = 30
	}
	if in.RenewBeforeDays < 7 || in.RenewBeforeDays > 60 {
		return nil, fmt.Errorf("提前续约天数须在 7 至 60 天之间")
	}

	dirURL, err := EffectiveDirectoryURL(in.Provider, in.DirectoryURL)
	if err != nil {
		return nil, err
	}
	// 启用或配置了自定义目录时执行严格的 SSRF 与协议校验
	if in.Provider == ProviderCustom || in.Enabled {
		if _, err := ValidateDirectoryURL(ctx, dirURL, in.CustomDirectoryAllowlist); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(in.Email) != "" || in.Enabled {
		if err := ValidateEmail(in.Email); err != nil {
			return nil, err
		}
	}
	if in.Enabled && !in.TOSAgreed {
		return nil, fmt.Errorf("启用自动申请 SSL 证书前须同意 CA 服务条款（tos_agreed=true）")
	}
	if strings.TrimSpace(in.EABHMACKey) != "" {
		if _, err := decodeEABHMACKey(in.EABHMACKey); err != nil {
			return nil, fmt.Errorf("EAB HMAC 密钥格式无效: %w", err)
		}
	}

	return s.repo.UpdateConfig(ctx, in)
}

// TestConfig 校验并探测 ACME 目录连通性（不落库）。
func (s *Service) TestConfig(ctx context.Context, provider, directoryURL, allowlist string) (*TestConfigResult, error) {
	if err := ValidateProvider(provider); err != nil {
		return nil, err
	}
	dirURL, err := EffectiveDirectoryURL(provider, directoryURL)
	if err != nil {
		return nil, err
	}
	return s.issuer.TestDirectory(ctx, dirURL, allowlist)
}

// NeedsHTTP01Route 供网关配置生成器判断是否应注入 :80 jiuzhang_acme_http01 挑战路由。
func (s *Service) NeedsHTTP01Route(ctx context.Context) (bool, error) {
	cfg, err := s.repo.GetConfig(ctx)
	if err != nil {
		return false, err
	}
	if cfg.Enabled {
		return true, nil
	}
	return s.apps.HasAnyAutoSSLEnabled(ctx)
}

// GetAppAutoSSL 查询指定站点的自动 SSL 配置、状态、就绪警告与最新订单。
func (s *Service) GetAppAutoSSL(ctx context.Context, appID uuid.UUID) (*AppAutoSSLStatus, error) {
	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	cfg, err := s.repo.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	domains, err := s.apps.ListDomains(ctx, appID)
	if err != nil {
		return nil, err
	}
	activeOrder, err := s.repo.HasActiveOrderForApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	latestOrder, err := s.repo.GetLatestOrderForApp(ctx, appID)
	if err != nil {
		return nil, err
	}

	httpsDomains, warnings, ready := evaluateReadiness(app, domains, cfg)
	effRenewDays := cfg.RenewBeforeDays
	if app.AutoSSLRenewBeforeDays != nil && *app.AutoSSLRenewBeforeDays >= 7 && *app.AutoSSLRenewBeforeDays <= 60 {
		effRenewDays = *app.AutoSSLRenewBeforeDays
	}
	challengeType := app.AutoSSLChallengeType
	if challengeType == "" {
		challengeType = ChallengeHTTP01
	}

	return &AppAutoSSLStatus{
		ApplicationID:            app.ID,
		Enabled:                  app.AutoSSLEnabled,
		ChallengeType:            challengeType,
		RenewBeforeDays:          app.AutoSSLRenewBeforeDays,
		EffectiveRenewBeforeDays: effRenewDays,
		GlobalACMEEnabled:        cfg.Enabled,
		GlobalProvider:           cfg.Provider,
		AutoPublish:              cfg.AutoPublish,
		HTTPSDomains:             httpsDomains,
		LastStatus:               app.AutoSSLLastStatus,
		LastError:                app.AutoSSLLastError,
		FailCount:                app.AutoSSLFailCount,
		NextRetryAt:              app.AutoSSLNextRetryAt,
		LastAttemptAt:            app.AutoSSLLastAttemptAt,
		HasActiveOrder:           activeOrder,
		LatestOrder:              latestOrder,
		Ready:                    ready,
		Warnings:                 warnings,
	}, nil
}

// UpdateAppAutoSSL 更新站点自动 SSL 开关；若开启且无有效证书且全局已就绪，则异步唤醒首次申请。
func (s *Service) UpdateAppAutoSSL(ctx context.Context, appID uuid.UUID, enabled bool, challengeType string, renewBeforeDays *int) (*AppAutoSSLStatus, error) {
	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	if challengeType == "" {
		challengeType = ChallengeHTTP01
	}
	if challengeType != ChallengeHTTP01 {
		return nil, fmt.Errorf("一期仅支持 HTTP01 验证方式（DNS-01 扩展接口已预留）")
	}
	if renewBeforeDays != nil && (*renewBeforeDays < 7 || *renewBeforeDays > 60) {
		return nil, fmt.Errorf("提前续约天数须在 7 至 60 天之间")
	}
	if enabled {
		if app.DeploymentMode == applications.DeployModeMirror {
			return nil, ErrMirrorUnsupported
		}
		domains, err := s.apps.ListDomains(ctx, appID)
		if err != nil {
			return nil, err
		}
		httpsDomains := extractActiveHTTPSDomains(domains)
		for _, d := range httpsDomains {
			if strings.HasPrefix(d, "*.") {
				return nil, fmt.Errorf("%w: %s", ErrWildcardHTTP01, d)
			}
		}
	}
	if err := s.apps.UpdateAutoSSLConfig(ctx, appID, enabled, challengeType, renewBeforeDays); err != nil {
		return nil, err
	}
	if enabled && s.notifyAppFn != nil {
		s.notifyAppFn(appID)
	}
	return s.GetAppAutoSSL(ctx, appID)
}

// TriggerAppIssue 手动立即申请/重签指定站点的 SSL 证书（异步执行并返回新建的 PENDING 订单）。
func (s *Service) TriggerAppIssue(ctx context.Context, appID uuid.UUID, triggerType string, operatorID *uuid.UUID, requestID string) (*Order, error) {
	order, err := s.prepareOrder(ctx, appID, triggerType, operatorID, requestID)
	if err != nil {
		return nil, err
	}
	go func(ord *Order) {
		bgCtx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		if err := s.ExecuteOrder(bgCtx, ord.ID); err != nil {
			slog.Warn("async acme certificate order failed", "order_id", ord.ID, "app_id", ord.ApplicationID, "error", err)
		}
	}(order)
	return order, nil
}

// TriggerAppIssueSync 同步执行单次签发/续约（后台调度器与端到端测试调用）。
func (s *Service) TriggerAppIssueSync(ctx context.Context, appID uuid.UUID, triggerType string, operatorID *uuid.UUID, requestID string) (*Order, error) {
	order, err := s.prepareOrder(ctx, appID, triggerType, operatorID, requestID)
	if err != nil {
		return nil, err
	}
	execErr := s.ExecuteOrder(ctx, order.ID)
	finalOrder, getErr := s.repo.GetOrder(ctx, order.ID)
	if getErr != nil {
		return order, execErr
	}
	return finalOrder, execErr
}

// TriggerCertRenew 对指定 ACME 托管证书触发立即续约（查找其当前活动绑定应用并创建 MANUAL_RENEW 订单）。
func (s *Service) TriggerCertRenew(ctx context.Context, certID uuid.UUID, operatorID *uuid.UUID, requestID string) (*Order, error) {
	cert, err := s.certs.GetByID(ctx, certID)
	if err != nil {
		return nil, err
	}
	if cert.ManagedBy != certificates.ManagedByACME {
		return nil, ErrManualCertNotRenew
	}
	appIDs, err := s.certs.ListApplicationIDs(ctx, certID)
	if err != nil {
		return nil, err
	}
	if len(appIDs) == 0 {
		return nil, fmt.Errorf("该证书当前未绑定任何活动应用，无法执行续约")
	}
	return s.TriggerAppIssue(ctx, appIDs[0], TriggerManualRenew, operatorID, requestID)
}

// ListOrders 分页查询 ACME 订单。
func (s *Service) ListOrders(ctx context.Context, f OrderFilter) ([]Order, int64, error) {
	return s.repo.ListOrders(ctx, f)
}

// EvaluateAndProcessApp 检查指定站点是否满足自动申请/到期续约/域名增补条件，满足则同步执行一轮签发。
func (s *Service) EvaluateAndProcessApp(ctx context.Context, appID uuid.UUID, respectBackoff bool) (bool, error) {
	cfg, err := s.repo.GetConfig(ctx)
	if err != nil {
		return false, err
	}
	if !cfg.Enabled || !cfg.TOSAgreed || strings.TrimSpace(cfg.Email) == "" {
		return false, nil
	}
	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		return false, err
	}
	if !app.AutoSSLEnabled || app.Status != applications.StatusActive || app.DeploymentMode == applications.DeployModeMirror {
		return false, nil
	}
	now := s.nowFn()
	if respectBackoff && app.AutoSSLNextRetryAt != nil && now.Before(*app.AutoSSLNextRetryAt) {
		return false, nil
	}

	domains, err := s.apps.ListDomains(ctx, appID)
	if err != nil {
		return false, err
	}
	httpsDomains := extractActiveHTTPSDomains(domains)
	if len(httpsDomains) == 0 {
		return false, nil
	}
	for _, d := range httpsDomains {
		if strings.HasPrefix(d, "*.") {
			return false, nil
		}
	}

	boundCert, err := s.certs.GetApplicationCertificate(ctx, appID)
	if err != nil {
		return false, err
	}
	renewDays := cfg.RenewBeforeDays
	if app.AutoSSLRenewBeforeDays != nil && *app.AutoSSLRenewBeforeDays >= 7 && *app.AutoSSLRenewBeforeDays <= 60 {
		renewDays = *app.AutoSSLRenewBeforeDays
	}

	trigger := decideAutoTrigger(boundCert, httpsDomains, renewDays, now)
	if trigger == "" {
		return false, nil
	}

	reqID := fmt.Sprintf("acme-%s-%s", strings.ToLower(trigger), now.Format("20060102T150405Z"))
	_, err = s.TriggerAppIssueSync(ctx, appID, trigger, nil, reqID)
	if errors.Is(err, ErrOrderInProgress) {
		return false, nil
	}
	return true, err
}

// decideAutoTrigger 判断已开启自动 SSL 的站点是否需要自动申请或续约：
//  1. 无绑定证书 → AUTO_INIT（如果站点以前没有 SSL 证书自动去申请）；
//  2. 绑定证书已过期或剩余有效期 ≤ renewBeforeDays → AUTO_RENEW（到期前自动续约）；
//  3. 绑定证书属 ACME 托管且未覆盖站点新增的 HTTPS 域名 → AUTO_DOMAIN_SYNC。
// 其余情况（例如已绑定有效期充足且域名全覆盖的证书，包括手工证书）保持不动。
func decideAutoTrigger(boundCert *certificates.Certificate, httpsDomains []string, renewBeforeDays int, now time.Time) string {
	if boundCert == nil {
		return TriggerAutoInit
	}
	if boundCert.Status == certificates.StatusExpired || boundCert.Status == certificates.StatusInvalid || boundCert.Status == certificates.StatusKeyMismatch {
		return TriggerAutoRenew
	}
	if boundCert.NotAfter != nil {
		threshold := now.Add(time.Duration(renewBeforeDays) * 24 * time.Hour)
		if !boundCert.NotAfter.After(threshold) {
			return TriggerAutoRenew
		}
	}
	if boundCert.ManagedBy == certificates.ManagedByACME {
		parsed := &certificates.ParsedCertificate{CommonName: boundCert.CommonName}
		var sans []string
		_ = json.Unmarshal(boundCert.SANDomains, &sans)
		parsed.SANDomains = sans
		if unmatched := certificates.MatchDomains(parsed, httpsDomains); len(unmatched) > 0 {
			return TriggerAutoDomainSync
		}
	}
	return ""
}

func (s *Service) prepareOrder(ctx context.Context, appID uuid.UUID, triggerType string, operatorID *uuid.UUID, requestID string) (*Order, error) {
	cfg, err := s.repo.GetConfig(ctx)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, ErrConfigNotEnabled
	}
	if !cfg.TOSAgreed || strings.TrimSpace(cfg.Email) == "" {
		return nil, ErrConfigIncomplete
	}
	dirURL, err := EffectiveDirectoryURL(cfg.Provider, cfg.DirectoryURL)
	if err != nil {
		return nil, err
	}

	app, err := s.apps.GetByID(ctx, appID)
	if err != nil {
		return nil, err
	}
	if app.DeploymentMode == applications.DeployModeMirror {
		return nil, ErrMirrorUnsupported
	}
	domains, err := s.apps.ListDomains(ctx, appID)
	if err != nil {
		return nil, err
	}
	httpsDomains := extractActiveHTTPSDomains(domains)
	if len(httpsDomains) == 0 {
		return nil, ErrNoHTTPSDomains
	}
	for _, d := range httpsDomains {
		if strings.HasPrefix(d, "*.") {
			return nil, fmt.Errorf("%w: %s", ErrWildcardHTTP01, d)
		}
		if cfg.Provider != ProviderCustom && isPrivateOrLocalHostname(d) {
			return nil, fmt.Errorf("%w: %s", ErrPrivateDomainOnCA, d)
		}
	}

	active, err := s.repo.HasActiveOrderForApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, ErrOrderInProgress
	}

	var prevCertID *uuid.UUID
	if bound, err := s.certs.GetApplicationCertificate(ctx, appID); err == nil && bound != nil {
		prevCertID = &bound.ID
	}

	if triggerType == "" {
		if prevCertID == nil {
			triggerType = TriggerManualIssue
		} else {
			triggerType = TriggerManualRenew
		}
	}

	order := &Order{
		ApplicationID:         appID,
		AppCode:               app.Code,
		AppName:               app.Name,
		TriggerType:           triggerType,
		Provider:              cfg.Provider,
		DirectoryURL:          dirURL,
		ChallengeType:         ChallengeHTTP01,
		Domains:               httpsDomains,
		Status:                OrderPending,
		PreviousCertificateID: prevCertID,
		RequestedBy:           operatorID,
		RequestID:             requestID,
	}
	if err := s.repo.CreateOrder(ctx, order); err != nil {
		return nil, err
	}
	return order, nil
}

// ExecuteOrder 执行单笔 ACME 签发/续约订单的完整状态机：
// 获取单应用锁 → 确认 :80 HTTP-01 路由就绪 → 注册/复用账户 → ACME HTTP-01 验证签发 →
// 事务入库与绑定 → 按配置自动发布网关 → 更新状态/退避/审计/告警。
func (s *Service) ExecuteOrder(ctx context.Context, orderID uuid.UUID) error {
	order, err := s.repo.GetOrder(ctx, orderID)
	if err != nil {
		return err
	}
	app, err := s.apps.GetByID(ctx, order.ApplicationID)
	if err != nil {
		return err
	}
	unlock, acquired, err := s.acquireAppLock(ctx, order.ApplicationID)
	if err != nil {
		s.failOrder(ctx, app, order, "LOCK_ERROR", err.Error(), nil, nil)
		return err
	}
	if !acquired {
		s.failOrder(ctx, app, order, "LOCK_BUSY", ErrOrderInProgress.Error(), nil, nil)
		return ErrOrderInProgress
	}
	defer unlock()

	started := s.nowFn()
	_ = s.repo.UpdateOrderProgress(ctx, order.ID, OrderPreparing, &started)
	_ = s.apps.UpdateAutoSSLRuntimeState(ctx, app.ID, OrderPreparing, "", app.AutoSSLFailCount, app.AutoSSLNextRetryAt, &started)

	cfg, err := s.repo.GetConfig(ctx)
	if err != nil {
		s.failOrder(ctx, app, order, "CONFIG_LOAD_FAILED", err.Error(), nil, nil)
		return err
	}
	if !cfg.Enabled || !cfg.TOSAgreed || strings.TrimSpace(cfg.Email) == "" {
		s.failOrder(ctx, app, order, "CONFIG_INCOMPLETE", ErrConfigIncomplete.Error(), nil, nil)
		return ErrConfigIncomplete
	}

	// 步骤 1：确认网关 :80 已挂载 jiuzhang_acme_http01 挑战路由（未挂载时自动发布一次使其就绪）
	if s.publisher != nil {
		ready, checkErr := s.publisher.HasActiveACMEHTTP01Route(ctx)
		if checkErr != nil {
			slog.Warn("check active acme http-01 route failed, attempting publish", "app", app.Code, "error", checkErr)
		}
		if !ready {
			var uid uuid.UUID
			if order.RequestedBy != nil {
				uid = *order.RequestedBy
			}
			task, pubErr := s.publishWithLockRetry(ctx, gatewayconfig.PublishInput{
				RequestedBy: uid,
				RequestID:   order.RequestID + "-prep-http01",
			})
			if pubErr != nil || (task != nil && task.Status != gatewayconfig.TaskSuccess) {
				msg := "未能自动就绪网关 80 端口 ACME HTTP-01 挑战路由"
				if pubErr != nil {
					msg += ": " + pubErr.Error()
				} else if task != nil && task.FailureMessage != "" {
					msg += ": " + task.FailureMessage
				}
				s.failOrder(ctx, app, order, "GATEWAY_HTTP01_NOT_READY", msg, nil, nil)
				return errors.New(msg)
			}
		}
	}

	// 步骤 2：加载或创建加密 ACME 账户
	acct, acctSigner, err := s.repo.GetOrCreateAccount(ctx, cfg.Provider, order.DirectoryURL, cfg.Email, cfg.EABKID)
	if err != nil {
		s.failOrder(ctx, app, order, "ACCOUNT_INIT_FAILED", err.Error(), nil, nil)
		return err
	}

	// 步骤 3：调用 ACME v2 客户端执行 HTTP-01 验证与 CSR 签发
	issueRes, err := s.issuer.IssueCertificate(ctx, IssueRequest{
		DirectoryURL: order.DirectoryURL,
		Allowlist:    cfg.CustomDirectoryAllowlist,
		Email:        cfg.Email,
		AccountKey:   acctSigner,
		AccountURI:   acct.AccountURI,
		EABKID:       cfg.EABKID,
		EABHMACKey:   cfg.eabHMACKey,
		Domains:      order.Domains,
		KeyType:      cfg.KeyType,
		Solver:       s.solver,
		OnStageChange: func(stage string) {
			_ = s.repo.UpdateOrderProgress(context.Background(), order.ID, stage, nil)
		},
	})
	if err != nil {
		s.failOrder(ctx, app, order, "ACME_ISSUE_FAILED", err.Error(), nil, nil)
		return err
	}
	if issueRes.AccountURI != "" && issueRes.AccountURI != acct.AccountURI {
		if err := s.repo.UpdateAccountURI(ctx, acct.ID, issueRes.AccountURI); err != nil {
			slog.Warn("update acme account uri failed", "account_id", acct.ID, "error", err)
		}
	}

	// 步骤 4：校验、加密入库并原子切换应用证书绑定（旧 ACME 证书标记 REPLACED 保留回滚私钥）
	renewDays := cfg.RenewBeforeDays
	if app.AutoSSLRenewBeforeDays != nil && *app.AutoSSLRenewBeforeDays >= 7 && *app.AutoSSLRenewBeforeDays <= 60 {
		renewDays = *app.AutoSSLRenewBeforeDays
	}
	newCert, prevCertID, err := s.certs.CreateManagedAndBind(ctx, certificates.ManagedIssueInput{
		ApplicationID:    app.ID,
		AppDomains:       order.Domains,
		NamePrefix:       fmt.Sprintf("acme-%s", app.Code),
		CertPEM:          issueRes.CertPEM,
		ChainPEM:         issueRes.ChainPEM,
		KeyPEM:           issueRes.KeyPEM,
		ACMEProvider:     cfg.Provider,
		ACMEDirectoryURL: order.DirectoryURL,
		ACMEAccountID:    &acct.ID,
		AutoRenew:        true,
		RenewBeforeDays:  renewDays,
		OperatorID:       order.RequestedBy,
	})
	if err != nil {
		s.failOrder(ctx, app, order, "CERT_PERSIST_FAILED", err.Error(), nil, nil)
		return err
	}
	_ = s.repo.UpdateOrderProgress(ctx, order.ID, OrderIssued, nil)

	// 步骤 5：按全局策略自动触发网关配置发布生效
	var pubTaskID *uuid.UUID
	if cfg.AutoPublish && s.publisher != nil {
		_ = s.repo.UpdateOrderProgress(ctx, order.ID, OrderPublishing, nil)
		var uid uuid.UUID
		if order.RequestedBy != nil {
			uid = *order.RequestedBy
		}
		task, pubErr := s.publishWithLockRetry(ctx, gatewayconfig.PublishInput{
			RequestedBy: uid,
			RequestID:   order.RequestID + "-cert-publish",
		})
		if task != nil {
			pubTaskID = &task.ID
		}
		if pubErr != nil || (task != nil && task.Status != gatewayconfig.TaskSuccess) {
			msg := "证书已签发并绑定，但自动发布网关配置失败"
			if pubErr != nil {
				msg += ": " + pubErr.Error()
			} else if task != nil && task.FailureMessage != "" {
				msg += ": " + task.FailureMessage
			}
			s.finishPublishFailed(ctx, app, order, newCert.ID, prevCertID, pubTaskID, msg)
			return errors.New(msg)
		}
	}

	// 步骤 6：全部成功 → 回填订单、重置应用重试计数、写操作审计、自愈历史失败告警
	_ = s.repo.FinishOrder(ctx, order.ID, OrderSucceeded, &newCert.ID, prevCertID, pubTaskID, "", "")
	now := s.nowFn()
	_ = s.apps.UpdateAutoSSLRuntimeState(ctx, app.ID, OrderSucceeded, "", 0, nil, &now)
	s.recordOrderAudit(ctx, app, order, &newCert.ID, audits.ResultSuccess, "")
	if s.alerts != nil {
		if err := s.alerts.RecoverRenewalFailure(ctx); err != nil {
			slog.Warn("recover certificate auto renew alert failed", "error", err)
		}
	}
	return nil
}

func (s *Service) publishWithLockRetry(ctx context.Context, in gatewayconfig.PublishInput) (*gatewayconfig.PublishTask, error) {
	var lastTask *gatewayconfig.PublishTask
	var lastErr error
	for attempt := 0; attempt < publishRetryMax; attempt++ {
		task, err := s.publisher.PublishSync(ctx, in)
		lastTask, lastErr = task, err
		if err == nil && task != nil && task.Status == gatewayconfig.TaskSuccess {
			return task, nil
		}
		isLockBusy := (task != nil && task.FailureCode == "LOCK_BUSY") || errors.Is(err, gatewayconfig.ErrLockBusy)
		if !isLockBusy || attempt == publishRetryMax-1 {
			return task, err
		}
		select {
		case <-ctx.Done():
			return task, ctx.Err()
		case <-time.After(s.publishRetryDelay):
		}
	}
	return lastTask, lastErr
}

func (s *Service) failOrder(ctx context.Context, app *applications.Application, order *Order, code, msg string, certID, pubTaskID *uuid.UUID) {
	now := s.nowFn()
	nextFailCount := app.AutoSSLFailCount + 1
	nextRetry := now.Add(BackoffDuration(nextFailCount))
	_ = s.repo.FinishOrder(ctx, order.ID, OrderFailed, certID, order.PreviousCertificateID, pubTaskID, code, msg)
	_ = s.apps.UpdateAutoSSLRuntimeState(ctx, app.ID, OrderFailed, msg, nextFailCount, &nextRetry, &now)
	s.recordOrderAudit(ctx, app, order, certID, audits.ResultFailure, msg)
	if s.alerts != nil {
		title := fmt.Sprintf("站点 %s 自动申请/续约 SSL 证书失败", app.Code)
		alertMsg := fmt.Sprintf("应用 %s（域名 %s）自动证书任务失败（%s）：%s", app.Code, strings.Join(order.Domains, ", "), code, msg)
		if err := s.alerts.RaiseRenewalFailure(ctx, title, alertMsg); err != nil {
			slog.Warn("raise certificate auto renew failed alert error", "app", app.Code, "error", err)
		}
	}
}

func (s *Service) finishPublishFailed(ctx context.Context, app *applications.Application, order *Order, certID uuid.UUID, prevCertID, pubTaskID *uuid.UUID, msg string) {
	now := s.nowFn()
	nextFailCount := app.AutoSSLFailCount + 1
	nextRetry := now.Add(BackoffDuration(nextFailCount))
	_ = s.repo.FinishOrder(ctx, order.ID, OrderPublishFailed, &certID, prevCertID, pubTaskID, "AUTO_PUBLISH_FAILED", msg)
	_ = s.apps.UpdateAutoSSLRuntimeState(ctx, app.ID, OrderPublishFailed, msg, nextFailCount, &nextRetry, &now)
	s.recordOrderAudit(ctx, app, order, &certID, audits.ResultFailure, msg)
	if s.alerts != nil {
		title := fmt.Sprintf("站点 %s 证书签发后自动发布失败", app.Code)
		alertMsg := fmt.Sprintf("应用 %s 新证书 %s 已入库绑定，但自动发布失败：%s", app.Code, certID, msg)
		if err := s.alerts.RaiseRenewalFailure(ctx, title, alertMsg); err != nil {
			slog.Warn("raise certificate auto publish failed alert error", "app", app.Code, "error", err)
		}
	}
}

func (s *Service) recordOrderAudit(ctx context.Context, app *applications.Application, order *Order, certID *uuid.UUID, result, failReason string) {
	if s.audits == nil {
		return
	}
	action := "acme_issue"
	if order.TriggerType == TriggerAutoRenew || order.TriggerType == TriggerManualRenew {
		action = "acme_renew"
	}
	summary, _ := json.Marshal(map[string]any{
		"order_id":     order.ID,
		"app_code":     app.Code,
		"trigger_type": order.TriggerType,
		"provider":     order.Provider,
		"domains":      order.Domains,
		"cert_id":      certID,
	})
	objID := order.ID.String()
	if certID != nil {
		objID = certID.String()
	}
	username := "system-acme"
	if order.RequestedBy != nil {
		username = ""
	}
	audits.RecordWithFallback(ctx, s.audits, audits.RecordInput{
		UserID:        order.RequestedBy,
		Username:      username,
		Module:        "certificates",
		Action:        action,
		ObjectType:    "certificate",
		ObjectID:      objID,
		ObjectName:    app.Code,
		AfterSummary:  string(summary),
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskMedium,
		RequestID:     order.RequestID,
	})
}

func (s *Service) acquireAppLock(ctx context.Context, appID uuid.UUID) (func(), bool, error) {
	if s.cache != nil && s.cache.Redis() != nil {
		key := appLockKeyPrefix + appID.String()
		token := uuid.NewString()
		ok, err := s.cache.Redis().SetNX(ctx, key, token, appLockTTL).Result()
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}
		return func() {
			relCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = s.cache.Redis().Eval(relCtx, releaseLockLua, []string{key}, token).Result()
		}, true, nil
	}

	s.localLockMu.Lock()
	if _, exists := s.localLocks[appID]; exists {
		s.localLockMu.Unlock()
		return nil, false, nil
	}
	s.localLocks[appID] = struct{}{}
	s.localLockMu.Unlock()
	return func() {
		s.localLockMu.Lock()
		delete(s.localLocks, appID)
		s.localLockMu.Unlock()
	}, true, nil
}

func extractActiveHTTPSDomains(domains []applications.Domain) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d.Status != "ACTIVE" || !d.HTTPSEnabled {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(d.NormalizedHostname))
		if host == "" {
			host = strings.ToLower(strings.TrimSpace(d.Hostname))
		}
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func evaluateReadiness(app *applications.Application, domains []applications.Domain, cfg *Config) ([]string, []ReadinessWarning, bool) {
	httpsDomains := extractActiveHTTPSDomains(domains)
	warnings := make([]ReadinessWarning, 0)
	ready := true

	if app.DeploymentMode == applications.DeployModeMirror {
		ready = false
		warnings = append(warnings, ReadinessWarning{
			Code: "MIRROR_MODE", Level: "error",
			Message: "镜像旁路模式不终结 TLS，无需且不支持自动申请 SSL 证书",
		})
		return httpsDomains, warnings, ready
	}
	if !cfg.Enabled {
		ready = false
		warnings = append(warnings, ReadinessWarning{
			Code: "GLOBAL_ACME_DISABLED", Level: "warning",
			Message: "全局自动证书（ACME）尚未启用，请先在「HTTPS 证书 → 自动证书设置」中配置联系邮箱并启用",
		})
	} else if !cfg.TOSAgreed || strings.TrimSpace(cfg.Email) == "" {
		ready = false
		warnings = append(warnings, ReadinessWarning{
			Code: "GLOBAL_ACME_INCOMPLETE", Level: "error",
			Message: "全局 ACME 配置缺少联系邮箱或未同意服务条款，请先完善配置",
		})
	}
	if len(httpsDomains) == 0 {
		ready = false
		warnings = append(warnings, ReadinessWarning{
			Code: "NO_HTTPS_DOMAINS", Level: "warning",
			Message: "当前站点未启用任何 HTTPS 域名，请先在「域名管理」中开启 HTTPS 监听",
		})
	}
	for _, d := range httpsDomains {
		if strings.HasPrefix(d, "*.") {
			ready = false
			warnings = append(warnings, ReadinessWarning{
				Code: "WILDCARD_UNSUPPORTED_HTTP01", Level: "error",
				Message: fmt.Sprintf("域名 %s 为泛域名，当前 HTTP-01 验证方式不支持泛域名证书（需使用精确域名或手动上传）", d),
			})
		} else if cfg.Provider != ProviderCustom && isPrivateOrLocalHostname(d) {
			ready = false
			warnings = append(warnings, ReadinessWarning{
				Code: "PRIVATE_DOMAIN_ON_PUBLIC_CA", Level: "error",
				Message: fmt.Sprintf("域名 %s 为私有/保留域名，无法通过公网 CA 签发（请改用公网域名或自定义私有 ACME CA）", d),
			})
		}
	}
	if ready {
		warnings = append(warnings, ReadinessWarning{
			Code: "HTTP01_PORT80_REQUIREMENT", Level: "info",
			Message: "HTTP-01 验证要求待签发域名已解析至本网关公网 IP，且 TCP 80 端口对 CA 验证节点可达",
		})
	}
	return httpsDomains, warnings, ready
}

func isPrivateOrLocalHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" || h == "localhost" || net.ParseIP(h) != nil {
		return true
	}
	for _, suffix := range []string{".local", ".localhost", ".internal", ".lan", ".home", ".localdomain", ".invalid", ".test"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

// SystemAlertsAdapter 将 *systemalerts.Engine 适配为 ACME AlertSink。
type SystemAlertsAdapter struct {
	Engine *systemalerts.Engine
}

func (a SystemAlertsAdapter) RaiseRenewalFailure(ctx context.Context, title, message string) error {
	if a.Engine == nil {
		return nil
	}
	_, err := a.Engine.NotifyFailure(ctx, systemalerts.TypeCertificateAutoRenewFailed, "CERTIFICATE", title, message)
	return err
}

func (a SystemAlertsAdapter) RecoverRenewalFailure(ctx context.Context) error {
	if a.Engine == nil {
		return nil
	}
	_, err := a.Engine.AutoRecover(ctx, "CERTIFICATE", systemalerts.TypeCertificateAutoRenewFailed)
	return err
}
