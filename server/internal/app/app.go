// Package app 装配管理后端应用（依赖注入与路由注册）。
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/aiagents"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aicost"
	"github.com/jiuzhang-waf/server/internal/aihandlers"
	"github.com/jiuzhang-waf/server/internal/aimemory"
	"github.com/jiuzhang-waf/server/internal/aimodel"
	"github.com/jiuzhang-waf/server/internal/ainoise"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aiprompts"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/analytics"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/apiauthzacks"
	"github.com/jiuzhang-waf/server/internal/apiauthzauthority"
	"github.com/jiuzhang-waf/server/internal/apiauthzwizard"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/apidataflow"
	"github.com/jiuzhang-waf/server/internal/apiexposure"
	"github.com/jiuzhang-waf/server/internal/apifiles"
	"github.com/jiuzhang-waf/server/internal/apiflows"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/apigql"
	"github.com/jiuzhang-waf/server/internal/apigroups"
	"github.com/jiuzhang-waf/server/internal/apigrpcdesc"
	"github.com/jiuzhang-waf/server/internal/apillm"
	"github.com/jiuzhang-waf/server/internal/apimachineid"
	"github.com/jiuzhang-waf/server/internal/apimcp"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/apiops"
	"github.com/jiuzhang-waf/server/internal/apirevokedcreds"
	"github.com/jiuzhang-waf/server/internal/apiscan"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
	"github.com/jiuzhang-waf/server/internal/apm"
	"github.com/jiuzhang-waf/server/internal/appconfigs"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/attacksessions"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/auth"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/behaviorpolicy"
	"github.com/jiuzhang-waf/server/internal/botpolicy"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/containerops"
	"github.com/jiuzhang-waf/server/internal/coverage"
	"github.com/jiuzhang-waf/server/internal/customrules"
	"github.com/jiuzhang-waf/server/internal/dashboards"
	"github.com/jiuzhang-waf/server/internal/delivery"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/hagroups"
	"github.com/jiuzhang-waf/server/internal/hastatus"
	"github.com/jiuzhang-waf/server/internal/ingest"
	"github.com/jiuzhang-waf/server/internal/jwttrust"
	"github.com/jiuzhang-waf/server/internal/l7rules"
	"github.com/jiuzhang-waf/server/internal/license"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/metrics"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/netconfig"
	"github.com/jiuzhang-waf/server/internal/netdiag"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
	"github.com/jiuzhang-waf/server/internal/notify"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/protectionpolicies"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/regression"
	"github.com/jiuzhang-waf/server/internal/reports"
	"github.com/jiuzhang-waf/server/internal/requestpcap"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/restores"
	"github.com/jiuzhang-waf/server/internal/riskpolicy"
	"github.com/jiuzhang-waf/server/internal/roles"
	"github.com/jiuzhang-waf/server/internal/ruleoverrides"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/securityevents"
	"github.com/jiuzhang-waf/server/internal/securityidentities"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/sitediscovery"
	"github.com/jiuzhang-waf/server/internal/strongflow"
	"github.com/jiuzhang-waf/server/internal/syslogfw"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
	"github.com/jiuzhang-waf/server/internal/systemops"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
	"github.com/jiuzhang-waf/server/internal/threatintel"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
	"github.com/jiuzhang-waf/server/internal/upgrades"
	"github.com/jiuzhang-waf/server/internal/upstreams"
	"github.com/jiuzhang-waf/server/internal/users"
	"github.com/jiuzhang-waf/server/internal/validations"
	"github.com/jiuzhang-waf/server/internal/vulnintel"
	"github.com/jiuzhang-waf/server/internal/vulnrefs"
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
	auditSvc *audits.Service
	// syslog 外发器（三期）：采集器 fan-out 与 syslog-test 接口共用
	syslogFw *syslogfw.Forwarder
	// 告警通知外发（一期）：通知调度器（main 启动其 Run 循环）
	notifyDispatcher *notify.Dispatcher
	// 阶段6后台工人（由 StartStage6Workers 启动）
	alertEngine     *systemalerts.Engine
	reportWorker    *reports.Handler
	backupWorker    *backups.Worker
	netdiagWorker   *netdiag.Worker
	upgradeSvc      *upgrades.Service
	healthCollector *runtimehealth.Collector
	// 阶段7 增量：AI 自动降噪后台工人（仅 AI 模块启用时启动）
	noiseWorker *ainoise.Worker
	// 阶段8 / WDSP：API 专项指标采集器（仅 API 动态防护开启时装配，StartAPIMetrics 启动）
	apiMetrics *metrics.APICollector
	// AUTHZ-01：旧权属安全迁移与可信 JWT 候选关系生成。
	authzStore   *apiauthz.Store
	authzKeyHex  string
	authzPublish apiauthz.PublishFunc
	// 阶段8 / WDSP：API 主动扫描工人（仅 API 动态防护开启时装配，StartStage6Workers 内启动）
	scanWorker *apiscan.Worker
	// 阶段8 / WDSP：数据出境 GeoIP 读取器（文件缺失时 nil 降级，看板 geo_enabled=false）
	apiGeoLookup *apigeo.MMDB
	// 阶段8 / WDSP：AI 定时运营调度器（仅 API 动态防护开启时装配，StartStage6Workers 内启动）
	aiOpsSweeper *apiops.Sweeper
	// 阶段8 / WDSP：多节点版本校验聚合器（§201 遥测路径，仅 API 动态防护开启时装配）
	apiNodesSweeper *apinodes.Sweeper
	// 阶段8 / WDSP：API 网络暴露面判定引擎（仅 API 动态防护开启时装配；
	// 10 分钟周期评估由 cmd/api/main.go sweeper 群启动）
	apiExposureSweeper *apiexposure.Sweeper
	haStatusSweeper    *hastatus.Sweeper
	// 离线授权：产品侧授权服务（门控中间件/发布通道/配额强制共用其内存状态；
	// StartStage6Workers 启动 60s 周期复核）
	licenseSvc *license.Service
	// 攻击活动会话聚合器（WDSP AI 自动化渗透防护增强 阶段4；恒装配，
	// StartStage6Workers 内启动 60s 一轮聚合 + Business 滥用检测）
	attackSessionAgg *attacksessions.Aggregator
	// APM 阶段4：深度诊断会话到期扫描工人（恒装配，StartStage6Workers 内启动每分钟
	// 扫描；APM 总开关关闭时每轮空转——运行期热生效，见 SetEnabledFunc）
	apmDiagSweeper *apm.DiagnosticsSweeper
	// WDSP 流量采集 Agent Phase 3：HTTP 事件保留清理器（契约 §6：每日删除
	// created_at 早于 7 天记录；恒装配，StartStage6Workers 内启动）
	trafficAgentSweeper *agents.HTTPEventSweeper
	// 漏洞情报提醒（VULN_INTEL MVP）：NVD 每日同步器（恒装配；StartStage6Workers
	// 内启动每日循环，vuln_intel.sync_enabled 关闭时每轮空转；手动同步走接口直连）
	vulnIntelSyncer         *vulnintel.Syncer
	kafkaBroker             *ingest.Broker
	apiObservationProjector *apidataflow.Projector
	dataflowWorker          *apidataflow.DataflowWorker
	requestPCAP             *requestpcap.Runtime
}

func (a *App) StartRequestPCAP(ctx context.Context) {
	if a.requestPCAP != nil {
		go a.requestPCAP.Run(ctx)
	}
}

func newAPIDataflowReader(resolve func(context.Context) apm.CHQuerier, db *pgxpool.Pool) *apidataflow.CHReader {
	return apidataflow.NewCHReader(resolve).
		WithRuntimeFields(apidataflow.NewPGXRuntimeFieldReader(db))
}

type publisherFirewallConfigurer interface {
	SetFirewallEnsurer(gatewayconfig.FirewallEnsurer)
}

func configurePublisherFirewallEnsurer(publisher publisherFirewallConfigurer, cfg *config.Config) {
	publisher.SetFirewallEnsurer(func(ports []int, userID uuid.UUID, requestID string) error {
		return systemops.EnsureFirewallPorts(cfg.SystemOps.HostctlDir, ports, userID, requestID)
	})
}

// New 装配生产应用，授权验签信任根来自二进制内嵌公钥表。
func New(cfg *config.Config, db *pgxpool.Pool, c *cache.Client) (*App, error) {
	return newWithVendorKeys(cfg, db, c, license.LoadVendorKeys())
}

// NewWithVendorKeys 供测试装配显式注入验签公钥。
// 生产入口必须使用 New，避免把运行时配置变成授权信任根。
func NewWithVendorKeys(cfg *config.Config, db *pgxpool.Pool, c *cache.Client, vendorKeys map[string]ed25519.PublicKey) (*App, error) {
	return newWithVendorKeys(cfg, db, c, vendorKeys)
}

func newWithVendorKeys(cfg *config.Config, db *pgxpool.Pool, c *cache.Client, vendorKeys map[string]ed25519.PublicKey) (*App, error) {
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
	if err := auditSvc.ConfigureFallback(filepath.Join(cfg.Gateway.DataDir, "audit-outbox")); err != nil {
		return nil, fmt.Errorf("initialize audit fallback: %w", err)
	}
	captchaSvc := security.NewCaptchaService(c)
	authSvc := auth.NewService(userStore, sessSvc, settingsSvc, logSvc, auditSvc, captchaSvc, c, encSvc)

	// 离线授权：产品侧授权服务（内存状态供门控中间件/发布通道/配额强制共用）。
	// encSvc 为 nil 时以 nil Encryptor 构造（raw_file 落 NULL，不落明文）；
	// 未配置任何验签公钥时全部验签失败 = 锁定（fail-closed，见 license.LoadVendorKeys）。
	var licEnc license.Encryptor
	if encSvc != nil {
		licEnc = encSvc
	}
	licSvc := license.NewService(license.NewStore(db), licEnc, vendorKeys)
	// 包装配能力集注入：授权形态宽于本包能力时复核 WARN 一次（仅告警；env 只能收窄不能放宽）
	licSvc.SetCapabilityProvider(func() (apiEnabled, webWAFEnabled bool) {
		return cfg.Product.APIDynamicProtectionEnabled(), cfg.Product.WebWAFProtectionEnabled()
	})
	licHandler := license.NewHandler(licSvc).SetAudits(auditSvc)
	// republishForLicense 授权状态翻转触发的整站重发布入口（publisher 装配后赋值；
	// nil = 发布通道不可用——加密服务缺失形态下授权锁定仍生效，仅无网关联动）
	var republishForLicense func(ctx context.Context)

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
		configurePublisherFirewallEnsurer(publisher, cfg)
		// 网关原生 OTel tracing 下发开关（默认关；仅影响生成内容，不改变发布流程）
		publisher.SetGatewayTracing(cfg.Gateway.TracingEnabled)
		appHandler = applications.NewHandler(appStore, auditSvc, certStore)
		// API 准入覆盖率快照（WDSP P1）：切入 PROTECT 时把切换时刻的确认覆盖率与
		// 未确认命中面记入审计 details（设计 §5.1 软门禁审计侧；窗口取缺省 168h）
		appHandler.SetAdmissionCoverageProvider(func(ctx context.Context, appID uuid.UUID) (any, error) {
			return apisecurity.NewStore(db).AdmissionCoverage(ctx, appID, apisecurity.AdmissionDefaultHitsWindowHours)
		})
		// 离线授权：应用数量配额强制（license 内存状态无 IO；无效授权返回 0=不限制——
		// 管理面已被授权门控锁定，此处不重复强制）
		appHandler.SetMaxApplicationsProvider(func(context.Context) int64 {
			st := licSvc.State()
			if !st.Valid {
				return 0
			}
			return st.Quotas.MaxApplications
		})
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
	// CNNVD 兼容性 P1：漏洞档案（vuln_refs）管理面与交叉查询（迁移 000167）
	vulnRefHandler := vulnrefs.NewHandler(vulnrefs.NewStore(db), auditSvc)
	ruleOverrideHandler := ruleoverrides.NewHandler(ruleOverrideStore, auditSvc)
	exceptionHandler := exceptions.NewHandler(exceptionStore, auditSvc)
	eventStore := securityevents.NewStore(db)
	eventExceptionAdapter := &eventExceptionCreator{store: exceptionStore, events: eventStore}
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
	l7RuleStore := l7rules.NewStore(db)
	// client_identity 体系与行为策略（WDSP AI 自动化渗透防护增强 阶段1；表/权限种子见迁移 000097-000099）
	identityQueryStore := securityidentities.NewStore(db)
	behaviorPolicyStore := behaviorpolicy.NewStore(db)
	// 身份风险处置策略（WDSP AI 自动化渗透防护增强 阶段3；表/权限种子见迁移 000101-000102）
	riskPolicyStore := riskpolicy.NewStore(db)
	// 业务 JWT 信任链管理面（WDSP P0-03；表见迁移 000125，权限种子见 000126）
	jwtTrustStore := jwttrust.NewStore(db)
	// Bot 挑战策略管理面（WDSP P1-02 B1；表见迁移 000128，权限种子见 000129）
	botPolicyStore := botpolicy.NewStore(db)
	// 安全回归证据登记与发布门禁（WDSP P1-04 R3；表见迁移 000134，权限种子见 000135）。
	// 受控证据存储为双方共用的受控本地存储适配器（S0 协调表：P0-01 服务端存储不存在，
	// 由本任务提供）；装配失败 fail-closed（证据根目录不可写时不带病启动）。
	regressionStore := regression.NewStore(db)
	regEvidence, err := regression.NewLocalEvidenceStore(filepath.Join(cfg.Gateway.DataDir, "regression-evidence"), regressionStore)
	if err != nil {
		return nil, fmt.Errorf("initialize regression evidence store: %w", err)
	}
	regressionHandler := regression.NewHandler(regressionStore, regEvidence,
		regression.NewImporter(regressionStore, regEvidence, settingsSvc.GetString), auditSvc)
	// 攻击活动会话聚合（WDSP AI 自动化渗透防护增强 阶段4；表/权限种子见迁移 000103-000104）：
	// 仓储与处理器恒装配（管理面查询）；聚合器 60s 一轮由 StartStage6Workers 启动，
	// Business 滥用检测器随聚合器注入（默认 OBSERVE，数据源缺失形态自然零产出）。
	attackSessionStore := attacksessions.NewStore(db)
	attackSessionAgg := attacksessions.NewAggregator(attackSessionStore)
	attackSessionAgg.SetBusinessDetector(attacksessions.NewBusinessDetector(attackSessionStore))
	// WDSP 分布式流量采集 Agent（Phase 1；表/权限种子见迁移 000108-000109，
	// 契约 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md）：状态查询时派生，无后台 goroutine。
	trafficAgentStore := agents.NewStore(db)

	proxyHandler := trustedproxies.NewHandler(proxyStore, auditSvc)
	protectedHandler := protectedaddresses.NewHandler(protectedStore, auditSvc)
	accessRuleHandler := accessrules.NewHandler(accessRuleStore, auditSvc, protectedStore)
	// 威胁情报导入（WDSP P2-C1）：Feodo C2 情报对账写入 IP 黑名单（复用 access_control 域）
	threatIntelHandler := threatintel.NewHandler(threatintel.NewService(db, protectedStore), auditSvc)
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
	l7RuleHandler := l7rules.NewHandler(l7RuleStore, auditSvc)
	// client_identity 体系与行为策略处理器
	identityHandler := securityidentities.NewHandler(identityQueryStore).SetAudits(auditSvc)
	behaviorPolicyHandler := behaviorpolicy.NewHandler(behaviorPolicyStore, auditSvc)
	// 身份风险处置策略处理器
	riskPolicyHandler := riskpolicy.NewHandler(riskPolicyStore, auditSvc)
	riskOverrideHandler := riskpolicy.NewOverrideHandler(riskPolicyStore, auditSvc)
	// 业务 JWT 信任链处理器：管线状态（产品开关 + settings 覆盖解析）、
	// REMOTE_JWKS 内网 IdP 允许清单（system_settings jwt_trust:remote_jwks_allowlist）、
	// 网关节点状态（预检/发布门禁）注入
	jwtTrustHandler := jwttrust.NewHandler(jwtTrustStore, appStore, auditSvc)
	jwtTrustHandler.SetPipelineState(func(ctx context.Context) (bool, string, error) {
		enabled := cfg.Product.APIDynamicProtectionEnabled()
		mode := cfg.Product.EffectiveAPIProtectionMode()
		if enabled {
			override, found, err := settingsSvc.GetStringWithSource(ctx, apisecurity.PolicySettingsGroup, apisecurity.PolicyModeKey)
			if err != nil {
				return false, "", err
			}
			if found {
				if v := strings.ToUpper(strings.TrimSpace(override)); v == "OFF" || v == "OBSERVE" || v == "PROTECT" {
					mode = v
				}
			}
		}
		return enabled, mode, nil
	})
	jwtTrustHandler.SetAllowlist(func(ctx context.Context) string {
		return settingsSvc.GetString(ctx, "jwt_trust", "remote_jwks_allowlist", "")
	})
	jwtTrustHandler.SetNodeLister(apinodes.NewStore(db))
	// Bot 挑战策略处理器：网关节点状态（GET 状态摘要/预检）、L7 规则/路径转发/保护地址
	// （路由保留冲突预检）、共享状态存储就绪（与发布门禁 checkBotPolicyDeps 同口径）注入
	botPolicyHandler := botpolicy.NewHandler(botPolicyStore, appStore, auditSvc)
	botPolicyHandler.SetNodeLister(apinodes.NewStore(db))
	botPolicyHandler.SetL7RuleLister(l7RuleStore)
	botPolicyHandler.SetPathRouteLister(appconfigs.NewStore(db))
	botPolicyHandler.SetProtectedLister(protectedStore)
	botPolicyHandler.SetSharedStateFunc(func(context.Context) bool {
		return cfg.Gateway.ValkeyAddress(cfg.Cache) != ""
	})
	// 签名密钥就绪检查（预检 signing_key；与发布门禁 checkBotPolicyDeps 同一加载器同口径，
	// 见 guardProvider.SetBotSigningKeysLoader）
	botPolicyHandler.SetSigningKeysLoader(guardconfig.NewBotSigningKeysLoader(settingsSvc.GetString, encSvc.Decrypt))
	// 攻击活动会话处理器
	attackSessionHandler := attacksessions.NewHandler(attackSessionStore)

	// 阶段5：guard 配置组装与发布/回滚集成
	if publisher != nil {
		guardProvider := guardconfig.NewProvider(proxyStore, protectedStore, accessRuleStore, rateLimitStore, acVersionStore,
			guardconfig.Config{
				ValkeyAddress:  cfg.Gateway.ValkeyAddress(cfg.Cache),
				ValkeyPassword: cfg.Cache.Password,
				ValkeyDB:       cfg.Cache.DB,
				EventsLog:      cfg.WAF.GuardEventsLogGateway,
				GatewayNode:    cfg.WAF.GatewayNodeName,
				FailOpen:       cfg.WAF.GuardFailOpen,
				// 阶段8 / WDSP：关闭时下发 JSON 与纯 WAF 完全一致
				APIDynamicProtection: cfg.Product.APIDynamicProtectionEnabled(),
				APIProtectionMode:    cfg.Product.EffectiveAPIProtectionMode(),
				APIEventsLog:         cfg.WAF.APIEventsLogGateway,
				// 全量访问日志（二期）：网关容器内日志路径
				AccessLogPath: cfg.WAF.AccessFullLogGateway,
				// 身份与行为事件日志（client_identity 体系）：网关容器内路径（随 identity_behavior 段下发）
				IdentityEventsLog: cfg.WAF.IdentityEventsLogGateway,
			})
		// 行为策略（security_behavior_policy GLOBAL 行）随发布下发 identity_behavior 段
		guardProvider.SetBehaviorPolicyLister(behaviorPolicyStore)
		// 风险策略（security_risk_policy GLOBAL 行）随发布下发 risk_policy 段
		guardProvider.SetRiskPolicyLister(riskPolicyStore)
		// JWT 信任策略（jwt_trust_policies 按应用行）随发布下发 jwt_trust 段（仅 WDSP 开启；
		// PROTECT 发布门禁：管线模式 + 节点已知同步失败检查——失败即拒绝发布，不静默降级）
		guardProvider.SetJWTTrustLister(jwtTrustStore)
		guardProvider.SetJWTTrustNodeGuard(jwttrust.NodePublishGuard(apinodes.NewStore(db)))
		// Bot 挑战策略（bot_policies 按应用行）随发布下发 bot_policy 段（仅 WDSP 开启；
		// 读取失败中止发布 fail-hard；PROTECT 发布门禁：共享状态存储 Valkey 必须已配置，
		// 且 challenge.key_ref 引用的签名密钥必须已注入（bot_signing_keys 密文经解密下发，
		// 密钥材料不落快照/版本戳/审计——与扫描/文件签名密钥同一通道纪律））
		guardProvider.SetBotPolicyLister(botPolicyStore)
		guardProvider.SetBotSigningKeysLoader(guardconfig.NewBotSigningKeysLoader(settingsSvc.GetString, encSvc.Decrypt))
		// API 引擎受限例外（exception_policies target_engine=API 启用行）随发布下发
		// api_exceptions 段（仅 WDSP 开启；读取失败中止发布 fail-hard；无启用行不下发该段）
		guardProvider.SetAPIExceptionsLister(exceptionStore)
		// 全量访问日志（二期）：logging 组系统设置随发布下发网关（热生效走现有发布链路）
		guardProvider.SetAccessLogLoader(func(ctx context.Context) (guardconfig.AccessLogSettings, error) {
			return guardconfig.AccessLogSettings{
				Enabled:                settingsSvc.GetBool(ctx, "logging", "access_log_enabled", false),
				CaptureRequestHeaders:  settingsSvc.GetBool(ctx, "logging", "capture_request_headers", true),
				CaptureRequestBody:     settingsSvc.GetBool(ctx, "logging", "capture_request_body", false),
				CaptureResponseHeaders: settingsSvc.GetBool(ctx, "logging", "capture_response_headers", true),
				CaptureResponseBody:    settingsSvc.GetBool(ctx, "logging", "capture_response_body", false),
				BodyLimitKB:            settingsSvc.GetInt(ctx, "logging", "body_limit_kb", 64),
			}, nil
		})
		// 阶段8：冻结正式模型与已知端点基线随发布下发网关（WDSP 开启时）
		if cfg.Product.APIDynamicProtectionEnabled() {
			guardProvider.SetAPIModels(apimodels.NewStore(db))
			apiAssetStore := apiassets.NewStore(db)
			guardProvider.SetAPIAssets(apiAssetStore)
			guardProvider.SetAPIEndpointActionsLister(apiAssetStore)
			guardProvider.SetAPIEndpointGroupsLister(apigroups.NewStore(db))
			// API 准入策略（applications.api_admission_mode<>'OFF' 行 + 各应用 CONFIRMED
			// 确认集）随发布下发 api_admission 段（WDSP P1；读取失败中止发布 fail-hard）
			guardProvider.SetAPIAdmissionLister(guardconfig.NewAdmissionPolicyStore(db, apiassets.NewStore(db)))
			// GraphQL 成本预算策略（api_graphql_policies enabled 行）随发布下发 api_graphql 段
			// （NG-GQL-03；读取失败中止发布 fail-hard 同口径；无启用行 = 不下发零行为变化）
			guardProvider.SetAPIGraphQLLister(apigql.NewStore(db))
			// API 防护模式：settings 表覆盖优先（API策略页写库，发布时下发生效）
			guardProvider.SetAPIModeOverride(func(ctx context.Context) (string, bool, error) {
				return settingsSvc.GetStringWithSource(ctx, apisecurity.PolicySettingsGroup, apisecurity.PolicyModeKey)
			})
			// 网关运行时设置（gateway_runtime 组：behavior_store/identity_salt/阈值等）随发布下发；
			// 缺省键不下发=网关内置默认，读取失败向上返回中止发布（不静默降级）
			guardProvider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
				out := map[string]string{}
				for _, key := range []string{
					"behavior_store", "behavior_store_ttl_seconds", "identity_salt", "tls_session_ticket_key",
					"credential_ip_spread_limit", "credential_concurrency_limit", "credential_rate_per_minute", "tenant_rate_per_minute",
					"action_rate_per_minute", "group_rate_per_minute", "api_write_rate_per_minute",
					"api_rate_limit_action", "api_temp_block_seconds",
					"api_quota_per_hour", "api_quota_per_day", "object_rate_per_minute",
					"max_page_size", "max_batch_size", "debug_cc_counter",
					"api_response_fail_policy", "api_response_capture_max_bytes", "api_response_sample_ratio", "api_llm_allowed_models",
					"api_grpc_max_frame_bytes", "api_grpc_allow_compression",
					// NG-AZ-02 D6/D8：节点心跳周期与授权漂移上限随发布下发
					"api_node_heartbeat_seconds", "authz_clock_skew_max_seconds",
					"api_file_watermark_enabled", "api_file_watermark_template",
					"api_file_watermark_content_types", "api_file_watermark_json_key",
				} {
					v, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, key)
					if err != nil {
						return nil, err
					}
					if found {
						out[key] = v
					}
				}
				return out, nil
			})
			// 响应脱敏规则（api_masking_rules 表）随发布下发；表缺失/失败时发布侧 Warn 跳过
			guardProvider.SetMaskRuleLister(guardconfig.NewMaskRuleStore(db))
			guardProvider.SetMaskCryptoLoader(guardconfig.NewMaskCryptoLoader(settingsSvc.GetString, encSvc.Decrypt))
			// 授权基线（api_role_baselines confirmed 行 / api_field_permissions 行）随发布下发；表缺失/失败时 Warn 跳过
			guardProvider.SetRoleBaselineLister(guardconfig.NewRoleBaselineStore(db))
			guardProvider.SetFieldPermissionLister(guardconfig.NewFieldPermissionStore(db))
			// 流程基线（api_flow_baselines 表 enabled 行，§44）随发布下发；表缺失/失败时 Warn 跳过
			guardProvider.SetFlowBaselineLister(guardconfig.NewFlowBaselineStore(db))
			// NG-FLOW-01：强流程定义发布段（api_strong_flows；ACTIVE 行+步骤）
			guardProvider.SetStrongFlowLister(guardconfig.NewStrongFlowStore(db))
			// 已吊销凭据清单（api_revoked_credentials 表当前生效行，§35）随发布下发；表缺失/失败时 Warn 跳过
			guardProvider.SetRevokedCredentialLister(guardconfig.NewRevokedCredentialStore(db))
			guardProvider.SetAuthzSnapshotLister(guardconfig.NewAuthzSnapshotStore(db))
			guardProvider.SetAuthzObjectHMACKeyLoader(guardconfig.NewAuthzObjectHMACKeyLoader(settingsSvc.GetString, encSvc.Decrypt))
			// 响应基线（api_response_schemas 学习行）与扫描签名密钥随发布下发（P1-07 隔离闭环/P0-06 偏离检测）；
			// 密钥经加密服务解密，快照明文脱敏，缺失/失败时 Warn 跳过
			guardProvider.SetResponseBaselineLister(guardconfig.NewResponseBaselineStore(db))
			guardProvider.SetScanVerificationLoader(guardconfig.NewScanVerificationLoader(settingsSvc.GetString, encSvc.Decrypt))
			// 文件签名密钥（密文解密）与文件合规规则随发布下发（P2-02/P2-03）；表缺失/失败时 Warn 跳过
			guardProvider.SetFileSignatureLoader(guardconfig.NewFileSignatureLoader(settingsSvc.GetString, encSvc.Decrypt))
			guardProvider.SetFileComplianceRuleLister(guardconfig.NewFileComplianceRuleStore(db))
			// 值级敏感检测规则（api_sensitive_data_types 表）随发布下发；表缺失/失败时发布侧 Warn 跳过
			guardProvider.SetSensitiveValueRuleLister(guardconfig.NewSensitiveValueRuleStore(db))
			// LLM 输入保护策略随整站发布下发；保存仅产生待发布版本，不冒充即时生效
			guardProvider.SetLLMSecurityPolicyLister(apillm.NewStore(db))
			// gRPC 描述符集（api_grpc_descriptors 表 ENABLED 行）随发布下发；表缺失/失败时发布侧 Warn 跳过
			guardProvider.SetGRPCDescriptorLister(guardconfig.NewGRPCDescriptorStore(db))
			// gRPC 描述符 per-app 绑定（api_grpc_bindings 表全行，NG-GRPC G1 批次 B1）随发布下发；表缺失/失败时发布侧 Warn 跳过（空绑定=全局可见现状语义）
			guardProvider.SetGRPCBindingLister(guardconfig.NewGRPCBindingStore(db))
			// MCP 工具目录（mcp_tool_catalogs ENABLED 行仅含 APPROVED 工具）与 per-app 绑定（mcp_catalog_bindings 全行，
			// NG-MCP G1 批次 B1）随发布下发；表缺失/失败时发布侧 Warn 跳过（空段=网关 MCP 管控零行为变化）
			mcpCatalogStore := guardconfig.NewMCPCatalogStore(db)
			guardProvider.SetMCPToolCatalogLister(mcpCatalogStore)
			guardProvider.SetMCPBindingLister(mcpCatalogStore)
			// 机器身份登记册（machine_identities ENABLED 行+全状态键行，迁移 000183）与 per-app 绑定
			// 及撤销水位元数据（迁移 000184，NG-ID g1 批次 B1）随发布下发；表缺失/失败时发布侧
			// Warn 跳过（空段=网关机器身份验证零行为变化，NG-T-C01）
			machineIDStore := guardconfig.NewMachineIdentityStore(db)
			guardProvider.SetMachineIdentityLister(machineIDStore)
			guardProvider.SetMachineIdentityBindingLister(machineIDStore)
			guardProvider.SetMachineIdentityMetaLister(machineIDStore)
		}
		publisher.SetGuardProvider(guardProvider)
		// 安全回归发布门禁（WDSP P1-04 R3 §7.2）：候选编译完成后、发往节点前评估；
		// 规则启停/自定义规则/模型激活/运行时发布最终都走此入口（模型回滚经
		// RollbackRuntimePolicy → PublishSync 同一通道，发布失败已映射 FAILED/502，
		// 不会在门禁失败时对外报告网关 ACTIVE）。策略默认 OFF，未登记证据不改变发布。
		publisher.SetRegressionGate(regressionGateAdapter{
			gate: regression.NewGate(regressionStore, settingsSvc.GetString, regEvidence),
		})
		guardProvider.SetIdentityBlockLister(identityQueryStore)
		// 行为策略变更触发网关配置发布（identity_behavior 段热生效；异步发布任务，
		// 触发失败仅记日志——策略已落库，发布任务可追踪重试，与其他策略变更同一口径）
		behaviorPolicyHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("behavior policy publish trigger failed", "error", err)
			}
		})
		identityHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("identity manual block publish trigger failed", "error", err)
			}
		})
		// 风险策略变更触发网关配置发布（risk_policy 段热生效；口径同上）
		riskPolicyHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("risk policy publish trigger failed", "error", err)
			}
		})
		riskOverrideHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("risk policy override publish trigger failed", "error", err)
			}
		})
		// Bot 挑战策略变更触发网关配置发布（bot_policy 段随整站快照下发；口径同上）
		botPolicyHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("bot policy publish trigger failed", "error", err)
			}
		})
		// 威胁情报导入生效集变化触发网关配置发布（IP 黑名单段热生效；口径同上）
		threatIntelHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
				slog.Error("threat intel publish trigger failed", "error", err)
			}
		})
		// 离线授权：发布通道实时读取授权内存状态——无效授权强制纯透传
		// （Guard=nil、全部应用 BYPASS）；有效授权注入 max_qps 全局限速配额
		publisher.SetLicenseStateProvider(func(context.Context) (bool, int64) {
			st := licSvc.State()
			return st.Valid, st.Quotas.MaxQPS
		})
		// 完整性事实源暂不可用时保留当前网关配置，不把不确定故障重发布为旁路；
		// 到期、指纹失配和确定篡改仍由既有授权状态门控处理。
		publisher.SetLicensePublishAllowedProvider(func(context.Context) (bool, string) {
			if licSvc.AllowsGatewayConfigPublish() {
				return true, ""
			}
			return false, "授权完整性暂不可用，已暂停配置发布并保留当前网关配置"
		})
		// 授权状态翻转（导入成功/到期/指纹变化/恢复）→ 触发整站重发布。
		// svc 侧已异步调用且 panic 安全；发布锁（Valkey SetNX）防重入——
		// 并发触发退化为 LOCK_BUSY 失败任务如实记录，不产生并发发布。
		republishForLicense = func(ctx context.Context) {
			if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{
				RequestedBy: uuid.Nil,
				RequestID:   "license-" + time.Now().UTC().Format("20060102T150405Z"),
			}); err != nil {
				slog.Error("license: 授权触发整站重发布失败", "error", err)
			}
		}
		licSvc.SetRepublishHook(republishForLicense)
		publisher.SetCustomRulesProvider(customRuleStore)
		publisher.SetRuleOverridesProvider(ruleOverrideStore)
		// 头合规与路径转发配置提供者（发布时随快照下发；DB 错误中止发布，禁止静默降级）
		publisher.SetAppConfigsProvider(appconfigs.NewStore(db))
		// 镜像/透明边车配置（发布成功后写共享卷 mirrorcap.json/tproxyd.json；附加产物，失败只记日志）
		publisher.SetSidecarConfig(cfg.WAF.GatewayNodeName, nodeinterfaces.NewStore(db))
		// 边车共享卷目录（空串保持默认 DefaultSidecarDir；网络配置边车 network.json 同卷）
		publisher.SetSidecarDir(cfg.WAF.SidecarDir)
		// L7 访问控制：仅 WAF/WDSP 交付形态下发 l7_rules 段（API 形态 GuardConfig 与历史一致）
		if cfg.Product.WebWAFProtectionEnabled() {
			guardProvider.SetL7Rules(l7RuleStore)
		}
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
	// 磁盘探针路径：容器内为 /app；裸机/开发/测试环境 /app 不存在时回退数据目录
	// （DataDir 承载报告/备份，正是需要监控容量的盘），避免存储接口 500。
	diskPath := "/app"
	if _, err := os.Stat(diskPath); err != nil {
		diskPath = cfg.Gateway.DataDir
	}
	storageProbe := runtimehealth.NewStorageProbe(db, c, diskPath,
		filepath.Join(cfg.Gateway.DataDir, "reports"), filepath.Join(cfg.Gateway.DataDir, "backups"))
	healthHandler := runtimehealth.NewHandler(healthStore, storageProbe)
	// APM 运行期配置（系统设置界面可配、热生效）：界面设置（system_settings apm 组
	// DB 行）优先、环境变量（APM_ENABLED / APM_CLICKHOUSE_DSN）兜底——与
	// guardProvider.SetAPIModeOverride 的"DB 覆盖优先于构造配置"先例一致；
	// DB 无行（管理员从未在界面配置）时行为与纯 env 部署完全一致。
	apmRuntimeCfg := apm.NewRuntimeConfig(settingsSvc, cfg.APM.Enabled, cfg.APM.ClickHouseDSN)
	// ClickHouse 数据面连接管理器：DSN 运行期可变，按需惰性建连/重建；空 DSN 或
	// 连接失败 Warn 降级为纯无 Agent 模式（遥测故障不影响管理面，与原启动期
	// 建连降级口径一致）。告警评估源（采集滞后）、健康探针与 APM 查询接口共享
	// 同一管理器缓存连接。
	chManager := apm.NewCHManager(apmRuntimeCfg)
	alertStore := systemalerts.NewStore(db)
	// API 安全告警（P1-08）：findings 统计源与 api_alert 组设置注入（未注入则对应评估空转）
	// 安全事件聚合告警（通知二期）：security_events / access_control_events 统计源注入
	alertEngineOpts := systemalerts.EngineOptions{
		APIFindings:    alertStore,
		SecuritySpikes: alertStore,
		Settings:       settingsSvc,
		// APM 告警源恒注入：运行期总开关（界面设置优先）由 APMEnabled 每轮判定，
		// 关闭时三评估器空转（与原"未注入"形态等价，默认部署零行为变化）
		APMEnabled: apmRuntimeCfg.Enabled,
		// APM 阶段1（WP5）端点性能告警评估源（端点聚合统计）
		EndpointPerf: alertStore,
		// APM SLO 违约告警评估源（apm_slos + 小时聚合表）
		SLOBreach: apm.NewSLOStore(db),
		// APM 数据面采集滞后读数源：manager 适配（无连接时 ok=false，评估自然空转）
		IngestLag: apm.NewIngestLagSource(chManager),
		// 告警维护窗口（阶段6 §11.5）：窗口内匹配告警评估抑制（suppressed_count 可观测）
		Maintenance: alertStore,
	}
	alertEngine := systemalerts.NewEngine(alertStore, alertEngineOpts)
	auditSvc.SetFallbackHooks(
		func(ctx context.Context, pending uint64, _ error) {
			if _, err := alertEngine.NotifyFailure(ctx, systemalerts.TypeAuditWriteFailed, "AUDIT",
				"操作审计写入失败",
				fmt.Sprintf("操作审计已进入本地持久化补写队列，待补写 %d 条", pending)); err != nil {
				slog.Warn("raise audit write alert failed", "pending", pending, "error", err)
			}
		},
		func(ctx context.Context) {
			if _, err := alertEngine.AutoRecover(ctx, "AUDIT", systemalerts.TypeAuditWriteFailed); err != nil {
				slog.Warn("recover audit write alert failed", "error", err)
			}
		},
	)
	alertHandler := systemalerts.NewHandler(alertStore, auditSvc)
	// 漏洞情报提醒（VULN_INTEL MVP；表/权限种子见迁移 000189）：NVD 每日同步 PHP 漏洞 +
	// 离线 JSON 导入 + 技术栈订阅去重提醒（VULN_INTEL_NEW 经系统告警引擎进入告警中心与通知链路）。
	// 同步器 URL 硬编码 NVD API 2.0（纯下行，不接受自定义地址）；提醒引擎复用 settings
	// vuln_intel 组订阅配置（watch_techs/min_severity/sync_enabled，界面热生效）。
	vulnIntelStore := vulnintel.NewStore(db)
	vulnIntelSyncer := vulnintel.NewSyncer(vulnIntelStore, nil)
	vulnIntelAlerter := vulnintel.NewAlerter(vulnIntelStore, settingsSvc)
	vulnIntelAlerter.SetRaiseFunc(alertEngine.Raise)
	vulnIntelHandler := vulnintel.NewHandler(vulnIntelStore, vulnIntelSyncer, vulnIntelAlerter,
		settingsSvc, settingsSvc, auditSvc)
	alertFn := backups.AlertFunc(func(alertType, component, title, message string) {
		// 归一化非标准类型（引擎仅接受规则矩阵内的类型）
		if alertType == "RESTORE_FAILED" {
			alertType = "RESTORE_VALIDATION_FAILED"
		}
		if _, err := alertEngine.NotifyFailure(context.Background(), alertType, component, title, message); err != nil {
			slog.Warn("raise alert failed", "type", alertType, "error", err)
		}
	})
	// 离线授权告警：svc 复核/导入钩子 → 系统告警（类型已在 severityRules 注册，
	// 同指纹合并/冷却复用引擎机制；detail 只含中文原因文案，不落授权原文/签名）
	licSvc.SetAlertHook(func(ctx context.Context, ev license.AlertEvent) {
		if _, err := alertEngine.NotifyFailure(ctx, ev.Type, "LICENSE", ev.Title, ev.Message); err != nil {
			slog.Warn("raise license alert failed", "type", ev.Type, "error", err)
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
	// 升级包上传：存储目录默认在数据目录下，大小上限默认 4GiB（均可 env 覆盖）
	upgradePackagesDir := os.Getenv("UPGRADE_PACKAGES_DIR")
	if upgradePackagesDir == "" {
		upgradePackagesDir = filepath.Join(cfg.Gateway.DataDir, "upgrade-packages")
	}
	var upgradeMaxBytes int64
	if v, err := strconv.ParseInt(os.Getenv("UPGRADE_PACKAGE_MAX_BYTES"), 10, 64); err == nil {
		upgradeMaxBytes = v
	}
	upgradeHandler.SetUploadDir(upgradePackagesDir, upgradeMaxBytes)
	upgradeHandler.SetUploadTimeout(cfg.HTTP.UploadTimeout)
	prechecker.SetPackagesDir(upgradePackagesDir)
	if upgradeSvc != nil {
		upgradeExecutorDir := os.Getenv("UPGRADE_EXECUTOR_DIR")
		if upgradeExecutorDir == "" {
			upgradeExecutorDir = filepath.Join(cfg.Gateway.DataDir, "upgrade-executor")
		}
		upgradeSvc.SetExecutorDirs(upgradePackagesDir, upgradeExecutorDir)
		// 定时升级到点 promote 的审计入口（系统动作，操作人取任务创建人）
		upgradeSvc.SetAuditFunc(func(ctx context.Context, in audits.RecordInput) error {
			return auditSvc.Record(ctx, in)
		})
	}
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
	aiQuotas := aicost.DefaultQuotas()
	aiCostRec := aicost.NewRecorder(db, aiQuotas)
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
	// 阶段8 / WDSP：API 动态防护 Tool（任务书第四十八章，全部 READ_ONLY；
	// 仅 WDSP 且开关开启时挂接，纯 WAF 形态下注册表与 ai_tools 同步均不出现）
	if cfg.Product.APIDynamicProtectionEnabled() {
		aitools.NewAPITools(aiRegistry, apiassets.NewStore(db), apimodels.NewStore(db), apisecurity.NewStore(db))
		// P1-02 第一批：弱点/敏感数据/运行时策略/规范/态势（全部 READ_ONLY）
		aitools.NewAPIOpsTools(aiRegistry, apiweakness.NewStore(db), apidata.NewStore(db), apimodels.NewStore(db), apisecurity.NewStore(db), apisecurity.NewStore(db))
	}
	// Tool 执行强制尊重 ai_tools 表启停状态
	aiRegistry.SetEnabledChecker(aihandlers.ToolEnabledChecker(db))
	// AI 自动降噪：确定性指纹聚类 + 可选 LLM 误报评分（产物一律 DRAFT，人工审核；
	// 事件源在 WDSP 且 API 动态防护开启时追加 api_runtime_events）
	noiseStore := ainoise.NewStore(db)
	noiseSource := ainoise.NewEventSource(db, cfg.Product.APIDynamicProtectionEnabled())
	noiseWorker := ainoise.NewWorker(noiseStore, noiseSource, settingsSvc, aiGateway, aitools.NewDraftStore(db))
	aitools.NewNoiseTools(aiRegistry, noiseStore)
	// 编排器：注册 7 个专业 Agent（总调度由编排器内置承担）
	aiLimits := aiorchestrator.DefaultLimits()
	// 单次 LLM 调用输入上限与用户请求级输入配额对齐（aicost PerRequestTokens 为唯一权威字段）
	aiLimits.MaxInputTokens = aiQuotas.PerRequestTokens
	aiOrch := aiorchestrator.New(db, aiGateway, aiRegistry, aiAuditSvc, aiSessionStore, aiCostRec, aiLimits)
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
	// AI 能力增强第一波：API 安全分析 Agent 仅随 API 动态防护形态装配（纯 WAF 形态
	// 编排器与 ai_agents 目录均不出现 api_security，意图命中时编排器跳过未注册 Agent）；
	// extraAgentMetas 随 SyncRegistry 同步入 ai_agents（启停/白名单管理面口径与既有 Agent 一致）
	var extraAgentMetas []aihandlers.AgentMeta
	if cfg.Product.APIDynamicProtectionEnabled() {
		apiSecurityAgent := aiagents.NewAPISecurityAgent(db)
		aiOrch.RegisterAgent(apiSecurityAgent)
		agentCodes[apiSecurityAgent.Code()] = true
		extraAgentMetas = append(extraAgentMetas, aihandlers.AgentMeta{
			Code: apiSecurityAgent.Code(),
			Name: "API 安全分析 Agent",
			Description: "API 资产与态势、影子/僵尸接口、模型与参数偏离、BOLA/BFLA 越权风险、" +
				"弱点整改与敏感数据分析（全部 READ_ONLY Tool，不执行任何变更）",
		})
	}
	// Agent 调度强制尊重 ai_agents 表启停状态
	aiOrch.SetAgentEnabledChecker(aihandlers.AgentEnabledChecker(db))
	// Agent→Tool 白名单（ai_agents.allowed_tool_ids）在执行路径强制（CallTool 拒绝白名单外调用）
	aiOrch.SetAgentToolChecker(aihandlers.AgentToolChecker(db))
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
	// 已发布 Prompt 接入运行时回答总结器；未配置时使用编排器内置安全默认规则。
	aiOrch.SetPromptLoader(func(ctx context.Context, code string) (string, error) {
		content, err := aiPromptStore.CurrentContent(ctx, code)
		if errors.Is(err, aiprompts.ErrNotFound) {
			return "", nil
		}
		return content, err
	})
	// 启动同步：代码 registry 中的 Agent/Tool upsert 到 ai_agents/ai_tools（code 唯一，保留启停状态）；
	// 动态 Agent（api_security 等形态相关）经 extraAgentMetas 一并同步
	if err := aihandlers.SyncRegistry(context.Background(), db, aiRegistry, extraAgentMetas...); err != nil {
		slog.Warn("sync ai agent/tool registry failed", "error", err)
	}
	aiDeps := aihandlers.NewDeps(aihandlers.Deps{
		DB: db, Orch: aiOrch, Sessions: aiSessionStore, Gateway: aiGateway, Models: aiModelStore,
		Tools: aiRegistry, Drafts: aitools.NewDraftStore(db), Audit: aiAuditSvc, Cost: aiCostRec,
		Memories: aiMemoryStore, Prompts: aiPromptStore, Settings: settingsSvc, AgentCodes: agentCodes,
		Noise: noiseStore, NoiseWorker: noiseWorker,
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
	// 系统控制（重启/关机/恢复出厂）：密码二次确认后写宿主控制标志文件（权限种子见迁移 000121）
	systemopsHandler := systemops.NewHandler(userStore, auditSvc, cfg.SystemOps.HostctlDir)
	// 容器运维（containeropsd sidecar 通道，权限种子见迁移 000186）：管理 API 不挂载 docker.sock，
	// 经共享卷 Unix Socket 调用 containeropsd；CONTAINEROPS_SOCKET 未配置时接口 503 降级，
	// 不影响其他功能（裸机/未部署 sidecar 形态，设计见 docs/CONTAINER_OPS_DESIGN.md）
	containeropsHandler := containerops.NewHandler(containerops.NewClient(cfg.ContainerOps.Socket), userStore, auditSvc)
	// 网络诊断工具：管理面写共享卷 diag 请求文件，netmgrd 执行回写结果（权限种子见迁移 000161）；
	// pcap 产物由 Worker 从共享卷搬入服务端数据目录（NETDIAG_DATA_DIR 可覆盖，默认 <数据根>/netdiag）
	netdiagDataDir := os.Getenv("NETDIAG_DATA_DIR")
	if netdiagDataDir == "" {
		netdiagDataDir = filepath.Join(cfg.Gateway.DataDir, "netdiag")
	}
	netdiagStore := netdiag.NewStore(db)
	netdiagWorker := netdiag.NewWorker(netdiagStore, cfg.WAF.SidecarDir, netdiagDataDir, cfg.WAF.GatewayNodeName)
	netdiagHandler := netdiag.NewHandler(netdiagStore, auditSvc, cfg.WAF.SidecarDir, netdiagDataDir, cfg.WAF.GatewayNodeName)
	// syslog 外发（三期）：spool 落在可写数据目录
	syslogFw := syslogfw.NewForwarder(settingsSvc, cfg.Gateway.DataDir)
	syslogHandler := syslogfw.NewHandler(syslogFw, auditSvc)
	// syslog 外发范围扩展：操作审计/登录日志/系统告警入库成功后 fan-out 投递。
	// 三者构造早于 syslogFw，沿用采集器的 setter 注入模式，不调整构造顺序；
	// 以闭包绑定消息类型，避免 audits/loginlogs/systemalerts 反向依赖 syslogfw（循环导入）。
	auditSvc.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		syslogFw.Enqueue(syslogfw.KindOperationAudit, severityHint, payload)
	})
	logSvc.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		syslogFw.Enqueue(syslogfw.KindLoginLog, severityHint, payload)
	})
	alertEngine.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		syslogFw.Enqueue(syslogfw.KindSystemAlert, severityHint, payload)
	})
	// 告警通知外发（一期）：渠道管理 + 通知层风暴抑制；syslog 渠道复用 syslogfw
	// （闭包适配避免 notify 反向依赖 syslogfw；密值在 notify.Store 内 AES-256-GCM 加密落库）。
	notifyStore := notify.NewStore(db, encSvc)
	notifyDispatcher := notify.NewDispatcher(notifyStore, settingsSvc, cfg.Gateway.DataDir)
	// 通知出口 SSRF 防护（SEC-01）：内网目标允许列表走 settings notify 组，热读即时生效
	notify.SetOutboundAllowlistSource(func() string {
		return settingsSvc.GetString(context.Background(), "notify", notify.AllowlistSettingKey, "")
	})
	notifyDispatcher.SetSyslogSender(syslogNotifyAdapter{fw: syslogFw})
	notifyHandler := notify.NewHandler(notifyStore, notifyDispatcher, auditSvc)
	reportHandler.SetNotifyStore(notifyStore) // 定时报告邮件发送的 SMTP 配置来源
	alertEngine.SetNotifyForwarder(func(a systemalerts.Alert) {
		notifyDispatcher.Enqueue(notifyEventFromAlert(a))
	})
	alertHandler.SetNotifyResolvedFunc(func(a systemalerts.Alert) {
		notifyDispatcher.Enqueue(notifyEventFromAlert(a))
	})
	// 登录暴破告警（通知二期 / Tier 2）：登录失败锁定触发点闭包注入
	// （避免 auth 反向依赖 systemalerts；错误只记日志，不扩散到登录主流程）。
	authSvc.SetBruteForceAlertFunc(func(ctx context.Context, username, sourceIP string, lockMinutes int) {
		if _, err := alertEngine.NotifyFailure(ctx, systemalerts.TypeLoginBruteForce, username,
			"登录暴破锁定",
			fmt.Sprintf("账号 %s 连续登录失败已锁定（来源 IP %s，锁定 %d 分钟）", username, sourceIP, lockMinutes)); err != nil {
			slog.Warn("raise login brute force alert failed", "username", username, "error", err)
		}
	})
	profileHandler := users.NewProfileHandler(userStore, logSvc)

	a := &App{
		cfg: cfg, db: db, cache: c,
		users: userStore, sessions: sessSvc, settings: settingsSvc, authSvc: authSvc,
		auditSvc: auditSvc, syslogFw: syslogFw, notifyDispatcher: notifyDispatcher,
	}
	a.alertEngine = alertEngine
	a.licenseSvc = licSvc
	a.attackSessionAgg = attackSessionAgg
	a.vulnIntelSyncer = vulnIntelSyncer
	// 离线授权配额用量（status/import 响应 usage 字段）：应用计数经 appStore（加密服务
	// 缺失形态下为 nil 计 0），API 端点计数经 apiassets（表由阶段8迁移建立，waf 包恒 0）
	licHandler.SetUsageProvider(func(ctx context.Context) (int64, int64, error) {
		var appCount int64
		if appStore != nil {
			n, err := appStore.Count(ctx)
			if err != nil {
				return 0, 0, err
			}
			appCount = n
		}
		epCount, err := apiassets.NewStore(db).Count(ctx)
		if err != nil {
			return 0, 0, err
		}
		return appCount, epCount, nil
	})
	// 授权启动基线评估：门控/status 立即可用；评估失败保持 fail-closed 无效态（不阻断进程启动）
	if err := licSvc.Refresh(context.Background()); err != nil {
		slog.Error("license: 启动基线评估失败", "error", err)
	}
	// 基线为无效授权时按 svc 契约由装配层驱动一次透传发布（svc 首次评估不触发重发布，
	// 避免与启动首发重复——见 license.Service.commitStateLocked）；基线有效不重复发布，
	// 网关沿用当前已生效配置
	if republishForLicense != nil && !licSvc.State().Valid && licSvc.AllowsGatewayConfigPublish() {
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					slog.Error("license: 启动透传发布 panic", "panic", rec)
				}
			}()
			republishForLicense(context.Background())
		}()
	}
	a.reportWorker = reportHandler
	a.backupWorker = backupWorker
	a.netdiagWorker = netdiagWorker
	a.upgradeSvc = upgradeSvc
	// AI 自动降噪后台工人仅随 AI 模块启用（空转判断在 ticker 内按设置执行）
	if cfg.AI.Enabled {
		a.noiseWorker = noiseWorker
	}
	// APM 数据面 ClickHouse 组件探针：manager 运行期适配（无可用连接时 Available=false，
	// APM_CLICKHOUSE 组件不采集不判级，与原"未注入探针"形态等价，默认部署零行为变化；
	// DSN 界面热更新后下轮采集自动走重建后的连接）。
	var chProber runtimehealth.ClickHouseProber = apm.NewCHProberAdapter(chManager)
	a.healthCollector = runtimehealth.NewCollector(db, runtimehealth.Options{
		Caddy:                 gatewayconfig.NewCaddyClient(cfg.Gateway.AdminSocket),
		Cache:                 c,
		GuardEventsLog:        cfg.WAF.GuardEventsLog,
		SecurityCollectorID:   "collector-01",
		GuardEventsCheckpoint: filepath.Join(cfg.Gateway.DataDir, "guard-events.checkpoint"),
		AccessLogCheckpoint:   filepath.Join(cfg.Gateway.DataDir, "access-log.checkpoint"),
		AccessLogPath:         cfg.WAF.AccessLogPath,
		// APM 阶段1（WP5）：accesslog-01 链路新鲜度探针的设置源（logging.access_log_enabled
		// 总开关门控；开关关闭时不纳入判级，默认部署零行为变化）
		Settings: settingsSvc,
		// APM 数据面容量/健康：APM_CLICKHOUSE 组件探针（nil 时该组件不采集）
		APMClickHouse: chProber,
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
	// 登录第二步：双因子验证（与登录共用限流阈值）
	mux.Handle("POST /api/v1/auth/totp-verify", loginRate(http.HandlerFunc(authHandler.TOTPVerify)))

	// ---- 认证接口 ----
	authz := a.authChain()
	mux.Handle("POST /api/v1/auth/logout", authz(http.HandlerFunc(authHandler.Logout)))
	mux.Handle("GET /api/v1/auth/me", authz(http.HandlerFunc(authHandler.Me)))
	mux.Handle("POST /api/v1/auth/change-password", authz(sensitiveRate(http.HandlerFunc(authHandler.ChangePassword))))
	mux.Handle("GET /api/v1/auth/sessions", authz(http.HandlerFunc(authHandler.Sessions)))
	mux.Handle("DELETE /api/v1/auth/sessions/{id}", authz(http.HandlerFunc(authHandler.RevokeSession)))
	// 双因子认证（TOTP）自助管理
	mux.Handle("POST /api/v1/auth/totp/setup", authz(sensitiveRate(http.HandlerFunc(authHandler.TOTPSetup))))
	mux.Handle("POST /api/v1/auth/totp/enable", authz(sensitiveRate(http.HandlerFunc(authHandler.TOTPEnable))))
	mux.Handle("POST /api/v1/auth/totp/disable", authz(sensitiveRate(http.HandlerFunc(authHandler.TOTPDisable))))

	// ---- 离线授权（状态/导入/历史；权限种子见迁移 000078；锁定态下门控白名单放行）----
	license.RegisterRoutes(mux, authz, licHandler)

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
	// 管理员重置用户双因子认证（账号访问恢复，与重置密码同权限点）
	mux.Handle("POST /api/v1/users/{id}/totp/reset", authz(middleware.RequirePermission("users.reset_password")(sensitiveRate(http.HandlerFunc(userHandler.ResetTOTP)))))
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
	mux.Handle("POST /api/v1/system-settings/syslog-test", authz(middleware.RequirePermission("logging.syslog_test")(http.HandlerFunc(syslogHandler.Test))))

	// ---- 系统控制（重启/关机/恢复出厂，高危，密码二次确认 + CRITICAL 审计） ----
	systemopsHandler.RegisterRoutes(mux, authz)

	// ---- 容器运维（列表/日志 MEDIUM 审计；启停 HIGH + 密码二次确认；更新 CRITICAL + 确认文本） ----
	containeropsHandler.RegisterRoutes(mux, authz)

	// ---- 网络诊断工具（ping/端口探测/路由追踪/DNS 查询/抓包） ----
	netdiagHandler.RegisterRoutes(mux, authz)

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
		// 业务 JWT 信任链（WDSP P0-03；表/权限种子见迁移 000125/000126）：
		// 草稿保存不自动发布，发布走既有 gateway-config 发布通道；preflight 不自动发布
		mux.Handle("GET /api/v1/applications/{id}/jwt-trust-policy", authz(middleware.RequirePermission("jwt_trust.read")(http.HandlerFunc(jwtTrustHandler.Get))))
		mux.Handle("PUT /api/v1/applications/{id}/jwt-trust-policy", authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(jwtTrustHandler.Put))))
		mux.Handle("POST /api/v1/applications/{id}/jwt-trust-policy/preflight", authz(middleware.RequirePermission("jwt_trust.manage")(http.HandlerFunc(jwtTrustHandler.Preflight))))
		// Bot 挑战策略（WDSP P1-02 B1；表/权限种子见迁移 000128/000129）：
		// 保存草稿后触发既有发布通道（bot_policy 段随整站快照下发）；preflight 不保存不发布
		mux.Handle("GET /api/v1/applications/{id}/bot-policy", authz(middleware.RequirePermission("bot_policy.read")(http.HandlerFunc(botPolicyHandler.Get))))
		mux.Handle("PUT /api/v1/applications/{id}/bot-policy", authz(middleware.RequirePermission("bot_policy.edit")(http.HandlerFunc(botPolicyHandler.Put))))
		mux.Handle("POST /api/v1/applications/{id}/bot-policy/preflight", authz(middleware.RequirePermission("bot_policy.edit")(http.HandlerFunc(botPolicyHandler.Preflight))))
		// 安全回归证据登记与发布门禁（WDSP P1-04 R3 §7.1；权限种子见迁移 000135；
		// 导入只接受已登记受控对象 ID，不接收 URL/路径/压缩包/shell，不执行测试命令）
		mux.Handle("GET /api/v1/security/regressions", authz(middleware.RequirePermission("security_regression.read")(http.HandlerFunc(regressionHandler.List))))
		mux.Handle("GET /api/v1/security/regressions/{id}", authz(middleware.RequirePermission("security_regression.read")(http.HandlerFunc(regressionHandler.Get))))
		mux.Handle("GET /api/v1/security/regressions/{id}/cases", authz(middleware.RequirePermission("security_regression.read")(http.HandlerFunc(regressionHandler.ListCases))))
		mux.Handle("POST /api/v1/security/regressions/imports", authz(middleware.RequirePermission("security_regression.import")(http.HandlerFunc(regressionHandler.Import))))
		mux.Handle("GET /api/v1/security/regression-policy", authz(middleware.RequirePermission("security_regression.read")(http.HandlerFunc(regressionHandler.GetPolicy))))
		mux.Handle("PUT /api/v1/security/regression-policy", authz(middleware.RequirePermission("security_regression.policy")(http.HandlerFunc(regressionHandler.PutPolicy))))
		mux.Handle("POST /api/v1/security/regression-objects", authz(middleware.RequirePermission("security_regression.import")(http.HandlerFunc(regressionHandler.UploadObject))))
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
		// 头合规与路径转发（站点级 HTTP 头合规 / HTTP 代理配置 / 路径粒度转发）
		appconfigs.RegisterRoutes(mux, authz, appconfigs.NewHandler(appconfigs.NewStore(db), auditSvc))

		// 站点资产被动发现（mirrorcap 嗅探入库，采集器装配见 cmd/api/main.go；
		// 权限点 site_discovery.read/manage，种子见迁移 000077）
		sitediscovery.RegisterRoutes(mux, authz, sitediscovery.NewHandler(sitediscovery.NewStore(db), auditSvc))

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
	mux.Handle("GET /api/v1/waf-rules/effect-statistics", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(eventHandler.RuleEffectStats))))
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

	// CNNVD 漏洞档案（WAF 规则 CNNVD 兼容性 P1；读沿用 waf_rules.read，写用 waf_rule.vuln_ref.edit）
	mux.Handle("GET /api/v1/waf/vuln-refs", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(vulnRefHandler.List))))
	mux.Handle("POST /api/v1/waf/vuln-refs", authz(middleware.RequirePermission("waf_rule.vuln_ref.edit")(http.HandlerFunc(vulnRefHandler.Create))))
	mux.Handle("GET /api/v1/waf/vuln-refs/{cnnvd_id}", authz(middleware.RequirePermission("waf_rules.read")(http.HandlerFunc(vulnRefHandler.Get))))
	mux.Handle("PUT /api/v1/waf/vuln-refs/{cnnvd_id}", authz(middleware.RequirePermission("waf_rule.vuln_ref.edit")(http.HandlerFunc(vulnRefHandler.Update))))
	mux.Handle("DELETE /api/v1/waf/vuln-refs/{cnnvd_id}", authz(middleware.RequirePermission("waf_rule.vuln_ref.edit")(http.HandlerFunc(vulnRefHandler.Delete))))

	// 例外策略
	mux.Handle("GET /api/v1/exceptions", authz(middleware.RequirePermission("exceptions.read")(http.HandlerFunc(exceptionHandler.List))))
	mux.Handle("POST /api/v1/exceptions", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Create))))
	mux.Handle("GET /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.read")(http.HandlerFunc(exceptionHandler.Get))))
	mux.Handle("PUT /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Update))))
	mux.Handle("DELETE /api/v1/exceptions/{id}", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Delete))))
	mux.Handle("POST /api/v1/exceptions/{id}/enable", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Enable))))
	mux.Handle("POST /api/v1/exceptions/{id}/disable", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Disable))))
	// P0-04 契约 §8：例外生效预览（expected_version 乐观锁；不启用/不发布/不回放）
	mux.Handle("POST /api/v1/exceptions/{id}/preview", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(exceptionHandler.Preview))))

	// 安全事件
	mux.Handle("GET /api/v1/security-events", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.List))))
	mux.Handle("GET /api/v1/security-events/export", authz(middleware.RequirePermission("security_events.export")(http.HandlerFunc(eventHandler.Export))))
	mux.Handle("GET /api/v1/security-events/{id}", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.Get))))
	mux.Handle("GET /api/v1/security-events/{id}/related", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.Related))))
	mux.Handle("GET /api/v1/security-events/{id}/remediation", authz(middleware.RequirePermission("security_events.read")(http.HandlerFunc(eventHandler.GetRemediation))))
	mux.Handle("POST /api/v1/security-events/{id}/notes", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.AddNote))))
	mux.Handle("POST /api/v1/security-events/{id}/confirm-attack", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.ConfirmAttack))))
	mux.Handle("POST /api/v1/security-events/{id}/confirm-false-positive", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.ConfirmFalsePositive))))
	mux.Handle("POST /api/v1/security-events/{id}/ignore", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.Ignore))))
	mux.Handle("POST /api/v1/security-events/{id}/resolve", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.Resolve))))
	mux.Handle("POST /api/v1/security-events/{id}/mark-analyzing", authz(middleware.RequirePermission("security_events.disposition")(http.HandlerFunc(eventHandler.MarkAnalyzing))))
	mux.Handle("POST /api/v1/security-events/{id}/create-exception", authz(middleware.RequirePermission("exceptions.manage")(http.HandlerFunc(eventHandler.CreateException))))
	// 阶段5 §十一：事件→黑名单预填（只读；确认创建走 POST /access-rules 携带 source_type=SECURITY_EVENT）
	mux.Handle("GET /api/v1/security-events/{id}/blacklist-prefill", authz(middleware.RequirePermission("access_rules.manage")(http.HandlerFunc(accessRuleHandler.BlacklistPrefill))))

	// 全量访问日志（二期）
	accessLogHandler := accesslogs.NewHandler(accesslogs.NewStore(db), auditSvc)
	mux.Handle("GET /api/v1/access-logs", authz(middleware.RequirePermission("access_logs.read")(http.HandlerFunc(accessLogHandler.List))))
	mux.Handle("GET /api/v1/access-logs/trend", authz(middleware.RequirePermission("access_logs.read")(http.HandlerFunc(accessLogHandler.Trend))))
	mux.Handle("GET /api/v1/access-logs/flow", authz(middleware.RequirePermission("access_logs.read")(http.HandlerFunc(accessLogHandler.Flow))))
	mux.Handle("GET /api/v1/access-logs/export", authz(exportRate(middleware.RequirePermission("access_logs.export")(http.HandlerFunc(accessLogHandler.Export)))))
	mux.Handle("GET /api/v1/access-logs/{id}", authz(middleware.RequirePermission("access_logs.read")(http.HandlerFunc(accessLogHandler.Get))))

	var pcapService *requestpcap.Service
	if cfg.RequestPCAP.Enabled() {
		if encSvc == nil {
			return nil, fmt.Errorf("request PCAP requires the configured master encryption key")
		}
		runtime, err := requestpcap.NewRuntime(db, cfg.RequestPCAP, cfg.WAF.GatewayNodeName, encSvc)
		if err != nil {
			return nil, fmt.Errorf("initialize request PCAP runtime: %w", err)
		}
		a.requestPCAP = runtime
		pcapService, err = requestpcap.NewService(runtime.Store, runtime.Keyring, cfg.RequestPCAP.HotDir, cfg.RequestPCAP.WarmDir)
		if err != nil {
			runtime.Keyring.Close()
			return nil, fmt.Errorf("initialize request PCAP service: %w", err)
		}
	}
	pcapHandler := requestpcap.NewHandler(pcapService, userStore, auditSvc)
	if a.requestPCAP != nil {
		pcapHandler.SetRotation(a.requestPCAP.Rotate)
	}
	pcapHandler.RegisterRoutes(mux, authz, sensitiveRate)
	captureController := requestpcap.NewCaptureController(settingsSvc, cfg.SystemOps.HostctlDir, cfg.WAF.GatewayNodeName, auditSvc)
	mux.Handle("GET /api/v1/request-pcap/capture", authz(middleware.RequirePermission(requestpcap.PermissionCaptureControl)(http.HandlerFunc(captureController.Get))))
	mux.Handle("POST /api/v1/request-pcap/capture", authz(sensitiveRate(middleware.RequirePermission(requestpcap.PermissionCaptureControl)(http.HandlerFunc(captureController.Set)))))

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
	// 威胁情报导入（WDSP P2-C1）：Feodo C2 情报对账写入 IP 黑名单并触发发布；
	// 权限与 accessrules 导入一致（access_rules.import），/api/v1/threat-intel/ 不在授权门控白名单（业务接口）
	mux.Handle("POST /api/v1/threat-intel/import", authz(middleware.RequirePermission("access_rules.import")(http.HandlerFunc(threatIntelHandler.Import))))
	// 漏洞情报提醒（VULN_INTEL MVP；表/权限种子见迁移 000189）：
	// 读 vuln_intel.read（SYSTEM_ADMIN+SECURITY_ADMIN），写 vuln_intel.manage（仅 SYSTEM_ADMIN）；
	// 只提醒，不自动创建 WAF 规则；在线同步为纯下行（硬编码 NVD 地址）。
	mux.Handle("GET /api/v1/vuln-intel/overview", authz(middleware.RequirePermission("vuln_intel.read")(http.HandlerFunc(vulnIntelHandler.Overview))))
	mux.Handle("GET /api/v1/vuln-intel/advisories", authz(middleware.RequirePermission("vuln_intel.read")(http.HandlerFunc(vulnIntelHandler.ListAdvisories))))
	mux.Handle("GET /api/v1/vuln-intel/advisories/{cve_id}", authz(middleware.RequirePermission("vuln_intel.read")(http.HandlerFunc(vulnIntelHandler.GetAdvisory))))
	mux.Handle("POST /api/v1/vuln-intel/sync", authz(middleware.RequirePermission("vuln_intel.manage")(http.HandlerFunc(vulnIntelHandler.Sync))))
	mux.Handle("POST /api/v1/vuln-intel/import", authz(middleware.RequirePermission("vuln_intel.manage")(http.HandlerFunc(vulnIntelHandler.Import))))
	mux.Handle("GET /api/v1/vuln-intel/tech-assets", authz(middleware.RequirePermission("vuln_intel.read")(http.HandlerFunc(vulnIntelHandler.ListTechAssets))))
	mux.Handle("PUT /api/v1/vuln-intel/tech-assets", authz(middleware.RequirePermission("vuln_intel.manage")(http.HandlerFunc(vulnIntelHandler.PutTechAssets))))
	mux.Handle("GET /api/v1/vuln-intel/settings", authz(middleware.RequirePermission("vuln_intel.read")(http.HandlerFunc(vulnIntelHandler.GetSettings))))
	mux.Handle("PUT /api/v1/vuln-intel/settings", authz(middleware.RequirePermission("vuln_intel.manage")(http.HandlerFunc(vulnIntelHandler.PutSettings))))
	// 规则关联事件（阶段5 §8.5）：按 access_rule_id 过滤访问控制事件
	mux.Handle("GET /api/v1/access-rules/{id}/events", authz(middleware.RequirePermission("access_rules.read")(http.HandlerFunc(acEventHandler.ListByRule))))
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

	// ---- L7 访问控制（仅 WAF/WDSP 交付形态注册；edition=api 不出现）----
	// 发布复用既有 gateway 发布链（生成版本走 accesscontrolversions 机制，审计由发布处理器记录）。
	if cfg.Product.WebWAFProtectionEnabled() {
		mux.Handle("GET /api/v1/l7-rules", authz(middleware.RequirePermission("l7rules.read")(http.HandlerFunc(l7RuleHandler.List))))
		mux.Handle("POST /api/v1/l7-rules", authz(middleware.RequirePermission("l7rules.create")(http.HandlerFunc(l7RuleHandler.Create))))
		mux.Handle("GET /api/v1/l7-rules/{id}", authz(middleware.RequirePermission("l7rules.read")(http.HandlerFunc(l7RuleHandler.Get))))
		mux.Handle("PATCH /api/v1/l7-rules/{id}", authz(middleware.RequirePermission("l7rules.update")(http.HandlerFunc(l7RuleHandler.Update))))
		mux.Handle("DELETE /api/v1/l7-rules/{id}", authz(middleware.RequirePermission("l7rules.delete")(http.HandlerFunc(l7RuleHandler.Delete))))
		mux.Handle("POST /api/v1/l7-rules/test", authz(middleware.RequirePermission("l7rules.read")(http.HandlerFunc(l7RuleHandler.Test))))
		if gatewayHandler != nil {
			mux.Handle("POST /api/v1/l7-rules/publish", authz(middleware.RequirePermission("l7rules.publish")(http.HandlerFunc(gatewayHandler.Publish))))
		}
	}

	// ---- client_identity 体系与行为策略（WDSP AI 自动化渗透防护增强 阶段1；
	// 表见迁移 000097/000098，权限种子见 000099；数据由 identity-events 采集器写入，装配见 cmd/api/main.go）----
	mux.Handle("GET /api/v1/security/identities", authz(middleware.RequirePermission("security_identities.read")(http.HandlerFunc(identityHandler.List))))
	mux.Handle("GET /api/v1/security/identities/{id}", authz(middleware.RequirePermission("security_identities.read")(http.HandlerFunc(identityHandler.Get))))
	mux.Handle("GET /api/v1/security/identities/{id}/behavior", authz(middleware.RequirePermission("security_identities.read")(http.HandlerFunc(identityHandler.Behavior))))
	mux.Handle("GET /api/v1/security/identities/{id}/events", authz(middleware.RequirePermission("security_identities.read")(http.HandlerFunc(identityHandler.Events))))
	mux.Handle("POST /api/v1/security/identities/{id}/block", authz(middleware.RequirePermission("security_identities.block")(http.HandlerFunc(identityHandler.Block))))
	mux.Handle("POST /api/v1/security/identities/{id}/unblock", authz(middleware.RequirePermission("security_identities.block")(http.HandlerFunc(identityHandler.Unblock))))
	mux.Handle("GET /api/v1/security/behavior-policy", authz(middleware.RequirePermission("behavior_policy.read")(http.HandlerFunc(behaviorPolicyHandler.Get))))
	mux.Handle("PUT /api/v1/security/behavior-policy", authz(middleware.RequirePermission("behavior_policy.edit")(http.HandlerFunc(behaviorPolicyHandler.Update))))
	mux.Handle("GET /api/v1/security/risk-policy", authz(middleware.RequirePermission("risk_policy.read")(http.HandlerFunc(riskPolicyHandler.Get))))
	mux.Handle("PUT /api/v1/security/risk-policy", authz(middleware.RequirePermission("risk_policy.edit")(http.HandlerFunc(riskPolicyHandler.Update))))
	riskpolicy.RegisterOverrideRoutes(mux, authz, riskOverrideHandler)
	// 攻击活动（WDSP AI 自动化渗透防护增强 阶段4；表见迁移 000103，权限种子见 000104；
	// 数据由 attacksessions 聚合器 60s 一轮异步维护，StartStage6Workers 内启动）
	mux.Handle("GET /api/v1/security/attack-sessions", authz(middleware.RequirePermission("attack_sessions.read")(http.HandlerFunc(attackSessionHandler.List))))
	mux.Handle("GET /api/v1/security/attack-sessions/{id}", authz(middleware.RequirePermission("attack_sessions.read")(http.HandlerFunc(attackSessionHandler.Get))))

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
	mux.Handle("GET /api/v1/analytics/site-access-trends", authz(analyticsSec(http.HandlerFunc(analyticsHandler.SiteAccessTrends))))
	mux.Handle("GET /api/v1/analytics/site-access-trends/domains", authz(analyticsSec(http.HandlerFunc(analyticsHandler.SiteAccessTrendDomains))))
	mux.Handle("GET /api/v1/analytics/site-traffic", authz(analyticsSec(http.HandlerFunc(analyticsHandler.SiteTraffic))))
	mux.Handle("GET /api/v1/analytics/disposition-overview", authz(middleware.RequirePermission("analytics.disposition.read")(http.HandlerFunc(analyticsHandler.DispositionOverview))))
	// 报告（含模板/任务/归档，权限在 handler 路由层）
	reportHandler.RegisterRoutes(mux, authz)
	// 运行监控
	mux.Handle("GET /api/v1/system-health", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.SystemHealth))))
	mux.Handle("GET /api/v1/system-health/components", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.Components))))
	mux.Handle("GET /api/v1/system-health/storage", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(healthHandler.Storage))))
	mux.Handle("GET /api/v1/metrics", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(audits.RenderMetrics()))
	}))))
	// 系统告警
	alertRead := requireAnyPerm("system_alerts.read", "system_alerts.read_security", "system_alerts.read_audit")
	alertWrite := requireAnyPerm("system_alerts.acknowledge", "system_alerts.acknowledge_security")
	mux.Handle("GET /api/v1/system-alerts", authz(alertRead(http.HandlerFunc(alertHandler.List))))
	// 告警导出（CSV，防公式注入，上限 10000 条；导出类接口共享限流）
	mux.Handle("GET /api/v1/system-alerts/export", authz(exportRate(alertRead(http.HandlerFunc(alertHandler.Export)))))
	mux.Handle("GET /api/v1/system-alerts/{id}", authz(alertRead(http.HandlerFunc(alertHandler.Get))))
	mux.Handle("POST /api/v1/system-alerts/{id}/acknowledge", authz(alertWrite(http.HandlerFunc(alertHandler.Acknowledge))))
	mux.Handle("POST /api/v1/system-alerts/{id}/resolve", authz(alertWrite(http.HandlerFunc(alertHandler.Resolve))))
	mux.Handle("POST /api/v1/system-alerts/{id}/ignore", authz(alertWrite(http.HandlerFunc(alertHandler.Ignore))))
	mux.Handle("POST /api/v1/system-alerts/{id}/notes", authz(alertWrite(http.HandlerFunc(alertHandler.AddNote))))
	// 告警静默/恢复（P1-08）：静默期内同指纹告警仍记录但不重复外发
	mux.Handle("POST /api/v1/system-alerts/{id}/silence", authz(alertWrite(http.HandlerFunc(alertHandler.Silence))))
	mux.Handle("POST /api/v1/system-alerts/{id}/resume", authz(alertWrite(http.HandlerFunc(alertHandler.Resume))))
	// 告警维护窗口（阶段6 §11.5）：窗口内匹配告警评估抑制，抑制计入 suppressed_count 可观测
	mux.Handle("GET /api/v1/system-alerts/maintenance-windows", authz(alertRead(http.HandlerFunc(alertHandler.ListMaintenanceWindows))))
	mux.Handle("POST /api/v1/system-alerts/maintenance-windows", authz(alertWrite(http.HandlerFunc(alertHandler.CreateMaintenanceWindow))))
	mux.Handle("DELETE /api/v1/system-alerts/maintenance-windows/{id}", authz(alertWrite(http.HandlerFunc(alertHandler.DeleteMaintenanceWindow))))
	// 告警通知外发（一期）：渠道 CRUD / 发送测试 / 元数据
	mux.Handle("GET /api/v1/notification-meta", authz(middleware.RequirePermission("notification.read")(http.HandlerFunc(notifyHandler.Meta))))
	mux.Handle("GET /api/v1/notification-channels", authz(middleware.RequirePermission("notification.read")(http.HandlerFunc(notifyHandler.List))))
	mux.Handle("POST /api/v1/notification-channels", authz(middleware.RequirePermission("notification.update")(http.HandlerFunc(notifyHandler.Create))))
	mux.Handle("PUT /api/v1/notification-channels/{id}", authz(middleware.RequirePermission("notification.update")(http.HandlerFunc(notifyHandler.Update))))
	mux.Handle("DELETE /api/v1/notification-channels/{id}", authz(middleware.RequirePermission("notification.update")(http.HandlerFunc(notifyHandler.Delete))))
	mux.Handle("POST /api/v1/notification-channels/{id}/test", authz(middleware.RequirePermission("notification.test")(http.HandlerFunc(notifyHandler.Test))))
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

	// ---- 阶段8 / WDSP：API 动态防护（任务书 /api/v1/api-security 命名空间）----
	if cfg.Product.APIDynamicProtectionEnabled() {
		authzStore := apiauthz.NewStore(db)
		authzKeyHex, authzKeyErr := apiauthz.LoadOrCreateObjectHMACKey(context.Background(), settingsSvc, encSvc)
		if authzKeyErr != nil {
			return nil, fmt.Errorf("initialize API authorization object key: %w", authzKeyErr)
		}
		a.authzStore = authzStore
		a.authzKeyHex = authzKeyHex
		apiEndpointStore := apiassets.NewStore(db)
		apiModelStore := apimodels.NewStore(db)
		apiEndpointHandler := apiassets.NewHandler(apiEndpointStore, auditSvc).
			SetExportModelReader(apiModelStore).
			SetExportExtrasProvider(apiEndpointStore)
		apiassets.RegisterRoutes(mux, authz, apiEndpointHandler, exportRate)
		apigroups.RegisterRoutes(mux, authz, apigroups.NewHandler(apigroups.NewStore(db), auditSvc))
		apiModelHandler := apimodels.NewHandler(apiModelStore, auditSvc)
		apimodels.RegisterRoutes(mux, authz, apiModelHandler)
		apiSecurityHandler := apisecurity.NewHandler(apisecurity.NewStore(db), auditSvc)
		// 策略接口：产品设置 + settings 覆盖 + 发布通道（publisher 不可用时发布接口返回 503）
		apiSecurityHandler.SetPolicySource(apisecurity.PolicySourceFromProduct(cfg.Product))
		apiSecurityHandler.SetPolicySettings(settingsSvc)
		if publisher != nil {
			apiSecurityHandler.SetPolicyPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) (*apisecurity.PolicyPublishResult, error) {
				task, err := publisher.PublishSync(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid})
				if err != nil {
					return nil, err
				}
				return &apisecurity.PolicyPublishResult{TaskID: task.ID.String(), Status: task.Status}, nil
			})
			// Runtime 策略回滚后重触发整站发布（P0-21；未接线时回滚接口返回 503）
			apiModelHandler.SetRuntimePolicyPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) (*apimodels.RuntimePolicyPublishResult, error) {
				task, err := publisher.PublishSync(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid})
				if err != nil {
					return nil, err
				}
				return &apimodels.RuntimePolicyPublishResult{TaskID: task.ID.String(), Status: task.Status}, nil
			})
		}
		apisecurity.RegisterRoutes(mux, authz, apiSecurityHandler)
		apidataflow.RegisterRoutes(mux, authz, apidataflow.NewHandler(
			newAPIDataflowReader(chManager.ResolveQuerier, db)).SetAudits(auditSvc))
		// 弱点中心（P0-13）与敏感数据管理面（P0-19）：权限点在各自路由层（种子见迁移 000041）
		apiweakness.RegisterRoutes(mux, authz, apiweakness.NewHandler(apiweakness.NewStore(db), auditSvc))
		apiDataHandler := apidata.NewHandler(apidata.NewStore(db), auditSvc)
		if encSvc != nil {
			apiDataHandler.SetMaskCryptoLoader(apidata.MaskCryptoLoader(guardconfig.NewMaskCryptoLoader(settingsSvc.GetString, encSvc.Decrypt)))
		}
		apidata.RegisterRoutes(mux, authz, apiDataHandler)
		// 授权基线（P0-15/16/17）：角色基线/对象权属/字段权限/BOLA 评估（种子见迁移 000048）
		authzHandler := apiauthz.NewHandler(authzStore, auditSvc)
		// 可信对象关系确认进入既有整站配置发布链；发布任务创建失败仅记录日志，
		// 已确认关系保留在数据库中，后续发布可重试带上最新授权快照。
		if publisher != nil {
			authzPublish := func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("authorization relation publish trigger failed", "error", err)
				}
			}
			authzHandler.SetPublishFunc(authzPublish)
			a.authzPublish = authzPublish
		}
		apiauthz.RegisterRoutes(mux, authz, authzHandler)
		// gRPC 描述符集（W14-DESC / P2-05 深化）：protoset 上传/列表/删除（权限复用 api_spec.manage，表见迁移 000076）
		apigrpcdesc.RegisterRoutes(mux, authz, apigrpcdesc.NewHandler(apigrpcdesc.NewStore(db), auditSvc))
		// MCP 工具目录与绑定（NG-MCP G1 批次 B1，表见迁移 000181/000182；权限复用 api_spec.read/manage 零新增）；
		// 绑定变更触发既有整站发布链热生效（发布失败仅记日志，绑定已落库可随后续发布重试——apiflows 同一口径）
		mcpHandler := apimcp.NewHandler(apimcp.NewStore(db), auditSvc)
		if publisher != nil {
			mcpHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("mcp catalog binding publish trigger failed", "error", err)
				}
			})
		}
		apimcp.RegisterRoutes(mux, authz, mcpHandler)
		// 机器身份登记（NG-ID g1 批次 B1，表见迁移 000183/000184；权限复用 jwt_trust.read/manage
		// 零新增——可信密钥管理同域）；身份/键/绑定/水位变更触发既有整站发布链热生效
		//（发布失败仅记日志，登记已落库可随后续发布重试——apimcp 同一口径）
		machineIDHandler := apimachineid.NewHandler(apimachineid.NewStore(db), auditSvc)
		if publisher != nil {
			machineIDHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("machine identity publish trigger failed", "error", err)
				}
			})
		}
		apimachineid.RegisterRoutes(mux, authz, machineIDHandler)
		// 业务流程基线（§44 发布下发面）：CRUD（权限 api_flow.read/manage，种子见迁移 000155）；
		// 基线变更触发现有整站发布链热生效（发布失败仅记日志，基线已落库可随后续发布重试）
		flowHandler := apiflows.NewHandler(apiflows.NewStore(db), auditSvc)
		if publisher != nil {
			flowHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("api flow baseline publish trigger failed", "error", err)
				}
			})
		}
		apiflows.RegisterRoutes(mux, authz, flowHandler)
		// 强流程定义（NG-FLOW-01）：CRUD+activate/retire（权限沿用 api_flow.read/manage
		// 既有种子，零新增权限点）；写操作 HIGH 审计；activate/retire 挂既有整站发布链
		// 热生效（NG-FLOW-02 闭环 FLOW-01 偏差 2——消费侧网关轨已就位；发布失败仅记
		// 日志，定义已落库可随后续发布重试）
		strongflowHandler := strongflow.NewHandler(strongflow.NewStore(db), auditSvc)
		if publisher != nil {
			strongflowHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("strong flow publish trigger failed", "error", err)
				}
			})
		}
		strongflow.RegisterRoutes(mux, authz, strongflowHandler)
		// 权威关系接入（NG-AZ-01）：来源登记/启停/范围/钥匙轮换 + 离线签名批次导入 +
		// 水位/缺口/冲突状态（权限 api_authorization.authority_manage/import，读沿用
		// api_authorization.read；种子见迁移 000172；导入成功触发整站发布——与手工
		// 确认关系同一生效通道，发布失败仅记日志，关系已落库可随后续发布重试）
		authorityHandler := apiauthzauthority.NewHandler(
			apiauthzauthority.NewService(apiauthzauthority.NewStore(db)), auditSvc)
		if publisher != nil {
			authorityHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("authority import publish trigger failed", "error", err)
				}
			})
		}
		apiauthzauthority.RegisterRoutes(mux, authz, authorityHandler)
		// 节点授权 ACK 视图（NG-AZ-02 D6）：全节点水位/租约/陈旧窗口/ack_state 五态
		// 只读查询（权限沿用 api_authorization.read，无新权限点；漂移上限经系统设置
		// authz.clock_skew_max_seconds 覆盖，默认 60s 夹紧 10~300s，D8）
		apiauthzacks.RegisterRoutes(mux, authz,
			apiauthzacks.NewHandler(apiauthzacks.NewStore(db), settingsSvc))
		// PROTECT 切换向导（NG-AZ-04 §4.A）：readiness 派生（唯一事实源）/影响评估/
		// 业务确认单生命周期/OPEN 冲突独立查询；权限全部沿用 api_authorization.*
		// 既有点零新增；节点能力经 sidecar 清单检查（发布门同一事实源）。
		wizardStore := apiauthzwizard.NewStore(db)
		apiauthzwizard.RegisterRoutes(mux, authz,
			apiauthzwizard.NewHandler(wizardStore, apiauthzacks.NewStore(db), settingsSvc,
				apiauthzwizard.SidecarCapabilityChecker(cfg.WAF.SidecarDir)))
		// 已吊销凭据（§35 凭据异常数据源）：CRUD（权限 api_credential.read/manage，种子见迁移 000156）；
		// 吊销时效敏感，变更同样触发整站发布链热生效（口径同上）
		revokedHandler := apirevokedcreds.NewHandler(apirevokedcreds.NewStore(db), auditSvc)
		if publisher != nil {
			revokedHandler.SetPublishFunc(func(ctx context.Context, uid uuid.UUID, rid string) {
				if _, err := publisher.Publish(ctx, gatewayconfig.PublishInput{RequestedBy: uid, RequestID: rid}); err != nil {
					slog.Error("revoked credential publish trigger failed", "error", err)
				}
			})
		}
		apirevokedcreds.RegisterRoutes(mux, authz, revokedHandler)
		// API 主动扫描（P1-07）：目标/授权/任务/发现 + 复测桥接弱点中心（权限种子见迁移 000056）；
		// 签名密钥不可用时探针降级为不带签名头（WARN 记录），不阻断装配
		scanStore := apiscan.NewStore(db)
		scanSigner, scanSignErr := apiscan.LoadOrCreateSigner(context.Background(), settingsSvc, encSvc)
		if scanSignErr != nil {
			slog.Warn("api scan signer unavailable, probes run unsigned", "error", scanSignErr)
		}
		a.scanWorker = apiscan.NewWorker(scanStore, apiscan.NewBuiltinEngine(nil), scanSigner, settingsSvc, auditSvc)
		apiscan.RegisterRoutes(mux, authz,
			apiscan.NewHandler(scanStore, auditSvc).
				SetController(a.scanWorker).
				SetRetest(apiscan.NewBuiltinEngine(nil), scanSigner, apiscan.NewWeaknessRetestWriter(apiweakness.NewStore(db))))
		// 数据出境（P1-03）：GeoIP 数据文件缺失时 nil 降级（Sweep 空转、看板 geo_enabled=false）
		if mmdb, err := apigeo.OpenMMDB(filepath.Join(cfg.Gateway.DataDir, "geoip", "country.mmdb")); err != nil {
			slog.Warn("api geo mmdb unavailable, cross-border detection degraded", "error", err)
		} else {
			a.apiGeoLookup = mmdb
		}
		apigeo.RegisterRoutes(mux, authz, apigeo.NewHandler(apigeo.NewStore(db), a.apiGeoLookup, settingsSvc))
		// 态势访问来源 Geo 维度（mmdb 缺失时 a.apiGeoLookup 为 nil，不注入保持降级；
		// 注意 typed-nil：*apigeo.MMDB(nil) 注入接口后非 nil 守卫会失效，必须判空后注入）
		if a.apiGeoLookup != nil {
			apiSecurityHandler.SetGeoLookup(a.apiGeoLookup)
		}
		// API 网络暴露面判定引擎（迁移 000190）：读复用 api_asset.read、重评复用
		// api_asset.edit（零新增权限点）；公网 DNS 视角判定器按 settings 配置服务器
		// 拨号；周期评估由 cmd/api/main.go sweeper 群启动；采集钩子注入见
		// main.go apiruntime Collector SetSourceRecorder
		exposureStore := apiexposure.NewStore(db)
		a.apiExposureSweeper = apiexposure.NewSweeper(exposureStore, settingsSvc).
			SetResolver(apiexposure.NewPublicResolver())
		apiexposure.RegisterRoutes(mux, authz,
			apiexposure.NewHandler(exposureStore, auditSvc).SetSweeper(a.apiExposureSweeper))
		// LLM API 安全观测与输入保护策略管理
		llmStore := apillm.NewStore(db)
		apillm.RegisterRoutes(mux, authz, apillm.NewHandler(llmStore))
		apillm.RegisterSecurityPolicyRoutes(mux, authz, apillm.NewSecurityPolicyHandler(llmStore, auditSvc))
		// 多节点版本校验（§201 遥测路径）：节点列表/一致性视图 + 周期聚合（权限复用 api_runtime.read）
		apiNodeStore := apinodes.NewStore(db)
		a.apiNodesSweeper = apinodes.NewSweeper(apiNodeStore).SetAlerter(alertEngine)
		apinodes.RegisterRoutes(mux, authz, apinodes.NewHandler(apiNodeStore).SetAudits(auditSvc))
		// 统一执行覆盖查询（NG-COV-02 查询侧）：五态聚合 agg / 节点阶段计数 stages
		// （权限 api_protection.read，种子见迁移 000169；采集摄入见 cmd/api/main.go）
		coverage.RegisterRoutes(mux, authz, coverage.NewHandler(coverage.NewStore(db)))
		// 无副作用模拟（NG-COV-03）：POST/GET protection/validations——脱敏 Finding 批次
		// 决策层重放（零副作用）；策略摘要取发布链当前生效版本 configuration_hash，
		// 模式与发布链同口径（EffectiveAPIProtectionMode）；创建 api_protection.validate、
		// 读取 api_protection.read（种子见迁移 000170/000169）
		validationSvc := validations.NewService(validations.NewStore(db),
			validations.NewPublishPolicySource(db, func() decision.Mode {
				return decision.Mode(cfg.Product.EffectiveAPIProtectionMode())
			}))
		validations.RegisterRoutes(mux, authz, validations.NewHandler(validationSvc))
		// GraphQL 成本预算策略（NG-GQL-03 管理面）：apps/{id}/graphql-policy 读/写/删
		// （权限沿用 api_policy.read/edit 无新权限点；表见迁移 000171；发布链见上注入）
		apigql.RegisterRoutes(mux, authz, apigql.NewHandler(apigql.NewStore(db), auditSvc))
		// 多节点发布扇出（§200 配置面同步）：主发布成功后将同一份配置推送至登记的次要节点（逐节点记录结果）
		if publisher != nil {
			publisher.SetNodeSyncStore(apiNodeStore)
			publisher.SetSyncAlerter(syncAlerterAdapter{alertEngine})
		}
		// 文件资产（P1-04）：列表/统计（权限复用 api_data.read）
		apifiles.RegisterRoutes(mux, authz, apifiles.NewHandler(apifiles.NewStore(db)))
		// 文件合规规则（P2-03 管理面）+ 文件签名验证/密钥轮换（P2-02 验证面）
		apifiles.RegisterComplianceRoutes(mux, authz, apifiles.NewComplianceHandler(apifiles.NewComplianceStore(db), auditSvc))
		apifiles.RegisterSignatureRoutes(mux, authz, apifiles.NewSignatureHandler(settingsSvc, encSvc, auditSvc))
		// AI 定时运营任务（P1-02 续；表见迁移 000062，权限种子见 000063，熔断列见 000187）；
		// 全局开关 api_ai_ops.schedules_enabled（settings，默认关）门控调度与立即执行；
		// 连续失败达 api_ai_ops.circuit_threshold（默认 3）自动熔断停用，
		// 熔断经系统告警引擎 Raise（AI_OPS_SCHEDULE_CIRCUIT_OPEN，HIGH，组件 AI_OPS）+ 操作审计
		aiOpsStore := apiops.NewStore(db)
		a.aiOpsSweeper = apiops.NewSweeper(aiOpsStore, apiops.NewSQLSource(db)).
			SetSettings(settingsSvc).
			SetAudits(auditSvc).
			SetAlerter(alertEngine)
		// AI 能力增强第一波：AI 模块启用时接 LLM 摘要润色（模型网关低复杂度档位）；
		// 润色失败/空输出由 apiops polishSummary 回退模板草稿，AI 关闭时不接（纯模板摘要）
		if cfg.AI.Enabled {
			a.aiOpsSweeper.SetSummarizer(newAIOpsSummarizer(aiGateway))
		}
		apiops.RegisterRoutes(mux, authz, apiops.NewHandler(aiOpsStore, auditSvc).SetRunner(a.aiOpsSweeper))
		// API 专项指标（§158 有数据源子集）：Prometheus 文本输出（采集由 StartAPIMetrics 启动）
		a.apiMetrics = metrics.NewAPICollector(db)
		mux.Handle("GET /api/v1/api-security/metrics", authz(middleware.RequirePermission("api_runtime.read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = w.Write([]byte(a.apiMetrics.Render()))
		}))))
		// WDSP 阶段A：节点网口管理（清单采集见 cmd/api/main.go；权限复用 system_health/system_settings）
		nodeinterfaces.RegisterRoutes(mux, authz, nodeinterfaces.NewHandler(nodeinterfaces.NewStore(db), auditSvc))
		// WDSP：页面配置网桥与路由牵引（docs/NETWORK_MODES_DESIGN.md §七；网络变更 MEDIUM 风险审计，
		// 严格校验 MANAGEMENT 口禁入桥、成员口存在且 present、CIDR/IP 合法，仅默认节点可写）
		netHandler := netconfig.NewHandler(netconfig.NewStore(db), nodeinterfaces.NewStore(db), auditSvc, cfg.WAF.GatewayNodeName)
		netHandler.SetSidecarDir(cfg.WAF.SidecarDir)
		netconfig.RegisterRoutes(mux, authz, netHandler)
		// WDSP：主备高可用（VIP 漂移 + 端口联动，docs/HA_ACTIVE_STANDBY_DESIGN.md §8）；
		// 成员节点限定已登记网关节点（apinodes），VRRP 认证串经 encSvc 加密落库，高危审计
		haHandler := hagroups.NewHandler(hagroups.NewStore(db), haNodeLister{apiNodeStore}, encSvc, auditSvc)
		haHandler.SetSidecarDir(cfg.WAF.SidecarDir)
		hagroups.RegisterRoutes(mux, authz, haHandler)
		// HA/网络执行状态告警清扫（M4）：周期读本节点边车状态文件 → 系统告警 → 通知渠道
		a.haStatusSweeper = hastatus.NewSweeper(cfg.WAF.SidecarDir).SetAlerter(alertEngine)
	}
	// 产品 edition 探测（已登录可读，供前端菜单/路由按产品形态过滤）。
	// 生效形态由授权决定：有效授权按 license.product 返回 edition，能力位与包装配能力取交集
	// （wdsp 包 + waf 授权 → edition=waf 且 API 能力 false；waf 包未装配 API 能力则授权
	// wdsp/api 也无法解锁，api_dynamic_protection 如实为 false）；无有效授权如实返回
	// license_valid=false 与空 edition（向后兼容字段保留不删）。
	mux.Handle("GET /api/v1/product/edition", authz(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := licSvc.State()
		edition := ""
		apiDyn, webWAF := false, false
		if st.Valid {
			edition = st.Product
			switch st.Product {
			case "waf":
				webWAF = cfg.Product.WebWAFProtectionEnabled()
			case "api":
				apiDyn = cfg.Product.APIDynamicProtectionEnabled()
			default: // wdsp：两个能力域均按包装配能力取交集
				apiDyn = cfg.Product.APIDynamicProtectionEnabled()
				webWAF = cfg.Product.WebWAFProtectionEnabled()
			}
		}
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"edition":                edition,
			"license_valid":          st.Valid,
			"api_dynamic_protection": apiDyn,
			"web_waf_enabled":        webWAF,
			// APM 为共享底座能力（ADR D11），不参与授权 product 交集：运行期总开关
			// （界面设置 apm:enabled 优先、APM_ENABLED 环境变量兜底，热生效）
			"apm_enabled":           apmRuntimeCfg.Enabled(r.Context()),
			"product_name":          product.ProductDisplayName(product.Edition(edition)),
			"max_body_parse_bytes":  cfg.Product.MaxBodyParseBytes,
			"max_body_sample_bytes": cfg.Product.MaxBodySampleBytes,
		})
	})))

	// ---- APM 业务性能监控（无 Agent 模式起步，docs/APM_STAGE0_ADR.md；共享底座能力）----
	// 总开关运行期热生效（界面设置 apm:enabled 优先、APM_ENABLED 兜底）：路由恒注册，
	// 关闭时经 gate 统一 503 降级（响应报文与原启动期 stub 完全一致）。
	// 管理面路由经 gatedAuthz 把 gate 挂在 authz 链内，保持原 stub 的认证/CSRF 前置
	// 行为（匿名 POST 先被 CSRF 拦 403 而非直接 503）；Agent 机器端点由 MachineGate
	// 按开关在"无会话直通"与"authz + 503 stub"间切换。
	agentCfg := apm.NewAgentControlConfig(cfg.APM.CollectorAddr, cfg.APM.AgentCertTTLHours, cfg.APM.AgentOfflineMinutes)
	// 内置 CA 材料经 encSvc 加密落系统设置（JIUZHANG_MASTER_KEY 体系，私钥不落明文）；
	// 加载失败 fail-closed（不静默降级为无 CA 运行）。
	agentCA, caErr := apm.LoadOrCreateAgentCA(context.Background(), settingsSvc, encSvc)
	if caErr != nil {
		return nil, fmt.Errorf("initialize APM agent CA: %w", caErr)
	}
	agentStore := apm.NewAgentStore(db)
	diagStore := apm.NewDiagnosticsStore(db)
	gatedAuthz := func(h http.Handler) http.Handler { return authz(apm.NewGate(apmRuntimeCfg, h)) }
	// ClickHouse 查询器由 CHManager 逐次解析（DSN 热更新后新查询走重建连接；
	// 未接入时解析为 nil，OTel 检索降级 agentless 空数据）。
	apm.RegisterRoutes(mux, gatedAuthz,
		apm.NewHandler(apm.NewStore(db, chManager.ResolveQuerier), settingsSvc, agentCfg.OfflineAfter))
	// APM SLO 目标管理（设计 §16.2/§18；读 apm.overview.read、写 apm.settings.manage，
	// 写操作中风险审计）
	apm.RegisterSLORoutes(mux, gatedAuthz, apm.NewSLOHandler(apm.NewSLOStore(db)).SetAudits(auditSvc))
	// APM 阶段2 上半：Agent 控制面（设计 §8.3/§9/§16.2）。
	// 管理接口走会话 + RBAC（变更全部高风险审计）；
	// Agent 面接口为机器端点——开启时不挂 authz 链（无会话/CSRF 面），
	// 注册用一次性令牌、其余用 CA 证书 PoP 签名认证（见 apm/agentapi_handler.go）。
	apm.RegisterAgentAdminRoutes(mux, gatedAuthz,
		apm.NewAgentAdminHandler(agentStore, agentCA, agentCfg).SetAudits(auditSvc))
	agentMux := http.NewServeMux()
	apm.RegisterAgentDataRoutes(agentMux, apm.NewAgentAPIHandler(agentStore, agentCA, agentCfg))
	mux.Handle("/api/v1/apm/agent/", apm.NewMachineGate(apmRuntimeCfg, agentMux, authz))
	// APM 阶段4：深度诊断会话控制面（设计 §6.3/§16.2/§21.2）。
	// 会话/停止/kill switch 全部高风险审计（kill switch 为 Critical），复用 WP8
	// 签名策略机制下发诊断叠加与基线恢复；到期扫描工人每分钟对账（含 stop/kill
	// 同步恢复失败的兜底重试），Agent 失联兜底 = 策略信封硬截止本地失效。
	apm.RegisterDiagnosticRoutes(mux, gatedAuthz,
		apm.NewDiagnosticsHandler(diagStore, agentStore, agentCA, agentCfg).
			SetAudits(auditSvc).SetAuditLister(auditSvc))
	a.apmDiagSweeper = apm.NewDiagnosticsSweeper(diagStore, agentStore, agentCA, agentCfg).
		SetEnabledFunc(apmRuntimeCfg.Enabled)
	// 兜底：开关关闭时未匹配到具体路由的 /api/v1/apm/* 路径同样 503（原 stub 的
	// 子树匹配语义）；开启时 404（无此路由）。
	mux.Handle("/api/v1/apm/", gatedAuthz(http.NotFoundHandler()))
	// APM 总开关与 ClickHouse DSN 专用设置接口：不受 503 门控（否则关闭后无法经
	// 界面重新开启），权限与系统设置一致（system_settings.read/update）；
	// DSN 任何接口不回显原文，写操作高风险审计。
	apm.RegisterSettingsRoutes(mux, authz,
		apm.NewSettingsHandler(apmRuntimeCfg, settingsSvc, chManager).SetAudits(auditSvc))

	// ---- 阶段7：AI 安全运营（可独立启停，关闭不影响 WAF 核心）----
	if cfg.AI.Enabled {
		aiDeps.RegisterRoutes(mux, authz)
		// 详情 GET（阶段7 §30 路径对齐）：权限跟随对应列表接口现有读权限模式，handler 实现见 aihandlers/details_handler.go
		mux.Handle("GET /api/v1/ai/models/{id}", authz(middleware.RequirePermission("ai.models.read")(http.HandlerFunc(aiDeps.ModelGet))))
		mux.Handle("GET /api/v1/ai/agents/{id}", authz(middleware.RequirePermission("ai.agents.read")(http.HandlerFunc(aiDeps.AgentGet))))
		mux.Handle("GET /api/v1/ai/tools/{id}", authz(middleware.RequirePermission("ai.tools.read")(http.HandlerFunc(aiDeps.ToolGet))))
		mux.Handle("GET /api/v1/ai/audits/{id}", authz(middleware.RequirePermission("ai.audits.read")(http.HandlerFunc(aiDeps.AuditGet))))
		mux.Handle("GET /api/v1/ai/evaluations/{id}", authz(requireAnyPerm("ai.evaluations.run", "ai.usage.read", "ai.audits.read")(http.HandlerFunc(aiDeps.EvalRunGet))))
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

	// ---- WDSP 分布式流量采集 Agent（Phase 1 + Phase 2-B，契约 §3/§4/§7-§12）----
	// 管理端走会话 + RBAC（traffic.agents.view/manage，写操作 HIGH 级审计）；
	// 机器端不挂 authz 链（无会话/CSRF 面）：PoP 三头齐全走证书 PoP 认证，全缺回退
	// Bearer wda_ credential 摘要反查（过渡期兼容，防降级纪律见 agents/machine_handler.go）。
	// traffic-agent CA 材料经 encSvc 加密落系统设置（与 APM CA 同构、命名空间独立），
	// 加载失败按 APM 先例 fail-closed（不静默降级为无 CA 运行）。
	trafficAgentCA, caErr := agents.LoadOrCreateAgentCA(context.Background(), settingsSvc, encSvc)
	if caErr != nil {
		return nil, fmt.Errorf("initialize traffic agent CA: %w", caErr)
	}
	agents.RegisterAdminRoutes(mux, authz, agents.NewHandler(trafficAgentStore).SetAudits(auditSvc))
	// Phase 3（契约 §6）：机器端 http 端点挂 API 资产联动（复用 apiassets 既有
	// UpsertDiscovery 入口，与 apiruntime 网关采集器同一通道；离线授权端点配额强制
	// 与 main.go 采集链路同口径——license 内存状态无 IO，无效授权返回 0=不限制）。
	agentHTTPAssets := apiassets.NewStore(db)
	if a.licenseSvc != nil {
		agentHTTPAssets.SetEndpointQuotaProvider(func(context.Context) int64 {
			st := a.licenseSvc.State()
			if !st.Valid {
				return 0
			}
			return st.Quotas.MaxAPIEndpoints
		})
	}
	machineHandler := agents.NewMachineHandler(trafficAgentStore).
		SetCA(trafficAgentCA).SetDiscoveryUpserter(agentHTTPAssets)
	if cfg.Kafka.Enabled {
		brokerConfig := ingest.Config{
			Brokers: cfg.Kafka.Brokers, ClientID: "jiuzhang-server",
			TLSEnabled: cfg.Kafka.TLSEnabled, TLSCAFile: cfg.Kafka.TLSCAFile,
			TLSCertFile: cfg.Kafka.TLSCertFile, TLSKeyFile: cfg.Kafka.TLSKeyFile,
			TLSServerName: cfg.Kafka.TLSServerName, SASLMechanism: cfg.Kafka.SASLMechanism,
			SASLUsername: cfg.Kafka.SASLUsername, SASLPassword: cfg.Kafka.SASLPassword,
			AllowInsecureSASL: cfg.Kafka.AllowInsecureSASL, ProduceTimeout: cfg.Kafka.ProduceTimeout,
			MaxBatchBytes: cfg.Kafka.MaxBatchBytes, MaxBatchRecords: cfg.Kafka.MaxBatchRecords,
		}
		if err := brokerConfig.Validate(); err != nil {
			return nil, fmt.Errorf("Kafka configuration: %w", err)
		}
		a.kafkaBroker = ingest.NewBroker(brokerConfig)
		machineHandler.SetAPIObservationReceiver(a.kafkaBroker, cfg.Kafka.Topic,
			trafficAgentStore, trafficAgentStore, trafficAgentStore)
		a.apiObservationProjector = apidataflow.NewProjector(a.kafkaBroker, a.kafkaBroker,
			cfg.Kafka.Topic, cfg.Kafka.DLQTopic,
			apidataflow.NewCHObservationStore(chManager.ResolveQuerier),
			apidataflow.NewPostgresAssetProjector(db, agentHTTPAssets))
		a.dataflowWorker = apidataflow.NewDataflowWorker(a.kafkaBroker, a.kafkaBroker,
			cfg.Kafka.Topic, cfg.Kafka.DLQTopic,
			apidataflow.NewCHContributionStore(chManager.ResolveQuerier))
	}
	agents.RegisterMachineRoutes(mux, machineHandler)
	// Phase 3（契约 §6）：HTTP 事件保留清理（每日删 created_at 早于 7 天记录，
	// StartStage6Workers 内启动）。
	a.trafficAgentSweeper = agents.NewHTTPEventSweeper(trafficAgentStore)

	// 全局中间件链
	var handler http.Handler = mux
	handler = middleware.MaintenanceGate(&maintenanceFlag{c: c})(handler)
	handler = middleware.RecoverPanic(handler)
	handler = middleware.AccessLog(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.CORS(cfg.Security.CORSAllowedOrigins)(handler)
	handler = middleware.RequestID(handler)
	handler = clientIPMiddleware(handler)
	// 环境标识（P-T1，最外层）：所有响应（含错误与 panic 恢复）携带 X-Jiuzhang-Environment，
	// 独立测试工程门禁在登录前即可识别目标环境（docs/INDEPENDENT_REGRESSION_TEST_AUTOMATION_DESIGN.md §7.1）
	handler = middleware.EnvironmentHeader(cfg.Env)(handler)

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
// SyslogForwarder 返回 syslog 外发器（main 装配采集器 fan-out 与后台发送循环用）。
func (a *App) SyslogForwarder() *syslogfw.Forwarder { return a.syslogFw }

// APIGeoLookup 返回数据出境 GeoIP 读取器（nil = 数据文件缺失降级；main 装配周期 Sweep 用）。
func (a *App) APIGeoLookup() *apigeo.MMDB { return a.apiGeoLookup }

// APIExposureSweeper 返回暴露面判定评估器（nil = API 动态防护未开启；main 挂 sweeper 群用）。
func (a *App) APIExposureSweeper() *apiexposure.Sweeper { return a.apiExposureSweeper }

// NotifyDispatcher 返回告警通知调度器（main 启动其 Run 循环用）。
func (a *App) NotifyDispatcher() *notify.Dispatcher { return a.notifyDispatcher }

// LicenseService 返回离线授权服务（main 装配采集链路配额 provider 用；装配保证非 nil）。
func (a *App) LicenseService() *license.Service { return a.licenseSvc }

// AlertEngine 返回系统告警引擎（main 装配采集链路告警回调用）。
func (a *App) AlertEngine() *systemalerts.Engine { return a.alertEngine }

// APMDiagnosticsSweeper 返回 APM 深度诊断到期扫描工人（恒装配；集成测试经此直接
// 驱动 SweepOnce，不必等待分钟级 ticker）。
func (a *App) APMDiagnosticsSweeper() *apm.DiagnosticsSweeper { return a.apmDiagSweeper }

// AttackSessionAggregator 返回攻击活动会话聚合器（集成测试经此直接驱动 SweepOnce，
// 不必等待 60s ticker；与阶段6集成测试同步驱动后台工人同一纪律）。
func (a *App) AttackSessionAggregator() *attacksessions.Aggregator { return a.attackSessionAgg }

// syslogNotifyAdapter 把 syslogfw.Forwarder 适配为 notify.SyslogSender
// （notify 包不反向依赖 syslogfw；syslog 渠道沿用 logging 组 syslog 配置）。
type syslogNotifyAdapter struct {
	fw *syslogfw.Forwarder
}

func (a syslogNotifyAdapter) EnqueueSyslogAlert(severityHint string, payload interface{}) {
	a.fw.Enqueue(syslogfw.KindSystemAlert, severityHint, payload)
}

func (a syslogNotifyAdapter) SendTestMessage(ctx context.Context) error {
	return a.fw.SendTestMessage(ctx)
}

// notifyEventFromAlert 把系统告警转换为通知事件（值语义快照）。
func notifyEventFromAlert(a systemalerts.Alert) notify.Event {
	return notify.Event{
		AlertType:  a.AlertType,
		Severity:   a.Severity,
		Component:  a.Component,
		Title:      a.Title,
		Message:    a.Message,
		Status:     a.Status,
		OccurredAt: a.LastSeenAt,
	}
}

// StartAPIMetrics 启动 API 专项指标周期采集（仅 WDSP 装配后非 nil；幂等安全）。
func (a *App) StartAPIMetrics(ctx context.Context) {
	if a.apiMetrics != nil {
		go a.apiMetrics.Run(ctx, metrics.DefaultAPICollectInterval)
	}
}

// regressionGateAdapter 适配 gatewayconfig.RegressionGate（regression 包不反引发布包；
// 错误分类在此显式映射——依赖不可用与证据拒绝是两种不同的发布失败码，不混用）。
type regressionGateAdapter struct{ gate *regression.Gate }

func (a regressionGateAdapter) EvaluatePublish(ctx context.Context, in gatewayconfig.RegressionGateInput) gatewayconfig.RegressionGateOutcome {
	res, err := a.gate.Evaluate(ctx, regression.GateInput{
		Fingerprint:    in.Fingerprint,
		PublishTaskID:  &in.TaskID,
		VersionID:      &in.VersionID,
		RestoreChannel: in.RestoreChannel,
	})
	if err == nil {
		return gatewayconfig.RegressionGateOutcome{Allowed: true}
	}
	if errors.Is(err, regression.ErrGateRejected) {
		msg := err.Error()
		if res != nil && len(res.Reasons) > 0 {
			msg = strings.Join(res.Reasons, "; ")
		}
		return gatewayconfig.RegressionGateOutcome{Allowed: false, Message: msg}
	}
	// ErrGateUnavailable 及其他错误统一按依赖不可用处理（明确失败，不静默放行）
	return gatewayconfig.RegressionGateOutcome{Allowed: false, Unavailable: true, Message: err.Error()}
}

// syncAlerterAdapter 适配 gatewayconfig.SyncAlerter（规避 systemalerts→gatewayconfig 传递依赖成环；

// NotifyFailure 返回 (*Alert, error)，适配器收敛为仅 error 的最小接口）。
type syncAlerterAdapter struct{ e *systemalerts.Engine }

func (a syncAlerterAdapter) NotifyFailure(ctx context.Context, alertType, component, title, message string) error {
	_, err := a.e.NotifyFailure(ctx, alertType, component, title, message)
	return err
}

// haNodeLister 适配 hagroups.NodeLister（apinodes 节点登记表为成员节点数据源）。
type haNodeLister struct{ store *apinodes.Store }

func (a haNodeLister) Exists(ctx context.Context, nodeID string) (bool, error) {
	id, err := uuid.Parse(nodeID)
	if err != nil {
		return false, nil
	}
	if _, err := a.store.GetNode(ctx, id); err != nil {
		if errors.Is(err, apinodes.ErrNodeNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (a haNodeLister) Names(ctx context.Context, nodeIDs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, raw := range nodeIDs {
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		n, err := a.store.GetNode(ctx, id)
		if err != nil {
			if errors.Is(err, apinodes.ErrNodeNotFound) {
				continue
			}
			return nil, err
		}
		out[raw] = n.NodeName
	}
	return out, nil
}

func (a *App) StartStage6Workers(ctx context.Context) {
	if a.auditSvc != nil {
		go a.auditSvc.RunFallback(ctx, 10*time.Second)
	}
	if a.reportWorker != nil {
		go a.reportWorker.Run(ctx, 2*time.Second)
	}
	if a.backupWorker != nil {
		go a.backupWorker.Run(ctx)
	}
	if a.netdiagWorker != nil {
		go a.netdiagWorker.Run(ctx, 2*time.Second)
	}
	if a.upgradeSvc != nil {
		go a.upgradeSvc.RunResultReconciler(ctx)
		go a.upgradeSvc.RunScheduler(ctx)
	}
	if a.healthCollector != nil {
		go a.healthCollector.Run(ctx, 30*time.Second)
	}
	// AI 自动降噪：周期聚类扫描（enabled=false 时 ticker 内空转）
	if a.noiseWorker != nil {
		go a.noiseWorker.Run(ctx)
	}
	// API 主动扫描工人（P1-07；settings api_scan.enabled 默认关闭时空转）
	if a.scanWorker != nil {
		go a.scanWorker.Run(ctx)
	}
	if a.apiObservationProjector != nil {
		go a.apiObservationProjector.Run(ctx)
	}
	if a.dataflowWorker != nil {
		go a.dataflowWorker.Run(ctx)
	}
	// AI 定时运营调度（P1-02 续；api_ai_ops.schedules_enabled 默认关闭时空转）
	if a.aiOpsSweeper != nil {
		go a.aiOpsSweeper.Run(ctx)
	}
	// 多节点版本校验聚合（§201 遥测路径；周期从 api_runtime_events 聚合并判定一致性）
	if a.haStatusSweeper != nil {
		go a.haStatusSweeper.Run(ctx)
	}
	if a.apiNodesSweeper != nil {
		go a.apiNodesSweeper.Run(ctx)
	}
	if a.authzStore != nil {
		go func() {
			if a.authzKeyHex != "" {
				if n, err := a.authzStore.MigrateLegacyOwnershipOnce(ctx, a.authzKeyHex); err != nil {
					slog.Warn("api authz legacy ownership migration failed", "error", err)
				} else if n > 0 {
					slog.Info("api authz legacy ownership migration completed", "rows", n)
				}
			}
			run := func() {
				if a.authzKeyHex == "" {
					return
				}
				for {
					res, err := a.authzStore.SweepRelationCandidatesOnce(ctx, a.authzKeyHex)
					if err != nil {
						slog.Warn("api authz candidate sweep failed", "error", err)
						return
					}
					if res == nil || !res.HasMore {
						return
					}
				}
			}
			run()
			expire := func() {
				relations, err := a.authzStore.ExpireObjectRelations(ctx, time.Now().UTC())
				if err != nil {
					slog.Warn("api authz relation expiration failed", "error", err)
					return
				}
				if len(relations) == 0 {
					return
				}
				requestID := "authz-expire-" + time.Now().UTC().Format("20060102T150405Z")
				for _, rel := range relations {
					audits.RecordWithFallback(ctx, a.auditSvc, audits.RecordInput{
						Module: "api_authorization", Action: "expire_object_relation", ObjectType: "api_object_relation",
						ObjectID: rel.ID.String(), BeforeSummary: `{"status":"CONFIRMED"}`,
						AfterSummary: `{"status":"EXPIRED"}`, Result: "SUCCESS", RiskLevel: "HIGH", RequestID: requestID,
					})
				}
				if a.authzPublish != nil {
					a.authzPublish(ctx, uuid.Nil, requestID)
				}
			}
			expire()
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					run()
					expire()
				}
			}
		}()
	}
	// 离线授权周期复核（60s：到期/指纹变化翻转 → 告警 + 触发整站重发布；ctx 取消即退出）
	if a.licenseSvc != nil {
		go a.licenseSvc.Run(ctx)
	}
	// 攻击活动会话聚合（60s：四源事件滑动窗聚合 + 收口 + Business 滥用检测）
	if a.attackSessionAgg != nil {
		go a.attackSessionAgg.Run(ctx)
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
					// API 安全告警评估（P1-08）：CRITICAL finding/激增/MASK 失败
					if err := a.alertEngine.EvaluateAPIFindings(ctx); err != nil {
						slog.Warn("alert api-findings evaluate failed", "error", err)
					}
					// 安全事件聚合告警评估（通知二期）：安全事件激增 / CC 封禁激增
					if err := a.alertEngine.EvaluateSecuritySpikes(ctx); err != nil {
						slog.Warn("alert security-spikes evaluate failed", "error", err)
					}
					// APM 端点性能告警评估（阶段1 WP5）：慢端点 p95 / 端点 5xx 错误率
					// （APM 总开关关闭时评估器内部空转——运行期热生效）
					if err := a.alertEngine.EvaluateEndpointPerf(ctx); err != nil {
						slog.Warn("alert endpoint-perf evaluate failed", "error", err)
					}
					// APM 数据面采集滞后告警评估：ClickHouse otel_traces 最新遥测超阈未更新
					// （APM 关闭空转；DSN 空/连接失败降级时读数 ok=false 自然空转）
					if err := a.alertEngine.EvaluateIngestLag(ctx); err != nil {
						slog.Warn("alert ingest-lag evaluate failed", "error", err)
					}
				}
			}
		}()
	}
	// APM SLO 违约告警评估：每分钟评估全部 SLO（7d/30d 窗口走小时聚合表；
	// APM 总开关关闭时评估器内部空转——运行期热生效，默认部署零行为变化）
	if a.alertEngine != nil {
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := a.alertEngine.EvaluateSLOBreach(ctx); err != nil {
						slog.Warn("alert slo-breach evaluate failed", "error", err)
					}
				}
			}
		}()
	}
	// APM 深度诊断：每分钟到期扫描 + 基线恢复对账（恒装配恒启动；APM 总开关关闭时
	// 每轮空转——运行期热生效。Agent 失联兜底为诊断策略信封硬截止的本地失效，
	// 不依赖本任务——设计 §9.2/§21.2）
	if a.apmDiagSweeper != nil {
		go a.apmDiagSweeper.Run(ctx)
	}
	// WDSP 流量采集 Agent HTTP 事件保留清理（Phase 3 契约 §6：每日删 created_at
	// 早于 7 天记录，硬上限防无限增长；启动即清一轮，单轮失败仅 Warn 下轮重试）
	if a.trafficAgentSweeper != nil {
		go a.trafficAgentSweeper.Run(ctx)
	}
	// 漏洞情报 NVD 每日同步（VULN_INTEL MVP）：vuln_intel.sync_enabled 开启时执行
	// （settings 热读，界面即时生效；关闭时每轮空转——默认部署零行为变化）；
	// 手动同步经 POST /vuln-intel/sync 直连同一同步器（互斥防并发，失败原因落 sync_state）
	if a.vulnIntelSyncer != nil {
		go a.vulnIntelSyncer.RunDaily(ctx, func(ctx context.Context) bool {
			return a.settings.GetBool(ctx, vulnintel.SettingsGroup, vulnintel.KeySyncEnabled, false)
		})
	}
}

// authChain 构造认证链：会话解析 → 认证检查 → CSRF 防护。
func (a *App) authChain() func(http.Handler) http.Handler { // 豁免路径（must_change_password 时也可访问）
	exempt := []string{
		"POST /api/v1/auth/change-password",
		"POST /api/v1/auth/logout",
		"GET /api/v1/auth/me",
	}
	// 离线授权门控：认证链之后逐路由实时判定（license 内存状态，无 IO）；
	// 锁定态白名单与能力域 403 口径见 license.Gate。公开路由（login/captcha/
	// totp-verify/health）不经此链，任何授权状态下永远可达。
	gate := license.Gate(a.licenseSvc)
	return func(next http.Handler) http.Handler {
		// 包装顺序（从外到内执行）：
		// sessionMiddleware(注入Principal) → CSRFProtect → RequireAuth → LicenseGate → next
		h := middleware.RequireAuth(exempt...)(gate(next))
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
	store  *exceptions.Store
	events *securityevents.Store // 重取事件 matches（可信源：规则 ID 证据不接受客户端入参）
}

// CreateFromEvent 实现 securityevents.ExceptionCreator 接口。
// P0-04 契约 §9：ApplicationID/Method/Path（不含 query）/RuleIDs/SourceEventID 全部
// 取自服务端事件记录（规则 ID 经 GetByID 重取 matches 去重）；缺应用或规则证据时
// 草稿为 NEEDS_REVIEW，启用门禁拒绝并说明缺失项。
func (e *eventExceptionCreator) CreateFromEvent(ctx context.Context, evt *securityevents.Event, createdBy uuid.UUID) (uuid.UUID, error) {
	var ruleIDs []int
	if e.events != nil {
		_, matches, err := e.events.GetByID(ctx, evt.ID)
		if err != nil {
			return uuid.Nil, fmt.Errorf("load event %s matches for exception draft: %w", evt.ID, err)
		}
		seen := map[int]bool{}
		for _, m := range matches {
			if m.RuleID > 0 && !seen[m.RuleID] {
				seen[m.RuleID] = true
				ruleIDs = append(ruleIDs, m.RuleID)
			}
		}
		sort.Ints(ruleIDs) // 编译摘要随 rule_ids 顺序变化，排序保证确定性
	}
	return e.store.CreateFromEvent(ctx, exceptions.CreateFromEventInput{
		EventID:       evt.ID,
		SourceEventID: evt.ID,
		ApplicationID: evt.ApplicationID,
		Method:        evt.Method,
		Path:          evt.Path,
		ClientIP:      evt.ClientIP,
		Domain:        evt.Domain,
		AttackType:    evt.AttackType,
		RuleIDs:       ruleIDs,
		CreatedBy:     createdBy,
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
	// environment/product 供独立测试工程门禁在登录前做环境指纹校验
	//（P-T1：取值 APP_ENV 与产品形态，均为部署侧配置，不含敏感信息）
	fmt.Fprintf(w, `{"status":"%s","postgres":%t,"valkey":%t,"environment":"%s","product":"%s"}`,
		status, dbOK, cacheOK, a.cfg.Env, a.cfg.Product.Edition)
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
