package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
	"github.com/redis/go-redis/v9"
)

// 发布任务状态
const (
	TaskPending     = "PENDING"
	TaskValidating  = "VALIDATING"
	TaskGenerating  = "GENERATING"
	TaskPublishing  = "PUBLISHING"
	TaskVerifying   = "VERIFYING"
	TaskSuccess     = "SUCCESS"
	TaskFailed      = "FAILED"
	TaskRollingBack = "ROLLING_BACK"
	TaskRolledBack  = "ROLLED_BACK"
)

// 任务类型
const (
	TaskTypePublish  = "PUBLISH"
	TaskTypeRollback = "ROLLBACK"
)

// 发布错误
var (
	ErrLockBusy      = errors.New("another publish task is running")
	ErrInvalidState  = errors.New("invalid publish state")
	ErrNoApps        = errors.New("no applications to publish")
	ErrPublishFailed = errors.New("publish failed")

	errPreviousConfigRead = errors.New("read previous gateway config")
)

// publishRollbackFailureCode 将发布主流程失败与回滚结果归一化为任务失败码。
// 回滚失败优先级最高；回滚成功时保留调用方对应的已回滚失败码。
func publishRollbackFailureCode(operationCode string, rollbackErr error) string {
	if rollbackErr != nil {
		return "ROLLBACK_FAILED"
	}
	switch operationCode {
	case "VERIFY_FAILED":
		return "VERIFY_FAILED_ROLLED_BACK"
	case "SET_CURRENT_VERSION_FAILED":
		return "SET_CURRENT_VERSION_FAILED_ROLLED_BACK"
	default:
		return operationCode
	}
}

// PublishTask 是发布任务。
type PublishTask struct {
	ID                uuid.UUID  `json:"id"`
	TaskType          string     `json:"task_type"`
	Status            string     `json:"status"`
	RequestedBy       *uuid.UUID `json:"requested_by"`
	RequestedAt       time.Time  `json:"requested_at"`
	StartedAt         *time.Time `json:"started_at"`
	FinishedAt        *time.Time `json:"finished_at"`
	TargetVersionID   *uuid.UUID `json:"target_version_id"`
	PreviousVersionID *uuid.UUID `json:"previous_version_id"`
	CurrentStep       string     `json:"current_step"`
	Progress          int        `json:"progress"`
	ResultSummary     string     `json:"result_summary"`
	FailureCode       string     `json:"failure_code"`
	FailureMessage    string     `json:"failure_message"`
	RequestID         string     `json:"request_id"`
}

// PolicyParams 是应用策略参数。
type PolicyParams struct {
	PolicyID          string // 绑定策略 ID（可空）
	ProtectionMode    string
	ParanoiaLevel     int
	InboundThreshold  int
	OutboundThreshold int
}

// PolicyProvider 是应用与域名策略查询接口（由 protectionpolicies.Store 实现）。
type PolicyProvider interface {
	GetApplicationPolicyParams(ctx context.Context, appID uuid.UUID) (*PolicyParams, error)
	GetPolicyParams(ctx context.Context, policyID uuid.UUID) (*PolicyParams, error)
}

// ExceptionRule 是下发到网关的例外规则（SecLang 文本）。
// 作用域字段（ScopeType/ApplicationID/PolicyID）供生成器按应用过滤下发：
// 仅 GLOBAL 与归属本应用（APPLICATION）的例外进入该应用的 WAF 指令段。
// ExceptionID/ExceptionVersion 为发布时可反查的稳定映射（WDSP P0-04）：
// 生成器在每条规则前写 `# jiuzhang-exc-map: <rule_id> <exception_id> <version>`
// 注释行，且 SecLang 规则自身携带 tag:'exc:<uuid>' / tag:'excv:<version>'，
// 事件侧据此反查，不再依赖当次列表序号归因。
type ExceptionRule struct {
	RuleID           int
	SecLang          string
	ScopeType        string // GLOBAL / APPLICATION（其余取值 fail-closed 不下发）
	ApplicationID    string // APPLICATION 作用域的归属应用 ID（空 = 未绑定）
	PolicyID         string // 预留：POLICY 作用域（当前 API 不可创建）
	ExceptionID      string // 来源例外 UUID（空 = 旧版构建产物，不可反查）
	ExceptionVersion int    // 发布时例外行版本
}

// ExceptionProvider 是启用例外策略发布快照接口（由 exceptions.Store 实现）。
// WDSP P0-04：返回全量 ENABLED+VALID 的 WAF 引擎例外（单查询、按 exception_id
// 字典序稳定排序，marker/effect 规则 ID 由提供方分配）；读取或编译失败返回错误，
// 发布 fail-hard，禁止静默清空例外。
type ExceptionProvider interface {
	ListForPublish(ctx context.Context) ([]ExceptionRule, error)
}

// CustomRulesProvider 是启用自定义规则 SecLang 查询接口（由 customrules.Store 实现）。
type CustomRulesProvider interface {
	ListEnabledSecLang(ctx context.Context) ([]string, error)
}

// RuleOverridesProvider 是规则覆盖查询接口（由 ruleoverrides.Store 实现）。
type RuleOverridesProvider interface {
	// SecLangForApp 返回该应用生效的 DISABLE 覆盖 SecLang（已按优先级解析）。
	SecLangForApp(ctx context.Context, appID uuid.UUID, policyID *uuid.UUID) ([]string, error)
}

// GuardProvider 是阶段5访问控制/CC 配置提供者（由 guardconfig.Provider 实现）。
type GuardProvider interface {
	BuildGuardConfig(ctx context.Context) (*GuardConfig, error)
	SaveVersionSnapshot(ctx context.Context, cfg *GuardConfig, taskID, createdBy uuid.UUID) (uuid.UUID, error)
	MarkVersionResult(ctx context.Context, id uuid.UUID, result string) error
	GetVersionConfig(ctx context.Context, versionID uuid.UUID) (*GuardConfig, error)
}

// AppConfigsProvider 应用头合规、协议策略与路径转发配置提供者（appconfigs.Store 实现，可为 nil）。
// GetHeaderConfig/GetTLSConfig 未配置时返回 (nil, nil)（采用默认行为）；DB 错误如实返回（中止发布，禁止静默降级）。
type AppConfigsProvider interface {
	GetHeaderConfig(ctx context.Context, appID uuid.UUID) (*AppHeaderConfig, error)
	GetTLSConfig(ctx context.Context, appID uuid.UUID) (*AppTLSConfig, error)
	ListEnabledPathRoutes(ctx context.Context, appID uuid.UUID) ([]AppPathRoute, error)
}

// ---------- W18-SYNC 多节点发布扇出（任务书 §200 配置面主动同步 v2） ----------

// 节点同步结果词表（api_gateway_nodes.last_sync_result；空串 = 从未同步）。
const (
	NodeSyncSuccess      = "SUCCESS"
	NodeSyncFailed       = "FAILED"
	NodeSyncHashMismatch = "HASH_MISMATCH"
)

// 同步失败告警类型与组件。类型复用 systemalerts 既有词表（字面量镜像：
// 推送失败 = CONFIG_PUBLISH_FAILED，内容不一致 = CONFIG_HASH_MISMATCH）；
// 本包不能直接 import systemalerts——systemalerts 经 runtimehealth 传递依赖
// 本包，反向引用会成环，故告警出口用下方最小接口 + 装配侧适配器。
const (
	syncAlertTypePublishFailed = "CONFIG_PUBLISH_FAILED"
	syncAlertTypeHashMismatch  = "CONFIG_HASH_MISMATCH"
	// SyncAlertComponent 扇出失败告警组件名（逐节点失败合并到同一指纹，
	// 节点名与地址在 title/message 中如实呈现）。
	SyncAlertComponent = "API_GATEWAY_NODE_SYNC"
)

// SyncTarget 是一个登记参与扇出的次要网关节点。
type SyncTarget struct {
	NodeID        uuid.UUID
	NodeName      string
	AdminAddr     string // Caddy Admin 通道标识（unix socket 路径或 http(s)://host[:port]）
	SyncAgentAddr string // 可选：节点协同代理 hasyncd 地址（http(s)://host:port），优先于直连 AdminAddr
}

// NodeAgentSyncer 是跨节点协同代理（hasyncd）的可选同步挂钩（由 Phase 3 server/internal/nodesync 实现）。
// 当节点配置了 SyncAgentAddr 且注入该挂钩时，Publisher 优先通过安全协同代理完成：
//   - 代理加载 Caddy 配置并读取规范化业务配置哈希（与 CanonicalBusinessConfigHash 同口径）；
//   - 远端原子同步边车文件（tproxyd.json / mirrorcap.json）；
//   - 远端提交宿主机防火墙公网监听端口放行指令（firewall_ensure）。
// 未注入（nil）或节点未配置 SyncAgentAddr 时，自动保持/回退到直连 AdminAddr 路径。
type NodeAgentSyncer interface {
	SyncCaddyConfig(ctx context.Context, target SyncTarget, configJSON string) (loadedBusinessHash string, err error)
	SyncSidecarFile(ctx context.Context, target SyncTarget, name string, payload []byte) error
	SyncFirewallPorts(ctx context.Context, target SyncTarget, ports []int, requestedBy uuid.UUID, requestID string) error
}

// NodeSyncStore 多节点同步目标查询与结果回填接口（由 apinodes.Store 实现；
// nil 时发布不扇出，行为与单网关完全一致）。
type NodeSyncStore interface {
	// ListSyncTargets 返回全部 sync_enabled 且已登记 admin_addr 的节点（主节点不在其中——
	// 主发布走 Publisher 自身 CaddyClient，登记针对的是次要节点）。
	ListSyncTargets(ctx context.Context) ([]SyncTarget, error)
	// RecordSyncResult 回填单节点 last_sync_*（result 取 NodeSync* 词表）。
	RecordSyncResult(ctx context.Context, nodeID uuid.UUID, result, errMsg string, versionID uuid.UUID) error
}

// failedNodeSyncStore 是可选的恢复查询扩展。旧的 NodeSyncStore 实现仍可只提供
// 全量目标查询；实现该扩展的持久化仓储可以把版本级恢复收敛到本次版本实际失败的节点。
type failedNodeSyncStore interface {
	ListFailedSyncTargets(ctx context.Context, versionID uuid.UUID) ([]SyncTarget, error)
}

// SyncAlerter 次要节点同步失败告警出口（装配侧以 *systemalerts.Engine 适配实现；
// nil 时失败事实仅落库 + slog.Warn——不静默吞错，也不因告警未接线阻断发布）。
type SyncAlerter interface {
	NotifyFailure(ctx context.Context, alertType, component, title, message string) error
}

// Publisher 是配置发布控制器。
type Publisher struct {
	db            *pgxpool.Pool
	cache         *cache.Client
	apps          *applications.Store
	certs         *certificates.Store
	caddy         *CaddyClient
	dataDir       string // 配置与证书文件目录（runtime）
	policies      PolicyProvider
	exceptions    ExceptionProvider
	customRules   CustomRulesProvider
	ruleOverrides RuleOverridesProvider
	guard         GuardProvider
	appConfigs    AppConfigsProvider
	// 镜像/透明边车配置（docs/NETWORK_MODES_DESIGN.md §4.2/§4.3）：
	// gatewayNode 为网关节点名；mirrorIfaces 提供镜像口清单；sidecarDir 为共享卷目录（空用默认）；
	// sidecar*Log 为网关侧输出日志路径（裸机可覆写为安装根内路径，容器默认 /var/log/caddy/...）。
	gatewayNode         string
	mirrorIfaces        MirrorInterfacesProvider
	bridgePorts         BridgePortsProvider
	sidecarDir          string
	sidecarEventsLog    string
	sidecarAuditLog     string
	sidecarDiscoveryLog string
	tproxyListen        string
	tproxyTarget        string
	tproxyTargetTLS     string
	tproxyPassthrough   func(ctx context.Context) (string, error)
	// W18-SYNC 多节点扇出（§200）：nodeSync 提供登记次要节点与结果回填；
	// syncAlerter 为失败告警出口；localNodeName 用于扇出时自动跳过本机主节点；
	// nodeAgentSyncer 为可选的 hasyncd 协同代理同步挂钩（Phase 3 接线）。
	nodeSync        NodeSyncStore
	syncAlerter     SyncAlerter
	localNodeName   string
	nodeAgentSyncer NodeAgentSyncer
	// certKeyLoader / gmCertMaterialLoader / loadVersionFn 仅测试注入覆盖，生产路径分别走 p.certs.GetDecryptedKey / p.certs.GetGMCertMaterial / p.getVersion。
	certKeyLoader        func(ctx context.Context, certID uuid.UUID) (string, error)
	gmCertMaterialLoader func(ctx context.Context, certID uuid.UUID) (*certificates.GMCertMaterial, error)
	loadVersionFn        func(ctx context.Context, id uuid.UUID) (*ConfigVersion, error)
	// licenseState 授权状态视图（装配层注入 license 内存状态，发布时实时读取无 IO）：
	// 无效授权 → 强制纯透传（Guard=nil、全部应用 BYPASS）；有效且配额 max_qps>0 →
	// Guard 注入 LicenseMaxQPS。nil 视为授权有效（未装配授权时发布行为与历史一致）。
	licenseState func(ctx context.Context) (valid bool, maxQPS int64)
	// licensePublishAllowed 由授权服务提供。完整性事实源不可用时必须暂停发布，
	// 防止把已运行防护配置错误重生成为授权失效时的旁路配置；nil 视为允许。
	licensePublishAllowed func(ctx context.Context) (allowed bool, reason string)
	// regressionGate 安全回归发布门禁（WDSP P1-04 R3；nil = 未装配，与历史行为一致）
	regressionGate RegressionGate
	// gatewayTracing 网关原生 OTel tracing 下发开关（装配侧从 GATEWAY_TRACING_ENABLED
	// 注入，默认 false；见 GenerateInput.GatewayTracing）
	gatewayTracing bool
	// 阶段5 §十七 发布后流量验证（publisher_smoke.go）：smokeDialAddr 为显式数据面
	// 拨号地址（空 = 读 GATEWAY_PUBLISH_SMOKE_ADDR，仍空 = 127.0.0.1:应用端口）；
	// smokeClient 为测试注入的 HTTP 客户端（nil = 按目标构造）。
	smokeDialAddr string
	smokeClient   *http.Client
	// lockBackend 仅用于测试注入；生产路径由 cache.Redis() 构造 Redis 后端。
	lockBackend publishLockBackend
	// firewallEnsurer 在候选配置加载前提交实际监听端口的防火墙放行指令；
	// nil 保持未接入宿主通道环境的既有发布行为。
	firewallEnsurer FirewallEnsurer
	// acmeHTTP01Provider 返回是否应在 :80 注入 ACME HTTP-01 挑战路由（nil=未启用）。
	acmeHTTP01Provider func(ctx context.Context) (*ACMEHTTP01Config, error)
}

type gatewayConfigLoader interface {
	GetCurrentConfig(ctx context.Context) (string, error)
	LoadConfig(ctx context.Context, configJSON string) error
}

func loadGatewayConfig(ctx context.Context, loader gatewayConfigLoader, configJSON string) (string, error) {
	previousConfig, err := loader.GetCurrentConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errPreviousConfigRead, err)
	}
	if err := loader.LoadConfig(ctx, configJSON); err != nil {
		return previousConfig, err
	}
	return previousConfig, nil
}

// NewPublisher 创建发布控制器。
func NewPublisher(db *pgxpool.Pool, c *cache.Client, apps *applications.Store, certs *certificates.Store, socketPath, dataDir string, policies PolicyProvider, exceptions ExceptionProvider) *Publisher {
	return &Publisher{
		db:         db,
		cache:      c,
		apps:       apps,
		certs:      certs,
		caddy:      NewCaddyClient(socketPath),
		dataDir:    dataDir,
		policies:   policies,
		exceptions: exceptions,
	}
}

// SetGuardProvider 注入阶段5访问控制配置提供者（可选，注入后发布包含 guard 配置）。
func (p *Publisher) SetGuardProvider(g GuardProvider) {
	p.guard = g
}

// SetGatewayTracing 注入网关原生 OTel tracing 下发开关（默认关；仅影响配置生成内容，
// 不改变发布流程本身）。
func (p *Publisher) SetGatewayTracing(enabled bool) {
	p.gatewayTracing = enabled
}

// SetCustomRulesProvider 注入自定义规则提供者（启用规则写入发布配置）。
func (p *Publisher) SetCustomRulesProvider(c CustomRulesProvider) {
	p.customRules = c
}

// SetAppConfigsProvider 注入应用头合规与路径转发配置提供者（可选）。
func (p *Publisher) SetAppConfigsProvider(provider AppConfigsProvider) {
	p.appConfigs = provider
}

// SetRuleOverridesProvider 注入规则覆盖提供者。
func (p *Publisher) SetRuleOverridesProvider(r RuleOverridesProvider) {
	p.ruleOverrides = r
}

// SetSidecarConfig 注入镜像/透明边车配置写出所需的网关节点名与镜像口提供者（可选；
// 未注入 mirrorIfaces 时 interfaces 输出空数组）。
func (p *Publisher) SetSidecarConfig(gatewayNode string, ifaces MirrorInterfacesProvider) {
	p.gatewayNode = gatewayNode
	p.mirrorIfaces = ifaces
}

// SetSidecarDir 覆盖边车配置目录（默认 DefaultSidecarDir；测试用临时目录）。
func (p *Publisher) SetSidecarDir(dir string) {
	p.sidecarDir = dir
}

// SetSidecarLogPaths 注入下发到 mirrorcap.json 的网关侧日志路径（空串沿用 mirrorcap 默认）。
func (p *Publisher) SetSidecarLogPaths(eventsLog, auditLog, discoveryLog string) {
	p.sidecarEventsLog = eventsLog
	p.sidecarAuditLog = auditLog
	p.sidecarDiscoveryLog = discoveryLog
}

// SetBridgePortsProvider 注入节点网桥成员口查询（用于透明模式站点被动发现补齐）。
func (p *Publisher) SetBridgePortsProvider(bp BridgePortsProvider) {
	p.bridgePorts = bp
}

// SetTproxyAddresses 注入透明串接模式 tproxyd 监听与下游 Caddy 回环目标地址（空串沿用默认值）。
func (p *Publisher) SetTproxyAddresses(listen, target, targetTLS string) {
	p.tproxyListen = strings.TrimSpace(listen)
	p.tproxyTarget = strings.TrimSpace(target)
	p.tproxyTargetTLS = strings.TrimSpace(targetTLS)
}

// SetTproxyPassthroughAllowlistProvider 注入透明模式 TLS SNI 透传白名单设置读取器
// （通常绑定 system_settings 的 network:tproxy_passthrough_allowlist 键）。
func (p *Publisher) SetTproxyPassthroughAllowlistProvider(fn func(ctx context.Context) (string, error)) {
	p.tproxyPassthrough = fn
}

// SetNodeSyncStore 注入多节点同步目标仓储（W18-SYNC §200；nil 时发布不扇出）。
func (p *Publisher) SetNodeSyncStore(s NodeSyncStore) {
	p.nodeSync = s
}

// SetSyncAlerter 注入次要节点同步失败告警出口（可为 nil；nil 时失败仅落库与日志）。
func (p *Publisher) SetSyncAlerter(a SyncAlerter) {
	p.syncAlerter = a
}

// SetLocalNodeName 注入本机主网关节点名；多节点扇出时自动跳过本机主节点，
// 避免主发布已加载本机后又经由次要节点清单重复 /load。
func (p *Publisher) SetLocalNodeName(name string) {
	p.localNodeName = strings.TrimSpace(name)
}

// SetNodeAgentSyncer 注入跨节点协同代理（hasyncd）同步挂钩（可选，nil 时走直连 AdminAddr）。
func (p *Publisher) SetNodeAgentSyncer(s NodeAgentSyncer) {
	p.nodeAgentSyncer = s
}

// SetLicenseStateProvider 注入授权状态视图（离线授权门控；nil 视为授权有效）。
// 语义见 applyLicenseState；视图由装配层闭包读取 license 内存状态，发布路径无额外 IO。
func (p *Publisher) SetLicenseStateProvider(fn func(ctx context.Context) (valid bool, maxQPS int64)) {
	p.licenseState = fn
}

// SetLicensePublishAllowedProvider 注入授权完整性发布闸门。返回 false 时本次任务
// 明确失败，不读取业务快照、不生成候选配置，也不改写当前网关配置。
func (p *Publisher) SetLicensePublishAllowedProvider(fn func(ctx context.Context) (allowed bool, reason string)) {
	p.licensePublishAllowed = fn
}

// SetSmokeProbe 注入发布后流量验证的显式数据面拨号地址与 HTTP 客户端
// （阶段5 §十七；测试与特殊部署用。生产零值即可：拨号地址读
// GATEWAY_PUBLISH_SMOKE_ADDR，仍空时默认 127.0.0.1:应用端口）。
func (p *Publisher) SetSmokeProbe(dialAddr string, client *http.Client) {
	p.smokeDialAddr = dialAddr
	p.smokeClient = client
}

// SetACMEHTTP01Provider 注入 ACME HTTP-01 网关挑战路由配置提供者（nil 表示不注入）。
func (p *Publisher) SetACMEHTTP01Provider(fn func(ctx context.Context) (*ACMEHTTP01Config, error)) {
	p.acmeHTTP01Provider = fn
}

// DataDir 返回发布器数据目录路径（ACME 本地挑战目录与证书目录同源）。
func (p *Publisher) DataDir() string {
	return p.dataDir
}

// HasActiveACMEHTTP01Route 检查网关当前运行配置是否已包含 jiuzhang_acme_http01 挑战路由。
func (p *Publisher) HasActiveACMEHTTP01Route(ctx context.Context) (bool, error) {
	current, err := p.caddy.GetCurrentConfig(ctx)
	if err != nil {
		return false, err
	}
	return strings.Contains(current, `"jiuzhang_acme_http01"`), nil
}

func (p *Publisher) loadACMEHTTP01Config(ctx context.Context, guardCfg *GuardConfig) (*ACMEHTTP01Config, error) {
	if p.acmeHTTP01Provider == nil {
		return nil, nil
	}
	cfg, err := p.acmeHTTP01Provider(ctx)
	if err != nil || cfg == nil || !cfg.Enabled {
		return cfg, err
	}
	cp := *cfg
	if cp.Valkey == nil && guardCfg != nil && guardCfg.Valkey != nil {
		v := *guardCfg.Valkey
		cp.Valkey = &v
	}
	return &cp, nil
}

const publishLockKey = "jiuzhang:gateway:publish_lock"
const publishLockTTL = 120 * time.Second
const publishLockRecoveryTimeout = 5 * time.Second

type publishLockBackend interface {
	Acquire(ctx context.Context, key, token string, ttl time.Duration) (bool, error)
	Renew(ctx context.Context, key, token string, ttl time.Duration) (bool, error)
	Release(ctx context.Context, key, token string) error
}

type redisPublishLockBackend struct{ rdb redisCmdable }

// redisCmdable 是发布锁所需的最小 Redis 客户端接口，避免锁语义依赖整个客户端接口。
type redisCmdable interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

func (b redisPublishLockBackend) Acquire(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	return b.rdb.SetNX(ctx, key, token, ttl).Result()
}

const renewPublishLockScript = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end`
const releasePublishLockScript = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`

func (b redisPublishLockBackend) Renew(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	n, err := b.rdb.Eval(ctx, renewPublishLockScript, []string{key}, token, ttl.Milliseconds()).Int64()
	return n == 1, err
}

func (b redisPublishLockBackend) Release(ctx context.Context, key, token string) error {
	_, err := b.rdb.Eval(ctx, releasePublishLockScript, []string{key}, token).Int64()
	return err
}

type publishLockLease struct {
	backend     publishLockBackend
	key         string
	token       string
	ttl         time.Duration
	stop        chan struct{}
	done        chan struct{}
	lost        chan struct{}
	stopOnce    sync.Once
	lostOnce    sync.Once
	releaseOnce sync.Once
}

func (l *publishLockLease) markLost() {
	l.lostOnce.Do(func() { close(l.lost) })
}

func (l *publishLockLease) start() {
	go func() {
		defer close(l.done)
		interval := l.ttl / 3
		if interval <= 0 {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-ticker.C:
				ok, err := l.backend.Renew(context.Background(), l.key, l.token, l.ttl)
				if err != nil || !ok {
					l.markLost()
					return
				}
			}
		}
	}()
}

func (l *publishLockLease) ensure(ctx context.Context) error {
	select {
	case <-l.lost:
		return ErrPublishLockLost
	default:
	}
	ok, err := l.backend.Renew(ctx, l.key, l.token, l.ttl)
	if err != nil {
		l.markLost()
		return fmt.Errorf("renew publish lock: %w", err)
	}
	if !ok {
		l.markLost()
		return ErrPublishLockLost
	}
	return nil
}

// restoreConfigAfterPublishLockLoss uses a request-independent bounded context.
// Losing the lease must stop all configuration application, while still allowing
// the already loaded previous config to be restored after the request is canceled.
func (p *Publisher) restoreConfigAfterPublishLockLoss(configJSON string) error {
	ctx, cancel := context.WithTimeout(context.Background(), publishLockRecoveryTimeout)
	defer cancel()
	if err := p.rollbackToConfig(ctx, configJSON); err != nil {
		return err
	}
	_, err := WriteActiveConfig(p.dataDir, "current", configJSON)
	return err
}

// restoreAfterPublishLockLoss 执行失锁后的双重补偿。网关恢复失败时仍继续恢复
// 数据库状态，最终将两个错误一起返回给任务收尾逻辑。
func restoreAfterPublishLockLoss(restoreGateway, restoreDatabase func(context.Context) error) error {
	var gatewayErr, databaseErr error
	if restoreGateway != nil {
		ctx, cancel := context.WithTimeout(context.Background(), publishLockRecoveryTimeout)
		gatewayErr = restoreGateway(ctx)
		cancel()
	}
	if restoreDatabase != nil {
		ctx, cancel := context.WithTimeout(context.Background(), publishLockRecoveryTimeout)
		databaseErr = restoreDatabase(ctx)
		cancel()
	}
	return errors.Join(gatewayErr, databaseErr)
}

func (p *Publisher) restorePublishStateAfterPublishLockLoss(configJSON string, state *publishActivationState) error {
	return restoreAfterPublishLockLoss(
		func(ctx context.Context) error {
			if err := p.rollbackToConfig(ctx, configJSON); err != nil {
				return err
			}
			_, err := WriteActiveConfig(p.dataDir, "current", configJSON)
			return err
		},
		func(ctx context.Context) error { return p.restoreActivationState(ctx, state) },
	)
}

// ensureLeaseAfterConfigLoad closes the post-/load ownership gap. A lost lease
// restores the previous gateway config and returns before any verification,
// activation, or fan-out callback can run.
func ensureLeaseAfterConfigLoad(ctx context.Context, lease *publishLockLease, restore func(context.Context) error) error {
	if err := lease.ensure(ctx); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), publishLockRecoveryTimeout)
		defer cancel()
		if restoreErr := restore(recoveryCtx); restoreErr != nil {
			return fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		return err
	}
	return nil
}

func (l *publishLockLease) release(ctx context.Context) {
	l.releaseOnce.Do(func() {
		l.stopOnce.Do(func() { close(l.stop) })
		<-l.done
		if err := l.backend.Release(ctx, l.key, l.token); err != nil {
			slog.Warn("release publish lock failed", "error", err)
		}
	})
}

// ErrPublishLockLost 表示发布期间租约失去所有权，调用方必须停止配置应用。
var ErrPublishLockLost = errors.New("publish lock ownership lost")

// acquireLock 获取发布锁（同一时间仅一个发布任务）。
func (p *Publisher) acquireLock(ctx context.Context, owner string) (*publishLockLease, error) {
	return p.acquireLockWithTTL(ctx, owner, publishLockTTL)
}

func (p *Publisher) acquireLockWithTTL(ctx context.Context, owner string, ttl time.Duration) (*publishLockLease, error) {
	backend := p.lockBackend
	if backend == nil {
		if p.cache == nil {
			return nil, errors.New("publish lock backend is not configured")
		}
		backend = redisPublishLockBackend{rdb: p.cache.Redis()}
	}
	token := owner + ":" + uuid.NewString()
	ok, err := backend.Acquire(ctx, publishLockKey, token, ttl)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	lease := &publishLockLease{
		backend: backend, key: publishLockKey, token: token, ttl: ttl,
		stop: make(chan struct{}), done: make(chan struct{}), lost: make(chan struct{}),
	}
	lease.start()
	return lease, nil
}

// releaseLock 释放发布锁（仅持有者可释放）。
func (p *Publisher) releaseLock(ctx context.Context, lease *publishLockLease) {
	if lease != nil {
		lease.release(ctx)
	}
}

// PublishInput 是发布输入。
type PublishInput struct {
	RequestedBy    uuid.UUID
	RequestID      string
	IdempotencyKey string
	// AppIDs 限定发布的应用（为空表示全部活动应用）。
	AppIDs []uuid.UUID
	// GuardOverride 阶段5访问控制配置覆盖（回滚历史版本时使用；nil 表示从数据库实时组装）。
	// 使用前按当前产品开关再门控（API 动态防护关闭时剥除 API 段，见 gateGuardOverride）。
	GuardOverride *GuardConfig
}

// Publish 执行完整发布流程。
func (p *Publisher) Publish(ctx context.Context, in PublishInput) (*PublishTask, error) {
	// 幂等检查
	if in.IdempotencyKey != "" {
		if existing, err := p.getTaskByIdempotencyKey(ctx, in.IdempotencyKey); err == nil && existing != nil {
			return existing, nil
		}
	}

	// 创建任务
	task, err := p.createTask(ctx, TaskTypePublish, in.RequestedBy, in.RequestID, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}

	// 异步执行（调用方决定是否同步等待）
	go p.executePublish(context.Background(), task.ID, in)

	return task, nil
}

// PublishSync 同步执行发布（返回最终任务状态）。
func (p *Publisher) PublishSync(ctx context.Context, in PublishInput) (*PublishTask, error) {
	if in.IdempotencyKey != "" {
		if existing, err := p.getTaskByIdempotencyKey(ctx, in.IdempotencyKey); err == nil && existing != nil {
			return existing, nil
		}
	}
	task, err := p.createTask(ctx, TaskTypePublish, in.RequestedBy, in.RequestID, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	p.executePublish(ctx, task.ID, in)
	return p.GetTask(ctx, task.ID)
}

// executePublish 执行发布流程（状态机）。
func (p *Publisher) executePublish(ctx context.Context, taskID uuid.UUID, in PublishInput) {
	if allowed, reason := p.allowsLicensePublish(ctx); !allowed {
		p.finishTask(ctx, taskID, TaskFailed, "LICENSE_INTEGRITY_UNAVAILABLE", reason, nil)
		return
	}
	lockOwner := taskID.String()
	// 获取发布锁
	lease, err := p.acquireLock(ctx, lockOwner)
	if err != nil || lease == nil {
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_BUSY", "其他发布任务正在执行，请稍后重试", nil)
		return
	}
	defer p.releaseLock(context.Background(), lease)

	// 步骤1：读取业务数据快照
	p.updateTaskStep(ctx, taskID, TaskGenerating, "读取业务数据快照", 10)
	appsData, snapshot, err := p.buildSnapshot(ctx, in.AppIDs)
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "SNAPSHOT_FAILED", err.Error(), nil)
		return
	}

	// 读取启用的例外策略（下发到网关；失败则中止发布，禁止静默清空例外）
	var exceptionRules []ExceptionRule
	if p.exceptions != nil {
		exceptionRules, err = p.exceptions.ListForPublish(ctx)
		if err != nil {
			p.finishTask(ctx, taskID, TaskFailed, "EXCEPTIONS_SNAPSHOT_FAILED", err.Error(), nil)
			return
		}
	}

	// 启用的自定义规则 SecLang
	var customSecLang []string
	if p.customRules != nil {
		customSecLang, err = p.customRules.ListEnabledSecLang(ctx)
		if err != nil {
			p.finishTask(ctx, taskID, TaskFailed, "CUSTOM_RULES_SNAPSHOT_FAILED", err.Error(), nil)
			return
		}
	}

	// 阶段5：组装访问控制/CC 配置（或回滚覆盖）
	var guardCfg *GuardConfig
	if p.guard != nil {
		if in.GuardOverride != nil {
			// 回滚覆盖快照按当前产品开关再门控（防跨重启泄漏 API 段，见 gateGuardOverride）
			guardCfg, err = p.gateGuardOverride(ctx, in.GuardOverride)
			if err != nil {
				p.finishTask(ctx, taskID, TaskFailed, "GUARD_OVERRIDE_GATE_FAILED", err.Error(), nil)
				return
			}
		} else {
			guardCfg, err = p.guard.BuildGuardConfig(ctx)
			if err != nil {
				p.finishTask(ctx, taskID, TaskFailed, "GUARD_SNAPSHOT_FAILED", err.Error(), nil)
				return
			}
		}
	}

	// 阶段5 §5.1：自定义 429/阻断响应页面（system_settings block_response 组）随发布注入；
	// 读取/校验失败中止发布（不静默回退——避免管理面显示与网关行为不一致）；
	// 回滚覆盖（GuardOverride）按快照历史内容回放，不以当前设置重放（非秘密材料，
	// 与 InjectRuntimeSecrets 的秘密材料重放纪律相反——页面内容应回到历史版本）
	if guardCfg != nil && in.GuardOverride == nil {
		blockResponse, brErr := LoadBlockResponse(ctx, p.db)
		if brErr != nil {
			p.finishTask(ctx, taskID, TaskFailed, "BLOCK_RESPONSE_SNAPSHOT_FAILED", brErr.Error(), nil)
			return
		}
		guardCfg.BlockResponse = blockResponse
		softwareBypass, sbErr := LoadSoftwareBypass(ctx, p.db)
		if sbErr != nil {
			p.finishTask(ctx, taskID, TaskFailed, "SOFTWARE_BYPASS_SNAPSHOT_FAILED", sbErr.Error(), nil)
			return
		}
		guardCfg.SoftwareBypass = softwareBypass
	}

	// 离线授权门控：无效授权强制纯透传（Guard=nil、全部应用 BYPASS）；
	// 有效授权注入 max_qps 全局限速配额（license 内存状态，发布路径无额外 IO）
	licenseValid, licenseMaxQPS := true, int64(0)
	if p.licenseState != nil {
		licenseValid, licenseMaxQPS = p.licenseState(ctx)
	}
	appsData, guardCfg = applyLicenseState(appsData, guardCfg, snapshot, licenseValid, licenseMaxQPS)

	// 每次发布（含访问控制回滚重发）都新建独立探针密钥与 taskID 绑定；
	// 在 Generate 前注入，保证实际加载配置与后续冒烟使用同一份认证材料。
	if err := preparePublishSmoke(taskID, guardCfg); err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "SMOKE_AUTH_INIT_FAILED", err.Error(), nil)
		return
	}

	acmeHTTP01Cfg, acmeErr := p.loadACMEHTTP01Config(ctx, guardCfg)
	if acmeErr != nil {
		p.finishTask(ctx, taskID, TaskFailed, "ACME_HTTP01_CONFIG_FAILED", acmeErr.Error(), nil)
		return
	}

	// 步骤2：生成候选配置
	p.updateTaskStep(ctx, taskID, TaskGenerating, "生成候选配置", 25)
	gen, err := Generate(GenerateInput{
		Apps:                   appsData,
		AdminSocket:            p.caddy.SocketPath(),
		Exceptions:             exceptionRules,
		CustomRules:            customSecLang,
		Guard:                  guardCfg,
		GatewayTracing:         p.gatewayTracing,
		TransparentHTTPListen:  p.effectiveTproxyTarget(),
		TransparentHTTPSListen: p.effectiveTproxyTargetTLS(),
		ACMEHTTP01:             acmeHTTP01Cfg,
	})
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "GENERATE_FAILED", err.Error(), nil)
		return
	}

	// 步骤3：配置校验（含透明模式源站与 tproxyd.json 边车契约校验）
	p.updateTaskStep(ctx, taskID, TaskValidating, "校验配置", 40)
	tproxySidecar, err := p.validateTransparentConfig(ctx, appsData)
	if err != nil {
		p.saveFailedCandidate(gen, snapshot, err)
		p.finishTask(ctx, taskID, TaskFailed, "VALIDATE_FAILED", err.Error(), nil)
		return
	}
	if err := p.caddy.ValidateConfig(ctx, gen.JSON); err != nil {
		p.saveFailedCandidate(gen, snapshot, err)
		p.finishTask(ctx, taskID, TaskFailed, "VALIDATE_FAILED", err.Error(), nil)
		return
	}
	snapshot["tproxyd"] = tproxySidecar

	// 步骤4：保存版本（不可变）
	version, err := p.saveVersion(ctx, gen, snapshot, in, taskID)
	if err != nil {
		p.finishTask(ctx, taskID, TaskFailed, "SAVE_VERSION_FAILED", err.Error(), nil)
		return
	}
	_ = p.setTaskTargetVersion(ctx, taskID, version.ID)

	// 安全回归发布门禁（WDSP P1-04 R3 §7.2）：候选编译完成且不可变版本已保存、
	// 发往节点（主节点 Caddy /load 及次要节点扇出）之前评估。评估绑定本次实际
	// 构建的候选指纹（cfgfpv1 + gen.Hash），随后发送的仍是同一份 gen.JSON——
	// 排队后正式执行前核对，检查后无替换窗口。GuardOverride 历史快照重放按
	// 已知良好恢复通道口径评估（§7.3）。ENFORCE 阻止/依赖不可用时任务明确失败。
	if ok, code, msg := p.evaluateRegressionGate(ctx, taskID, version.ID, "cfgfpv1:"+gen.Hash, in.GuardOverride != nil); !ok {
		p.markVersionResult(ctx, version.ID, "FAILED")
		p.finishTask(ctx, taskID, TaskFailed, code, msg, &version.ID)
		return
	}

	// 节点能力发布门（NG-COV-04 §2.1）：回归门禁之后、发往节点 /load 之前评估。
	// required_capabilities 由本次负载特性段推导；空需求免门禁（存量发布零变化），
	// 缺能力（CAPABILITY_MISSING）/清单缺失或过期（CAPABILITY_MANIFEST_UNAVAILABLE）
	// 该节点发布失败并展示缺口明细，不发送 /load、不得静默降级。
	if ok, code, msg := p.evaluateCapabilityGateWithApps(ctx, guardCfg, appsData, in.AppIDs...); !ok {
		p.markVersionResult(ctx, version.ID, "FAILED")
		p.finishTask(ctx, taskID, TaskFailed, code, msg, &version.ID)
		return
	}

	// 阶段5：保存访问控制配置版本快照（PENDING，结果后续回填）
	var acVersionID uuid.UUID
	if p.guard != nil && guardCfg != nil {
		acVersionID, err = p.guard.SaveVersionSnapshot(ctx, guardCfg, taskID, in.RequestedBy)
		if err != nil {
			// 快照失败中止发布并如实记录（不静默跳过——缺失快照会使访问控制版本无法回滚溯源）
			p.finishTask(ctx, taskID, TaskFailed, "AC_VERSION_SAVE_FAILED", err.Error(), nil)
			return
		}
	}

	// 阶段5：回填访问控制版本结果（背景 ctx，避免请求取消丢失）
	markAC := func(result string) {
		if p.guard != nil && acVersionID != uuid.Nil {
			if err := p.guard.MarkVersionResult(context.Background(), acVersionID, result); err != nil {
				slog.Warn("mark access control version result failed", "version", acVersionID, "error", err)
			}
		}
	}

	// 步骤5：发布到 Caddy
	p.updateTaskStep(ctx, taskID, TaskPublishing, "发布到网关", 60)
	if err := lease.ensure(ctx); err != nil {
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}
	prevConfig, firewallPorts, err := p.loadGatewayConfigWithFirewall(ctx, p.caddy, gen.JSON, appsData, in)
	if err != nil {
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		if code, message, ok := firewallEnsureTaskFailure(err); ok {
			slog.Error("submit firewall ensure command failed", "task", taskID, "version", version.ID, "error", err)
			p.finishTask(ctx, taskID, TaskFailed, code, message, &version.ID)
			return
		}
		if errors.Is(err, errPreviousConfigRead) {
			p.finishTask(ctx, taskID, TaskFailed, "PREVIOUS_CONFIG_READ_FAILED",
				"无法读取发布前网关配置: "+sanitizeCaddyError(err), &version.ID)
			return
		}
		p.finishTask(ctx, taskID, TaskFailed, "PUBLISH_FAILED", sanitizeCaddyError(err), &version.ID)
		return
	}
	if err := ensureLeaseAfterConfigLoad(ctx, lease, func(recoveryCtx context.Context) error {
		return p.rollbackToConfig(recoveryCtx, prevConfig)
	}); err != nil {
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}

	// 步骤6：发布验证
	p.updateTaskStep(ctx, taskID, TaskVerifying, "发布验证", 80)
	verifyErr := p.verifyPublish(ctx, gen, appsData)
	var smoke *smokeReport
	if verifyErr == nil {
		// 阶段5 §十七：配置一致性通过后执行数据面功能性冒烟（真实IP→黑名单→CC
		// 合成探针）；探针不可用时降级并如实记录，只有响应与预期不符的正面证据才判 FAIL
		smoke = p.runPublishSmoke(ctx, taskID, version.ID, appsData, guardCfg)
		if smoke.failed() {
			verifyErr = fmt.Errorf("发布后流量验证未通过：%s", smoke.failureDetail())
		}
	}
	if verifyErr != nil {
		// 发布验证失败：自动回滚到上一配置
		p.updateTaskStep(ctx, taskID, TaskRollingBack, "验证失败，自动回滚", 90)
		rollbackErr := p.rollbackToConfig(ctx, prevConfig)
		p.markVersionResult(ctx, version.ID, "VERIFY_FAILED")
		markAC("FAILED")
		if rollbackErr != nil {
			p.finishTask(ctx, taskID, TaskFailed, publishRollbackFailureCode("VERIFY_FAILED", rollbackErr),
				fmt.Sprintf("验证失败(%s)且回滚失败(%s)", verifyErr.Error(), rollbackErr.Error()), &version.ID)
			return
		}
		p.finishTask(ctx, taskID, TaskFailed, publishRollbackFailureCode("VERIFY_FAILED", nil),
			"发布后验证失败，已自动回滚: "+verifyErr.Error(), &version.ID)
		return
	}

	// 激活数据库版本前再次确认租约，避免校验耗时期间锁已被接管。
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}
	activationState, err := p.snapshotActivationState(ctx, in.AppIDs)
	if err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("snapshot activation state: %v; restore previous config: %v", err, restoreErr)
		}
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "ACTIVATION_STATE_SNAPSHOT_FAILED", err.Error(), &version.ID)
		return
	}
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}
	// 成功
	if err := p.activatePublishedVersion(ctx, version.ID, in.AppIDs); err != nil {
		rollbackErr := p.rollbackToConfig(ctx, prevConfig)
		p.markVersionResult(ctx, version.ID, "ACTIVATION_FAILED")
		markAC("FAILED")
		if rollbackErr != nil {
			p.finishTask(ctx, taskID, TaskFailed, publishRollbackFailureCode("SET_CURRENT_VERSION_FAILED", rollbackErr),
				fmt.Sprintf("切换当前版本失败(%s)且网关回滚失败(%s)", err.Error(), rollbackErr.Error()), &version.ID)
			return
		}
		p.finishTask(ctx, taskID, TaskFailed, publishRollbackFailureCode("SET_CURRENT_VERSION_FAILED", nil),
			"激活版本状态失败，网关已自动回滚: "+err.Error(), &version.ID)
		return
	}
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restorePublishStateAfterPublishLockLoss(prevConfig, activationState); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}
	markAC("SUCCESS")
	if _, err := WriteActiveConfig(p.dataDir, "current", gen.JSON); err != nil {
		slog.Warn("write active gateway config failed", "version", version.ID, "error", err)
	}
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restorePublishStateAfterPublishLockLoss(prevConfig, activationState); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.markVersionResult(ctx, version.ID, "FAILED")
		markAC("FAILED")
		p.finishTask(ctx, taskID, TaskFailed, "LOCK_LOST", err.Error(), &version.ID)
		return
	}
	// 镜像/透明边车配置（附加产物：写失败只记日志，不回滚已加载的 Caddy 配置）。
	//   - mirrorcap.json 不依赖 Caddy 路由，局部发布（len(in.AppIDs)>0）仍按全部活动应用生成，
	//     避免局部发布反代应用时误关镜像边车；
	//   - tproxyd.json 强依赖 Caddy 透明回环路由，必须严格按本次实际加载进 Caddy 的有效应用集
	//     （appsData）生成，杜绝局部发布导致 Caddy 与 tproxyd.json 分裂。
	mirrorcapApps := appsData
	if len(in.AppIDs) > 0 && p.apps != nil {
		if allApps, _, serr := p.buildSnapshot(ctx, nil); serr == nil {
			if !licenseValid {
				for i := range allApps {
					allApps[i].ProtectionMode = applications.ModeBypass
				}
			}
			mirrorcapApps = allApps
		} else {
			slog.Warn("load full apps snapshot for mirrorcap sidecar config failed, falling back to publish slice", "error", serr)
		}
	}
	p.writeMirrorcapSidecarConfig(ctx, mirrorcapApps)
	p.writeTproxydSidecarConfig(ctx, appsData)
	// W18-SYNC §200：主节点全链路成功后，将远端防火墙端口放行、最终配置及边车配置扇出到登记次要节点
	// （逐节点回填 last_sync_*；次要节点失败不阻断主发布——记录并告警）。
	p.syncRemoteFirewallPorts(ctx, firewallPorts, in.RequestedBy, in.RequestID)
	p.SyncConfigToNodes(ctx, gen.JSON, version.ID)
	p.syncRemoteSidecars(ctx, mirrorcapApps, appsData, nil)
	successMsg := "发布成功"
	if smoke != nil {
		successMsg += "；" + smoke.summary()
	}
	if p.firewallEnsurer != nil {
		successMsg += firewallEnsureSummary(firewallPorts)
	}
	p.finishTask(ctx, taskID, TaskSuccess, "", successMsg, &version.ID)
}

func (p *Publisher) allowsLicensePublish(ctx context.Context) (bool, string) {
	if p.licensePublishAllowed == nil {
		return true, ""
	}
	allowed, reason := p.licensePublishAllowed(ctx)
	if allowed {
		return true, ""
	}
	if reason == "" {
		reason = "授权完整性暂不可用，已暂停配置发布并保留当前网关配置"
	}
	return false, reason
}

// SyncConfigToNodes 将本次构建的最终配置扇出到全部登记次要节点（W18-SYNC §200
// 配置面主动同步 v2）。纪律：
//   - 直接使用主发布已验证的 configJSON（不重新构建），保证全节点内容一致；
//     注意配置内 admin.listen 为主节点 socket 路径约定，次要节点须以相同路径
//     部署（同构部署前提，部署侧登记责任）；
//   - 逐节点 /load + 规范化哈希比对（与主发布 verifyPublish 同口径），
//     结果回填 api_gateway_nodes.last_sync_*；
//   - 任一节点失败不影响其余节点、不阻断主发布（失败如实落库并产系统告警，
//     告警类型复用 CONFIG_PUBLISH_FAILED / CONFIG_HASH_MISMATCH）；
//   - 主节点失败按既有回滚语义处理，不进入本函数。
func (p *Publisher) SyncConfigToNodes(ctx context.Context, configJSON string, versionID uuid.UUID) {
	_ = p.syncConfigToNodes(ctx, configJSON, versionID)
}

// nodeSyncOutcome 是一次扇出的可持久化结果汇总。普通发布继续忽略该结果，
// 但显式回滚必须据此决定任务是否可以进入 SUCCESS，避免主节点恢复而次节点
// 仍停留在旧配置时产生错误的成功状态。
type nodeSyncOutcome struct {
	attempted      int
	succeeded      int
	failed         int
	recordFailures int
	queryErr       error
	hashErr        error
	contextErr     error
}

// rollbackFailure 返回显式回滚扇出未完成时要落库的任务失败码和消息。
func (o nodeSyncOutcome) rollbackFailure(versionID uuid.UUID) (code, message string, incomplete bool) {
	if o.queryErr != nil {
		return "ROLLBACK_NODE_SYNC_FAILED",
			fmt.Sprintf("主节点已回滚到版本 %s，但次要节点目标查询失败：%s", versionID, sanitizeCaddyError(o.queryErr)), true
	}
	if o.hashErr != nil {
		return "ROLLBACK_NODE_SYNC_FAILED",
			fmt.Sprintf("主节点已回滚到版本 %s，但次要节点同步内容校验失败：%s", versionID, sanitizeCaddyError(o.hashErr)), true
	}
	if o.failed > 0 {
		return "ROLLBACK_NODE_SYNC_FAILED",
			fmt.Sprintf("主节点已回滚到版本 %s，但次要节点同步不完整：%d/%d 个节点失败，可重试", versionID, o.failed, o.attempted), true
	}
	if o.recordFailures > 0 {
		return "ROLLBACK_NODE_SYNC_STATE_PERSIST_FAILED",
			fmt.Sprintf("主节点已回滚到版本 %s，但次要节点同步结果未能完整落库：%d 条记录失败，可重试", versionID, o.recordFailures), true
	}
	return "", "", false
}

// syncConfigToNodes 执行一次扇出并返回结果汇总。普通发布由公开包装方法
// 保持既有的失败不阻断语义；显式回滚直接消费该汇总以持久化准确终态。
func (p *Publisher) syncConfigToNodes(ctx context.Context, configJSON string, versionID uuid.UUID) nodeSyncOutcome {
	var outcome nodeSyncOutcome
	if p.nodeSync == nil {
		return outcome
	}
	targets, err := p.nodeSync.ListSyncTargets(ctx)
	if err != nil {
		slog.Error("list gateway node sync targets failed", "version", versionID, "error", err)
		outcome.queryErr = err
		return outcome
	}
	if len(targets) == 0 {
		return outcome
	}
	return p.syncConfigToTargets(ctx, configJSON, versionID, targets)
}

// syncConfigToTargets 将同一份已验证配置同步到给定节点集合。
// 目标集合由调用方决定：正常发布使用全部启用节点，版本恢复可使用持久化失败筛选。
// 本机主节点（与 localNodeName 同名或指向主 Caddy Unix Socket）自动跳过，避免重复 /load。
func (p *Publisher) syncConfigToTargets(ctx context.Context, configJSON string, versionID uuid.UUID, targets []SyncTarget) nodeSyncOutcome {
	var outcome nodeSyncOutcome
	if err := ctx.Err(); err != nil {
		outcome.contextErr = err
		return outcome
	}
	wantHash, err := CanonicalBusinessConfigHash(configJSON)
	if err != nil {
		slog.Error("hash fanout config failed", "version", versionID, "error", err)
		outcome.hashErr = err
		return outcome
	}
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			outcome.contextErr = err
			break
		}
		if p.isLocalPrimaryTarget(t) {
			slog.Info("skip local primary gateway node in secondary fanout", "node", t.NodeName, "admin_addr", t.AdminAddr, "version", versionID)
			continue
		}
		outcome.attempted++
		result, errMsg := p.syncConfigToNode(ctx, t, configJSON, wantHash)
		// 节点管理通道的瞬时 5xx/连接中断不应立即把一次发布标记为永久失败。
		// 只重试一次，并仅保留最终结果，避免重复写入同步状态和重复告警；配置原文
		// 始终来自本次已验证快照，恢复入口仍可继续处理最终失败节点。
		if result == NodeSyncFailed && isRetryableNodeSyncError(errMsg) {
			if err := waitNodeSyncRetry(ctx); err == nil {
				result, errMsg = p.syncConfigToNode(ctx, t, configJSON, wantHash)
			}
		}
		if result == NodeSyncSuccess {
			outcome.succeeded++
		} else {
			outcome.failed++
		}
		// 回填用背景 ctx：请求取消不丢同步事实（与 markAC 同一纪律）
		if err := p.nodeSync.RecordSyncResult(context.Background(), t.NodeID, result, errMsg, versionID); err != nil {
			slog.Error("record node sync result failed", "node", t.NodeName, "version", versionID, "error", err)
			outcome.recordFailures++
		}
		if result != NodeSyncSuccess {
			p.notifyNodeSyncFailure(t, result, errMsg, versionID)
		}
		if err := ctx.Err(); err != nil {
			outcome.contextErr = err
			break
		}
	}
	return outcome
}

// normalizeUnixSocketPath 规范化 Unix Socket 路径表示（兼容裸路径、unix// 与 unix:// 前缀）。
func normalizeUnixSocketPath(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(s, "unix://"):
		s = strings.TrimPrefix(s, "unix://")
	case strings.HasPrefix(s, "unix/"):
		s = strings.TrimPrefix(s, "unix/")
	}
	if !strings.HasPrefix(s, "/") {
		return ""
	}
	return path.Clean(s)
}

// isLocalPrimaryTarget 判定同步目标是否为当前管理面直连的本机主网关节点：
// 节点名匹配 localNodeName（非空时）或 AdminAddr 解析到与主 Caddy 完全相同的 Unix Socket 路径。
func (p *Publisher) isLocalPrimaryTarget(t SyncTarget) bool {
	if p.localNodeName != "" && strings.TrimSpace(t.NodeName) == p.localNodeName {
		return true
	}
	if p.caddy != nil {
		localSock := normalizeUnixSocketPath(p.caddy.SocketPath())
		targetSock := normalizeUnixSocketPath(t.AdminAddr)
		if localSock != "" && targetSock != "" && localSock == targetSock {
			return true
		}
	}
	return false
}

func waitNodeSyncRetry(ctx context.Context) error {
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func isRetryableNodeSyncError(errMsg string) bool {
	msg := strings.ToLower(errMsg)
	return strings.Contains(msg, "status 500") ||
		strings.Contains(msg, "status 502") ||
		strings.Contains(msg, "status 503") ||
		strings.Contains(msg, "status 504") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "eof")
}

// prepareTargetConfigJSON 为目标节点准备待推送配置副本：
//   - Unix Socket 目标与主节点同构，直接推送原 configJSON；
//   - HTTP(S) TCP 目标先通过 GET /config/admin 读取次要节点当前 admin 段并回填到副本的 root["admin"]，
//     若无法安全保留目标节点的非 Unix admin.listen 则 fail-closed 报错，绝不把主节点 unix socket
//     admin.listen 推送给跨机 HTTP(S) 次要节点导致失联。
func prepareTargetConfigJSON(ctx context.Context, client *CaddyClient, target SyncTarget, configJSON string) (string, error) {
	if !client.IsHTTP() {
		return configJSON, nil
	}
	targetAdmin, err := client.GetAdminConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("读取次要节点 %s 当前 admin 配置失败（拒绝覆盖管理监听）: %w", target.NodeName, err)
	}
	if disabled, _ := targetAdmin["disabled"].(bool); disabled {
		return "", fmt.Errorf("次要节点 %s 当前 admin 配置为 disabled，无法安全保留管理监听", target.NodeName)
	}
	listen, _ := targetAdmin["listen"].(string)
	listen = strings.TrimSpace(listen)
	if listen == "" || strings.HasPrefix(listen, "unix/") || strings.HasPrefix(listen, "unix://") {
		return "", fmt.Errorf("次要节点 %s 当前 admin.listen (%q) 无效，拒绝以主节点配置覆盖管理通道", target.NodeName, listen)
	}
	root, err := parseConfigJSON(configJSON)
	if err != nil {
		return "", fmt.Errorf("解析待同步配置失败: %w", err)
	}
	root["admin"] = targetAdmin
	out, err := marshalDeterministic(root)
	if err != nil {
		return "", fmt.Errorf("重序列化次要节点配置失败: %w", err)
	}
	return string(out), nil
}

// syncConfigToNode 推送配置到单节点并验证业务配置哈希一致性，返回（结果词表，错误摘要）。
// 目标配置了 SyncAgentAddr 且注入了 NodeAgentSyncer 时优先经由 hasyncd 代理加载；
// 否则平滑回退到直连 AdminAddr（HTTP(S) 目标自动保留目标 admin 段）。
func (p *Publisher) syncConfigToNode(ctx context.Context, t SyncTarget, configJSON, wantHash string) (string, string) {
	if p.nodeAgentSyncer != nil && strings.TrimSpace(t.SyncAgentAddr) != "" {
		loadedHash, err := p.nodeAgentSyncer.SyncCaddyConfig(ctx, t, configJSON)
		if err != nil {
			return NodeSyncFailed, sanitizeCaddyError(err)
		}
		if strings.TrimSpace(loadedHash) == "" {
			return NodeSyncFailed, "读取节点配置哈希失败: 协同代理未返回有效哈希"
		}
		if loadedHash != wantHash {
			return NodeSyncHashMismatch,
				fmt.Sprintf("同步内容与节点实际加载配置不一致（hash %.12s != %.12s）", wantHash, loadedHash)
		}
		return NodeSyncSuccess, ""
	}
	// 推送前再校验登记地址（登记接口已校验，此处防御 DB 直改等绕过路径）
	client, err := NewCaddyClientForAdminAddr(t.AdminAddr)
	if err != nil {
		return NodeSyncFailed, "管理通道地址非法: " + err.Error()
	}
	targetConfigJSON, err := prepareTargetConfigJSON(ctx, client, t, configJSON)
	if err != nil {
		return NodeSyncFailed, sanitizeCaddyError(err)
	}
	if err := client.LoadConfig(ctx, targetConfigJSON); err != nil {
		return NodeSyncFailed, sanitizeCaddyError(err)
	}
	loadedHash, err := client.GetBusinessConfigHash(ctx)
	if err != nil {
		return NodeSyncFailed, "读取节点配置哈希失败: " + sanitizeCaddyError(err)
	}
	if loadedHash != wantHash {
		return NodeSyncHashMismatch,
			fmt.Sprintf("同步内容与节点实际加载配置不一致（hash %.12s != %.12s）", wantHash, loadedHash)
	}
	return NodeSyncSuccess, ""
}

// syncRemoteFirewallPorts 将公网监听端口放行指令同步到所有接入 hasyncd 的远端次要节点（附加步骤，失败仅告警）。
func (p *Publisher) syncRemoteFirewallPorts(ctx context.Context, ports []int, requestedBy uuid.UUID, requestID string) {
	if p.nodeAgentSyncer == nil || p.nodeSync == nil || len(ports) == 0 {
		return
	}
	targets, err := p.nodeSync.ListSyncTargets(ctx)
	if err != nil {
		slog.Warn("list sync targets for remote firewall ensure failed", "error", err)
		return
	}
	p.syncRemoteFirewallPortsToTargets(ctx, targets, ports, requestedBy, requestID)
}

func (p *Publisher) syncRemoteFirewallPortsToTargets(ctx context.Context, targets []SyncTarget, ports []int, requestedBy uuid.UUID, requestID string) {
	if p.nodeAgentSyncer == nil || len(ports) == 0 {
		return
	}
	for _, t := range targets {
		if p.isLocalPrimaryTarget(t) || strings.TrimSpace(t.SyncAgentAddr) == "" {
			continue
		}
		if err := p.nodeAgentSyncer.SyncFirewallPorts(ctx, t, ports, requestedBy, requestID); err != nil {
			slog.Warn("sync remote firewall ports failed", "node", t.NodeName, "ports", ports, "error", err)
		}
	}
}

// buildMirrorcapSidecarForNode 按目标节点自身的网口角色与透明网桥成员口生成 mirrorcap.json 结构体。
func (p *Publisher) buildMirrorcapSidecarForNode(ctx context.Context, nodeName string, apps []AppData) MirrorcapSidecar {
	var interfaces, trafficIfaces []string
	if p.mirrorIfaces != nil {
		ifs, err := p.mirrorIfaces.ListMirrorInterfaces(ctx, nodeName)
		if err != nil {
			slog.Warn("list mirror interfaces for remote sidecar failed", "node", nodeName, "error", err)
		} else {
			interfaces = ifs
		}
		tifs, err := p.mirrorIfaces.ListInterfacesByRole(ctx, nodeName, nodeinterfaces.RoleTraffic)
		if err != nil {
			slog.Warn("list traffic interfaces for remote sidecar failed", "node", nodeName, "error", err)
		} else {
			trafficIfaces = tifs
		}
	}
	if p.bridgePorts != nil && hasAppMode(apps, applications.DeployModeTransparent) {
		bports, err := p.bridgePorts.ListBridgePorts(ctx, nodeName)
		if err != nil {
			slog.Warn("list bridge ports for remote transparent site discovery failed", "node", nodeName, "error", err)
		} else {
			trafficIfaces = append(trafficIfaces, bports...)
		}
	}
	discovery := buildMirrorcapDiscovery(apps, interfaces, trafficIfaces)
	if p.sidecarDiscoveryLog != "" {
		discovery.Log = p.sidecarDiscoveryLog
	}
	mc := buildMirrorcapSidecar(apps, nodeName, interfaces, discovery)
	if p.sidecarEventsLog != "" {
		mc.EventsLog = p.sidecarEventsLog
	}
	if p.sidecarAuditLog != "" {
		mc.AuditLog = p.sidecarAuditLog
	}
	return mc
}

// syncRemoteSidecars 将 mirrorcap.json（按节点自身网口角色生成）与 tproxyd.json 推送至接入 hasyncd 的远端次要节点。
// 边车同步属附加步骤，单节点失败只记日志，不回滚已加载的 Caddy 配置。
func (p *Publisher) syncRemoteSidecars(ctx context.Context, mirrorcapApps, tproxyApps []AppData, tproxyOverride *TproxydSidecar) {
	if p.nodeAgentSyncer == nil || p.nodeSync == nil {
		return
	}
	targets, err := p.nodeSync.ListSyncTargets(ctx)
	if err != nil {
		slog.Warn("list sync targets for remote sidecar sync failed", "error", err)
		return
	}
	var tpPayload []byte
	if tproxyOverride != nil {
		tpPayload, err = json.MarshalIndent(tproxyOverride, "", "  ")
		if err != nil {
			slog.Warn("marshal override tproxyd sidecar for remote sync failed", "error", err)
		}
	} else if tproxyApps != nil {
		sc, serr := p.buildTproxydSidecarFor(ctx, tproxyApps)
		if serr != nil {
			sc = buildTproxydSidecarWithOptions(
				tproxyApps,
				p.effectiveTproxyListen(),
				p.effectiveTproxyTarget(),
				p.effectiveTproxyTargetTLS(),
				nil,
			)
		}
		tpPayload, err = json.MarshalIndent(sc, "", "  ")
		if err != nil {
			slog.Warn("marshal tproxyd sidecar for remote sync failed", "error", err)
		}
	}
	for _, t := range targets {
		if p.isLocalPrimaryTarget(t) || strings.TrimSpace(t.SyncAgentAddr) == "" {
			continue
		}
		if mirrorcapApps != nil {
			mc := p.buildMirrorcapSidecarForNode(ctx, t.NodeName, mirrorcapApps)
			mcPayload, merr := json.MarshalIndent(mc, "", "  ")
			if merr != nil {
				slog.Warn("marshal mirrorcap sidecar for remote sync failed", "node", t.NodeName, "error", merr)
			} else if serr := p.nodeAgentSyncer.SyncSidecarFile(ctx, t, "mirrorcap.json", mcPayload); serr != nil {
				slog.Warn("sync remote mirrorcap.json failed", "node", t.NodeName, "error", serr)
			}
		}
		if len(tpPayload) > 0 {
			if serr := p.nodeAgentSyncer.SyncSidecarFile(ctx, t, "tproxyd.json", tpPayload); serr != nil {
				slog.Warn("sync remote tproxyd.json failed", "node", t.NodeName, "error", serr)
			}
		}
	}
}

// syncRemoteSidecarsAfterRollback 在回滚完成后同步刷新远端 hasyncd 节点的 mirrorcap.json 与 tproxyd.json。
func (p *Publisher) syncRemoteSidecarsAfterRollback(ctx context.Context, version *ConfigVersion) {
	if p.nodeAgentSyncer == nil || p.nodeSync == nil {
		return
	}
	var liveApps []AppData
	if p.apps != nil {
		if appsData, _, err := p.buildSnapshot(ctx, nil); err == nil {
			licenseValid := true
			if p.licenseState != nil {
				licenseValid, _ = p.licenseState(ctx)
			}
			if !licenseValid {
				for i := range appsData {
					appsData[i].ProtectionMode = applications.ModeBypass
				}
			}
			liveApps = appsData
		} else {
			slog.Warn("load live apps snapshot for remote rollback sidecars failed", "error", err)
		}
	}
	var tpOverride *TproxydSidecar
	if version != nil {
		if sc, ok := extractTproxydFromSnapshot(version.BusinessSnapshot); ok {
			if strings.TrimSpace(sc.Listen) == "" {
				sc.Listen = p.effectiveTproxyListen()
			}
			if strings.TrimSpace(sc.Target) == "" {
				sc.Target = p.effectiveTproxyTarget()
			}
			if strings.TrimSpace(sc.TargetTLS) == "" {
				sc.TargetTLS = p.effectiveTproxyTargetTLS()
			}
			if sc.Ports == nil {
				sc.Ports = []int{}
			}
			if sc.ProtectHosts == nil {
				sc.ProtectHosts = []string{}
			}
			if sc.PassthroughAllowlist == nil {
				sc.PassthroughAllowlist = []string{}
			}
			tpOverride = &sc
		} else {
			hasTransparentServer := strings.Contains(version.ConfigurationJSON, `"srv_transparent_http"`) ||
				strings.Contains(version.ConfigurationJSON, `"srv_transparent_https"`)
			if !hasTransparentServer {
				allowlist, _ := p.loadTproxyPassthroughAllowlist(ctx)
				if allowlist == nil {
					allowlist = []string{}
				}
				disabled := TproxydSidecar{
					Enabled:              false,
					Listen:               p.effectiveTproxyListen(),
					Target:               p.effectiveTproxyTarget(),
					Ports:                []int{},
					TargetTLS:            p.effectiveTproxyTargetTLS(),
					ProtectHosts:         []string{},
					PassthroughAllowlist: allowlist,
				}
				tpOverride = &disabled
			}
		}
	}
	p.syncRemoteSidecars(ctx, liveApps, liveApps, tpOverride)
}

// notifyNodeSyncFailure 次要节点同步失败告警（alerter 未接线时仅记日志，不静默）。
func (p *Publisher) notifyNodeSyncFailure(t SyncTarget, result, errMsg string, versionID uuid.UUID) {
	alertType := syncAlertTypePublishFailed
	if result == NodeSyncHashMismatch {
		alertType = syncAlertTypeHashMismatch
	}
	title := fmt.Sprintf("次要网关节点 %s 配置同步失败", t.NodeName)
	msg := fmt.Sprintf("配置版本 %s 同步到节点 %s 失败（结果 %s）：%s", versionID, t.NodeName, result, errMsg)
	if p.syncAlerter == nil {
		slog.Warn("gateway node config sync failed (alerter not wired, recorded only)",
			"component", SyncAlertComponent, "node", t.NodeName, "result", result, "error", errMsg)
		return
	}
	// 告警用背景 ctx：请求取消不丢告警（与 markAC 同一纪律）
	if err := p.syncAlerter.NotifyFailure(context.Background(), alertType, SyncAlertComponent, title, msg); err != nil {
		slog.Error("raise node sync alert failed", "node", t.NodeName, "error", err)
	}
}

// applyLicenseState 按授权状态调整发布生成输入（executePublish 生成候选配置前调用）：
// 授权无效 → Guard=nil 且快照内全部应用 ProtectionMode 强制 BYPASS——生成侧 BYPASS
// 语义（headers.go buildChainHandles）产出「RequestID + 安全响应头 + reverse_proxy」的
// 纯透传配置，快照 mode 同步修正，保证版本记录与实发配置一致；
// 授权有效且 maxQPS>0 → Guard 非 nil 时注入 LicenseMaxQPS（0=不限制不下发；
// GuardConfig 拷贝后修改，不污染回滚覆盖快照 in.GuardOverride）。
func applyLicenseState(appsData []AppData, guardCfg *GuardConfig, snapshot map[string]interface{}, valid bool, maxQPS int64) ([]AppData, *GuardConfig) {
	if !valid {
		for i := range appsData {
			appsData[i].ProtectionMode = applications.ModeBypass
		}
		if items, ok := snapshot["apps"].([]map[string]interface{}); ok {
			for _, item := range items {
				item["mode"] = applications.ModeBypass
			}
		}
		return appsData, nil
	}
	if guardCfg != nil && maxQPS > 0 {
		cp := *guardCfg
		cp.LicenseMaxQPS = int(maxQPS)
		guardCfg = &cp
	}
	return appsData, guardCfg
}

// buildSnapshot 读取业务数据并组装生成输入。
func (p *Publisher) buildSnapshot(ctx context.Context, appIDs []uuid.UUID) ([]AppData, map[string]interface{}, error) {
	var appList []applications.Application
	if len(appIDs) > 0 {
		for _, id := range appIDs {
			a, err := p.apps.GetByID(ctx, id)
			if err != nil {
				return nil, nil, err
			}
			appList = append(appList, *a)
		}
	} else {
		// 全部活动应用
		list, _, err := p.apps.List(ctx, applications.ListFilter{Status: applications.StatusActive, PageSize: 1000})
		if err != nil {
			return nil, nil, err
		}
		appList = list
	}

	var appsData []AppData
	snapshot := map[string]interface{}{"apps": []map[string]interface{}{}}
	for _, app := range appList {
		if app.Status != applications.StatusActive {
			continue
		}
		domains, err := p.apps.ListDomains(ctx, app.ID)
		if err != nil {
			return nil, nil, err
		}
		upstreams, err := p.apps.ListUpstreams(ctx, app.ID)
		if err != nil {
			return nil, nil, err
		}
		ad := AppData{
			AppID:          app.ID.String(),
			Code:           app.Code,
			ProtectionMode: app.ProtectionMode,
			DeploymentMode: app.DeploymentMode,
			Domains:        domains,
			Upstreams:      upstreams,
		}
		// 头合规、协议策略与路径转发（注入者存在时加载；DB 错误中止发布，禁止静默降级为默认行为）
		if p.appConfigs != nil {
			hc, err := p.appConfigs.GetHeaderConfig(ctx, app.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("load header config for %s: %w", app.Code, err)
			}
			ad.HeaderConfig = hc
			tc, err := p.appConfigs.GetTLSConfig(ctx, app.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("load tls config for %s: %w", app.Code, err)
			}
			ad.TLSConfig = tc
			prs, err := p.appConfigs.ListEnabledPathRoutes(ctx, app.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("load path routes for %s: %w", app.Code, err)
			}
			ad.PathRoutes = prs
		}
		// 阶段4：读取应用绑定的策略参数（策略模式优先于应用字段）
		var boundPolicyID *uuid.UUID
		if p.policies != nil {
			pp, err := p.policies.GetApplicationPolicyParams(ctx, app.ID)
			if err != nil {
				slog.Warn("get application policy params failed", "app", app.Code, "error", err)
			}
			if err == nil && pp != nil {
				// BYPASS（数据透传）为排障/应急直通，必须绝对生效，不允许被绑定策略的模式覆盖
				if pp.ProtectionMode != "" && ad.ProtectionMode != applications.ModeBypass {
					ad.ProtectionMode = pp.ProtectionMode
				}
				ad.ParanoiaLevel = pp.ParanoiaLevel
				ad.InboundThreshold = pp.InboundThreshold
				ad.OutboundThreshold = pp.OutboundThreshold
				if pp.PolicyID != "" {
					if pid, err := uuid.Parse(pp.PolicyID); err == nil {
						boundPolicyID = &pid
					}
				}
			}
		}
		// 规则覆盖（应用级 > 策略级 > 全局）
		if p.ruleOverrides != nil {
			lines, err := p.ruleOverrides.SecLangForApp(ctx, app.ID, boundPolicyID)
			if err != nil {
				return nil, nil, fmt.Errorf("应用 %s 规则覆盖快照失败: %w", app.Code, err)
			}
			ad.RuleOverrideSecLang = lines
		}
		// 域名级防护策略覆盖（按域名独立解析策略参数与对应策略级规则覆盖；查库失败 fail-hard）
		if p.policies != nil {
			policyCache := make(map[uuid.UUID]*PolicyParams)
			for _, d := range domains {
				if d.PolicyID == nil {
					continue
				}
				dpp, cached := policyCache[*d.PolicyID]
				if !cached {
					var err error
					dpp, err = p.policies.GetPolicyParams(ctx, *d.PolicyID)
					if err != nil {
						return nil, nil, fmt.Errorf("应用 %s 域名 %s 绑定的防护策略不可用: %w", app.Code, d.NormalizedHostname, err)
					}
					if dpp == nil {
						return nil, nil, fmt.Errorf("应用 %s 域名 %s 绑定的防护策略不存在", app.Code, d.NormalizedHostname)
					}
					policyCache[*d.PolicyID] = dpp
				}
				dp := DomainPolicy{
					PolicyID:          dpp.PolicyID,
					ProtectionMode:    dpp.ProtectionMode,
					ParanoiaLevel:     dpp.ParanoiaLevel,
					InboundThreshold:  dpp.InboundThreshold,
					OutboundThreshold: dpp.OutboundThreshold,
				}
				if p.ruleOverrides != nil {
					dLines, err := p.ruleOverrides.SecLangForApp(ctx, app.ID, d.PolicyID)
					if err != nil {
						return nil, nil, fmt.Errorf("应用 %s 域名 %s 规则覆盖快照失败: %w", app.Code, d.NormalizedHostname, err)
					}
					dp.HasRuleOverrides = true
					dp.RuleOverrideSecLang = dLines
				}
				if ad.DomainPolicies == nil {
					ad.DomainPolicies = make(map[string]DomainPolicy)
				}
				ad.DomainPolicies[d.ID.String()] = dp
			}
		}
		// 证书（HTTPS 应用；MIRROR 镜像旁路不终结 TLS、不加载证书，跳过强制证书校验）
		// 支持双槽位并存：通用国际证书、国密 SM_TLCP 双证书，或二者同时绑定。
		hasHTTPS := false
		for _, d := range domains {
			if d.HTTPSEnabled {
				hasHTTPS = true
				break
			}
		}
		if hasHTTPS && app.DeploymentMode != applications.DeployModeMirror {
			bindings, err := p.certs.GetApplicationCertificates(ctx, app.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("应用 %s 查询证书失败: %w", app.Code, err)
			}
			var intlCert, gmCert *certificates.Certificate
			if bindings != nil {
				intlCert = bindings.International
				gmCert = bindings.GM
			}
			if intlCert == nil && gmCert == nil {
				// 若显式配置为仅国密模式（GM_ONLY），自动 SSL 无法签发国密双证书，须立即报错
				if ad.TLSConfig != nil && strings.EqualFold(strings.TrimSpace(ad.TLSConfig.TLSProtocolMode), TLSProtocolModeGMOnly) {
					return nil, nil, fmt.Errorf("应用 %s 已配置为仅国密模式（GM_ONLY），但未绑定国密 SM_TLCP 双证书", app.Code)
				}
				if app.AutoSSLEnabled {
					// 开启自动 SSL 且首次证书尚未签发：放行 :80 与 ACME HTTP-01 挑战路由，
					// 暂缓 :443 与 308 跳转，待证书签发绑定后再自动发布上线。
					ad.PendingAutoSSL = true
				} else {
					return nil, nil, fmt.Errorf("应用 %s 启用 HTTPS 但未绑定证书", app.Code)
				}
			} else {
				if intlCert != nil {
					// 读取证书链与解密私钥供 Caddy load_pem / jiuzhang_tls_mux 内存加载（跨节点无需共享磁盘文件），
					// 同时保留本地落盘以兼容既有排障/文件依赖。
					certFile, certPEM, chainPEM, keyPEM, err := p.prepareCertMaterial(ctx, intlCert)
					if err != nil {
						return nil, nil, fmt.Errorf("应用 %s 证书准备失败: %w", app.Code, err)
					}
					ad.HasCert = true
					ad.CertID = intlCert.ID.String()
					ad.CertFileName = certFile
					ad.CertPEM = certPEM
					ad.ChainPEM = chainPEM
					ad.KeyPEM = keyPEM
				}
				if gmCert != nil {
					gmMat, err := p.prepareGMCertMaterial(ctx, gmCert)
					if err != nil {
						return nil, nil, fmt.Errorf("应用 %s 国密双证书准备失败: %w", app.Code, err)
					}
					ad.HasGMCert = true
					ad.GMCertID = gmCert.ID.String()
					ad.GMSignCertPEM = gmMat.SignCertPEM
					ad.GMSignKeyPEM = gmMat.SignKeyPEM
					ad.GMEncCertPEM = gmMat.EncCertPEM
					ad.GMEncKeyPEM = gmMat.EncKeyPEM
					ad.GMChainPEM = gmMat.ChainPEM
				}
				if err := validateAppTLSConsistency(ad); err != nil {
					return nil, nil, err
				}
			}
		}
		appsData = append(appsData, ad)
		appSnap := map[string]interface{}{
			"code": app.Code, "mode": app.ProtectionMode,
			"deployment_mode": app.DeploymentMode,
			"domains":         len(domains), "upstreams": len(upstreams),
		}
		if len(ad.DomainPolicies) > 0 {
			appSnap["domain_policies"] = len(ad.DomainPolicies)
		}
		if ad.PendingAutoSSL {
			appSnap["cert_pending_auto_ssl"] = true
		}
		if ad.HasGMCert {
			appSnap["has_gm_cert"] = true
		}
		snapshot["apps"] = append(snapshot["apps"].([]map[string]interface{}), appSnap)
	}
	return appsData, snapshot, nil
}

// validateAppTLSConsistency 发布前校验站点协议模式与已绑定证书槽位的一致性（fail-closed）：
//   - GM_ONLY 必须绑定国密 SM_TLCP 双证书；
//   - INTERNATIONAL_ONLY 必须绑定通用国际证书；
//   - 至少存在国际证书或国密双证书之一（PendingAutoSSL 例外不进入本函数）。
func validateAppTLSConsistency(ad AppData) error {
	if ad.PendingAutoSSL {
		if ad.TLSConfig != nil && strings.EqualFold(strings.TrimSpace(ad.TLSConfig.TLSProtocolMode), TLSProtocolModeGMOnly) {
			return fmt.Errorf("应用 %s 已配置为仅国密模式（GM_ONLY），但未绑定国密 SM_TLCP 双证书", ad.Code)
		}
		return nil
	}
	if !ad.HasCert && !ad.HasGMCert {
		return fmt.Errorf("应用 %s 启用 HTTPS 但未绑定证书", ad.Code)
	}
	if ad.TLSConfig == nil {
		return nil
	}
	mode := strings.ToUpper(strings.TrimSpace(ad.TLSConfig.TLSProtocolMode))
	switch mode {
	case TLSProtocolModeGMOnly:
		if !ad.HasGMCert {
			return fmt.Errorf("应用 %s 已配置为仅国密模式（GM_ONLY），但未绑定国密 SM_TLCP 双证书", ad.Code)
		}
	case TLSProtocolModeInternationalOnly:
		if !ad.HasCert {
			return fmt.Errorf("应用 %s 已配置为仅国际模式（INTERNATIONAL_ONLY），但未绑定国际通用证书", ad.Code)
		}
	}
	return nil
}

// prepareGMCertMaterial 读取并解密国密 SM_TLCP 双证书完整材料（签名证/签名私钥 + 加密证/加密私钥 + 证书链）。
func (p *Publisher) prepareGMCertMaterial(ctx context.Context, cert *certificates.Certificate) (*certificates.GMCertMaterial, error) {
	mat, err := p.certs.GetGMCertMaterial(ctx, cert.ID)
	if err != nil {
		return nil, err
	}
	if mat == nil ||
		strings.TrimSpace(mat.SignCertPEM) == "" ||
		strings.TrimSpace(mat.SignKeyPEM) == "" ||
		strings.TrimSpace(mat.EncCertPEM) == "" ||
		strings.TrimSpace(mat.EncKeyPEM) == "" {
		return nil, fmt.Errorf("国密证书 %s 缺少有效的签名或加密证书/私钥 PEM 内容", cert.ID)
	}
	return mat, nil
}

// prepareCertMaterial 读取证书链与解密私钥，并同步写入数据目录（权限 0600，保留本地兼容）。
func (p *Publisher) prepareCertMaterial(ctx context.Context, cert *certificates.Certificate) (certFile, certPEM, chainPEM, keyPEM string, err error) {
	certPEM, chainPEM, err = p.certs.GetCertPEM(ctx, cert.ID)
	if err != nil {
		return "", "", "", "", err
	}
	keyPEM, err = p.certs.GetDecryptedKey(ctx, cert.ID)
	if err != nil {
		return "", "", "", "", err
	}
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return "", "", "", "", fmt.Errorf("证书 %s 缺少有效的证书或私钥 PEM 内容", cert.ID)
	}
	fullCertPEM := mergeCertChainPEM(certPEM, chainPEM)
	certFile, err = WriteCertificateFiles(p.dataDir, cert.ID.String(), fullCertPEM, keyPEM)
	if err != nil {
		return "", "", "", "", err
	}
	return certFile, certPEM, chainPEM, keyPEM, nil
}

// writeCertFiles 将证书与私钥写入数据目录（权限0600）。
func (p *Publisher) writeCertFiles(ctx context.Context, cert *certificates.Certificate) (string, error) {
	certFile, _, _, _, err := p.prepareCertMaterial(ctx, cert)
	return certFile, err
}

// verifyPublish 发布后验证（Caddy 可用 + 配置已加载 + 内容与发布一致）。
func (p *Publisher) verifyPublish(ctx context.Context, gen *Generated, appsData []AppData) error {
	// 1. Caddy Admin 可用
	if err := p.caddy.Ping(ctx); err != nil {
		return fmt.Errorf("发布后网关管理接口不可用: %w", err)
	}
	// 2. 当前配置非空且包含预期 server
	current, err := p.caddy.GetCurrentConfig(ctx)
	if err != nil {
		return fmt.Errorf("读取当前配置失败: %w", err)
	}
	if gen.ServerCount > 0 && !strings.Contains(current, "servers") {
		return fmt.Errorf("发布后配置未包含预期的 server 定义")
	}
	// 3. 生效校验（P0-21）：发布内容与网关实际加载配置的规范化哈希必须一致，
	//    不一致视为未生效 → 上层触发自动回滚
	wantHash, err := CanonicalConfigHash(gen.JSON)
	if err != nil {
		return fmt.Errorf("计算发布内容哈希失败: %w", err)
	}
	loadedHash, err := p.caddy.GetConfigHash(ctx)
	if err != nil {
		return fmt.Errorf("读取网关配置哈希失败: %w", err)
	}
	if wantHash != loadedHash {
		return fmt.Errorf("发布内容与网关实际加载配置不一致（hash %.12s != %.12s）", wantHash, loadedHash)
	}
	return nil
}

// rollbackToConfig 回滚到指定配置。
func (p *Publisher) rollbackToConfig(ctx context.Context, configJSON string) error {
	if configJSON == "" {
		return fmt.Errorf("无可用历史配置")
	}
	return p.caddy.LoadConfig(ctx, configJSON)
}

// RollbackInput 是回滚输入。
type RollbackInput struct {
	VersionID   uuid.UUID
	RequestedBy uuid.UUID
	RequestID   string
}

// Rollback 回滚到历史版本。
func (p *Publisher) Rollback(ctx context.Context, in RollbackInput) (*PublishTask, error) {
	task, err := p.createTask(ctx, TaskTypeRollback, in.RequestedBy, in.RequestID, "")
	if err != nil {
		return nil, err
	}
	lockOwner := task.ID.String()
	lease, err := p.acquireLock(ctx, lockOwner)
	if err != nil || lease == nil {
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_BUSY", "其他发布任务正在执行", nil)
		return p.GetTask(ctx, task.ID)
	}
	defer p.releaseLock(context.Background(), lease)

	// 读取目标版本
	version, err := p.getVersion(ctx, in.VersionID)
	if err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "VERSION_NOT_FOUND", "目标版本不存在", nil)
		return p.GetTask(ctx, task.ID)
	}
	if version.PublishResult != "SUCCESS" {
		p.finishTask(ctx, task.ID, TaskFailed, "VERSION_NOT_PUBLISHED", "目标版本未成功发布，不能回滚", nil)
		return p.GetTask(ctx, task.ID)
	}

	// 密钥语义与 RollbackAccessControl 统一为「重注入当前密钥」：版本表不再保存密钥明文
	// （saveVersion 脱敏存储），存量历史版本可能含旧明文，统一在重放前按当前设置重注入
	// guard 段密钥类字段（valkey 密码、identity_salt、扫描/文件签名 key_hex、TLS 票据键），
	// 取不到当前值则失败并明确报错（见 config_secrets.go）
	rollbackJSON, err := p.reinjectConfigSecrets(ctx, version.ConfigurationJSON)
	if err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_SECRET_REINJECT_FAILED", err.Error(), nil)
		return p.GetTask(ctx, task.ID)
	}
	if ok, code, message := p.evaluateRollbackRegressionGate(ctx, task.ID, version.ID, rollbackJSON); !ok {
		p.finishTask(ctx, task.ID, TaskFailed, code, message, &version.ID)
		return p.GetTask(ctx, task.ID)
	}

	p.updateTaskStep(ctx, task.ID, TaskPublishing, "回滚发布", 50)
	if err := lease.ensure(ctx); err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_LOST", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	prevConfig, err := loadGatewayConfig(ctx, p.caddy, rollbackJSON)
	if err != nil {
		if errors.Is(err, errPreviousConfigRead) {
			p.finishTask(ctx, task.ID, TaskFailed, "PREVIOUS_CONFIG_READ_FAILED",
				"无法读取回滚前网关配置: "+sanitizeCaddyError(err), nil)
			return p.GetTask(ctx, task.ID)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_PUBLISH_FAILED", sanitizeCaddyError(err), nil)
		return p.GetTask(ctx, task.ID)
	}
	if err := ensureLeaseAfterConfigLoad(ctx, lease, func(recoveryCtx context.Context) error {
		return p.rollbackToConfig(recoveryCtx, prevConfig)
	}); err != nil {
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_LOST", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}

	// 验证
	if err := p.verifyPublish(ctx, &Generated{JSON: rollbackJSON, ServerCount: 1}, nil); err != nil {
		if restoreErr := p.rollbackToConfig(ctx, prevConfig); restoreErr != nil {
			p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_FAILED",
				fmt.Sprintf("回滚后验证失败(%s)且恢复原配置失败(%s)", err.Error(), restoreErr.Error()), nil)
			return p.GetTask(ctx, task.ID)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_VERIFY_FAILED", "回滚后验证失败，已恢复", nil)
		return p.GetTask(ctx, task.ID)
	}

	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_LOST", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	activationState, err := p.snapshotCurrentVersionState(ctx)
	if err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("snapshot current version state: %v; restore previous config: %v", err, restoreErr)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "ACTIVATION_STATE_SNAPSHOT_FAILED", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restoreConfigAfterPublishLockLoss(prevConfig); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_LOST", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	if err := p.setCurrentVersion(ctx, in.VersionID); err != nil {
		if restoreErr := p.rollbackToConfig(ctx, prevConfig); restoreErr != nil {
			p.finishTask(ctx, task.ID, TaskFailed, "ROLLBACK_FAILED",
				fmt.Sprintf("切换当前版本失败(%s)且恢复原配置失败(%s)", err.Error(), restoreErr.Error()), nil)
			return p.GetTask(ctx, task.ID)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "SET_CURRENT_VERSION_FAILED_ROLLED_BACK",
			"切换当前版本失败，网关已恢复原配置: "+err.Error(), nil)
		return p.GetTask(ctx, task.ID)
	}
	if err := lease.ensure(ctx); err != nil {
		if restoreErr := p.restorePublishStateAfterPublishLockLoss(prevConfig, activationState); restoreErr != nil {
			err = fmt.Errorf("%w; restore previous config: %v", err, restoreErr)
		}
		p.finishTask(ctx, task.ID, TaskFailed, "LOCK_LOST", err.Error(), &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	// 主节点已完成回滚与当前版本切换：优先同步刷新主节点 mirrorcap/tproxyd 边车配置
	// （不得因次要节点扇出失败而跳过主节点边车恢复，附加产物失败仅记日志）。
	if err := p.restoreSidecarsAfterRollback(context.Background(), version); err != nil {
		slog.Warn("refresh sidecar configs after rollback failed", "version", in.VersionID, "error", err)
	}
	// 回滚同样同步远端节点公网端口放行（先放行后加载）与边车配置。
	if rbPorts, ok := extractPublicTCPPortsFromConfig(rollbackJSON); ok && len(rbPorts) > 0 {
		p.syncRemoteFirewallPorts(context.Background(), rbPorts, in.RequestedBy, in.RequestID)
	}
	// 显式回退也必须把已验证的恢复配置扇出到次要节点；否则主节点已切回旧版本，
	// 次要节点仍可能继续提供被回退的版本。扇出沿用发布成功后的逐节点记录/告警语义，
	// 且使用独立上下文，避免回退请求取消后丢失节点水位更新。
	syncOutcome := p.syncConfigToNodes(context.Background(), rollbackJSON, in.VersionID)
	p.syncRemoteSidecarsAfterRollback(context.Background(), version)
	if code, message, incomplete := syncOutcome.rollbackFailure(in.VersionID); incomplete {
		p.finishTask(ctx, task.ID, TaskFailed, code, message, &in.VersionID)
		return p.GetTask(ctx, task.ID)
	}
	p.finishTask(ctx, task.ID, TaskSuccess, "", "回滚成功", &in.VersionID)
	return p.GetTask(ctx, task.ID)
}

// RollbackAccessControl 回滚访问控制配置到历史版本（以快照覆盖重新走完整发布流程）。
func (p *Publisher) RollbackAccessControl(ctx context.Context, versionID uuid.UUID, requestedBy uuid.UUID, requestID string) (*PublishTask, error) {
	if p.guard == nil {
		return nil, fmt.Errorf("guard provider not configured")
	}
	override, err := p.guard.GetVersionConfig(ctx, versionID)
	if err != nil {
		return nil, fmt.Errorf("读取访问控制版本快照失败: %w", err)
	}
	return p.PublishSync(ctx, PublishInput{
		RequestedBy:   requestedBy,
		RequestID:     requestID,
		GuardOverride: override,
	})
}

// gateGuardOverride 回滚覆盖快照按当前产品开关再门控（防跨重启泄漏）：
// 快照可能取自 WDSP 开启时期，当前 API_DYNAMIC_PROTECTION_ENABLED=false 或
// edition=waf 时剥除 API 段（口径与 buildGuardHandler 一致——仅 APIDynamicProtection
// 为 true 才下发 API 段），避免把 API 动态防护能力回放到纯 WAF 产品形态。
// 当前开关以 BuildGuardConfig 产物的 APIDynamicProtection 为准（装配侧 env/edition 口径）；
// 读取失败如实返回（回滚发布失败，不静默放行快照 API 段）。
// 快照未开启 API 段或当前开关开启时原样返回（不修改入参）。
func (p *Publisher) gateGuardOverride(ctx context.Context, override *GuardConfig) (*GuardConfig, error) {
	if override == nil || !override.APIDynamicProtection {
		return override, nil
	}
	cur, err := p.guard.BuildGuardConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("读取当前访问控制配置以门控回滚快照失败: %w", err)
	}
	if cur.APIDynamicProtection {
		return override, nil
	}
	return stripAPIGuardSections(override), nil
}

// stripAPIGuardSections 返回剥除 API 动态防护段后的 GuardConfig 拷贝（不修改入参；
// 剥除口径与 buildGuardHandler 的 if g.APIDynamicProtection 块一致；
// 非 API 字段——valkey、L7、访问日志、TLS 票据键、授权限速等——原样保留）。
func stripAPIGuardSections(g *GuardConfig) *GuardConfig {
	cp := *g
	cp.APIDynamicProtection = false
	cp.APIProtectionMode = ""
	cp.APIEventsLog = ""
	cp.APIFormalSchemas = nil
	cp.APIFormalModelVersions = nil
	cp.APIParameterConstraints = nil
	cp.APIKnownEndpoints = nil
	// WDSP P1：API 准入策略随 API 动态防护门控下发，一并剥除
	cp.APIAdmission = nil
	cp.APIPolicyVersion = ""
	// P0-04：API 引擎受限例外随 API 动态防护门控下发，一并剥除
	cp.APIExceptions = nil
	// 网关运行时设置（gateway_runtime 组）仅在 API 段内下发，一并剥除
	cp.BehaviorStore = ""
	cp.BehaviorStoreTTLSeconds = 0
	cp.IdentitySalt = ""
	cp.CredentialIPSpreadLimit = 0
	cp.CredentialConcurrencyLimit = 0
	cp.CredentialRatePerMinute = 0
	cp.TenantRatePerMinute = 0
	cp.ActionRatePerMinute = 0
	cp.APIEndpointActions = nil
	cp.GroupRatePerMinute = 0
	cp.APIEndpointGroups = nil
	cp.APIWriteRatePerMinute = 0
	cp.APIRateLimitAction = ""
	cp.APITempBlockSeconds = 0
	cp.APIQuotaPerHour = 0
	cp.APIQuotaPerDay = 0
	cp.ObjectRatePerMinute = 0
	cp.APIMaxPageSize = 0
	cp.APIMaxBatchSize = 0
	cp.APIMaskRules = nil
	cp.APIMaskCrypto = nil
	cp.APIIdentityBlocks = nil
	cp.APISensitiveValueRules = nil
	cp.APIRoleBaselines = nil
	cp.APIAuthzModels = nil
	cp.APIAuthzRelations = nil
	cp.APIAuthzRoleBaselines = nil
	cp.APIAuthzObjectHMACKeyHex = ""
	cp.APIAuthzPreviousValid = nil
	cp.APIFieldPermissions = nil
	cp.APIScanVerification = nil
	cp.APIResponseBaselines = nil
	cp.APIParameterRelations = nil
	// 阶段8 §44：流程基线随 API 动态防护门控下发，一并剥除
	cp.APIFlowBaselines = nil
	// 阶段8 §35：已吊销凭据清单随 API 动态防护门控下发，一并剥除
	cp.APIRevokedCredentials = nil
	// NG-GQL-03：GraphQL 成本预算策略随 API 动态防护门控下发，一并剥除
	cp.APIGraphQL = nil
	// NG-AZ-02：v2 快照元数据随 API 动态防护门控下发，一并剥除（PreviousValid 同上口径置 nil）
	cp.APIAuthzSchema = ""
	cp.APIAuthzRevocationWatermark = nil
	cp.APIAuthzConflictedObjects = nil
	cp.APIAuthzProducedAt = nil
	cp.APIAuthzLeaseSeconds = nil
	cp.APIAuthzClockSkewMaxSeconds = 0
	cp.APINodeHeartbeatSeconds = 0
	cp.APILLMAllowedModels = nil
	cp.APILLMSecurityPolicies = nil
	cp.APIFileWatermark = nil
	cp.APIFileSignature = nil
	cp.APIFileComplianceRules = nil
	cp.APIResponseFailPolicy = ""
	cp.APIResponseCaptureMaxBytes = 0
	cp.APIResponseSampleRatio = nil
	cp.APIGRPCMaxFrameBytes = 0
	cp.APIGRPCAllowCompression = false
	cp.APIGRPCDescriptors = nil
	cp.JWTTrust = nil
	cp.BotPolicy = nil
	// P1-02 B3 预备：Bot 签名密钥随 bot_policy 段同一门控剥除（秘密材料不得
	// 在 WDSP 关闭形态下随回滚快照回放）
	cp.BotSigningKeys = nil
	cp.AICrawlPolicy = nil
	cp.AICrawlLabyrinthKeyHex = ""
	cp.ClientSidePolicy = nil
	cp.APIA2APolicy = nil
	cp.SemanticGuardPolicy = nil
	cp.WasmPlugins = nil
	return &cp
}

// sanitizeCaddyError 清理 Caddy 错误信息（不泄露内部细节）。
func sanitizeCaddyError(err error) string {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500] + "...(truncated)"
	}
	return msg
}

// saveFailedCandidate 保存失败候选配置（供排查；写入磁盘前经 RedactConfigSecrets 脱敏）。
func (p *Publisher) saveFailedCandidate(gen *Generated, snapshot map[string]interface{}, cause error) {
	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		redacted = `{"redacted_on_parse_error":true}`
	}
	_ = WriteFailedCandidate(p.dataDir, redacted, cause.Error())
}
