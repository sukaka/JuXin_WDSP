// Package botpolicy 应用级 Bot 挑战策略管理面（WDSP P1-02 B0/B1，任务书
// docs/tasks/wdsp-p1/P1-02_BOT_CHALLENGE.md）：按应用的 Bot 策略 CRUD/校验/路由保留
// 冲突预检，经既有配置发布通道下发网关 bot_policy 段。
//
// B0 冻结决策（本包常量即冻结口径，改动需升 SchemaVersion）：
//   - 信号三组：request_behavior（请求行为组：状态码族/方法/URI 分布，复用
//     identitybehavior 窗口计数）、access_sequence（访问序列组：已知 URI 比例、
//     方法枚举异常）、client_claim（客户端声明组：UA 分类 + TLS 版本/密码套件
//     轻量特征——可伪造弱信号，不能独立构成挑战依据）；
//   - 提出挑战需 ≥2 个独立信号组同时满足且至少 1 个行为组；同源计数派生指标
//     （同 group+metric+params）不重复计权；
//   - 建议默认值：nonce_ttl=90s（30..300）、clearance_ttl=900s（60..3600）、
//     difficulty=14bit（10..18）、单题最多 3 次验证尝试（1..5）；
//   - selectors 仅 GET + 路径精确或规范化前缀，禁止正则与全站通配；
//   - 保留端点命名空间 ReservedNamespace（verify 在其下）；route_reservation
//     记录保留状态（ENABLED/RESERVED_TOMBSTONE/RELEASED），属版本化配置；
//   - Valkey 键前缀 ValkeyKeyPrefix 冻结保留（B2 启用，本阶段不写运行时逻辑）。
//
// 本阶段（B1）只落地策略与配置链：mode 校验与存储、signal_rules/challenge 参数
// 校验、版本与发布；挑战生成/verify 端点/Eval 处置不实现（B2/B3）。
package botpolicy

import (
	"time"

	"github.com/google/uuid"
)

// 策略模式（默认 OFF：不观测、不挑战、不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 信号组（B0 冻结）。client_claim 为可伪造弱信号声明组；
// 行为组 = request_behavior / access_sequence（实际行为观测）。
const (
	GroupRequestBehavior = "request_behavior"
	GroupAccessSequence  = "access_sequence"
	GroupClientClaim     = "client_claim"
)

// 信号指标（按组白名单，B0 冻结；未知指标拒绝）。
const (
	// request_behavior（复用 identitybehavior 窗口计数）
	MetricStatusFamilyRatio = "status_family_ratio" // 窗口内某状态码族请求占比（params.family，≥阈值触发）
	MetricMethodRatio       = "method_ratio"        // 窗口内某方法请求占比（params.method，≥阈值触发）
	MetricURIConcentration  = "uri_concentration"   // 窗口内最热 URI 占比（无参数，≥阈值触发）
	// access_sequence
	MetricKnownURIRatio         = "known_uri_ratio"         // 窗口内已知 URI 请求占比（无参数，≤阈值触发——低比例=枚举）
	MetricMethodEnumerationSize = "method_enumeration_size" // 窗口内 distinct 方法数（无参数，≥阈值触发）
	// client_claim（可伪造弱信号，命中即触发，threshold 不使用）
	MetricUAClassMatch  = "ua_class_match"  // UA 分类命中（params.class ∈ BOT/APPLICATION/SERVICE/AGENT/UNKNOWN）
	MetricTLSClientHint = "tls_client_hint" // TLS 版本/密码套件轻量特征精确比对（params.field ∈ version/cipher_suite，params.equals）
)

// 路由保留状态机（route_reservation.state，版本化配置）：
//   - ENABLED：保留路由已注册（应用启用或明确保留 Bot 路由）；
//   - RESERVED_TOMBSTONE：从已启用状态关闭——保留本地 404 墓碑路由，
//     直到运维明确解除保留（防旧挑战提交打到业务源站）；
//   - RELEASED：保留解除（首次 OFF 且从未启用的应用不抢占业务路径）。
const (
	ReservationEnabled   = "ENABLED"
	ReservationTombstone = "RESERVED_TOMBSTONE"
	ReservationReleased  = "RELEASED"
)

// 保留端点命名空间（B0 冻结；verify 端点 = ReservedVerifyPath）。
// 命名空间更换需升 SchemaVersion 并经冲突预检重新评估。
const (
	ReservedNamespace  = "/_wdsp/bot/v1/"
	ReservedVerifyPath = "/_wdsp/bot/v1/verify"
	// ValkeyKeyPrefix Bot 挑战共享状态 Valkey 键前缀（B0 冻结保留；
	// B2 挑战状态/nonce 原子消费启用，本阶段不落运行时逻辑）。
	ValkeyKeyPrefix = "jiuzhang:guard:bot"
)

// 校验边界（B0 冻结默认值与上下界；任务书 §4.1/§5.2）。
const (
	MaxSelectors       = 64   // 每策略 selector 上限
	MaxSelectorPathLen = 512  // path_exact/path_prefix 长度上限
	MaxSignalRules     = 32   // 每策略信号规则上限
	MaxRuleIDLen       = 64   // 规则 ID 长度上限
	MinGroups          = 2    // min_independent_groups 下限（B0：≥2 个独立信号组）
	MaxGroups          = 3    // min_independent_groups 上限（信号组总数）
	MinWindowSeconds   = 30   // 信号窗口下限（秒）
	MaxWindowSeconds   = 3600 // 信号窗口上限（秒）
	DefaultWindow      = 300  // 信号窗口默认值（秒）
	MaxRuleWeight      = 10   // 规则权重上限（开区间下界 0；组满足 = 组内已触发权重和 ≥1）
	// 挑战参数（任务书 §5.2 建议初值，非性能保证）
	DefaultNonceTTL     = 90  // nonce_ttl_seconds 默认（秒）
	MinNonceTTL         = 30  // nonce_ttl_seconds 下限（秒）
	MaxNonceTTL         = 300 // nonce_ttl_seconds 上限（秒）
	DefaultClearanceTTL = 900 // clearance_ttl_seconds 默认（秒）
	MinClearanceTTL     = 60  // clearance_ttl_seconds 下限（秒）
	MaxClearanceTTL     = 3600
	DefaultDifficulty   = 14 // difficulty 默认（bit）
	MinDifficulty       = 10 // difficulty 下限（bit）
	MaxDifficulty       = 18 // difficulty 上限（bit）
	DefaultMaxAttempts  = 3  // max_attempts 默认（单题验证尝试）
	MinMaxAttempts      = 1
	MaxMaxAttempts      = 5
	MaxKeyRefLen        = 64  // key_ref 引用名长度上限（仅引用名，不含任何密钥材料）
	MaxReasonLen        = 500 // 变更理由长度上限
	// SchemaVersion 下发网关 bot_policy 段的配置结构版本（旧网关节点不识别该段时
	// 必须拒绝加载而不是忽略强制语义——与 jwt_trust 同一纪律，网关侧严格解码）。
	SchemaVersion = 1
)

// Selector 挑战适用范围选择器（B0 冻结）：仅 GET 浏览器文档导航；path_exact/
// path_prefix 二选一；prefix 按完整路径段匹配（/docs 匹配 /docs 与 /docs/a，
// 不匹配 /docsx）；路径为解码后形式，大小写敏感，禁止正则、百分号编码与全站通配；
// 不同 selector 之间 OR。
type Selector struct {
	PathExact  string `json:"path_exact,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// SignalRule 单条信号规则（id 稳定、策略内唯一；threshold 语义按指标冻结：
// 占比/计数类 ≥ 阈值触发，known_uri_ratio ≤ 阈值触发，声明匹配类命中即触发
// 且 threshold 恒 0）。params 为指标参数（字符串键值；允许键按指标白名单）。
type SignalRule struct {
	ID            string            `json:"id"`
	Group         string            `json:"group"`
	Metric        string            `json:"metric"`
	Params        map[string]string `json:"params,omitempty"`
	WindowSeconds int               `json:"window_seconds"`
	Weight        float64           `json:"weight"`
	Threshold     float64           `json:"threshold"`
}

// SignalRules 多信号判定配置（B0 冻结决策口径）：提出挑战需
// MinIndependentGroups 个独立信号组同时满足（组满足 = 组内已触发规则权重和 ≥1），
// 且 RequireBehaviorGroup 恒 true（至少 1 个行为组——声明组不可单独构成依据）。
type SignalRules struct {
	MinIndependentGroups int          `json:"min_independent_groups"`
	RequireBehaviorGroup bool         `json:"require_behavior_group"`
	Rules                []SignalRule `json:"rules"`
}

// Challenge 挑战参数（仅 type=JS 第一方挑战；TTL/难度/尝试数上下界见常量；
// KeyRef 仅引用预置内部签名密钥的引用名——任何接口与审计均不返回密钥材料）。
type Challenge struct {
	Type                string `json:"type"`
	NonceTTLSeconds     int    `json:"nonce_ttl_seconds"`
	ClearanceTTLSeconds int    `json:"clearance_ttl_seconds"`
	Difficulty          int    `json:"difficulty"`
	MaxAttempts         int    `json:"max_attempts"`
	KeyRef              string `json:"key_ref,omitempty"`
}

// RouteReservation 保留路由状态（版本化配置；namespace 恒为 ReservedNamespace）。
type RouteReservation struct {
	State     string `json:"state"`
	Namespace string `json:"namespace"`
}

// Policy 应用 Bot 策略（当前草稿；与 bot_policies 表列对应）。
// Version 为乐观锁版本（不可变递增；PUT 携带 expected_version 防并发覆盖）。
// 无策略记录的应用按 DefaultPolicy 处理（OFF 空策略，version=0）。
type Policy struct {
	ID               uuid.UUID        `json:"id"`
	ApplicationID    uuid.UUID        `json:"application_id"`
	Mode             string           `json:"mode"`
	Version          int              `json:"version"`
	Selectors        []Selector       `json:"selectors"`
	SignalRules      SignalRules      `json:"signal_rules"`
	Challenge        Challenge        `json:"challenge"`
	RouteReservation RouteReservation `json:"route_reservation"`
	UpdatedBy        string           `json:"updated_by"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// DefaultChallenge B0 默认挑战参数（type=JS + 建议初值）。
func DefaultChallenge() Challenge {
	return Challenge{
		Type:                "JS",
		NonceTTLSeconds:     DefaultNonceTTL,
		ClearanceTTLSeconds: DefaultClearanceTTL,
		Difficulty:          DefaultDifficulty,
		MaxAttempts:         DefaultMaxAttempts,
	}
}

// DefaultSignalRules B0 默认信号判定配置（无规则：不产生任何判定）。
func DefaultSignalRules() SignalRules {
	return SignalRules{
		MinIndependentGroups: MinGroups,
		RequireBehaviorGroup: true,
		Rules:                []SignalRule{},
	}
}

// DefaultPolicy 历史应用无记录时的默认策略（OFF 空策略，version=0，保留释放；
// PUT 以 expected_version=0 创建首版草稿）。
func DefaultPolicy(appID uuid.UUID) *Policy {
	return &Policy{
		ApplicationID: appID,
		Mode:          ModeOff,
		Version:       0,
		Selectors:     []Selector{},
		SignalRules:   DefaultSignalRules(),
		Challenge:     DefaultChallenge(),
		RouteReservation: RouteReservation{
			State:     ReservationReleased,
			Namespace: ReservedNamespace,
		},
	}
}

// PublishState 最近成功发布快照中本应用策略的生效状态
// （Found=false = 从未成功发布；PolicyVersion=0 = 该快照未下发本应用策略）。
type PublishState struct {
	Found         bool      `json:"found"`
	VersionNo     int       `json:"version_no"`     // 发布批次号（access_control_versions.version_no）
	VersionID     uuid.UUID `json:"version_id"`     // 发布批次 ID（与节点 last_sync_version_id 比对）
	PolicyVersion int       `json:"policy_version"` // 快照 bot_policy 段中本应用策略版本
}

// NodeSyncState 扇出节点同步状态（GET 状态摘要；主节点生效以发布批次 SUCCESS 为准）。
type NodeSyncState struct {
	NodeName          string     `json:"node_name"`
	LastSyncResult    string     `json:"last_sync_result"`     // SUCCESS/FAILED/HASH_MISMATCH；空=从未同步
	LastSyncVersionID *uuid.UUID `json:"last_sync_version_id"` // 最近同步的配置版本；nil=从未同步
	Effective         bool       `json:"effective"`            // 已同步到最新成功发布批次
}

// StatusSummary GET 状态摘要：草稿版本 vs 发布批次 vs 节点有效版本分离返回
// （不混成一个 enabled；发布失败不回退草稿——旧有效版本继续运行）。
// state 取值：NOT_CONFIGURED（无草稿）/ DRAFT_PENDING（草稿未发布或领先已发布）/
// PUBLISHED（草稿与最近成功发布一致）。
type StatusSummary struct {
	State        string          `json:"state"`
	DraftVersion int             `json:"draft_version"`
	Published    PublishState    `json:"published"`
	Nodes        []NodeSyncState `json:"nodes,omitempty"`
}

// 状态词表。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)
