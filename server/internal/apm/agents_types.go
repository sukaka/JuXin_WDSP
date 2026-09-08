// agents_types.go APM Agent 控制面类型与生命周期状态机（设计 §8.3）。
//
// 状态机存态（apm_agents.status，CHECK 约束兜底）：
//
//	ENROLLING ──注册成功──► CONNECTED_BASELINE ◄──────┐
//	CONNECTED_BASELINE ──开启诊断(阶段4)──► DIAGNOSING ─┘(到期/停止)
//	任意非终态 ──撤销──► REVOKED（终态）
//
// OFFLINE 不落库：由查询侧按 last_heartbeat_at（无心跳退化为 registered_at）
// 超阈值推导（DeriveAgentStatus）；ENROLL_FAILED 不入本批（注册失败即无登记行）。
package apm

import (
	"time"

	"github.com/google/uuid"
)

// Agent 生命周期状态词表（apm_agents.status；OFFLINE 为派生展示态，不落库）。
const (
	AgentStatusEnrolling         = "ENROLLING"
	AgentStatusConnectedBaseline = "CONNECTED_BASELINE"
	AgentStatusDiagnosing        = "DIAGNOSING"
	AgentStatusOffline           = "OFFLINE" // 派生态：心跳超时，非存储值
	AgentStatusRevoked           = "REVOKED" // 终态
)

// canTransitionAgent 状态机合法迁移表（from → 允许的 to 集合）。
// OFFLINE 不参与（派生态）；心跳不驱动状态迁移（只刷新 last_heartbeat_at，
// ENROLLING 残留行由首心跳补进到 CONNECTED_BASELINE）。
var canTransitionAgent = map[string]map[string]bool{
	AgentStatusEnrolling:         {AgentStatusConnectedBaseline: true, AgentStatusRevoked: true},
	AgentStatusConnectedBaseline: {AgentStatusDiagnosing: true, AgentStatusRevoked: true},
	AgentStatusDiagnosing:        {AgentStatusConnectedBaseline: true, AgentStatusRevoked: true},
	AgentStatusRevoked:           {},
}

// CanTransitionAgent 判断状态迁移是否合法（§8.3；REVOKED 为终态，任何转出均非法）。
func CanTransitionAgent(from, to string) bool {
	return canTransitionAgent[from][to]
}

// DeriveAgentStatus 推导展示态：REVOKED 恒为 REVOKED；
// 其余按最近心跳（无心跳按注册时间）超 offlineAfter 判 OFFLINE。
func DeriveAgentStatus(stored string, lastHeartbeatAt *time.Time, registeredAt time.Time, offlineAfter time.Duration, now time.Time) string {
	if stored == AgentStatusRevoked {
		return AgentStatusRevoked
	}
	ref := registeredAt
	if lastHeartbeatAt != nil {
		ref = *lastHeartbeatAt
	}
	if now.Sub(ref) > offlineAfter {
		return AgentStatusOffline
	}
	return stored
}

// AgentControlConfig Agent 控制面运行参数（由 config.APMConfig 装配，构造时夹紧）。
type AgentControlConfig struct {
	// CollectorAddr 下发给 Agent 的 OTLP Collector 地址（空 = 数据面未就绪，如实返回空串）。
	CollectorAddr string
	// CertTTL 客户端证书有效期（夹紧 [24h, 7d]，默认 72h）。
	CertTTL time.Duration
	// OfflineAfter 心跳超时判 OFFLINE 阈值（夹紧 [1m, 24h]，默认 10m）。
	OfflineAfter time.Duration
	// PolicyValidity 策略有效期（默认 30 天，≥1h）。
	PolicyValidity time.Duration
}

// NewAgentControlConfig 构造控制面配置（非法值夹紧/回退默认，如实记录语义见各字段注释）。
func NewAgentControlConfig(collectorAddr string, certTTLHours, offlineMinutes int) AgentControlConfig {
	cfg := AgentControlConfig{
		CollectorAddr:  collectorAddr,
		CertTTL:        time.Duration(certTTLHours) * time.Hour,
		OfflineAfter:   time.Duration(offlineMinutes) * time.Minute,
		PolicyValidity: defaultPolicyValidity,
	}
	if cfg.CertTTL < minAgentCertTTL || cfg.CertTTL > maxAgentCertTTL {
		cfg.CertTTL = defaultAgentCertTTL
	}
	if cfg.OfflineAfter < time.Minute || cfg.OfflineAfter > 24*time.Hour {
		cfg.OfflineAfter = 10 * time.Minute
	}
	return cfg
}

// 允许上报的语言词表（§8.1 首期 P0/P1/P2；令牌 allowed_languages 与注册请求共用该词表）。
var allowedAgentLanguages = map[string]bool{
	"java": true, "go": true, "dotnet": true, "nodejs": true, "python": true, "php": true,
}

// ValidateAgentLanguage 校验语言取值（空串非法——注册必须显式声明）。
func ValidateAgentLanguage(lang string) bool { return allowedAgentLanguages[lang] }

// nodeInfoAllowedKeys 节点信息白名单键（自报信息仅展示用，不入任何鉴权决策）。
var nodeInfoAllowedKeys = map[string]bool{
	"hostname": true, "host_ip": true, "os": true, "arch": true,
	"pod": true, "namespace": true, "container_id": true,
}

// NodeInfo 自报节点信息（展示用途）。
type NodeInfo map[string]string

// AgentServiceRow apm_services 登记行（OTel service.name ↔ application 映射）。
type AgentServiceRow struct {
	ID            uuid.UUID  `json:"id"`
	ServiceName   string     `json:"service_name"`
	Environment   string     `json:"environment"`
	ApplicationID *uuid.UUID `json:"application_id"`
	ClaimStatus   string     `json:"claim_status"` // UNCLAIMED / CLAIMED
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
}

// AgentRow apm_agents 登记行（关联服务视图字段一并带出）。
type AgentRow struct {
	ID              uuid.UUID  `json:"id"`
	ServiceID       uuid.UUID  `json:"service_id"`
	ServiceName     string     `json:"service_name"`
	Environment     string     `json:"environment"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	InstanceID      string     `json:"instance_id"`
	Language        string     `json:"language"`
	AgentVersion    string     `json:"agent_version"`
	SdkVersion      string     `json:"sdk_version"`
	StoredStatus    string     `json:"stored_status"`     // 库存状态（ENROLLING/CONNECTED_BASELINE/DIAGNOSING/REVOKED）
	Status          string     `json:"status"`            // 展示态（OFFLINE 由心跳超时推导）
	CertFingerprint string     `json:"cert_fingerprint"`  // 当前证书 SHA-256 指纹
	CertNotAfter    time.Time  `json:"cert_not_after"`    // 当前证书到期时间
	LastHeartbeatAt *time.Time `json:"last_heartbeat_at"` // 无心跳为 null
	NodeInfo        NodeInfo   `json:"node_info"`         // 自报节点信息（仅展示）
	RegisteredAt    time.Time  `json:"registered_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
	RevokeReason    string     `json:"revoke_reason,omitempty"`
}

// EnrollmentTokenRow apm_enrollment_tokens 登记行（不含令牌原文——原文只在创建响应出现一次）。
type EnrollmentTokenRow struct {
	ID               uuid.UUID  `json:"id"`
	ApplicationID    *uuid.UUID `json:"application_id"`
	Environment      string     `json:"environment"`
	AllowedLanguages []string   `json:"allowed_languages"` // 空数组 = 不限制
	ExpiresAt        time.Time  `json:"expires_at"`
	UsedAt           *time.Time `json:"used_at"`
	UsedByAgentID    *uuid.UUID `json:"used_by_agent_id"`
	Note             string     `json:"note"`
	CreatedBy        *uuid.UUID `json:"created_by"`
	CreatedAt        time.Time  `json:"created_at"`
}

// LanguageAllowed 判断令牌是否允许指定语言（空数组 = 不限制）。
func (t *EnrollmentTokenRow) LanguageAllowed(lang string) bool {
	if len(t.AllowedLanguages) == 0 {
		return true
	}
	for _, l := range t.AllowedLanguages {
		if l == lang {
			return true
		}
	}
	return false
}

// PolicyRow apm_agent_policies 版本行。
type PolicyRow struct {
	ID        uuid.UUID              `json:"id"`
	Scope     string                 `json:"scope"`
	Version   int64                  `json:"version"`
	Policy    map[string]interface{} `json:"policy"`
	Signature string                 `json:"signature"`
	KeyID     string                 `json:"key_id"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	CreatedBy *uuid.UUID             `json:"created_by"`
}

// Envelope 转换为签名信封（接口响应/验签共用）。
func (p *PolicyRow) Envelope() *PolicyEnvelope {
	return &PolicyEnvelope{
		Scope:     p.Scope,
		Version:   p.Version,
		KeyID:     p.KeyID,
		IssuedAt:  p.IssuedAt,
		ExpiresAt: p.ExpiresAt,
		Policy:    p.Policy,
		Signature: p.Signature,
	}
}
