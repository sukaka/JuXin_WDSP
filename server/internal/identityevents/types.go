// types.go client_identity 体系网关事件记录解析（WDSP AI 自动化渗透防护增强 阶段1）。
// 镜像网关 identity-events.log JSONL 契约（网关工作流已冻结，snake_case 字段名一一对应）：
//   - identity_observation 身份观测（每请求一条：身份键/类型/IP/UA/指纹/凭据）；
//   - behavior_snapshot    行为窗口快照（1m/5m/30m/24h 窗口对齐计数）；
//   - recon_signal         侦察信号（规则命中 + risk_score_delta，驱动风险分级）。
//
// 单一 Record 结构承载三种记录（与 apiruntime.Record 同一纪律：旧版网关缺键时为零值，
// 采集全程容忍缺失）；record_type 未知或必填字段缺失的行视为坏行（入错误队列，不入库）。
package identityevents

import (
	"encoding/json"
	"fmt"
	"time"
)

// 记录类型（record_type 字段）。
const (
	RecordTypeObservation = "identity_observation"
	RecordTypeSnapshot    = "behavior_snapshot"
	RecordTypeSignal      = "recon_signal"
)

// 身份类型（identity_type 字段；管理面当前支持六类，旧 MACHINE 输入归一为 UNKNOWN）。
const (
	IdentityTypeHuman       = "HUMAN"
	IdentityTypeBot         = "BOT"
	IdentityTypeApplication = "APPLICATION"
	IdentityTypeService     = "SERVICE"
	IdentityTypeAgent       = "AGENT"
	IdentityTypeUnknown     = "UNKNOWN"
)

// 信号枚举（signal 字段；与行为策略 scores 键一一对应，跨分片契约）。
const (
	SignalURIEnumeration      = "URI_ENUMERATION"
	SignalNotFoundEnumeration = "NOT_FOUND_ENUMERATION"
	SignalSensitivePathProbe  = "SENSITIVE_PATH_PROBE"
	SignalMethodEnumeration   = "METHOD_ENUMERATION"
	SignalParameterMutation   = "PARAMETER_MUTATION"
	SignalAuthFailProbe       = "AUTH_FAIL_PROBE"
	SignalLowSlowRecon        = "LOW_SLOW_RECON"
	SignalHeadless            = "HEADLESS"
	SignalAccountEnumeration  = "ACCOUNT_ENUMERATION"
	SignalObjectEnumeration   = "OBJECT_ENUMERATION"
)

// validSignals 合法信号集合。
var validSignals = map[string]bool{
	SignalURIEnumeration:      true,
	SignalNotFoundEnumeration: true,
	SignalSensitivePathProbe:  true,
	SignalMethodEnumeration:   true,
	SignalParameterMutation:   true,
	SignalAuthFailProbe:       true,
	SignalLowSlowRecon:        true,
	SignalHeadless:            true,
	SignalAccountEnumeration:  true,
	SignalObjectEnumeration:   true,
}

// 凭据类型（credentials[].type 字段；网关契约七值，其余类型的凭据跳过不入库）。
var validCredentialTypes = map[string]bool{
	"JWT": true, "API_KEY": true, "SESSION": true, "COOKIE": true, "OAUTH": true, "CUSTOM": true, "MTLS": true,
}

// 行为窗口键（windows map 键；未知键跳过并告警，容忍网关后续新增窗口）。
var validWindowTypes = map[string]bool{
	"1m": true, "5m": true, "30m": true, "24h": true,
}

// Credential 凭据观测（只存哈希，不落明文凭据）。
type Credential struct {
	Type          string `json:"type"`
	Hash          string `json:"hash"`
	AccountID     string `json:"account_id"`
	JWTSubject    string `json:"jwt_subject"`
	OAuthClientID string `json:"oauth_client_id"`
}

// WindowCounters 单窗口行为计数（behavior_snapshot.windows 值）。
type WindowCounters struct {
	WindowStart            time.Time `json:"window_start"`
	RequestCount           int64     `json:"request_count"`
	UniqueURICount         int64     `json:"unique_uri_count"`
	NewURICount            int64     `json:"new_uri_count"`
	Status401Count         int64     `json:"status_401_count"`
	Status403Count         int64     `json:"status_403_count"`
	Status404Count         int64     `json:"status_404_count"`
	Status405Count         int64     `json:"status_405_count"`
	Status500Count         int64     `json:"status_500_count"`
	AuthFailCount          int64     `json:"auth_fail_count"`
	ParameterMutationCount int64     `json:"parameter_mutation_count"`
	SensitivePathHits      int64     `json:"sensitive_path_hits"`
	AccountEnumCount       int64     `json:"account_enum_count"`
	ObjectEnumCount        int64     `json:"object_enum_count"`
}

// Record 网关 identity-events.log 单行（三种记录共用；按 record_type 分发）。
type Record struct {
	RecordType         string    `json:"record_type"`
	RequestID          string    `json:"request_id"`
	OccurredAt         time.Time `json:"occurred_at"`
	GatewayNode        string    `json:"gateway_node"`
	AppID              string    `json:"app_id"`
	AppCode            string    `json:"app_code"`
	Domain             string    `json:"domain"`
	Method             string    `json:"method"`
	Path               string    `json:"path"`
	IdentityKey        string    `json:"identity_key"`
	IdentityType       string    `json:"identity_type"`
	IdentityConfidence uint8     `json:"identity_confidence"`
	IdentityEvidence   []string  `json:"identity_evidence"`
	ClientIP           string    `json:"client_ip"`
	UserAgent          string    `json:"user_agent"`

	// identity_observation 专有
	TLSFingerprint     string       `json:"tls_fingerprint"`
	BrowserFingerprint string       `json:"browser_fingerprint"`
	Credentials        []Credential `json:"credentials"`

	// behavior_snapshot 专有
	Windows map[string]WindowCounters `json:"windows"`

	// recon_signal 专有
	RuleCode       string         `json:"rule_code"`
	RuleVersion    string         `json:"rule_version"`
	Signal         string         `json:"signal"`
	RiskScoreDelta int            `json:"risk_score_delta"`
	Mode           string         `json:"mode"`
	Reason         string         `json:"reason"`
	Window         string         `json:"window"`
	Metadata       map[string]any `json:"metadata"`
}

// parseRecordLine 解析一行 JSONL 并按 record_type 做必填校验。
// 坏行返回错误（采集器写错误文件 + event_parse_failures 队列，不静默丢弃）。
func parseRecordLine(line []byte) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if rec.IdentityKey == "" {
		return nil, fmt.Errorf("missing identity_key")
	}
	if rec.OccurredAt.IsZero() {
		return nil, fmt.Errorf("missing occurred_at")
	}
	switch rec.RecordType {
	case RecordTypeObservation:
		rec.IdentityType = normalizeIdentityType(rec.IdentityType)
		rec.IdentityEvidence = sanitizeIdentityEvidence(rec.IdentityEvidence)
	case RecordTypeSnapshot:
		if len(rec.Windows) == 0 {
			return nil, fmt.Errorf("behavior_snapshot without windows")
		}
	case RecordTypeSignal:
		if rec.RuleCode == "" {
			return nil, fmt.Errorf("recon_signal missing rule_code")
		}
		if !validSignals[rec.Signal] {
			return nil, fmt.Errorf("recon_signal with unknown signal %q", rec.Signal)
		}
		if rec.Mode == "" {
			rec.Mode = "OBSERVE"
		}
		rec.IdentityEvidence = sanitizeIdentityEvidence(rec.IdentityEvidence)
		rec.Metadata = sanitizeSignalMetadata(rec.Metadata)
	default:
		return nil, fmt.Errorf("unknown record_type %q", rec.RecordType)
	}
	return &rec, nil
}

// normalizeIdentityType 非法身份类型归一为 UNKNOWN（采集侧宽容）。
func normalizeIdentityType(t string) string {
	switch t {
	case IdentityTypeHuman, IdentityTypeBot, IdentityTypeApplication,
		IdentityTypeService, IdentityTypeAgent:
		return t
	default:
		return IdentityTypeUnknown
	}
}

// derivedIdentityFields 从凭据列表提取身份主表派生列：
// account_id 取首个非空凭据账号；jwt_subject 取首个 JWT 凭据；api_key_hash 取首个
// API_KEY 凭据哈希；oauth_client_id 取首个 OAUTH 凭据。无对应凭据时为空串
// （UPSERT 时空串不覆盖现值，见 store.UpsertObservation）。
func derivedIdentityFields(creds []Credential) (accountID, jwtSubject, apiKeyHash, oauthClientID string) {
	for _, c := range creds {
		if accountID == "" && c.AccountID != "" {
			accountID = c.AccountID
		}
		switch c.Type {
		case "JWT":
			if jwtSubject == "" {
				jwtSubject = c.JWTSubject
			}
		case "API_KEY":
			if apiKeyHash == "" {
				apiKeyHash = c.Hash
			}
		case "OAUTH":
			if oauthClientID == "" {
				oauthClientID = c.OAuthClientID
			}
		}
	}
	return accountID, jwtSubject, apiKeyHash, oauthClientID
}

// RiskLevelForScore 风险分级（0-19 LOW / 20-39 MEDIUM / 40-69 HIGH / 70+ CRITICAL；
// 与 recon_signal 重算 SQL 共用同一阈值口径——分值在 Go 侧计算后写库，单一来源）。
func RiskLevelForScore(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// clampRiskScore 风险分截断到 [0,100]。
func clampRiskScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
