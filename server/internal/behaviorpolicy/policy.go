// policy.go 侦察/枚举行为检测策略（WDSP AI 自动化渗透防护增强 阶段1）。
// 单行全局策略（security_behavior_policy 表 scope='GLOBAL'，迁移 000098 种子）；
// 管理面全量更新（version 乐观锁），经发布通道下发网关 jiuzhang_guard
// identity_behavior 段（跨分片契约见 gatewayconfig.GuardIdentityBehavior）。
package behaviorpolicy

import (
	"time"

	"github.com/google/uuid"
)

// 策略作用域与模式（当前仅支持 GLOBAL 单行 + OBSERVE 观测模式——网关契约
// recon_signal.mode 已冻结为 OBSERVE，阻断模式随后续阶段开放）。
const (
	ScopeGlobal = "GLOBAL"
	ModeObserve = "OBSERVE"
)

// 信号枚举（scores 合法键；与网关 recon_signal.signal 契约一一对应）。
var ValidSignals = []string{
	"URI_ENUMERATION", "NOT_FOUND_ENUMERATION", "SENSITIVE_PATH_PROBE", "METHOD_ENUMERATION",
	"PARAMETER_MUTATION", "AUTH_FAIL_PROBE", "LOW_SLOW_RECON", "HEADLESS",
	"ACCOUNT_ENUMERATION", "OBJECT_ENUMERATION",
}

var validSignalSet = func() map[string]bool {
	m := make(map[string]bool, len(ValidSignals))
	for _, s := range ValidSignals {
		m[s] = true
	}
	return m
}()

// Policy 行为策略（全字段；与 security_behavior_policy 表列一一对应）。
type Policy struct {
	ID                       uuid.UUID      `json:"id"`
	Scope                    string         `json:"scope"`
	Enabled                  bool           `json:"enabled"`
	Mode                     string         `json:"mode"`
	Version                  int            `json:"version"`
	URIEnumUniqueThreshold   int            `json:"uri_enum_unique_threshold"`
	URIEnumNewRatioThreshold float64        `json:"uri_enum_new_ratio_threshold"`
	NotFoundRatioThreshold   float64        `json:"not_found_ratio_threshold"`
	NotFoundMinRequests      int            `json:"not_found_min_requests"`
	MethodEnumThreshold      int            `json:"method_enum_threshold"`
	ParamMutationThreshold   int            `json:"param_mutation_threshold"`
	AuthFailThreshold        int            `json:"auth_fail_threshold"`
	LowSlowSensitiveMinHits  int            `json:"low_slow_sensitive_min_hits"`
	AccountEnumThreshold     int            `json:"account_enum_threshold"`
	ObjectEnumThreshold      int            `json:"object_enum_threshold"`
	AccountIdentifierFields  []string       `json:"account_identifier_fields"`
	ObjectIdentifierFields   []string       `json:"object_identifier_fields"`
	SensitivePaths           []string       `json:"sensitive_paths"`
	Scores                   map[string]int `json:"scores"`
	WhitelistIPs             []string       `json:"whitelist_ips"`
	WhitelistUAs             []string       `json:"whitelist_uas"`
	UpdatedBy                string         `json:"updated_by"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}
