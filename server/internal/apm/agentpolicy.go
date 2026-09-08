// agentpolicy.go APM Agent 基线采集策略：模型、校验、签名与版本纪律
// （设计 §9.2：策略必须签名并带版本号、签发时间和过期时间；
// Agent 只接受版本递增且签名有效的策略；§12.3 策略篡改威胁行）。
//
// 签名方案（复用 license.go 的规范字节约定）：签名输入 =
// "JIUZHANG-APM-POLICY-v1\n" || canonicalJSON(payload)；canonicalJSON 为
// payload map 的 encoding/json 序列化（map 键字典序、紧凑无空白），对 PG jsonb
// 键序扰动免疫；签名密钥为内置 CA 的 Ed25519 私钥（域分隔前缀保证与 X.509/PoP
// 签名输入永不交叉）。Agent 侧用注册响应下发的 ca_public_key 验签。
package apm

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

// policySigningPrefix 策略签名域分隔前缀。
const policySigningPrefix = "JIUZHANG-APM-POLICY-v1"

// defaultPolicyValidity 基线策略默认有效期（30 天；过期策略 Agent 侧必须拒绝并回退
// 到最后一份有效策略——设计 §9.2）。
const defaultPolicyValidity = 30 * 24 * time.Hour

// 策略校验错误（handler 映射 HTTP 400）。
var (
	// ErrPolicyInvalid 策略内容不符合基线模式（未知键/类型/取值非法）。
	ErrPolicyInvalid = errors.New("策略内容非法")
	// ErrPolicyScopeInvalid 策略作用域非法（仅支持 global / application:<uuid>）。
	ErrPolicyScopeInvalid = errors.New("策略作用域非法")
	// ErrPolicyVersionConflict 乐观并发冲突（读取后他人已发布新版本）。
	ErrPolicyVersionConflict = errors.New("策略版本冲突，请刷新后重试")
)

// PolicyScopeGlobal 全局基线策略作用域。
const PolicyScopeGlobal = "global"

// policyScopeApplicationPrefix 应用级策略作用域前缀（application:<uuid>）。
const policyScopeApplicationPrefix = "application:"

// 策略允许的采集信号（§9.2 允许的信号）。
var allowedPolicySignals = map[string]bool{
	"traces": true, "metrics": true, "runtime": true, "exceptions": true,
}

// PolicyEnvelope 签名策略信封（issued_at/expires_at 一并入签，防签发时间/有效期被篡改）。
type PolicyEnvelope struct {
	Scope     string                 `json:"scope"`
	Version   int64                  `json:"version"`
	KeyID     string                 `json:"key_id"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Policy    map[string]interface{} `json:"policy"`
	Signature string                 `json:"signature"` // Ed25519 签名 hex
}

// ValidatePolicyScope 校验作用域取值（global 或 application:<uuid>）。
func ValidatePolicyScope(scope string) error {
	if scope == PolicyScopeGlobal {
		return nil
	}
	if rest, ok := strings.CutPrefix(scope, policyScopeApplicationPrefix); ok {
		if _, err := uuid.Parse(rest); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w：%q（仅支持 global / application:<uuid>）", ErrPolicyScopeInvalid, scope)
}

// ApplicationPolicyScope 构造应用级作用域。
func ApplicationPolicyScope(applicationID uuid.UUID) string {
	return policyScopeApplicationPrefix + applicationID.String()
}

// policyPayload 签名载荷（map 形态保证 canonicalJSON 键序确定）。
func (e *PolicyEnvelope) policyPayload() map[string]interface{} {
	return map[string]interface{}{
		"scope":      e.Scope,
		"version":    e.Version,
		"key_id":     e.KeyID,
		"issued_at":  e.IssuedAt.UTC().Format(time.RFC3339),
		"expires_at": e.ExpiresAt.UTC().Format(time.RFC3339),
		"policy":     e.Policy,
	}
}

// SignPolicy 生成签名（信封 Signature 字段回填；issued_at/expires_at 需调用前就位）。
func (ca *AgentCA) SignPolicy(env *PolicyEnvelope) error {
	canonical, err := json.Marshal(env.policyPayload())
	if err != nil {
		return fmt.Errorf("apm: 策略载荷序列化失败: %w", err)
	}
	sig := ed25519.Sign(ca.key, append([]byte(policySigningPrefix+"\n"), canonical...))
	env.Signature = hex.EncodeToString(sig)
	return nil
}

// VerifyPolicySignature 验签（pub 为 CA 公钥 hex；测试与 Agent 侧参考实现共用入口）。
// 载荷经 map 重构规范字节后与签名比对——与签发侧逐字节一致方可通过。
func VerifyPolicySignature(pubHex string, env *PolicyEnvelope) error {
	pubBytes, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("验签公钥非法")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(env.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("签名须为 Ed25519 签名 hex 编码")
	}
	canonical, err := json.Marshal(env.policyPayload())
	if err != nil {
		return fmt.Errorf("策略载荷序列化失败: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), append([]byte(policySigningPrefix+"\n"), canonical...), sig) {
		return fmt.Errorf("策略签名校验失败")
	}
	return nil
}

// DefaultBaselinePolicy 默认基线策略（§9.2 内容骨架；数据最小化口径内置：
// SQL 仅指纹、属性允许清单、值长上限、诊断默认关闭）。
func DefaultBaselinePolicy() map[string]interface{} {
	return map[string]interface{}{
		"signals":                   []interface{}{"traces", "metrics", "runtime", "exceptions"},
		"sampling_rate":             1.0,
		"slow_request_threshold_ms": 2000.0,
		"attribute_allowlist": []interface{}{
			"http.method", "http.route", "http.status_code", "http.response.status_code",
			"db.system", "db.operation", "db.namespace",
			"messaging.system", "messaging.operation", "peer.service",
			"service.name", "service.instance.id", "service.version", "deployment.environment",
		},
		"max_attribute_value_length": 256.0,
		"sql_mode":                   "fingerprint",
		"batch":                      map[string]interface{}{"max_size": 512.0, "timeout_ms": 5000.0},
		"queue":                      map[string]interface{}{"max_size": 4096.0},
		"memory_limit_mib":           256.0,
		"export_timeout_seconds":     10.0,
		"diagnostics":                map[string]interface{}{"enabled": false, "max_duration_minutes": 30.0},
	}
}

// ValidateBaselinePolicy 基线策略白名单校验（fail-closed：未知顶层键一律拒绝，
// 防误拼键静默失效；各键做类型/取值区间校验）。policy 须为 JSON 对象。
func ValidateBaselinePolicy(policy map[string]interface{}) error {
	if len(policy) == 0 {
		return fmt.Errorf("%w：policy 不能为空对象", ErrPolicyInvalid)
	}
	for key, v := range policy {
		if v == nil {
			return fmt.Errorf("%w：%s 不能为 null", ErrPolicyInvalid, key)
		}
		var err error
		switch key {
		case "signals":
			err = validateSignals(v)
		case "sampling_rate":
			err = validateNumberRange(key, v, 0, 1, false)
		case "slow_request_threshold_ms":
			err = validateNumberRange(key, v, 1, 600000, true)
		case "attribute_allowlist":
			err = validateStringList(key, v, 64, 64)
		case "max_attribute_value_length":
			err = validateNumberRange(key, v, 1, 4096, true)
		case "sql_mode":
			s, ok := v.(string)
			if !ok || (s != "fingerprint" && s != "fingerprint_plus_sanitized") {
				err = fmt.Errorf("%w：sql_mode 仅支持 fingerprint / fingerprint_plus_sanitized", ErrPolicyInvalid)
			}
		case "batch":
			err = validateNestedObject(key, v, map[string][2]float64{
				"max_size":   {1, 8192},
				"timeout_ms": {100, 60000},
			})
		case "queue":
			err = validateNestedObject(key, v, map[string][2]float64{
				"max_size": {1, 100000},
			})
		case "memory_limit_mib":
			err = validateNumberRange(key, v, 32, 8192, true)
		case "export_timeout_seconds":
			err = validateNumberRange(key, v, 1, 120, true)
		case "diagnostics":
			err = validateDiagnostics(v)
		default:
			err = fmt.Errorf("%w：不支持的策略键 %q", ErrPolicyInvalid, key)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// validateSignals 校验 signals 为允许信号的字符串数组（非空、元素唯一）。
func validateSignals(v interface{}) error {
	arr, ok := v.([]interface{})
	if !ok || len(arr) == 0 {
		return fmt.Errorf("%w：signals 须为非空字符串数组", ErrPolicyInvalid)
	}
	seen := map[string]bool{}
	for _, item := range arr {
		s, ok := item.(string)
		if !ok || !allowedPolicySignals[s] {
			return fmt.Errorf("%w：signals 元素仅支持 traces/metrics/runtime/exceptions", ErrPolicyInvalid)
		}
		if seen[s] {
			return fmt.Errorf("%w：signals 元素重复 %q", ErrPolicyInvalid, s)
		}
		seen[s] = true
	}
	return nil
}

// validateNumberRange 数值区间校验（integer=true 时须为整值；
// 边界统一为：下界开区间（>min），上界闭区间（<=max）——对应采样率 (0,1] 与阈值类 (0,max]）。
func validateNumberRange(name string, v interface{}, min, max float64, integer bool) error {
	f, ok := v.(float64)
	if !ok {
		return fmt.Errorf("%w：%s 须为数值", ErrPolicyInvalid, name)
	}
	if integer && f != math.Trunc(f) {
		return fmt.Errorf("%w：%s 须为整数", ErrPolicyInvalid, name)
	}
	if f <= min || f > max {
		return fmt.Errorf("%w：%s 取值须大于 %v 且不超过 %v", ErrPolicyInvalid, name, min, max)
	}
	return nil
}

// validateStringList 字符串数组校验（元素个数/单元素长度上限）。
func validateStringList(name string, v interface{}, maxItems, maxLen int) error {
	arr, ok := v.([]interface{})
	if !ok {
		return fmt.Errorf("%w：%s 须为字符串数组", ErrPolicyInvalid, name)
	}
	if len(arr) > maxItems {
		return fmt.Errorf("%w：%s 元素个数不能超过 %d", ErrPolicyInvalid, name, maxItems)
	}
	for _, item := range arr {
		s, ok := item.(string)
		if !ok || s == "" || len(s) > maxLen {
			return fmt.Errorf("%w：%s 元素须为 1~%d 字符的非空字符串", ErrPolicyInvalid, name, maxLen)
		}
	}
	return nil
}

// validateNestedObject 嵌套对象校验（仅允许表内列出的整数键，区间闭于 [min,max] 内
// 按 >min?——此处键区间语义为 [min,max] 闭区间，防误配 0/负值由 min≥1 保证）。
func validateNestedObject(name string, v interface{}, keys map[string][2]float64) error {
	obj, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w：%s 须为对象", ErrPolicyInvalid, name)
	}
	for k, item := range obj {
		bounds, known := keys[k]
		if !known {
			return fmt.Errorf("%w：%s 不支持的子键 %q", ErrPolicyInvalid, name, k)
		}
		f, ok := item.(float64)
		if !ok || f != math.Trunc(f) || f < bounds[0] || f > bounds[1] {
			return fmt.Errorf("%w：%s.%s 须为 %.0f~%.0f 的整数", ErrPolicyInvalid, name, k, bounds[0], bounds[1])
		}
	}
	return nil
}

// validateDiagnostics 诊断会话配置校验（默认关闭；时长上限防忘记关闭——§12.3）。
func validateDiagnostics(v interface{}) error {
	obj, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w：diagnostics 须为对象", ErrPolicyInvalid)
	}
	for k, item := range obj {
		switch k {
		case "enabled":
			if _, ok := item.(bool); !ok {
				return fmt.Errorf("%w：diagnostics.enabled 须为布尔值", ErrPolicyInvalid)
			}
		case "max_duration_minutes":
			if err := validateNumberRange("diagnostics.max_duration_minutes", item, 0, 240, true); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w：diagnostics 不支持的子键 %q", ErrPolicyInvalid, k)
		}
	}
	return nil
}
