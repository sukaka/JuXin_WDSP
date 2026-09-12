// agentpolicy_test.go 策略白名单校验 / 签名验签 / 作用域校验单元测试。
package apm

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidatePolicyScope(t *testing.T) {
	if err := ValidatePolicyScope("global"); err != nil {
		t.Errorf("global scope rejected: %v", err)
	}
	appScope := ApplicationPolicyScope(uuid.New())
	if err := ValidatePolicyScope(appScope); err != nil {
		t.Errorf("application scope rejected: %v", err)
	}
	for _, bad := range []string{"", "GLOBAL", "tenant:1", "application:bad-uuid", "global ", " application:..."} {
		if err := ValidatePolicyScope(bad); !errors.Is(err, ErrPolicyScopeInvalid) {
			t.Errorf("scope %q must be rejected: %v", bad, err)
		}
	}
}

func TestValidateBaselinePolicy(t *testing.T) {
	// 默认基线必须通过自身校验
	if err := ValidateBaselinePolicy(DefaultBaselinePolicy()); err != nil {
		t.Fatalf("default baseline rejected: %v", err)
	}
	// 空对象拒绝
	if err := ValidateBaselinePolicy(map[string]interface{}{}); !errors.Is(err, ErrPolicyInvalid) {
		t.Errorf("empty policy must be rejected: %v", err)
	}
	// 未知顶层键拒绝（fail-closed 防误拼静默失效）
	if err := ValidateBaselinePolicy(map[string]interface{}{"trace_all_methods": true}); !errors.Is(err, ErrPolicyInvalid) {
		t.Errorf("unknown key must be rejected: %v", err)
	}
	// 采样率区间 (0,1]
	for _, v := range []interface{}{0.0, -0.1, 1.1, "1.0"} {
		if err := ValidateBaselinePolicy(map[string]interface{}{"sampling_rate": v}); !errors.Is(err, ErrPolicyInvalid) {
			t.Errorf("sampling_rate %v must be rejected: %v", v, err)
		}
	}
	if err := ValidateBaselinePolicy(map[string]interface{}{"sampling_rate": 0.5}); err != nil {
		t.Errorf("sampling_rate 0.5 rejected: %v", err)
	}
	// signals 子集/重复/类型
	if err := ValidateBaselinePolicy(map[string]interface{}{"signals": []interface{}{"traces", "logs"}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("unknown signal must be rejected")
	}
	if err := ValidateBaselinePolicy(map[string]interface{}{"signals": []interface{}{"traces", "traces"}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("duplicated signal must be rejected")
	}
	if err := ValidateBaselinePolicy(map[string]interface{}{"signals": []interface{}{}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("empty signals must be rejected")
	}
	// sql_mode 枚举
	if err := ValidateBaselinePolicy(map[string]interface{}{"sql_mode": "raw_statement"}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("raw statement mode must be rejected（默认不保存原始 SQL——数据最小化）")
	}
	// 嵌套对象子键白名单与区间
	if err := ValidateBaselinePolicy(map[string]interface{}{"batch": map[string]interface{}{"max_size": 0}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("batch.max_size=0 must be rejected")
	}
	if err := ValidateBaselinePolicy(map[string]interface{}{"batch": map[string]interface{}{"unknown": 1}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("batch unknown subkey must be rejected")
	}
	// 诊断时长上限（§12.3 忘记关闭威胁行）
	if err := ValidateBaselinePolicy(map[string]interface{}{"diagnostics": map[string]interface{}{"max_duration_minutes": 10000}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("diagnostics max_duration_minutes >240 must be rejected")
	}
	// attribute_allowlist 长度护栏
	longVal := strings.Repeat("a", 65)
	if err := ValidateBaselinePolicy(map[string]interface{}{"attribute_allowlist": []interface{}{longVal}}); !errors.Is(err, ErrPolicyInvalid) {
		t.Error("overlong attribute key must be rejected")
	}
}

func TestPolicySignVerify(t *testing.T) {
	ca, _ := newTestCA(t)
	now := time.Now().UTC().Truncate(time.Second)
	env := &PolicyEnvelope{
		Scope: PolicyScopeGlobal, Version: 1, KeyID: PolicySignKeyID,
		IssuedAt: now, ExpiresAt: now.Add(defaultPolicyValidity),
		Policy: DefaultBaselinePolicy(),
	}
	if err := ca.SignPolicy(env); err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	if env.Signature == "" {
		t.Fatal("signature empty")
	}
	if err := VerifyPolicySignature(ca.PublicKeyHex(), env); err != nil {
		t.Fatalf("verify own signature: %v", err)
	}
	// 篡改策略正文 → 拒绝
	tampered := *env
	tampered.Policy = map[string]interface{}{"sampling_rate": 0.001}
	if err := VerifyPolicySignature(ca.PublicKeyHex(), &tampered); err == nil {
		t.Error("tampered policy must fail verification")
	}
	// 篡改版本号（回退）→ 拒绝
	rolled := *env
	rolled.Version = 0
	if err := VerifyPolicySignature(ca.PublicKeyHex(), &rolled); err == nil {
		t.Error("rolled-back version must fail verification")
	}
	// 篡改过期时间 → 拒绝
	ext := *env
	ext.ExpiresAt = now.Add(10 * defaultPolicyValidity)
	if err := VerifyPolicySignature(ca.PublicKeyHex(), &ext); err == nil {
		t.Error("extended expiry must fail verification")
	}
	// 错误公钥 → 拒绝
	ca2, _ := newTestCA(t)
	if err := VerifyPolicySignature(ca2.PublicKeyHex(), env); err == nil {
		t.Error("wrong public key must fail verification")
	}
	// 垃圾签名/公钥 → 拒绝（不 panic）
	if err := VerifyPolicySignature("zz", env); err == nil {
		t.Error("garbage pubkey must fail")
	}
	badSig := *env
	badSig.Signature = "zz"
	if err := VerifyPolicySignature(ca.PublicKeyHex(), &badSig); err == nil {
		t.Error("garbage signature must fail")
	}
}

func TestDefaultBaselinePolicy_Contents(t *testing.T) {
	p := DefaultBaselinePolicy()
	// §9.2 必备键
	for _, key := range []string{"signals", "sampling_rate", "attribute_allowlist", "sql_mode",
		"batch", "queue", "memory_limit_mib", "export_timeout_seconds", "diagnostics"} {
		if _, ok := p[key]; !ok {
			t.Errorf("default policy missing key %s", key)
		}
	}
	// 数据最小化内置口径：SQL 仅指纹、诊断默认关闭
	if p["sql_mode"] != "fingerprint" {
		t.Errorf("sql_mode = %v, want fingerprint", p["sql_mode"])
	}
	if diag, _ := p["diagnostics"].(map[string]interface{}); diag["enabled"] != false {
		t.Errorf("diagnostics.enabled = %v, want false", diag["enabled"])
	}
}
