// registry_test.go 强流程定义装配：版本不可变断言、同 id 多版本并存、
// 重复同版本去重、缺省归一、空段零行为。
package flowguard

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildRegistryEmptyZeroBehavior 段缺失/空数组 = 零行为（NG-T-C01）。
func TestBuildRegistryEmptyZeroBehavior(t *testing.T) {
	for _, defs := range [][]Definition{nil, {}} {
		r, err := BuildRegistry(defs)
		if err != nil || r != nil {
			t.Fatalf("空输入应 (nil,nil)，得 (%v,%v)", r, err)
		}
	}
	// nil Registry 访问安全（FLOW-02 消费侧判空兜底）
	var r *Registry
	if r.Len() != 0 || r.All() != nil {
		t.Fatal("nil Registry 应零值安全")
	}
	if _, ok := r.Get("x", 1); ok {
		t.Fatal("nil Registry Get 应 miss")
	}
}

// TestBuildRegistryMultiVersionCoexist 同 id 多版本并存合法（存量实例按创建时版本消费）。
func TestBuildRegistryMultiVersionCoexist(t *testing.T) {
	v1 := validDefinition()
	v2 := validDefinition()
	v2.Version = 2
	v2.Name = "checkout" // 同名义新版本（内容可不同——版本间无不可变约束）
	v2.Steps[1].TimeoutSeconds = 120
	r, err := BuildRegistry([]Definition{v2, v1}) // 乱序输入
	if err != nil {
		t.Fatalf("同 id 多版本应并存: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}
	got1, ok := r.Get(v1.ID, 1)
	if !ok || got1.Steps[1].TimeoutSeconds != 60 {
		t.Fatalf("Get v1 = %+v ok=%v", got1, ok)
	}
	got2, ok := r.Get(v2.ID, 2)
	if !ok || got2.Steps[1].TimeoutSeconds != 120 {
		t.Fatalf("Get v2 = %+v ok=%v", got2, ok)
	}
	if _, ok := r.Get(v1.ID, 3); ok {
		t.Fatal("不存在版本应 miss")
	}
	// All 稳定序：按 id、version 升序（与输入序无关）
	all := r.All()
	if len(all) != 2 || all[0].Version != 1 || all[1].Version != 2 {
		t.Fatalf("All 序 = %+v", all)
	}
}

// TestBuildRegistryDuplicateSameVersionDedup 重复同版本内容一致去重。
func TestBuildRegistryDuplicateSameVersionDedup(t *testing.T) {
	d := validDefinition()
	dup := validDefinition()
	// success_rule 空白差异经编码器压缩归一，仍视为同内容
	dup.Steps[0].SuccessRule = json.RawMessage(`{ "status_codes": [200], "body_jsonpath_equals": {"path":"$.status","value":"PAID"} }`)
	r, err := BuildRegistry([]Definition{d, dup})
	if err != nil {
		t.Fatalf("重复同版本内容一致应去重放行: %v", err)
	}
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1（去重）", r.Len())
	}
}

// TestBuildRegistryVersionConflictRejected 同 id 同 version 内容冲突拒载
// （版本不可变断言：激活版本不可变，冲突即快照异常，fail-closed）。
func TestBuildRegistryVersionConflictRejected(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Definition)
	}{
		{"步骤内容不同", func(d *Definition) { d.Steps[1].TimeoutSeconds = 61 }},
		{"判定式不同", func(d *Definition) { d.Steps[0].SuccessRule = json.RawMessage(`{"status_codes":[201]}`) }},
		{"mode 不同", func(d *Definition) { d.Mode = ModeProtect }},
		{"步骤数不同", func(d *Definition) { d.Steps = d.Steps[:1] }},
	}
	for _, tc := range cases {
		d := validDefinition()
		conflict := validDefinition()
		tc.mutate(&conflict)
		_, err := BuildRegistry([]Definition{d, conflict})
		if err == nil {
			t.Errorf("%s: 应拒载", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "内容冲突") {
			t.Errorf("%s: 错误 %q 未含「内容冲突」", tc.name, err.Error())
		}
	}
}

// TestBuildRegistryNormalizesDefaults 缺省值归一：mode/status 缺省显式化。
func TestBuildRegistryNormalizesDefaults(t *testing.T) {
	d := validDefinition()
	d.Mode, d.Status = "", ""
	r, err := BuildRegistry([]Definition{d})
	if err != nil {
		t.Fatalf("缺省 mode/status 应放行: %v", err)
	}
	got, ok := r.Get(d.ID, d.Version)
	if !ok {
		t.Fatal("Get miss")
	}
	if got.Mode != ModeObserve || got.Status != StatusActive {
		t.Fatalf("归一后 mode=%q status=%q", got.Mode, got.Status)
	}
}

// TestBuildRegistryInvalidFailClosed 非法定义装配失败（fail-closed，错误带下标）。
func TestBuildRegistryInvalidFailClosed(t *testing.T) {
	bad := validDefinition()
	bad.Steps[0].RetrySemantics = "RETRYABLE"
	r, err := BuildRegistry([]Definition{bad})
	if r != nil || err == nil {
		t.Fatalf("非法定义应拒载: (%v,%v)", r, err)
	}
	if !strings.Contains(err.Error(), "retry_semantics 非法") {
		t.Fatalf("错误 %q 未含词表说明", err.Error())
	}
}

// TestBuildRegistryDistinctIDsIndependent 不同 id 即不同定义（互不冲突）。
func TestBuildRegistryDistinctIDsIndependent(t *testing.T) {
	a := validDefinition()
	b := validDefinition()
	b.ID = "another-id"
	b.Version = 1
	b.Steps[1].TimeoutSeconds = 61 // 同版本号但不同 id：内容可自由不同
	r, err := BuildRegistry([]Definition{a, b})
	if err != nil || r.Len() != 2 {
		t.Fatalf("不同 id 应独立并存: (%v,%v)", r, err)
	}
}
