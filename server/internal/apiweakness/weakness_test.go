// weakness_test.go 生命周期状态机全迁移矩阵测试（纯逻辑，不依赖数据库）。
package apiweakness

import (
	"testing"
)

// allStatuses 全部状态；allActions 全部生命周期操作。
var (
	allStatuses = []string{
		StatusNew, StatusConfirmed, StatusToFix, StatusFixed,
		StatusReproduced, StatusIgnored, StatusArchived,
	}
	allActions = []string{
		ActionConfirm, ActionAssign, ActionMarkFixed,
		ActionRetestPass, ActionRetestFail, ActionIgnore, ActionArchive,
	}
)

// wantTransitions 合法迁移矩阵：action → from → to（与 transitions 表一一对应，独立手抄防同错）。
var wantTransitions = map[string]map[string]string{
	ActionConfirm:    {StatusNew: StatusConfirmed},
	ActionAssign:     {StatusConfirmed: StatusToFix, StatusToFix: StatusToFix, StatusReproduced: StatusToFix},
	ActionMarkFixed:  {StatusToFix: StatusFixed},
	ActionRetestPass: {StatusFixed: StatusArchived},
	ActionRetestFail: {StatusFixed: StatusReproduced},
	ActionIgnore: {
		StatusNew: StatusIgnored, StatusConfirmed: StatusIgnored,
		StatusToFix: StatusIgnored, StatusReproduced: StatusIgnored,
	},
	ActionArchive: {
		StatusConfirmed: StatusArchived, StatusToFix: StatusArchived, StatusFixed: StatusArchived,
		StatusReproduced: StatusArchived, StatusIgnored: StatusArchived,
	},
}

// TestTransitionMatrix 全量 action × status 组合：合法组合到达目标态，非法组合一律拒绝。
func TestTransitionMatrix(t *testing.T) {
	for _, action := range allActions {
		for _, from := range allStatuses {
			to, ok := ResolveTransition(action, from)
			wantTo, wantOK := wantTransitions[action][from]
			if ok != wantOK {
				t.Errorf("%s × %s: ok=%v, want %v", action, from, ok, wantOK)
				continue
			}
			if ok && to != wantTo {
				t.Errorf("%s × %s: to=%s, want %s", action, from, to, wantTo)
			}
		}
	}
	// 未知操作一律非法
	for _, from := range allStatuses {
		if _, ok := ResolveTransition("BOGUS", from); ok {
			t.Errorf("unknown action from %s should be rejected", from)
		}
	}
}

// TestTransitionMatrixCoverage 矩阵断言须覆盖全部组合（防漏测）。
func TestTransitionMatrixCoverage(t *testing.T) {
	legal := 0
	for _, action := range allActions {
		legal += len(wantTransitions[action])
	}
	// 合法迁移 16 条；总组合 7 操作 × 7 状态 = 49
	if legal != 16 {
		t.Fatalf("legal transitions=%d, want 16（矩阵手抄与实现可能同步出错）", legal)
	}
}

// TestStatusAndSeverityValidation 枚举校验白名单。
func TestStatusAndSeverityValidation(t *testing.T) {
	for _, s := range allStatuses {
		if !IsValidStatus(s) {
			t.Errorf("status %s should be valid", s)
		}
	}
	for _, s := range []string{"", "OPEN", "CLOSED", "new"} {
		if IsValidStatus(s) {
			t.Errorf("status %q should be invalid", s)
		}
	}
	for _, sev := range []string{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !IsValidSeverity(sev) {
			t.Errorf("severity %s should be valid", sev)
		}
	}
	for _, sev := range []string{"", "P0", "high"} {
		if IsValidSeverity(sev) {
			t.Errorf("severity %q should be invalid", sev)
		}
	}
}

// TestWeaknessMeta v1 弱点码元数据注册完整。
func TestWeaknessMeta(t *testing.T) {
	for _, code := range []string{
		CodeUnauthenticatedSensitiveAPI, CodeDeprecatedStillCalled,
		CodeSensitiveInQuery, CodeSchemaDriftPersistent,
	} {
		name, category, severity, ok := WeaknessMeta(code)
		if !ok || name == "" || category == "" || !IsValidSeverity(severity) {
			t.Errorf("code %s meta incomplete: %q %q %q ok=%v", code, name, category, severity, ok)
		}
	}
	if _, _, _, ok := WeaknessMeta("UNKNOWN_CODE"); ok {
		t.Error("unknown code should not have meta")
	}
}
