// diagnostics_types_test.go 深度诊断会话状态机、入参校验/夹紧、开销护栏与预估纯函数测试。
package apm

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDiagnosticSessionStateMachine(t *testing.T) {
	cases := []struct {
		from, to string
		want     bool
	}{
		{DiagnosticStatusActive, DiagnosticStatusExpired, true},
		{DiagnosticStatusActive, DiagnosticStatusStopped, true},
		{DiagnosticStatusActive, DiagnosticStatusKilled, true},
		{DiagnosticStatusActive, DiagnosticStatusActive, false},
		{DiagnosticStatusExpired, DiagnosticStatusActive, false},
		{DiagnosticStatusStopped, DiagnosticStatusActive, false},
		{DiagnosticStatusKilled, DiagnosticStatusStopped, false},
		{DiagnosticStatusKilled, DiagnosticStatusKilled, false},
		{"BOGUS", DiagnosticStatusActive, false},
	}
	for _, c := range cases {
		if got := CanTransitionDiagnosticSession(c.from, c.to); got != c.want {
			t.Errorf("CanTransitionDiagnosticSession(%s→%s) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestNormalizeDiagnosticScope(t *testing.T) {
	appID := uuid.NewString()
	// 合法全量
	scope, err := normalizeDiagnosticScope(diagnosticScopeInput{
		ApplicationID: appID, Service: "shop-svc", Environment: "prod",
		InstanceIDs: []string{"i-1", "i-2", "i-1"}, // 去重
	})
	if err != nil {
		t.Fatalf("valid scope: %v", err)
	}
	if scope.ApplicationID.String() != appID || scope.Service != "shop-svc" || scope.Environment != "prod" {
		t.Errorf("scope = %+v", scope)
	}
	if len(scope.InstanceIDs) != 2 {
		t.Errorf("instance_ids dedup = %v", scope.InstanceIDs)
	}
	// application_id 必填且合法
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{}); err == nil {
		t.Error("missing application_id must fail")
	}
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{ApplicationID: "not-uuid"}); err == nil {
		t.Error("bad uuid must fail")
	}
	// service / environment / instance_id 字符集
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{ApplicationID: appID, Service: "bad name!"}); err == nil {
		t.Error("bad service must fail")
	}
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{ApplicationID: appID, Environment: "Prod_"}); err == nil {
		t.Error("bad environment must fail")
	}
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{ApplicationID: appID, InstanceIDs: []string{"bad id"}}); err == nil {
		t.Error("bad instance_id must fail")
	}
	// 实例基数上限
	tooMany := make([]string, maxDiagnosticScopeInstanceIDs+1)
	for i := range tooMany {
		tooMany[i] = strings.Repeat("a", 1) + strings.TrimSpace(uuid.NewString())[:8]
	}
	if _, err := normalizeDiagnosticScope(diagnosticScopeInput{ApplicationID: appID, InstanceIDs: tooMany}); err == nil {
		t.Error("instance_ids over limit must fail")
	}
}

func TestNormalizeDiagnosticCapabilities(t *testing.T) {
	caps, err := normalizeDiagnosticCapabilities([]string{"sql_detail", " FUNCTION_PROBE ", "sql_detail"})
	if err != nil {
		t.Fatalf("valid caps: %v", err)
	}
	if len(caps) != 2 || caps[0] != "sql_detail" || caps[1] != "function_probe" {
		t.Errorf("caps = %v（应小写化、去空白、去重）", caps)
	}
	if _, err := normalizeDiagnosticCapabilities(nil); err == nil {
		t.Error("empty caps must fail")
	}
	if _, err := normalizeDiagnosticCapabilities([]string{"heap_dump"}); err == nil {
		t.Error("unknown capability must fail（白名单 fail-closed）")
	}
}

func TestDiagnosticClamp(t *testing.T) {
	if got := clampDiagnosticSamplingRate(0); got != minDiagnosticSamplingRate {
		t.Errorf("rate 0 → %v（缺省/下界夹紧 0.1）", got)
	}
	if got := clampDiagnosticSamplingRate(0.05); got != minDiagnosticSamplingRate {
		t.Errorf("rate 0.05 → %v", got)
	}
	if got := clampDiagnosticSamplingRate(0.7); got != 0.7 {
		t.Errorf("rate 0.7 → %v（合法值不动）", got)
	}
	if got := clampDiagnosticDurationMinutes(0); got != defaultDiagnosticDurationMinutes {
		t.Errorf("duration 0 → %d（缺省 15）", got)
	}
	if got := clampDiagnosticDurationMinutes(3); got != minDiagnosticDurationMinutes {
		t.Errorf("duration 3 → %d（下界夹紧 15）", got)
	}
	if got := clampDiagnosticDurationMinutes(60); got != 60 {
		t.Errorf("duration 60 → %d", got)
	}
}

func TestDiagnosticOverheadGuards(t *testing.T) {
	appID := uuid.New()
	exact := DiagnosticScope{ApplicationID: appID, Service: "shop-svc"}
	wide := DiagnosticScope{ApplicationID: appID}

	// 基线合法组合
	if err := checkDiagnosticOverheadGuards([]string{DiagCapSQLDetail}, wide, 1.0, 120); err != nil {
		t.Errorf("sql_detail 1.0/120 应通过: %v", err)
	}
	// 时长上限
	if err := checkDiagnosticOverheadGuards([]string{DiagCapSQLDetail}, wide, 1.0, 121); err == nil {
		t.Error("duration 121 必须被护栏拒绝")
	}
	// 采样率总上限
	if err := checkDiagnosticOverheadGuards([]string{DiagCapSQLDetail}, wide, 1.01, 30); err == nil {
		t.Error("rate 1.01 必须被护栏拒绝")
	}
	// 函数探针分级上限 0.5
	if err := checkDiagnosticOverheadGuards([]string{DiagCapFunctionProbe}, exact, 0.5, 30); err != nil {
		t.Errorf("function_probe 0.5 精确范围应通过: %v", err)
	}
	if err := checkDiagnosticOverheadGuards([]string{DiagCapFunctionProbe}, exact, 0.51, 30); err == nil {
		t.Error("function_probe rate 0.51 必须被护栏拒绝")
	}
	// 函数探针范围精确性：无 instance_ids 且无 service → 拒绝
	if err := checkDiagnosticOverheadGuards([]string{DiagCapFunctionProbe}, wide, 0.3, 30); err == nil {
		t.Error("function_probe 大范围必须被护栏拒绝")
	}
	// instance_ids 非空同样满足精确性
	withInstances := DiagnosticScope{ApplicationID: appID, InstanceIDs: []string{"i-1"}}
	if err := checkDiagnosticOverheadGuards([]string{DiagCapFunctionProbe}, withInstances, 0.3, 30); err != nil {
		t.Errorf("function_probe 指定实例应通过: %v", err)
	}
	// 混合能力：含 function_probe 同样受分级上限约束
	if err := checkDiagnosticOverheadGuards([]string{DiagCapSQLDetail, DiagCapFunctionProbe}, exact, 0.8, 30); err == nil {
		t.Error("混合能力含 function_probe 时 rate 0.8 必须被拒绝")
	}
}

func TestEstimateDiagnosticOverhead(t *testing.T) {
	est := EstimateDiagnosticOverhead([]string{DiagCapFunctionProbe}, 0.5, 30, 2)
	if !strings.Contains(est.CPUHint, "4.0%") { // 8% × 0.5
		t.Errorf("cpu_hint = %q", est.CPUHint)
	}
	if !strings.Contains(est.SpansPerSHint, "200 spans/s") { // 200 × 0.5 × 2 实例
		t.Errorf("spans_per_s_hint = %q", est.SpansPerSHint)
	}
	if !strings.Contains(est.DataVolumeHint, "MB") {
		t.Errorf("data_volume_hint = %q", est.DataVolumeHint)
	}
	if len(est.RiskNotes) == 0 {
		t.Error("risk_notes 不能为空（函数探针风险提示必须存在）")
	}
	// 超预算线提示（function_probe 0.5 + thread_block 0.5×3% = 5.5% > 5%）
	est = EstimateDiagnosticOverhead([]string{DiagCapFunctionProbe, DiagCapThreadBlock}, 0.5, 15, 1)
	foundBudget := false
	for _, n := range est.RiskNotes {
		if strings.Contains(n, "预算线") {
			foundBudget = true
		}
	}
	if !foundBudget {
		t.Errorf("超预算线风险提示缺失: %v", est.RiskNotes)
	}
	// 零匹配实例：如实提示正式创建将被拒绝
	est = EstimateDiagnosticOverhead([]string{DiagCapSQLDetail}, 1.0, 15, 0)
	last := est.RiskNotes[len(est.RiskNotes)-1]
	if !strings.Contains(last, "无匹配在线 Agent") {
		t.Errorf("零匹配提示缺失: %v", est.RiskNotes)
	}
}
