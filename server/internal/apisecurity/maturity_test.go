// maturity_test.go 模型成熟度纯推导逻辑单测（给定计数 → stage/metrics，不依赖数据库）。
// 规则见 maturity.go 各 derive*Maturity 注释（docs/API_MICRO_MODELS.md §四第 10 项）。
package apisecurity

import "testing"

func TestDeriveParameterMaturity(t *testing.T) {
	cases := []struct {
		name string
		c    maturityCounts
		want MaturityStage
	}{
		{"无任何参数行", maturityCounts{}, StageLearning},
		{"有参数但无约束产出", maturityCounts{ParamTotal: 5}, StageLearning},
		{"有推荐约束", maturityCounts{ParamTotal: 5, ParamRecommended: 2}, StageCandidate},
		{"有统计画像但无推荐仍LEARNING", maturityCounts{ParamTotal: 5, ParamWithStats: 3}, StageLearning},
		{"有确认约束", maturityCounts{ParamTotal: 5, ParamRecommended: 2, ParamConfirmed: 1}, StageConfirmed},
		{"已下发生效", maturityCounts{ParamTotal: 5, ParamRecommended: 2, ParamConfirmed: 1, FormalConstraints: 1}, StageEnforcing},
		{"仅required下发行无确认约束亦ENFORCING", maturityCounts{ParamTotal: 5, FormalConstraints: 2}, StageEnforcing},
	}
	for _, tc := range cases {
		m := deriveParameterMaturity(tc.c)
		if m.Stage != tc.want {
			t.Errorf("%s: stage = %s, want %s", tc.name, m.Stage, tc.want)
		}
		if m.Key != "parameter" || m.Name == "" || m.Summary == "" {
			t.Errorf("%s: key/name/summary 不完整: %+v", tc.name, m)
		}
	}
	// metrics 全量透出
	m := deriveParameterMaturity(maturityCounts{ParamTotal: 5, ParamRecommended: 2, ParamConfirmed: 1, ParamWithStats: 3, FormalConstraints: 1})
	for key, want := range map[string]int64{
		"parameters_total": 5, "with_recommended": 2, "with_confirmed": 1,
		"with_statistics": 3, "enforced_formal_constraints": 1,
	} {
		if got, ok := m.Metrics[key].(int64); !ok || got != want {
			t.Errorf("parameter metrics[%s] = %v, want %d", key, m.Metrics[key], want)
		}
	}
}

func TestDeriveIdentityMaturity(t *testing.T) {
	cases := []struct {
		name string
		c    maturityCounts
		want MaturityStage
	}{
		{"无事件", maturityCounts{}, StageLearning},
		{"有事件但全无身份指纹", maturityCounts{Events24h: 10}, StageLearning},
		{"覆盖率不足50%", maturityCounts{Events24h: 4, EventsWithIdentity24h: 1, DistinctIdentities24h: 1}, StageCandidate},
		{"覆盖率恰好50%", maturityCounts{Events24h: 4, EventsWithIdentity24h: 2, DistinctIdentities24h: 2}, StageConfirmed},
		{"覆盖率达标", maturityCounts{Events24h: 7, EventsWithIdentity24h: 4, DistinctIdentities24h: 3}, StageConfirmed},
	}
	for _, tc := range cases {
		m := deriveIdentityMaturity(tc.c)
		if m.Stage != tc.want {
			t.Errorf("%s: stage = %s, want %s", tc.name, m.Stage, tc.want)
		}
	}
	// 身份模型最高 CONFIRMED（只产信号不阻断），任何计数组合都不得出现 ENFORCING
	for _, c := range []maturityCounts{
		{Events24h: 100, EventsWithIdentity24h: 100, DistinctIdentities24h: 50},
		{Events24h: 1, EventsWithIdentity24h: 1, DistinctIdentities24h: 1},
	} {
		if m := deriveIdentityMaturity(c); m.Stage == StageEnforcing {
			t.Errorf("identity 不应到达 ENFORCING: %+v", c)
		}
	}
	// 覆盖率 round4：4/7 ≈ 0.5714
	m := deriveIdentityMaturity(maturityCounts{Events24h: 7, EventsWithIdentity24h: 4})
	if got := m.Metrics["identity_coverage_24h"]; got != 0.5714 {
		t.Errorf("identity_coverage_24h = %v, want 0.5714", got)
	}
}

func TestDeriveAccessEnvMaturity(t *testing.T) {
	cases := []struct {
		name string
		c    maturityCounts
		want MaturityStage
	}{
		{"无画像行", maturityCounts{EndpointsTotal: 3}, StageLearning},
		{"有画像但覆盖率不足", maturityCounts{ProfilesTotal: 1, ProfilesWithHourDist: 1, EndpointsWithProfiles: 1, EndpointsTotal: 3}, StageCandidate},
		{"覆盖率达标但无时段分布", maturityCounts{ProfilesTotal: 2, EndpointsWithProfiles: 2, EndpointsTotal: 3}, StageCandidate},
		{"覆盖率达标且含时段分布", maturityCounts{ProfilesTotal: 2, ProfilesWithHourDist: 1, EndpointsWithProfiles: 2, EndpointsTotal: 3}, StageConfirmed},
		{"覆盖率恰好45%", maturityCounts{ProfilesTotal: 9, ProfilesWithHourDist: 9, EndpointsWithProfiles: 9, EndpointsTotal: 20}, StageConfirmed},
		{"覆盖率低于45%", maturityCounts{ProfilesTotal: 2, ProfilesWithHourDist: 2, EndpointsWithProfiles: 2, EndpointsTotal: 5}, StageCandidate},
		{"端点总数为0防御（有画像无端点不CONFIRMED）", maturityCounts{ProfilesTotal: 1, ProfilesWithHourDist: 1, EndpointsWithProfiles: 1}, StageCandidate},
	}
	for _, tc := range cases {
		m := deriveAccessEnvMaturity(tc.c)
		if m.Stage != tc.want {
			t.Errorf("%s: stage = %s, want %s", tc.name, m.Stage, tc.want)
		}
		if m.Stage == StageEnforcing {
			t.Errorf("%s: access_env 不应到达 ENFORCING", tc.name)
		}
	}
	// 覆盖率 round4：2/3 ≈ 0.6667
	m := deriveAccessEnvMaturity(maturityCounts{ProfilesTotal: 2, ProfilesWithHourDist: 1, EndpointsWithProfiles: 2, EndpointsTotal: 3})
	if got := m.Metrics["endpoint_coverage"]; got != 0.6667 {
		t.Errorf("endpoint_coverage = %v, want 0.6667", got)
	}
}

func TestDeriveAccessObjectMaturity(t *testing.T) {
	// 无对象模型行：LEARNING（resource.* 命中只是信号，不抬升 stage）
	m := deriveAccessObjectMaturity(maturityCounts{ResourceHits24h: 9})
	if m.Stage != StageLearning {
		t.Errorf("object_models 空时 stage = %s, want LEARNING（信号不抬升）", m.Stage)
	}
	if got := m.Metrics["resource_signal_events_24h"]; got != int64(9) {
		t.Errorf("resource_signal_events_24h = %v, want 9", got)
	}
	// 有对象模型行但端点覆盖不足 45%：CANDIDATE
	m = deriveAccessObjectMaturity(maturityCounts{
		ObjectModelsTotal: 2, EndpointsWithObjectModels: 2, EndpointsTotal: 5, ResourceHits24h: 9,
	})
	if m.Stage != StageCandidate {
		t.Errorf("覆盖率 2/5=40%% 时 stage = %s, want CANDIDATE", m.Stage)
	}
	if got := m.Metrics["endpoints_with_object_models"]; got != int64(2) {
		t.Errorf("endpoints_with_object_models = %v, want 2", got)
	}
	if got := m.Metrics["object_endpoint_coverage"]; got != 0.4 {
		t.Errorf("object_endpoint_coverage = %v, want 0.4", got)
	}
	// 端点覆盖 ≥45%：CONFIRMED（只产信号不阻断，不得 ENFORCING）
	m = deriveAccessObjectMaturity(maturityCounts{
		ObjectModelsTotal: 9, EndpointsWithObjectModels: 9, EndpointsTotal: 20,
	})
	if m.Stage != StageConfirmed {
		t.Errorf("覆盖率 9/20=45%% 时 stage = %s, want CONFIRMED", m.Stage)
	}
	if m.Stage == StageEnforcing {
		t.Error("access_object 不应到达 ENFORCING")
	}
	if m.Key != "access_object" || m.Summary == "" {
		t.Errorf("access_object key/summary 不完整: %+v", m)
	}
}
