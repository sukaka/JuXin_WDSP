// api_collector_test.go API 专项指标单测：分组/聚合纯逻辑造数断言 +
// Render 文本输出包含全部 15 项指标。DB 聚合 SQL 路径由集成环境验证
// （包内单测不依赖 PG 凭据）。
package metrics

import (
	"strings"
	"testing"
	"time"
)

// TestFindingGroup finding_type 前缀分组（口径与 apiruntime/findings.go 生产方一致）。
func TestFindingGroup(t *testing.T) {
	cases := map[string]string{
		"SCHEMA_PARAM_LENGTH":                "schema", // schema.* 机械映射
		"SCHEMA_TYPE_MISMATCH":               "schema",
		"API_SCHEMA":                         "schema", // api_schema detector 兜底
		"AUTH_JWT_ALG_NONE":                  "auth",   // auth.* 机械映射
		"AUTHENTICATION":                     "auth",   // authentication detector 兜底
		"BOLA_UNAUTHENTICATED_OBJECT_ACCESS": "authz",  // 语义覆盖表
		"BOLA":                               "authz",
		"BFLA_FUNCTION_SCOPE":                "authz",
		"AUTHZ_ROLE_MISMATCH":                "authz", // 预留前缀
		"SENSITIVE_LEAK":                     "sensitive",
		"SENSITIVE_IN_QUERY":                 "sensitive",
		"BEHAVIOR":                           "behavior", // behavior detector 兜底
		"BEHAVIOR_RATE_SPIKE":                "behavior",
		"schema_param_length":                "schema", // 大小写不敏感
		"SHADOW":                             "",       // 生命周期类不计入五组
		"ZOMBIE":                             "",
		"DEPRECATED":                         "",
		"WAF_942100":                         "", // WAF 数字规则号兜底形态
		"IDENTITY_TOKEN_PRESENT":             "", // 身份观测类未列入本批五组
		"":                                   "",
	}
	for ft, want := range cases {
		if got := FindingGroup(ft); got != want {
			t.Errorf("FindingGroup(%q) = %q, want %q", ft, got, want)
		}
	}
}

// TestAggregateFindingsByGroup 造 finding_type 计数 → 五组聚合断言（组外类型不计入）。
func TestAggregateFindingsByGroup(t *testing.T) {
	counts := map[string]int64{
		"SCHEMA_PARAM_LENGTH": 2,
		"SCHEMA_EXTRA_FIELD":  1,
		"AUTH_JWT_ALG_NONE":   3,
		"BOLA":                4,
		"AUTHZ_X":             1,
		"SENSITIVE_LEAK":      5,
		"BEHAVIOR":            6,
		"SHADOW":              7, // 组外
		"WAF_942100":          8, // 组外
	}
	out := AggregateFindingsByGroup(counts)
	want := map[string]int64{
		SchemaFindings:    3,
		AuthFindings:      3,
		AuthzFindings:     5,
		SensitiveFindings: 5,
		BehaviorFindings:  6,
	}
	for name, w := range want {
		if out[name] != w {
			t.Errorf("%s = %d, want %d", name, out[name], w)
		}
	}
	if len(out) != 5 {
		t.Errorf("分组数 = %d, want 5", len(out))
	}
	// 空输入：五组均为 0（保证输出时序连续）
	out = AggregateFindingsByGroup(nil)
	for _, name := range []string{SchemaFindings, AuthFindings, AuthzFindings, SensitiveFindings, BehaviorFindings} {
		if out[name] != 0 {
			t.Errorf("空输入 %s = %d, want 0", name, out[name])
		}
	}
}

// TestAggregateModelVersions 模型版本状态计数 → 候选/已确认。
func TestAggregateModelVersions(t *testing.T) {
	candidates, confirmed := AggregateModelVersions(map[string]int64{
		"CANDIDATE":  2,
		"IN_REVIEW":  1,
		"FORMAL":     3,
		"SUPERSEDED": 4, // 曾正式已退出，不计入当前已确认
		"REJECTED":   1,
		"ARCHIVED":   1,
	})
	if candidates != 3 {
		t.Errorf("candidates = %d, want 3", candidates)
	}
	if confirmed != 3 {
		t.Errorf("confirmed = %d, want 3", confirmed)
	}
	candidates, confirmed = AggregateModelVersions(nil)
	if candidates != 0 || confirmed != 0 {
		t.Errorf("空输入 = %d/%d, want 0/0", candidates, confirmed)
	}
}

// TestAggregateRuntimePolicies 运行时策略状态计数 → 编译总数/失败数。
func TestAggregateRuntimePolicies(t *testing.T) {
	total, failed := AggregateRuntimePolicies(map[string]int64{
		"DRAFT":       1,
		"VALIDATED":   2,
		"ACTIVE":      3,
		"ROLLED_BACK": 1,
		"FAILED":      2,
	})
	if total != 9 {
		t.Errorf("total = %d, want 9", total)
	}
	if failed != 2 {
		t.Errorf("failed = %d, want 2", failed)
	}
	total, failed = AggregateRuntimePolicies(nil)
	if total != 0 || failed != 0 {
		t.Errorf("空输入 = %d/%d, want 0/0", total, failed)
	}
}

// 全部 15 项专项指标名（任务清单口径，防止渲染漏项）。
var allAPIMetricNames = []string{
	APIAssetsTotal, APIAssetsNew, APILearningJobs, APILearningSamples, APILearningExcluded,
	APICandidatesCreated, APIModelsConfirmed, RuntimeCompileTotal, RuntimeCompileError,
	SchemaFindings, AuthFindings, AuthzFindings, SensitiveFindings, BehaviorFindings,
	MaskResponseTotal,
}

// TestRenderAPISnapshot 造快照 → 断言文本包含全部指标名、HELP/TYPE 行与正确值。
func TestRenderAPISnapshot(t *testing.T) {
	snap := APISnapshot{
		CollectedAt:   time.Unix(1755000000, 0).UTC(),
		CollectErrors: 2,
		Values: map[string]int64{
			APIAssetsTotal:    42,
			APIAssetsNew:      3,
			MaskResponseTotal: 7,
			SchemaFindings:    5,
		},
	}
	out := RenderAPISnapshot(snap)
	for _, name := range allAPIMetricNames {
		if !strings.Contains(out, "# TYPE "+name+" gauge\n") {
			t.Errorf("输出缺少 TYPE 行: %s", name)
		}
	}
	for _, want := range []string{
		"api_assets_total 42\n",
		"api_assets_new 3\n",
		"mask_response_total 7\n",
		"schema_findings 5\n",
		"api_learning_jobs 0\n", // 未采集指标输出 0
		"api_metrics_collect_errors_total 2\n",
		"api_metrics_last_collect_timestamp_seconds 1755000000\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("输出缺少样本行 %q", strings.TrimSpace(want))
		}
	}
}

// TestRenderEmptySnapshot 空快照（未采集）仍输出全部指标且值为 0（抓取方时序连续）。
func TestRenderEmptySnapshot(t *testing.T) {
	out := RenderAPISnapshot(APISnapshot{Values: map[string]int64{}})
	for _, name := range allAPIMetricNames {
		if !strings.Contains(out, name+" 0\n") {
			t.Errorf("空快照缺少 %s 0", name)
		}
	}
	if !strings.Contains(out, "api_metrics_collect_errors_total 0\n") {
		t.Error("空快照缺少采集错误自指标")
	}
}

// TestCollectorSnapshotAndRender 采集器快照拷贝隔离 + Render 走最新快照。
func TestCollectorSnapshotAndRender(t *testing.T) {
	c := NewAPICollector(nil) // 仅快照/渲染路径，不触 DB
	c.values[APIAssetsTotal] = 10
	c.collectedAt = time.Unix(1755000000, 0).UTC()
	c.collectErrs = 1
	c.lastError = "api_endpoints: boom"

	snap := c.Snapshot()
	if snap.Values[APIAssetsTotal] != 10 || snap.CollectErrors != 1 || snap.LastError == "" {
		t.Fatalf("快照内容不符: %+v", snap)
	}
	// 拷贝隔离：改快照不影响采集器内部状态
	snap.Values[APIAssetsTotal] = 999
	if c.values[APIAssetsTotal] != 10 {
		t.Error("Snapshot 未做 map 拷贝，内部状态被外部修改")
	}
	if out := c.Render(); !strings.Contains(out, "api_assets_total 10\n") {
		t.Errorf("Render 未输出当前快照值: %q", out)
	}
}
