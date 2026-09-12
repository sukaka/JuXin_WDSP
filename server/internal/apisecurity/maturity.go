// maturity.go 模型成熟度状态机只读总览（WDSP 三微模型第三批，
// docs/API_MICRO_MODELS.md §四第 10 项：LEARNING → CANDIDATE → CONFIRMED → ENFORCING）。
// 本文件只做管理面查询与纯推导：所有 stage 均由真实表计数聚合得出，无任何写入口；
// 推导规则集中在 derive*Maturity 纯函数、阈值常量化，便于单测与调整。
package apisecurity

import (
	"context"
	"net/http"
	"time"

	"github.com/jiuzhang-waf/server/internal/response"
)

// MaturityStage 成熟度阶段（状态机 LEARNING → CANDIDATE → CONFIRMED → ENFORCING）。
type MaturityStage string

const (
	// StageLearning 观察学习：尚无可用产出。
	StageLearning MaturityStage = "LEARNING"
	// StageCandidate 已有候选产出（推荐约束 / 行为画像 / 身份事件），未确认。
	StageCandidate MaturityStage = "CANDIDATE"
	// StageConfirmed 已确认（人工确认约束 / 覆盖率达标）。
	StageConfirmed MaturityStage = "CONFIRMED"
	// StageEnforcing 已下发网关生效（仅参数微模型可达；身份/访问模型只产信号不阻断）。
	StageEnforcing MaturityStage = "ENFORCING"
)

// 成熟度推导阈值（规则常量化，调整只改这里）。
const (
	// maturityIdentityCoverageConfirm 身份覆盖率 CONFIRMED 阈值：近 24h 带身份指纹事件占比 ≥ 50%。
	maturityIdentityCoverageConfirm = 0.5
	// maturityAccessCoverageConfirm 访问微模型（环境/对象维度）CONFIRMED 阈值：画像/对象模型覆盖端点比例 ≥ 45%。
	maturityAccessCoverageConfirm = 0.45
	// maturityEventWindow 运行时事件回看窗口（身份覆盖率与 resource.* 命中统计共用）。
	maturityEventWindow = 24 * time.Hour
)

// ModelMaturity 单个微模型成熟度评估（summary 为中文一句话，供前端直接展示）。
type ModelMaturity struct {
	Key     string         `json:"key"`
	Name    string         `json:"name"`
	Stage   MaturityStage  `json:"stage"`
	Metrics map[string]any `json:"metrics"`
	Summary string         `json:"summary"`
}

// ModelMaturityReport 成熟度总览（GET /api/v1/api-security/model-maturity 响应 data）。
type ModelMaturityReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Models      []ModelMaturity `json:"models"`
}

// maturityCounts 推导输入：各模型依赖的真实表计数（由 GetModelMaturity 一次性聚合）。
type maturityCounts struct {
	// 参数微模型（api_parameter_models）
	ParamTotal        int64 // 参数总数
	ParamRecommended  int64 // recommended_constraints 非空的参数数
	ParamConfirmed    int64 // confirmed_constraints 非空的参数数
	ParamWithStats    int64 // 有统计画像（api_parameter_statistics）的参数数
	FormalConstraints int64 // 已下发生效的确认约束（ListFormalParameterConstraints 同源口径）
	// 身份微模型（近 24h 事件窗口，api_runtime_events）
	Events24h             int64 // 近 24h 运行时事件数
	EventsWithIdentity24h int64 // 其中 identity_fingerprint 非空的事件数
	DistinctIdentities24h int64 // 去重身份数
	// 访问微模型·环境维度（api_behavior_profiles / api_endpoints）
	ProfilesTotal         int64 // 行为画像行数
	ProfilesWithHourDist  int64 // 含 hour_dist 非空的画像行数
	EndpointsWithProfiles int64 // 有画像的去重端点数
	EndpointsTotal        int64 // 端点总数
	// 访问微模型·对象维度（api_object_models / api_runtime_events）
	ObjectModelsTotal         int64 // 对象模型表行数（SweepObjectModelsOnce 从运行时事件 upsert 沉淀）
	EndpointsWithObjectModels int64 // 有对象模型的去重端点数
	ResourceHits24h           int64 // 近 24h resource.* 规则命中的运行时事件数
}

// ---------- 推导规则（纯函数，单测直接覆盖） ----------

// deriveParameterMaturity 参数微模型：
// 存在已下发生效的确认约束（ListFormalParameterConstraints 同源口径非空）→ ENFORCING；
// 有 confirmed_constraints 非空 → CONFIRMED；
// 有 recommended_constraints 非空（第二批画像聚合产出）→ CANDIDATE；否则 LEARNING。
func deriveParameterMaturity(c maturityCounts) ModelMaturity {
	m := ModelMaturity{
		Key:  "parameter",
		Name: "参数微模型",
		Metrics: map[string]any{
			"parameters_total":            c.ParamTotal,
			"with_recommended":            c.ParamRecommended,
			"with_confirmed":              c.ParamConfirmed,
			"with_statistics":             c.ParamWithStats,
			"enforced_formal_constraints": c.FormalConstraints,
		},
	}
	switch {
	case c.FormalConstraints > 0:
		m.Stage = StageEnforcing
		m.Summary = "确认约束已随 FORMAL 模型版本下发网关，对运行时流量实际生效"
	case c.ParamConfirmed > 0:
		m.Stage = StageConfirmed
		m.Summary = "已有人工确认的参数约束，尚未随最新 FORMAL 版本下发到网关"
	case c.ParamRecommended > 0:
		m.Stage = StageCandidate
		m.Summary = "离线画像已产出推荐约束，待人工评审确认后生效"
	default:
		m.Stage = StageLearning
		m.Summary = "参数模型处于观察学习期，尚无推荐约束产出"
	}
	return m
}

// deriveIdentityMaturity 身份微模型（只有信号不阻断，stage 最高 CONFIRMED）：
// 近 24h 事件数 >0 且身份覆盖率 ≥50% → CONFIRMED；有身份事件但覆盖率不足 → CANDIDATE；
// 无身份事件（含事件存在但全无身份指纹：身份模型无聚合主体）→ LEARNING。
func deriveIdentityMaturity(c maturityCounts) ModelMaturity {
	coverage := 0.0
	if c.Events24h > 0 {
		coverage = float64(c.EventsWithIdentity24h) / float64(c.Events24h)
	}
	m := ModelMaturity{
		Key:  "identity",
		Name: "身份微模型",
		Metrics: map[string]any{
			"events_24h":               c.Events24h,
			"events_with_identity_24h": c.EventsWithIdentity24h,
			"identity_coverage_24h":    round4(coverage),
			"distinct_identities_24h":  c.DistinctIdentities24h,
		},
	}
	switch {
	case c.Events24h > 0 && coverage >= maturityIdentityCoverageConfirm:
		m.Stage = StageConfirmed
		m.Summary = "身份指纹覆盖率达标，身份坐标已可用于环境与对象维度聚合（仅产出信号，不阻断）"
	case c.EventsWithIdentity24h > 0:
		m.Stage = StageCandidate
		m.Summary = "身份指纹已随事件落库，但覆盖率不足 50%，身份坐标尚不完整"
	default:
		m.Stage = StageLearning
		m.Summary = "近 24h 无带身份指纹的运行时事件，身份坐标系尚未建立"
	}
	return m
}

// deriveAccessEnvMaturity 访问微模型·环境维度（行为画像只产信号，stage 最高 CONFIRMED）：
// 无画像行 → LEARNING；画像覆盖端点比例 ≥45% 且含时段分布 → CONFIRMED；否则 CANDIDATE。
func deriveAccessEnvMaturity(c maturityCounts) ModelMaturity {
	coverage := 0.0
	if c.EndpointsTotal > 0 {
		coverage = float64(c.EndpointsWithProfiles) / float64(c.EndpointsTotal)
	}
	m := ModelMaturity{
		Key:  "access_env",
		Name: "访问微模型·环境维度",
		Metrics: map[string]any{
			"profiles_total":          c.ProfilesTotal,
			"profiles_with_hour_dist": c.ProfilesWithHourDist,
			"endpoints_with_profiles": c.EndpointsWithProfiles,
			"endpoints_total":         c.EndpointsTotal,
			"endpoint_coverage":       round4(coverage),
		},
	}
	switch {
	case c.ProfilesTotal == 0:
		m.Stage = StageLearning
		m.Summary = "尚无行为基线画像，等待离线聚合任务从运行时事件产出"
	case coverage >= maturityAccessCoverageConfirm && c.ProfilesWithHourDist > 0:
		m.Stage = StageConfirmed
		m.Summary = "行为画像覆盖率达标且含时段分布，可作为访问时间基线（仅产出信号，不阻断）"
	default:
		m.Stage = StageCandidate
		m.Summary = "行为画像已产出，端点覆盖或时段分布尚不足以支撑确认态"
	}
	return m
}

// deriveAccessObjectMaturity 访问微模型·对象维度（只产信号，stage 最高 CONFIRMED）：
// 无对象模型行 → LEARNING；对象模型覆盖端点比例 ≥45% → CONFIRMED；否则 CANDIDATE。
// resource.* 命中为网关侧实时检测信号，仅作 metrics 事实呈现，不抬升 stage
// ——检测信号不等于模型沉淀（OBSERVE 纪律，见 docs/API_MICRO_MODELS.md §2.4）。
func deriveAccessObjectMaturity(c maturityCounts) ModelMaturity {
	coverage := 0.0
	if c.EndpointsTotal > 0 {
		coverage = float64(c.EndpointsWithObjectModels) / float64(c.EndpointsTotal)
	}
	m := ModelMaturity{
		Key:  "access_object",
		Name: "访问微模型·对象维度",
		Metrics: map[string]any{
			"object_models_total":          c.ObjectModelsTotal,
			"endpoints_with_object_models": c.EndpointsWithObjectModels,
			"object_endpoint_coverage":     round4(coverage),
			"resource_signal_events_24h":   c.ResourceHits24h,
		},
	}
	switch {
	case c.ObjectModelsTotal == 0:
		m.Stage = StageLearning
		m.Summary = "对象模型表尚无沉淀数据，等待聚合任务从运行时事件产出（resource.* 命中情况见 metrics）"
	case coverage >= maturityAccessCoverageConfirm:
		m.Stage = StageConfirmed
		m.Summary = "对象模型覆盖率达标，可作为 BOLA 辅助检测基线（仅产出信号，不阻断；所有者关系尚未建模）"
	default:
		m.Stage = StageCandidate
		m.Summary = "对象模型已开始沉淀，端点覆盖尚不足以支撑确认态"
	}
	return m
}

// ---------- 计数聚合 ----------

// GetModelMaturity 聚合四个微模型所需计数并推导成熟度（少量聚合查询，无 N+1）。
func (s *Store) GetModelMaturity(ctx context.Context) (*ModelMaturityReport, error) {
	var c maturityCounts
	// 参数微模型：参数总数 / 有推荐 / 有确认 / 有统计画像（单次 JOIN 聚合；
	// api_parameter_statistics.parameter_id 唯一，JOIN 不会放大计数）。
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE p.recommended_constraints <> '{}'::jsonb),
       count(*) FILTER (WHERE p.confirmed_constraints <> '{}'::jsonb),
       count(st.parameter_id)
FROM api_parameter_models p
LEFT JOIN api_parameter_statistics st ON st.parameter_id = p.id`).
		Scan(&c.ParamTotal, &c.ParamRecommended, &c.ParamConfirmed, &c.ParamWithStats); err != nil {
		return nil, err
	}
	// 已下发生效的确认约束：与 apimodels.ListFormalParameterConstraints 同一选取语义
	// （每端点最新 FORMAL 版本 + REQUEST 方向 + required 或 confirmed_constraints 非空）。
	if err := s.db.QueryRow(ctx, `
WITH formal AS (
    SELECT DISTINCT ON (endpoint_key) id
    FROM api_model_versions WHERE status='FORMAL'
    ORDER BY endpoint_key, confirmed_at DESC NULLS LAST
)
SELECT count(*)
FROM formal f
JOIN api_parameter_models p ON p.model_version_id = f.id
WHERE p.direction='REQUEST'
  AND (p.required OR p.confirmed_constraints <> '{}'::jsonb)`).Scan(&c.FormalConstraints); err != nil {
		return nil, err
	}
	// 近 24h 运行时事件单次扫描：身份覆盖率（身份微模型）与 resource.* 命中（访问对象维度）。
	// details_json 可能为 JSON null（无明细事件），jsonb_array_elements 前必须 typeof 守卫。
	since := time.Now().UTC().Add(-maturityEventWindow)
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE identity_fingerprint <> ''),
       count(DISTINCT identity_fingerprint) FILTER (WHERE identity_fingerprint <> ''),
       count(*) FILTER (WHERE jsonb_typeof(details_json) = 'array' AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(details_json) m
           WHERE m->>'rule_id' LIKE 'resource.%'))
FROM api_runtime_events WHERE occurred_at >= $1`, since).
		Scan(&c.Events24h, &c.EventsWithIdentity24h, &c.DistinctIdentities24h, &c.ResourceHits24h); err != nil {
		return nil, err
	}
	// 访问微模型·环境维度：画像行数 / 含时段分布行数 / 覆盖端点数 + 端点总数。
	if err := s.db.QueryRow(ctx, `
SELECT count(*),
       count(*) FILTER (WHERE hour_dist <> '{}'::jsonb),
       count(DISTINCT endpoint_id)
FROM api_behavior_profiles`).
		Scan(&c.ProfilesTotal, &c.ProfilesWithHourDist, &c.EndpointsWithProfiles); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM api_endpoints`).Scan(&c.EndpointsTotal); err != nil {
		return nil, err
	}
	// 访问微模型·对象维度：对象模型表行数与覆盖端点数（SweepObjectModelsOnce 沉淀的 BOLA 实体画像）。
	if err := s.db.QueryRow(ctx, `SELECT count(*), count(DISTINCT endpoint_id) FROM api_object_models`).
		Scan(&c.ObjectModelsTotal, &c.EndpointsWithObjectModels); err != nil {
		return nil, err
	}
	return &ModelMaturityReport{
		GeneratedAt: time.Now().UTC(),
		Models: []ModelMaturity{
			deriveParameterMaturity(c),
			deriveIdentityMaturity(c),
			deriveAccessEnvMaturity(c),
			deriveAccessObjectMaturity(c),
		},
	}, nil
}

// ModelMaturity GET /api/v1/api-security/model-maturity
// 四个微模型成熟度总览（全部从真实表计数推导，权限 api_runtime.read）。
func (h *Handler) ModelMaturity(w http.ResponseWriter, r *http.Request) {
	report, err := h.store.GetModelMaturity(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, report)
}
