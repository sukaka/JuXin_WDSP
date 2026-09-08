// stage8_api_llm_test.go LLM API 安全 v1（W10-LLM / P2-04 首批）集成测试。
// 覆盖：迁移 000066 表结构/索引；apillm.ObsStore 落库（findings 过滤/幂等重放/
// 缺失容忍）；SQL Store 列表过滤与统计聚合（模型分布/token 趋势/命中规则计数）；
// HTTP 接线与权限点 api_runtime.read。
//
// 说明：apiruntime.Collector → apillm 的采集接线（Record.llm_observation 字段 +
// handleRecord 分支）属集成方装配范围，本测试以 ObservationInput 手工映射驱动
// 同一写入接口（映射逻辑一行字段透传，见任务交接装配片段）。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apillm"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// llmSeedInput 构造一条采集输入（模拟采集器从统一主事件映射：观测本体 + 身份/端点 + 明细）。
func llmSeedInput(requestID, endpointKey, model, identity, bucket string, tokens int, stream bool,
	occurredAt time.Time, details []dsctx.DetectorMatch) apillm.ObservationInput {
	return apillm.ObservationInput{
		RequestID: requestID, OccurredAt: occurredAt, EndpointKey: endpointKey,
		IdentityFingerprint: identity,
		Observation: apillm.LLMObservation{
			Model: model, PromptPresent: true, PromptLenBucket: bucket,
			TotalTokens: tokens, Stream: stream,
		},
		Details: details,
	}
}

// TestStage8LLMMigration 迁移 000066 落位：表结构/列/索引。
func TestStage8LLMMigration(t *testing.T) {
	env := setupStage8Env(t)

	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name='api_llm_observations'`); n != 1 {
		t.Fatalf("api_llm_observations missing")
	}
	for _, col := range []string{"id", "occurred_at", "endpoint_key", "model", "identity_fingerprint",
		"prompt_len_bucket", "total_tokens", "stream", "findings", "created_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_llm_observations' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_llm_observations column %s missing", col)
		}
	}
	for _, idx := range []string{"idx_api_llm_observations_occurred", "idx_api_llm_observations_model",
		"idx_api_llm_observations_endpoint", "idx_api_llm_observations_findings"} {
		if n := s8Count(t, env, `SELECT count(*) FROM pg_indexes WHERE indexname=$1`, idx); n != 1 {
			t.Fatalf("index %s missing", idx)
		}
	}
}

// TestStage8LLMObservationRecorder 采集落库：findings 仅 llm.* 明细、
// 同 request_id 重放幂等（DO NOTHING）、缺失容忍（无端点键/无 request_id）。
func TestStage8LLMObservationRecorder(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	endpointKey := "POST /v1/chat/completions-" + rid
	now := time.Now().UTC()
	rec := apillm.NewObsStore(env.db)

	details := []dsctx.DetectorMatch{
		{Detector: "llm", RuleID: "llm.prompt_injection", Category: "OBSERVE", Severity: "LOW",
			Evidence: map[string]string{"rule": "ignore_previous_instructions", "message_index": "0", "role": "user"}},
		{Detector: "llm", RuleID: "llm.unauthorized_model", Category: "OBSERVE", Severity: "MEDIUM",
			Evidence: map[string]string{"model": "claude-3-opus"}},
		{Detector: "waf", RuleID: "942100", Severity: "HIGH"}, // 非 llm.* 明细：不入 findings
	}
	in := llmSeedInput("llm-req-"+rid, endpointKey, "claude-3-opus", "auth:u1", "M", 800, true, now, details)
	if err := rec.RecordLLMObservation(ctx, in); err != nil {
		t.Fatalf("record: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_llm_observations WHERE endpoint_key=$1`, endpointKey); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	// 落库内容断言：findings 只含 2 条 llm.*（waf 明细剔除），token/stream 透传
	var tokens int
	var stream bool
	var findingsRaw []byte
	if err := env.db.QueryRow(ctx, `SELECT total_tokens, stream, findings
		FROM api_llm_observations WHERE endpoint_key=$1`, endpointKey).Scan(&tokens, &stream, &findingsRaw); err != nil {
		t.Fatalf("query: %v", err)
	}
	if tokens != 800 || !stream {
		t.Fatalf("tokens=%d stream=%v", tokens, stream)
	}
	var findings []dsctx.DetectorMatch
	if err := json.Unmarshal(findingsRaw, &findings); err != nil || len(findings) != 2 {
		t.Fatalf("findings = %s (err=%v)", findingsRaw, err)
	}
	for _, f := range findings {
		if f.Detector != "llm" {
			t.Fatalf("non-llm finding leaked: %+v", f)
		}
	}

	// 幂等：同 request_id 重放（模拟断点回退重复采集）→ 仍一行
	if err := rec.RecordLLMObservation(ctx, in); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_llm_observations WHERE endpoint_key=$1`, endpointKey); n != 1 {
		t.Fatalf("rows after replay = %d, want 1 (idempotent)", n)
	}

	// 缺失容忍：无端点键不产出；无 request_id 退化随机主键正常落库（不幂等，防御路径）
	if err := rec.RecordLLMObservation(ctx, llmSeedInput("llm-req-noek-"+rid, "", "gpt-4o", "", "XS", 1, false, now, nil)); err != nil {
		t.Fatalf("empty endpoint: %v", err)
	}
	if err := rec.RecordLLMObservation(ctx, llmSeedInput("", endpointKey, "gpt-4o", "", "XS", 5, false, now, nil)); err != nil {
		t.Fatalf("empty request_id: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_llm_observations WHERE endpoint_key=$1`, endpointKey); n != 2 {
		t.Fatalf("rows after tolerance cases = %d, want 2", n)
	}
}

// TestStage8LLMStatsSQL SQL Store 列表过滤与统计聚合（模型分布/token 趋势/命中规则计数）。
func TestStage8LLMStatsSQL(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epChat := "POST /v1/chat/completions-" + rid
	epEmb := "POST /v1/embeddings-" + rid
	now := time.Now().UTC()
	rec := apillm.NewObsStore(env.db)

	inj := []dsctx.DetectorMatch{
		{Detector: "llm", RuleID: "llm.prompt_injection", Severity: "LOW",
			Evidence: map[string]string{"rule": "dan_mode", "message_index": "0"}},
	}
	seeds := []apillm.ObservationInput{
		llmSeedInput("s1-"+rid, epChat, "gpt-4o", "auth:u1", "S", 120, false, now, nil),
		llmSeedInput("s2-"+rid, epChat, "gpt-4o", "auth:u2", "M", 300, true, now, inj),
		llmSeedInput("s3-"+rid, epEmb, "text-embedding-3-large", "auth:u1", "XS", 12, false, now, nil),
		// 窗口外（9 天前）：默认 7 天窗口不计
		llmSeedInput("s4-"+rid, epChat, "gpt-4o", "auth:u9", "L", 9999, false, now.AddDate(0, 0, -9), nil),
	}
	for _, in := range seeds {
		if err := rec.RecordLLMObservation(ctx, in); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	store := apillm.NewStore(env.db)

	// 列表：model + endpoint 过滤 + 窗口纪律
	items, total, err := store.ListObservations(ctx, apillm.ObservationFilter{
		Days: 7, Model: "gpt-4o", EndpointKey: epChat, Page: 1, PageSize: 20,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("list = total %d items %d", total, len(items))
	}
	// findings_only
	_, total, err = store.ListObservations(ctx, apillm.ObservationFilter{Days: 7, FindingsOnly: true, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if total != 1 {
		t.Fatalf("findings_only total = %d, want 1", total)
	}

	// 统计：7 天窗口（s4 不计）
	stats, err := store.Stats(ctx, 7)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Summary.Observations != 3 || stats.Summary.WithFindings != 1 ||
		stats.Summary.TotalTokens != 432 || stats.Summary.StreamCalls != 1 || stats.Summary.DistinctModels != 2 {
		t.Fatalf("summary = %+v", stats.Summary)
	}
	// 模型分布：gpt-4o 2 条 420 token 1 命中
	var gptOK bool
	for _, m := range stats.ByModel {
		if m.Model == "gpt-4o" {
			gptOK = m.Observations == 2 && m.TotalTokens == 420 && m.Findings == 1
		}
	}
	if !gptOK {
		t.Fatalf("by_model = %+v", stats.ByModel)
	}
	// token 趋势：当日一桶，总量一致
	if len(stats.TokenTrend) != 1 || stats.TokenTrend[0].TotalTokens != 432 || stats.TokenTrend[0].Observations != 3 {
		t.Fatalf("token_trend = %+v", stats.TokenTrend)
	}
	// 命中规则分布：llm.prompt_injection ×1
	if len(stats.FindingsByRule) != 1 || stats.FindingsByRule[0].RuleID != "llm.prompt_injection" ||
		stats.FindingsByRule[0].Count != 1 {
		t.Fatalf("findings_by_rule = %+v", stats.FindingsByRule)
	}
	// 窗口放宽 30 天：窗口外行计入
	stats30, err := store.Stats(ctx, 30)
	if err != nil {
		t.Fatalf("stats30: %v", err)
	}
	if stats30.Summary.Observations != 4 {
		t.Fatalf("stats30 observations = %d, want 4", stats30.Summary.Observations)
	}
}

// llmInjectPrincipal 注入持有 api_runtime.read 权限的主体（200 断言用）。
func llmInjectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{"api_runtime.read": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w10llm-it", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "w10llm-it-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TestStage8LLMHTTP HTTP 接线：权限矩阵 / 列表与统计出参 / 参数校验。
func TestStage8LLMHTTP(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epChat := "POST /v1/chat/completions-" + rid

	rec := apillm.NewObsStore(env.db)
	if err := rec.RecordLLMObservation(ctx, llmSeedInput("http-"+rid, epChat, "gpt-4o", "auth:u1", "S", 64, false,
		time.Now().UTC(), []dsctx.DetectorMatch{
			{Detector: "llm", RuleID: "llm.unauthorized_model", Severity: "MEDIUM", Evidence: map[string]string{"model": "gpt-4o"}},
		})); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newMux := func(authzFn func(http.Handler) http.Handler) *http.ServeMux {
		mux := http.NewServeMux()
		apillm.RegisterRoutes(mux, authzFn, apillm.NewHandler(apillm.NewStore(env.db)))
		return mux
	}

	// 权限矩阵：未登录 401 / 无权限 403 / api_runtime.read 200
	if rr := apidataDo(t, newMux(xbInjectAnon), http.MethodGet, "/api/v1/api-security/llm/observations", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon: status=%d, want 401", rr.Code)
	}
	if rr := apidataDo(t, newMux(faInjectNoPerm), http.MethodGet, "/api/v1/api-security/llm/observations", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("noperm: status=%d, want 403", rr.Code)
	}
	rr := apidataDo(t, newMux(llmInjectPrincipal), http.MethodGet,
		"/api/v1/api-security/llm/observations?endpoint_key="+url.QueryEscape(epChat), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var listBody struct {
		Data struct {
			Total int64 `json:"total"`
			Items []struct {
				Model    string `json:"model"`
				Findings []struct {
					RuleID string `json:"rule_id"`
				} `json:"findings"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listBody); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if listBody.Data.Total != 1 || listBody.Data.Items[0].Model != "gpt-4o" ||
		len(listBody.Data.Items[0].Findings) != 1 ||
		listBody.Data.Items[0].Findings[0].RuleID != "llm.unauthorized_model" {
		t.Fatalf("list = %+v", listBody.Data)
	}
	// stats 出参
	rr = apidataDo(t, newMux(llmInjectPrincipal), http.MethodGet, "/api/v1/api-security/llm/stats?days=7", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var statsBody struct {
		Data struct {
			Summary struct {
				Observations int64 `json:"observations"`
				WithFindings int64 `json:"with_findings"`
			} `json:"summary"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &statsBody); err != nil {
		t.Fatalf("decode stats: %v (body=%s)", err, rr.Body.String())
	}
	if statsBody.Data.Summary.Observations != 1 || statsBody.Data.Summary.WithFindings != 1 {
		t.Fatalf("stats summary = %+v", statsBody.Data.Summary)
	}
	// 参数校验 400
	for _, u := range []string{
		"/api/v1/api-security/llm/observations?findings_only=maybe",
		"/api/v1/api-security/llm/observations?model=" + strings.Repeat("m", 129),
	} {
		if rr := apidataDo(t, newMux(llmInjectPrincipal), http.MethodGet, u, nil); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", u, rr.Code)
		}
	}
}
