package apiassets

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

type fakeLearningSettings struct {
	autoStartOnConfirm bool
}

func (f fakeLearningSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if group == LearningSettingGroup && key == LearningSettingAutoStartOnConfirm {
		return f.autoStartOnConfirm
	}
	return def
}

func muxWithPerms(h *Handler, perms ...string) *http.ServeMux {
	set := make(map[string]bool, len(perms))
	for _, perm := range perms {
		set[perm] = true
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, h)
	return mux
}

func TestLearningStartBatch(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	epNotStarted, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/a", Confidence: 0.9, IsAPI: true})
	epRunning, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "POST", PathTemplate: "/v1/b", Confidence: 0.9, IsAPI: true})
	epPaused, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "PUT", PathTemplate: "/v1/c", Confidence: 0.9, IsAPI: true})
	if _, err := store.StartLearning(ctx, epRunning.ID, 50, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartLearning(ctx, epPaused.ID, 50, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StopLearning(ctx, epPaused.ID, "tester"); err != nil {
		t.Fatal(err)
	}

	mux := newTestMux(NewHandler(store, nil))
	missingID := uuid.New()

	// 批量启动：包含未开始、已暂停、学习中（自动跳过）、重复 ID（去重）与不存在（failed）
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"ids": []string{
			epNotStarted.ID.String(),
			epNotStarted.ID.String(), // 重复 ID 应去重，不误判为跳过
			epPaused.ID.String(),
			epRunning.ID.String(),
			missingID.String(),
		},
		"sample_target": 200,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if int(data["started"].(float64)) != 2 {
		t.Fatalf("started=%v, want 2 body=%s", data["started"], rr.Body.String())
	}
	if int(data["skipped"].(float64)) != 1 {
		t.Fatalf("skipped=%v, want 1", data["skipped"])
	}
	if int(data["sample_target"].(float64)) != 200 {
		t.Fatalf("sample_target=%v, want 200", data["sample_target"])
	}
	failed := data["failed"].([]any)
	if len(failed) != 1 {
		t.Fatalf("failed len=%d, want 1", len(failed))
	}

	// 验证目标值与接口学习状态已落库
	for _, id := range []uuid.UUID{epNotStarted.ID, epPaused.ID} {
		ep, err := store.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if ep.LearningStatus != "LEARNING" {
			t.Fatalf("endpoint %s learning_status=%s, want LEARNING", id, ep.LearningStatus)
		}
		job, _, err := store.LearningStatus(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if job == nil || job.SampleTarget != 200 {
			t.Fatalf("endpoint %s job=%+v, want sample_target=200", id, job)
		}
	}

	// 再次对已全部学习中的接口调用：全部跳过
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"ids": []string{epNotStarted.ID.String(), epRunning.ID.String()},
	})
	data = decodeData(t, rr)
	if int(data["started"].(float64)) != 0 || int(data["skipped"].(float64)) != 2 {
		t.Fatalf("expected all skipped, got %v", data)
	}
	if int(data["sample_target"].(float64)) != DefaultSampleTarget {
		t.Fatalf("default sample_target=%v, want %d", data["sample_target"], DefaultSampleTarget)
	}
}

func TestLearningStartBatchValidationAndPermission(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	// 空 ids → 400
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{"ids": []string{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty ids status=%d", rr.Code)
	}

	// 超 100 个 → 400
	tooMany := make([]string, 101)
	for i := range tooMany {
		tooMany[i] = uuid.New().String()
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{"ids": tooMany})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("over limit status=%d", rr.Code)
	}

	// sample_target 越界 → 400
	for _, bad := range []int{0, 9, 100001} {
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
			"ids":           []string{uuid.New().String()},
			"sample_target": bad,
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("bad sample_target=%d status=%d", bad, rr.Code)
		}
	}

	// 无 api_learning.start 权限 → 403
	muxOnlyConfirm := muxWithPerms(h, "api_asset.read", "api_asset.confirm")
	rr = doJSON(t, muxOnlyConfirm, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"ids": []string{uuid.New().String()},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("without api_learning.start status=%d, want 403", rr.Code)
	}
}

func TestLearningOptions(t *testing.T) {
	store := NewMemStore()

	// 默认未注入 settings reader → false
	muxDefault := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, muxDefault, http.MethodGet, "/api/v1/api-security/endpoints/learning/options", nil)
	data := decodeData(t, rr)
	if data["auto_start_on_confirm"] != false {
		t.Fatalf("default auto_start_on_confirm=%v, want false", data["auto_start_on_confirm"])
	}
	if int(data["default_sample_target"].(float64)) != DefaultSampleTarget {
		t.Fatalf("default_sample_target=%v", data["default_sample_target"])
	}

	// 注入 auto_start_on_confirm=true
	hEnabled := NewHandler(store, nil).SetLearningSettingsReader(fakeLearningSettings{autoStartOnConfirm: true})
	muxEnabled := muxWithPerms(hEnabled, "api_asset.read")
	rr = doJSON(t, muxEnabled, http.MethodGet, "/api/v1/api-security/endpoints/learning/options", nil)
	data = decodeData(t, rr)
	if data["auto_start_on_confirm"] != true {
		t.Fatalf("enabled auto_start_on_confirm=%v, want true", data["auto_start_on_confirm"])
	}

	// 无 api_asset.read 权限 → 403
	muxNoRead := muxWithPerms(hEnabled, "api_learning.start")
	rr = doJSON(t, muxNoRead, http.MethodGet, "/api/v1/api-security/endpoints/learning/options", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no read perm status=%d, want 403", rr.Code)
	}
}

func TestConfirmBatchAutoStartLearning(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	epFresh, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/fresh", Confidence: 0.9, IsAPI: true})
	epRunning, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/running", Confidence: 0.9, IsAPI: true})
	epLearned, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/learned", Confidence: 0.9, IsAPI: true})
	if _, err := store.StartLearning(ctx, epRunning.ID, 50, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLearningStatus(ctx, epLearned.ID, "LEARNED"); err != nil {
		t.Fatal(err)
	}

	// 1. 显式 auto_start_learning=true（具备权限）：未开始的启动学习，学习中与已完成自动跳过
	h := NewHandler(store, nil)
	mux := newTestMux(h)
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids":                 []string{epFresh.ID.String(), epRunning.ID.String(), epLearned.ID.String()},
		"auto_start_learning": true,
		"sample_target":       150,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if int(data["confirmed"].(float64)) != 3 {
		t.Fatalf("confirmed=%v, want 3", data["confirmed"])
	}
	if int(data["learning_started"].(float64)) != 1 {
		t.Fatalf("learning_started=%v, want 1", data["learning_started"])
	}
	if int(data["learning_skipped"].(float64)) != 2 {
		t.Fatalf("learning_skipped=%v, want 2", data["learning_skipped"])
	}
	gotFresh, _ := store.GetByID(ctx, epFresh.ID)
	if gotFresh.AssetStatus != "CONFIRMED" || gotFresh.LearningStatus != "LEARNING" {
		t.Fatalf("fresh=%+v, want CONFIRMED + LEARNING", gotFresh)
	}
	job, _, _ := store.LearningStatus(ctx, epFresh.ID)
	if job == nil || job.SampleTarget != 150 {
		t.Fatalf("fresh job=%+v, want sample_target=150", job)
	}
	gotLearned, _ := store.GetByID(ctx, epLearned.ID)
	if gotLearned.LearningStatus != "LEARNED" {
		t.Fatalf("learned endpoint should stay LEARNED, got %s", gotLearned.LearningStatus)
	}

	// 2. 仅有 api_asset.confirm 权限、无 api_learning.start：显式传 true 返回 403，且不执行确认
	epNoPerm, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "POST", PathTemplate: "/v1/no-perm", Confidence: 0.9, IsAPI: true})
	muxConfirmOnly := muxWithPerms(h, "api_asset.confirm")
	rr = doJSON(t, muxConfirmOnly, http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids":                 []string{epNoPerm.ID.String()},
		"auto_start_learning": true,
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("explicit auto_start without perm status=%d, want 403", rr.Code)
	}
	gotNoPerm, _ := store.GetByID(ctx, epNoPerm.ID)
	if gotNoPerm.AssetStatus != "DISCOVERED" || gotNoPerm.LearningStatus != "NOT_STARTED" {
		t.Fatalf("403 must not mutate endpoint: %+v", gotNoPerm)
	}

	// 3. 系统设置 auto_start_on_confirm=true 时，省略字段按系统默认触发（需有权限）；显式传 false 可覆盖关闭
	hAuto := NewHandler(store, nil).SetLearningSettingsReader(fakeLearningSettings{autoStartOnConfirm: true})
	epAutoYes, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/auto-yes", Confidence: 0.9, IsAPI: true})
	epAutoNoOverride, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/auto-no-override", Confidence: 0.9, IsAPI: true})
	epAutoNoPerm, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/v1/auto-no-perm", Confidence: 0.9, IsAPI: true})

	// 3a. 有学习权限 + 省略字段 → 自动启动
	rr = doJSON(t, newTestMux(hAuto), http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids": []string{epAutoYes.ID.String()},
	})
	data = decodeData(t, rr)
	if int(data["learning_started"].(float64)) != 1 {
		t.Fatalf("setting=true omitted should auto start, got %v", data)
	}

	// 3b. 有学习权限 + 显式 false → 不启动
	rr = doJSON(t, newTestMux(hAuto), http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids":                 []string{epAutoNoOverride.ID.String()},
		"auto_start_learning": false,
	})
	data = decodeData(t, rr)
	if int(data["confirmed"].(float64)) != 1 || int(data["learning_started"].(float64)) != 0 {
		t.Fatalf("explicit false should override setting, got %v", data)
	}

	// 3c. 无学习权限 + 省略字段 → 正常确认，不绕过 api_learning.start 权限
	muxAutoConfirmOnly := muxWithPerms(hAuto, "api_asset.confirm")
	rr = doJSON(t, muxAutoConfirmOnly, http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids": []string{epAutoNoPerm.ID.String()},
	})
	data = decodeData(t, rr)
	if int(data["confirmed"].(float64)) != 1 || int(data["learning_started"].(float64)) != 0 {
		raw, _ := json.Marshal(data)
		t.Fatalf("confirm-only user must confirm without bypassing api_learning.start, got %s", raw)
	}
	gotAutoNoPerm, _ := store.GetByID(ctx, epAutoNoPerm.ID)
	if gotAutoNoPerm.AssetStatus != "CONFIRMED" || gotAutoNoPerm.LearningStatus != "NOT_STARTED" {
		t.Fatalf("got %+v, want CONFIRMED + NOT_STARTED", gotAutoNoPerm)
	}

	// 4. sample_target 越界 → 400
	rr = doJSON(t, newTestMux(h), http.MethodPost, "/api/v1/api-security/endpoints/confirm", map[string]any{
		"ids":                 []string{epFresh.ID.String()},
		"auto_start_learning": true,
		"sample_target":       5,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad sample_target status=%d, want 400", rr.Code)
	}
}

func TestLearningStartBatchApplyToFilteredCrossPage(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	appA := uuid.New()
	appB := uuid.New()

	// 在站点 A 下创建 125 个未开始接口（超过单页 100 上限），验证跨页扫描不漏项
	for i := 0; i < 125; i++ {
		if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
			ApplicationID: &appA,
			Method:        "GET",
			PathTemplate:  "/api/v1/items/" + uuid.NewString(),
			Confidence:    0.9,
			IsAPI:         true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// 站点 A 下混入：1 个学习中、1 个已完成、1 个已忽略、1 个已下线
	epRunning, _ := store.UpsertDiscovery(ctx, DiscoveryInput{ApplicationID: &appA, Method: "POST", PathTemplate: "/api/v1/running", Confidence: 0.9, IsAPI: true})
	_, _ = store.StartLearning(ctx, epRunning.ID, 50, nil)
	epLearned, _ := store.UpsertDiscovery(ctx, DiscoveryInput{ApplicationID: &appA, Method: "POST", PathTemplate: "/api/v1/learned", Confidence: 0.9, IsAPI: true})
	_ = store.SetLearningStatus(ctx, epLearned.ID, "LEARNED")
	epIgnored, _ := store.UpsertDiscovery(ctx, DiscoveryInput{ApplicationID: &appA, Method: "POST", PathTemplate: "/api/v1/ignored", Confidence: 0.9, IsAPI: true})
	_, _ = store.SetAssetStatus(ctx, epIgnored.ID, "IGNORED", "tester")
	epDeprecated, _ := store.UpsertDiscovery(ctx, DiscoveryInput{ApplicationID: &appA, Method: "POST", PathTemplate: "/api/v1/deprecated", Confidence: 0.9, IsAPI: true})
	_, _ = store.Deprecate(ctx, epDeprecated.ID, "tester")
	// 站点 B 下 1 个接口：不应受站点 A 筛选影响
	epOtherSite, _ := store.UpsertDiscovery(ctx, DiscoveryInput{ApplicationID: &appB, Method: "GET", PathTemplate: "/api/v1/other", Confidence: 0.9, IsAPI: true})

	mux := newTestMux(NewHandler(store, nil))

	// 1. 按站点 A 全部启动学习：125 个应全部启动，4 个（学习中/已完成/已忽略/已下线）自动跳过，站点 B 不受影响
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter": map[string]any{
			"application_id": appA.String(),
		},
		"sample_target": 120,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if int(data["matched_total"].(float64)) != 129 {
		t.Fatalf("matched_total=%v, want 129", data["matched_total"])
	}
	if int(data["started"].(float64)) != 125 {
		t.Fatalf("started=%v, want 125 body=%s", data["started"], rr.Body.String())
	}
	if int(data["skipped"].(float64)) != 4 {
		t.Fatalf("skipped=%v, want 4", data["skipped"])
	}
	if data["truncated"] != false {
		t.Fatalf("truncated=%v, want false", data["truncated"])
	}
	gotOther, _ := store.GetByID(ctx, epOtherSite.ID)
	if gotOther.LearningStatus != "NOT_STARTED" {
		t.Fatalf("other site endpoint should stay NOT_STARTED, got %s", gotOther.LearningStatus)
	}
	gotLearned, _ := store.GetByID(ctx, epLearned.ID)
	if gotLearned.LearningStatus != "LEARNED" {
		t.Fatalf("learned endpoint should be skipped when not filtering LEARNED, got %s", gotLearned.LearningStatus)
	}
	gotIgnored, _ := store.GetByID(ctx, epIgnored.ID)
	if gotIgnored.LearningStatus != "NOT_STARTED" {
		t.Fatalf("ignored endpoint should be skipped, got %s", gotIgnored.LearningStatus)
	}

	// 2. 显式筛选 learning_status=LEARNED 时允许重新学习该已完成接口
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter": map[string]any{
			"application_id":  appA.String(),
			"learning_status": "LEARNED",
		},
	})
	data = decodeData(t, rr)
	if int(data["started"].(float64)) != 1 || int(data["skipped"].(float64)) != 0 {
		t.Fatalf("explicit LEARNED filter should restart learned endpoint, got %v", data)
	}

	// 3. 筛选 learning_status=NOT_STARTED 跨页启动（站点 B 扩充至 110 个验证状态变更不引起翻页漏项）
	for i := 0; i < 109; i++ {
		_, _ = store.UpsertDiscovery(ctx, DiscoveryInput{
			ApplicationID: &appB,
			Method:        "GET",
			PathTemplate:  "/b/v1/" + uuid.NewString(),
			Confidence:    0.9,
			IsAPI:         true,
		})
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter": map[string]any{
			"application_id":  appB.String(),
			"learning_status": "NOT_STARTED",
		},
	})
	data = decodeData(t, rr)
	if int(data["started"].(float64)) != 110 {
		t.Fatalf("cross-page NOT_STARTED filter started=%v, want 110", data["started"])
	}
}

func TestLearningStartBatchApplyToFilteredValidationAndPermission(t *testing.T) {
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	// ids 与 apply_to_filtered 同时指定 → 400
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"ids":               []string{uuid.New().String()},
		"apply_to_filtered": true,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("both ids and apply_to_filtered status=%d, want 400", rr.Code)
	}

	// 非法 application_id → 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter":            map[string]any{"application_id": "not-a-uuid"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad application_id status=%d, want 400", rr.Code)
	}

	// 非法 business_type → 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter":            map[string]any{"business_type": "UNKNOWN_TYPE"},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad business_type status=%d, want 400", rr.Code)
	}

	// 空命中 → 200 且 started=0
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
		"filter":            map[string]any{"keyword": "/never-exists"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("empty match status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if int(data["matched_total"].(float64)) != 0 || int(data["started"].(float64)) != 0 {
		t.Fatalf("empty match data=%v", data)
	}

	// 无 api_learning.start 权限 → 403
	muxNoPerm := muxWithPerms(h, "api_asset.read")
	rr = doJSON(t, muxNoPerm, http.MethodPost, "/api/v1/api-security/endpoints/learning/start", map[string]any{
		"apply_to_filtered": true,
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no perm status=%d, want 403", rr.Code)
	}
}
