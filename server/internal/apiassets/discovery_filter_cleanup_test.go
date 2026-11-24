package apiassets

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

type fakeFilterSettingsStore struct {
	values map[string]string
}

func (f *fakeFilterSettingsStore) GetStringWithSource(_ context.Context, group, key string) (string, bool, error) {
	v, ok := f.values[group+":"+key]
	return v, ok, nil
}

func (f *fakeFilterSettingsStore) UpsertString(_ context.Context, group, key, value, _ string, _ uuid.UUID) error {
	if f.values == nil {
		f.values = map[string]string{}
	}
	f.values[group+":"+key] = value
	return nil
}

func TestDiscoveryFilterProviderAndValidation(t *testing.T) {
	ctx := context.Background()
	st := &fakeFilterSettingsStore{}
	provider := NewDiscoveryFilterProvider(st)

	// 初始加载内置默认配置
	defCfg, err := provider.LoadStrict(ctx)
	if err != nil {
		t.Fatalf("LoadStrict default: %v", err)
	}
	if !defCfg.ExcludeStaticAssets || !defCfg.FilterNonAPI || len(defCfg.ExcludeExtensions) == 0 {
		t.Fatalf("unexpected default config: %+v", defCfg)
	}

	// 非法扩展名和根路径 '/' 必须拒绝
	if _, err := NormalizeAndValidateDiscoveryFilter(DiscoveryFilterConfig{
		ExcludeExtensions: []string{"../etc"},
	}); err == nil {
		t.Fatal("expected invalid extension error")
	}
	if _, err := NormalizeAndValidateDiscoveryFilter(DiscoveryFilterConfig{
		ExcludePathPrefixes: []string{"/"},
	}); err == nil {
		t.Fatal("expected root path prefix error")
	}

	// 合法保存与规范化去重 + 立即热刷新缓存
	saved, err := provider.Save(ctx, DiscoveryFilterConfig{
		ExcludeStaticAssets: true,
		FilterNonAPI:        true,
		ExcludeExtensions:   []string{"PNG", ".png", "*.tar.gz", "js"},
		ExcludePathPrefixes: []string{"/astro/", "astro", "/_next/static"},
		IncludePathPrefixes: []string{"/api/public/"},
	}, uuid.New())
	if err != nil {
		t.Fatalf("Save valid config: %v", err)
	}
	if len(saved.ExcludeExtensions) != 3 || saved.ExcludeExtensions[0] != ".png" || saved.ExcludeExtensions[1] != ".tar.gz" {
		t.Fatalf("normalized extensions mismatch: %+v", saved.ExcludeExtensions)
	}
	if len(saved.ExcludePathPrefixes) != 2 || saved.ExcludePathPrefixes[0] != "/astro" {
		t.Fatalf("normalized exclude prefixes mismatch: %+v", saved.ExcludePathPrefixes)
	}

	got := provider.Get(ctx)
	if filtered, reason := got.ShouldFilterDiscovery("GET", "/astro/TheFooter.CYhiSQ7R", true); !filtered || reason != "exclude_path_prefix:/astro" {
		t.Fatalf("expected /astro filtered, got filtered=%v reason=%q", filtered, reason)
	}
	if filtered, _ := got.ShouldFilterDiscovery("GET", "/api/public/logo.png", false); filtered {
		t.Fatal("include whitelist prefix must bypass static and non-api filter")
	}
}

func TestListAndQuotaFilterIsAPIAndUpgradeOnConflict(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	store.SetEndpointQuotaProvider(func(context.Context) int64 { return 1 })

	// 历史非 API 行不计入 API 资产配额，且默认不出现在 List/SiteSummary/DirectoryTree
	nonAPI, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/products", Confidence: 0, IsAPI: false,
	})
	if err != nil {
		t.Fatalf("insert non-api: %v", err)
	}
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/api/v1/orders", Confidence: 0.8, IsAPI: true,
	}); err != nil {
		t.Fatalf("first real API should fit quota=1: %v", err)
	}
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/api/v1/users", Confidence: 0.8, IsAPI: true,
	}); err != ErrLicenseQuotaExceeded {
		t.Fatalf("second real API should hit quota=1, got err=%v", err)
	}

	list, total, err := store.List(ctx, ListFilter{})
	if err != nil || total != 1 || len(list) != 1 || list[0].NormalizedPath != "/api/v1/orders" {
		t.Fatalf("default List should only return is_api=true, got total=%d list=%+v err=%v", total, list, err)
	}
	allList, allTotal, err := store.List(ctx, ListFilter{IncludeNonAPI: true})
	if err != nil || allTotal != 2 || len(allList) != 2 {
		t.Fatalf("IncludeNonAPI List should return 2, got total=%d len=%d", allTotal, len(allList))
	}
	_, unassigned, err := store.SiteSummary(ctx)
	if err != nil || unassigned != 1 {
		t.Fatalf("SiteSummary unassigned should count only is_api=true (1), got %d", unassigned)
	}
	tree, err := store.DirectoryTree(ctx, nil, false)
	if err != nil || len(tree) != 1 || tree[0].DirectoryPath != "/api/v1" {
		t.Fatalf("DirectoryTree should exclude non-api, got %+v", tree)
	}

	// 同键再次命中且 IsAPI=true：冲突更新应将 is_api 从 false 升格为 true
	upgraded, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/products", Confidence: 0.6, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("upgrade non-api: %v", err)
	}
	if upgraded.ID != nonAPI.ID || !upgraded.IsAPI || upgraded.APIConfidence != 0.6 {
		t.Fatalf("expected conflict update to upgrade is_api=true: %+v", upgraded)
	}
}

func TestHandlerDiscoveryFilterBatchIgnoreAndNoiseCleanup(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	settingsStore := &fakeFilterSettingsStore{}
	provider := NewDiscoveryFilterProvider(settingsStore)
	h := NewHandler(store, nil).SetDiscoveryFilterProvider(provider)
	mux := newTestMux(h)

	// 1) GET / PUT discovery-filter
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/discovery-filter", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET discovery-filter status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if _, ok := data["default_extensions"]; !ok {
		t.Fatalf("missing default_extensions: %+v", data)
	}

	putBody := DiscoveryFilterConfig{
		ExcludeStaticAssets: true,
		FilterNonAPI:        true,
		ExcludeExtensions:   DefaultDiscoveryFilterConfig().ExcludeExtensions,
		ExcludePathPrefixes: []string{"/astro"},
		IncludePathPrefixes: []string{"/api/keep"},
	}
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/api-security/discovery-filter", putBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT discovery-filter status=%d body=%s", rr.Code, rr.Body.String())
	}

	// 2) 构造测试存量资产：真实 API、已确认的静态路径（受保护）、学习中路径（受保护）、
	// 白名单路径、静态图片/JS/压缩包、自定义前缀 /astro 路径、以及 is_api=false 的网页
	realAPI, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/api/v1/orders", Confidence: 0.9, IsAPI: true})
	confirmedStatic, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/manual-confirmed.png", Confidence: 0.8, IsAPI: true})
	_, _ = store.Confirm(ctx, confirmedStatic.ID)
	learningStatic, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/learning.js", Confidence: 0.8, IsAPI: true})
	_, _ = store.StartLearning(ctx, learningStatic.ID, 100, nil)
	whitelistStatic, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/api/keep/icon.png", Confidence: 0.8, IsAPI: true})

	noisePNG, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/备案图标.png", Confidence: 0.5, IsAPI: true})
	noiseJS, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/astro/page.BsuiZEAU.js", Confidence: 0.5, IsAPI: true})
	noiseZip, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/downloads/pkg.tar.gz", Confidence: 0.5, IsAPI: true})
	noiseHTML, _ := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/products", Confidence: 0, IsAPI: false})

	// 3) 预览噪声清理：4 条可清理，2 条受保护跳过（confirmedStatic + learningStatic）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/cleanup-noise/preview", map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rr.Code, rr.Body.String())
	}
	var previewEnv struct {
		Code string              `json:"code"`
		Data NoiseCleanupPreview `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &previewEnv); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if previewEnv.Data.Total != 4 || previewEnv.Data.ProtectedSkipped != 2 {
		t.Fatalf("preview want total=4 protected_skipped=2, got %+v", previewEnv.Data)
	}

	// 4) 尝试指定受保护 ID 执行清理：护栏必须拒绝删除受保护端点
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/cleanup-noise", map[string]any{
		"action": "DELETE",
		"ids":    []string{confirmedStatic.ID.String(), learningStatic.ID.String(), whitelistStatic.ID.String()},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("protected cleanup status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, err := store.GetByID(ctx, confirmedStatic.ID); err != nil {
		t.Fatal("confirmed endpoint was deleted!")
	}
	if _, err := store.GetByID(ctx, learningStatic.ID); err != nil {
		t.Fatal("learning endpoint was deleted!")
	}
	if _, err := store.GetByID(ctx, whitelistStatic.ID); err != nil {
		t.Fatal("whitelist endpoint was deleted!")
	}

	// 5) 先测试 IGNORE 模式清理单条 noisePNG
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/cleanup-noise", map[string]any{
		"action": "IGNORE",
		"ids":    []string{noisePNG.ID.String()},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("ignore cleanup status=%d body=%s", rr.Code, rr.Body.String())
	}
	afterIgnore, err := store.GetByID(ctx, noisePNG.ID)
	if err != nil || afterIgnore.AssetStatus != "IGNORED" {
		t.Fatalf("expected noisePNG IGNORED, got %+v err=%v", afterIgnore, err)
	}

	// 6) 执行全量 DELETE 清理（默认含 IGNORED）：4 条噪声全部删除，真实 API 与受保护项完好
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/cleanup-noise", map[string]any{
		"action": "DELETE",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("delete cleanup status=%d body=%s", rr.Code, rr.Body.String())
	}
	for _, deletedID := range []uuid.UUID{noisePNG.ID, noiseJS.ID, noiseZip.ID, noiseHTML.ID} {
		if _, err := store.GetByID(ctx, deletedID); err != ErrNotFound {
			t.Fatalf("noise endpoint %s should be deleted, err=%v", deletedID, err)
		}
	}
	for _, keptID := range []uuid.UUID{realAPI.ID, confirmedStatic.ID, learningStatic.ID, whitelistStatic.ID} {
		if _, err := store.GetByID(ctx, keptID); err != nil {
			t.Fatalf("kept endpoint %s missing: %v", keptID, err)
		}
	}

	// 7) 批量忽略接口 POST /api/v1/api-security/endpoints/ignore
	missingID := uuid.New()
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/endpoints/ignore", map[string]any{
		"ids": []string{realAPI.ID.String(), missingID.String()},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("ignore batch status=%d body=%s", rr.Code, rr.Body.String())
	}
	ignoreData := decodeData(t, rr)
	if ignoreData["ignored"].(float64) != 1 {
		t.Fatalf("want ignored=1, got %+v", ignoreData)
	}
	if ep, _ := store.GetByID(ctx, realAPI.ID); ep.AssetStatus != "IGNORED" {
		t.Fatalf("expected realAPI IGNORED, got %s", ep.AssetStatus)
	}
}
