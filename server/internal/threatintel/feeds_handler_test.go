package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/settings"
)

type fakeFeedSettingsStore struct {
	mu      sync.Mutex
	bools   map[string]bool
	ints    map[string]int
	version map[string]int
}

func newFakeFeedSettingsStore() *fakeFeedSettingsStore {
	return &fakeFeedSettingsStore{
		bools:   map[string]bool{SettingsGroup + ":" + KeyAutoUpdateEnabled: false},
		ints:    map[string]int{SettingsGroup + ":" + KeyCircuitThreshold: DefaultCircuitThreshold},
		version: map[string]int{SettingsGroup + ":" + KeyCircuitThreshold: 1},
	}
}

func (f *fakeFeedSettingsStore) GetBool(_ context.Context, g, k string, def bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.bools[g+":"+k]; ok {
		return v
	}
	return def
}

func (f *fakeFeedSettingsStore) GetInt(_ context.Context, g, k string, def int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.ints[g+":"+k]; ok {
		return v
	}
	return def
}

func (f *fakeFeedSettingsStore) UpsertBool(_ context.Context, g, k string, value bool, _ string, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bools[g+":"+k] = value
	return nil
}

func (f *fakeFeedSettingsStore) List(_ context.Context, group string) ([]settings.Setting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if group != SettingsGroup {
		return nil, nil
	}
	return []settings.Setting{
		{
			Group:     SettingsGroup,
			Key:       KeyCircuitThreshold,
			Value:     json.RawMessage(fmt.Sprintf("%d", f.ints[SettingsGroup+":"+KeyCircuitThreshold])),
			ValueType: "number",
			Version:   f.version[SettingsGroup+":"+KeyCircuitThreshold],
		},
	}, nil
}

func (f *fakeFeedSettingsStore) Update(_ context.Context, group, key string, value json.RawMessage, expectedVersion int, _ uuid.UUID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	gk := group + ":" + key
	if f.version[gk] != expectedVersion {
		return false, errors.New("version conflict")
	}
	var n int
	if err := json.Unmarshal(value, &n); err != nil {
		return false, err
	}
	f.ints[gk] = n
	f.version[gk]++
	return false, nil
}

func injectTestPrincipal(perms ...string) func(http.Handler) http.Handler {
	copied := append([]string{}, perms...)
	set := map[string]bool{}
	for _, perm := range perms {
		set[perm] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{
				UserID:      uuid.New(),
				Username:    "secadmin",
				Permissions: copied,
				PermsSet:    set,
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func noTestPrincipal(next http.Handler) http.Handler { return next }

func TestFeedsHandler_RBACAndFullLifecycle(t *testing.T) {
	feodoID := uuid.New()
	ipsumID := uuid.New()
	repo := newMemFeedRepo(
		&Feed{
			ID: feodoID, FeedKey: "feodo", Name: "abuse.ch Feodo C2 IP 清单",
			IsBuiltin: true, Enabled: true, SourceMode: SourceModeOfficial, OfficialPreset: "feodo",
			Format: "text", TTLDays: 30, ScheduleCron: DefaultScheduleCron,
			MinEntriesGuard: true, MaxDropRatio: 0.80, ActiveRuleCount: 12,
		},
		&Feed{
			ID: ipsumID, FeedKey: "ipsum_l5", Name: "IPsum 高置信恶意 IP 清单 (Level 5)",
			IsBuiltin: true, Enabled: false, SourceMode: SourceModeOfficial, OfficialPreset: "ipsum_l5",
			Format: "text", TTLDays: 7, ScheduleCron: "0 4 * * *",
			MinEntriesGuard: true, MaxDropRatio: 0.80, CircuitOpen: true, ConsecutiveFailures: 5,
		},
	)
	rec := newFakeReconciler(repo)
	st := newFakeFeedSettingsStore()
	dl := &fakeDownloader{
		fn: func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
			return &FeedFetchResponse{Body: []byte("192.0.2.10\n203.0.113.20\n"), ETag: `"v1"`, StatusCode: 200}, nil
		},
	}
	syncer := NewSyncer(repo, rec, dl, st)
	urlValidator := func(_ context.Context, _ string, rawURL string) error {
		if strings.Contains(rawURL, "169.254.169.254") || strings.HasPrefix(rawURL, "http://public.") {
			return errors.New("SSRF 策略拒绝目标地址")
		}
		return nil
	}
	h := NewFeedsHandler(repo, syncer, st, urlValidator, nil)

	// 1. RBAC: unauthenticated -> 401; read-only -> GET 200, writes 403
	muxNoAuth := http.NewServeMux()
	RegisterFeedRoutes(muxNoAuth, noTestPrincipal, h)
	w := httptest.NewRecorder()
	muxNoAuth.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET /feeds = %d, want 401", w.Code)
	}

	muxReadOnly := http.NewServeMux()
	RegisterFeedRoutes(muxReadOnly, injectTestPrincipal(PermThreatIntelRead), h)
	w = httptest.NewRecorder()
	muxReadOnly.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read-only GET /feeds = %d, want 200: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	muxReadOnly.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/settings",
		strings.NewReader(`{"auto_update_enabled":true}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only PUT /settings = %d, want 403", w.Code)
	}
	w = httptest.NewRecorder()
	muxReadOnly.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds/"+feodoID.String()+"/sync",
		strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only POST /sync = %d, want 403", w.Code)
	}

	// 2. Full manage permissions
	mux := http.NewServeMux()
	RegisterFeedRoutes(mux, injectTestPrincipal(PermThreatIntelRead, PermThreatIntelManage), h)

	// 2a. GET /feeds returns settings, summary, presets, feeds
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/feeds", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /feeds = %d: %s", w.Code, w.Body.String())
	}
	var listResp struct {
		Data FeedsListResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode listResp: %v", err)
	}
	if listResp.Data.Summary.EnabledCount != 1 || listResp.Data.Summary.TotalActiveRules != 12 || listResp.Data.Summary.CircuitOpenCount != 1 {
		t.Fatalf("summary wrong: %+v", listResp.Data.Summary)
	}
	if len(listResp.Data.Presets) != 4 || len(listResp.Data.Feeds) != 2 {
		t.Fatalf("presets=%d feeds=%d, want 4/2", len(listResp.Data.Presets), len(listResp.Data.Feeds))
	}
	if listResp.Data.Presets[0].Key != "ipsum_l5" || listResp.Data.Presets[1].Key != "spamhaus_drop" {
		t.Fatalf("expected ipsum_l5 & spamhaus_drop first, got %+v", listResp.Data.Presets)
	}

	// 2b. PUT /settings validation & persistence
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/settings",
		strings.NewReader(`{"circuit_threshold":21}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("threshold=21 got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/settings",
		strings.NewReader(`{"auto_update_enabled":true,"circuit_threshold":7}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /settings got %d: %s", w.Code, w.Body.String())
	}
	var stResp struct {
		Data ThreatIntelSettings `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &stResp)
	if !stResp.Data.AutoUpdateEnabled || stResp.Data.CircuitThreshold != 7 {
		t.Fatalf("updated settings wrong: %+v", stResp.Data)
	}

	// 2c. POST /feeds rejects SSRF URL and deprecated sslbl preset; accepts active official preset defaults
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds",
		strings.NewReader(`{"feed_key":"bad_ssrf","name":"Bad","source_mode":"CUSTOM_URL","custom_url":"http://169.254.169.254/latest/meta-data/"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("SSRF custom_url got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds",
		strings.NewReader(`{"feed_key":"old_sslbl","name":"Deprecated SSLBL","source_mode":"OFFICIAL","official_preset":"sslbl"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("deprecated sslbl preset got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds",
		strings.NewReader(`{"feed_key":"drop_mirror","name":"Spamhaus DROP 副本","source_mode":"OFFICIAL","official_preset":"spamhaus_drop"}`)))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST official spamhaus_drop preset got %d: %s", w.Code, w.Body.String())
	}
	var dropResp struct {
		Data Feed `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &dropResp)
	if !dropResp.Data.AllowCIDR || dropResp.Data.TTLDays != 30 || dropResp.Data.ScheduleCron != "0 */12 * * *" {
		t.Fatalf("expected spamhaus_drop defaults inherited, got %+v", dropResp.Data)
	}

	// 2d. POST /feeds creates custom feed, duplicate key -> 409
	createBody := `{"feed_key":"corp_soc","name":"企业 SOC","source_mode":"CUSTOM_URL","custom_url":"https://soc.example.com/ips.txt","format":"text","allow_cidr":true,"ttl_days":14,"schedule_cron":"*/30 * * * *","max_drop_ratio":0.75}`
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds", strings.NewReader(createBody)))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /feeds got %d: %s", w.Code, w.Body.String())
	}
	var createdResp struct {
		Data Feed `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &createdResp)
	customID := createdResp.Data.ID
	if customID == uuid.Nil || !createdResp.Data.AllowCIDR || createdResp.Data.IsBuiltin {
		t.Fatalf("created feed wrong: %+v", createdResp.Data)
	}

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds", strings.NewReader(createBody)))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate feed_key got %d, want 409", w.Code)
	}

	// 2e. PUT /feeds/{id} protects builtin feed_key / is_builtin
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+feodoID.String(),
		strings.NewReader(`{"feed_key":"hacked","name":"Feodo"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("altering builtin feed_key got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+feodoID.String(),
		strings.NewReader(`{"is_builtin":false,"name":"Feodo"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("altering is_builtin got %d, want 400", w.Code)
	}

	// 2f. DELETE /feeds/{id} rejects builtin with 400, deletes custom with 200
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/threat-intel/feeds/"+feodoID.String(), nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("deleting builtin feed got %d, want 400", w.Code)
	}

	// 2g. POST /feeds/{id}/sync succeeds and writes run history
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds/"+feodoID.String()+"/sync",
		strings.NewReader(`{"force_ignore_guard":false}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /sync got %d: %s", w.Code, w.Body.String())
	}
	var syncResp struct {
		Data SyncFeedResult `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &syncResp)
	if syncResp.Data.Run == nil || syncResp.Data.Run.Status != RunStatusSuccess || syncResp.Data.Run.Added != 2 {
		t.Fatalf("sync result wrong: %+v", syncResp.Data)
	}

	// 2h. GET /runs returns paginated history
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/runs?feed_key=feodo&trigger_type=MANUAL&status=SUCCESS&page=1&page_size=10", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /runs got %d: %s", w.Code, w.Body.String())
	}
	var runsResp struct {
		Data struct {
			Items []SyncRun `json:"items"`
			Total int64     `json:"total"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &runsResp)
	if runsResp.Data.Total != 1 || len(runsResp.Data.Items) != 1 {
		t.Fatalf("runs wrong: %+v", runsResp.Data)
	}

	// 2i. PUT custom feed clears cache headers on source/allow_cidr change & enforces URLValidator
	_ = repo.UpdateFeedSyncResult(context.Background(), FeedSyncUpdate{
		ID: customID, ETag: `"old"`, LastModified: "Mon", LastContentSHA256: "abc",
		UpdateCacheHeaders: true, LastStatus: RunStatusSuccess,
	})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+customID.String(),
		strings.NewReader(`{"source_mode":"CUSTOM_URL","custom_url":"http://169.254.169.254/meta"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT SSRF custom_url got %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+customID.String(),
		strings.NewReader(`{"source_mode":"CUSTOM_URL","custom_url":"https://soc.example.com/v2.txt","allow_cidr":false}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT custom feed got %d: %s", w.Code, w.Body.String())
	}
	var updatedResp struct {
		Data Feed `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &updatedResp)
	if updatedResp.Data.ETag != "" || updatedResp.Data.LastContentSHA256 != "" {
		t.Fatalf("expected cache headers cleared after source/allow_cidr change: %+v", updatedResp.Data)
	}

	// 2j. Guard abort -> 200 with guard_triggered=true, then force_ignore_guard=true succeeds
	dl.fn = func(_ context.Context, _ FeedFetchRequest) (*FeedFetchResponse, error) {
		return &FeedFetchResponse{Body: []byte("; empty\n"), StatusCode: 200}, nil
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds/"+customID.String()+"/sync",
		strings.NewReader(`{"force_ignore_guard":false}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /sync guard abort got %d: %s", w.Code, w.Body.String())
	}
	var guardResp struct {
		Data SyncFeedResult `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &guardResp)
	if !guardResp.Data.GuardTriggered || guardResp.Data.Run.Status != RunStatusGuardAborted {
		t.Fatalf("expected guard_triggered=true, got %+v", guardResp.Data)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds/"+customID.String()+"/sync",
		strings.NewReader(`{"force_ignore_guard":true}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST /sync force got %d: %s", w.Code, w.Body.String())
	}
	var forceResp struct {
		Data SyncFeedResult `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &forceResp)
	if forceResp.Data.GuardTriggered || forceResp.Data.Run.Status != RunStatusSuccess {
		t.Fatalf("expected force sync SUCCESS, got %+v", forceResp.Data)
	}

	// 2k. Switch custom feed to OFFLINE_ONLY -> POST /sync returns 400
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+customID.String(),
		strings.NewReader(`{"source_mode":"OFFLINE_ONLY"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT offline_only got %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds/"+customID.String()+"/sync", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST /sync on OFFLINE_ONLY got %d, want 400", w.Code)
	}

	// 2l. DELETE custom feed succeeds
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/v1/threat-intel/feeds/"+customID.String(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE custom feed got %d: %s", w.Code, w.Body.String())
	}
}

func TestFeedsHandler_PartialUpdateAndDefenseInDepthAndBuiltinRoundtrip(t *testing.T) {
	feodoID := uuid.New()
	customID := uuid.New()
	repo := newMemFeedRepo(
		&Feed{
			ID: feodoID, FeedKey: "feodo", Name: "Feodo", Description: "Built-in desc",
			IsBuiltin: true, Enabled: true, SourceMode: SourceModeOfficial, OfficialPreset: "feodo",
			Format: "text", TTLDays: 30, ScheduleCron: DefaultScheduleCron,
			MinEntriesGuard: true, MaxDropRatio: 0.80,
		},
		&Feed{
			ID: customID, FeedKey: "soc_custom", Name: "SOC", Description: "Keep this description",
			IsBuiltin: false, Enabled: true, SourceMode: SourceModeCustomURL,
			CustomURL: "https://soc.example.com/list.txt",
			Format: "text", TTLDays: 15, ScheduleCron: DefaultScheduleCron,
			MinEntriesGuard: true, MaxDropRatio: 0.80,
		},
	)
	st := newFakeFeedSettingsStore()
	// Permissive urlValidator to ensure basicValidateCustomURL still enforces userinfo/scheme checks
	permissiveValidator := func(context.Context, string, string) error { return nil }
	h := NewFeedsHandler(repo, NewSyncer(repo, newFakeReconciler(repo), nil, st), st, permissiveValidator, nil)

	mux := http.NewServeMux()
	RegisterFeedRoutes(mux, injectTestPrincipal(PermThreatIntelRead, PermThreatIntelManage), h)

	// 1. Partial PUT {"enabled": false} on CUSTOM_URL feed preserves custom_url & description
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+customID.String(),
		strings.NewReader(`{"enabled":false}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("partial PUT on CUSTOM_URL feed got %d: %s", w.Code, w.Body.String())
	}
	var customResp struct {
		Data Feed `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &customResp)
	if customResp.Data.Enabled || customResp.Data.CustomURL != "https://soc.example.com/list.txt" || customResp.Data.Description != "Keep this description" {
		t.Fatalf("partial PUT altered omitted fields: %+v", customResp.Data)
	}

	// 2. Explicit empty description "" clears description when provided
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+customID.String(),
		strings.NewReader(`{"description":""}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("explicit clear description got %d: %s", w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &customResp)
	if customResp.Data.Description != "" || customResp.Data.CustomURL != "https://soc.example.com/list.txt" {
		t.Fatalf("explicit clear description unexpected state: %+v", customResp.Data)
	}

	// 3. Defense-in-depth: embedded userinfo rejected even if urlValidator is permissive
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/feeds",
		strings.NewReader(`{"feed_key":"cred_url","name":"Cred","source_mode":"CUSTOM_URL","custom_url":"https://user:pass@soc.example.com/list.txt"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("userinfo in custom_url got %d, want 400", w.Code)
	}

	// 4. Builtin feed roundtrip: OFFICIAL -> OFFLINE_ONLY -> OFFICIAL without passing official_preset
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+feodoID.String(),
		strings.NewReader(`{"source_mode":"OFFLINE_ONLY"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("builtin -> OFFLINE_ONLY got %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/api/v1/threat-intel/feeds/"+feodoID.String(),
		strings.NewReader(`{"source_mode":"OFFICIAL"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("builtin OFFLINE_ONLY -> OFFICIAL roundtrip got %d: %s", w.Code, w.Body.String())
	}
	var builtinResp struct {
		Data Feed `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &builtinResp)
	if builtinResp.Data.OfficialPreset != "feodo" || builtinResp.Data.Description != "Built-in desc" {
		t.Fatalf("builtin roundtrip state wrong: %+v", builtinResp.Data)
	}
}

func TestImportHandler_OfflineImportRecordsRunAndActiveCount(t *testing.T) {
	feodoID := uuid.New()
	repo := newMemFeedRepo(&Feed{
		ID: feodoID, FeedKey: "feodo", Name: "Feodo",
		IsBuiltin: true, SourceMode: SourceModeOfficial, OfficialPreset: "feodo",
		Format: "text", TTLDays: 30, ScheduleCron: DefaultScheduleCron,
	})
	rec := newFakeReconciler(repo)
	h := NewHandler(nil, nil)
	h.reconciler = rec
	h.SetFeedStore(repo)
	pubCount := 0
	h.SetPublishFunc(func(context.Context, uuid.UUID, string) { pubCount++ })

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/threat-intel/import", injectTestPrincipal("access_rules.import")(http.HandlerFunc(h.Import)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/threat-intel/import",
		strings.NewReader(`{"format":"text","feed":"feodo","ttl_days":30,"content":"192.0.2.10 ; inline\n198.51.100.20\n"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /import got %d: %s", w.Code, w.Body.String())
	}
	if pubCount != 1 {
		t.Fatalf("expected 1 publish, got %d", pubCount)
	}
	feed, err := repo.GetFeed(context.Background(), feodoID)
	if err != nil {
		t.Fatalf("GetFeed: %v", err)
	}
	if feed.ActiveRuleCount != 2 || feed.LastStatus != RunStatusSuccess {
		t.Fatalf("feed active_rule_count=%d status=%s, want 2/SUCCESS", feed.ActiveRuleCount, feed.LastStatus)
	}
	runs, total, err := repo.ListRuns(context.Background(), RunFilter{FeedKey: "feodo", TriggerType: TriggerOfflineImport})
	if err != nil || total != 1 || len(runs) != 1 {
		t.Fatalf("offline import run not recorded: total=%d runs=%+v err=%v", total, runs, err)
	}
	if !runs[0].Published || runs[0].Added != 2 || runs[0].TotalParsed != 2 {
		t.Fatalf("offline import run details wrong: %+v", runs[0])
	}
}
