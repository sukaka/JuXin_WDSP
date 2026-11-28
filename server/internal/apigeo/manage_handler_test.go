// manage_handler_test.go GeoIP 状态查询、配置更新、在线同步、离线上传热加载、回滚、HA 重同步与流水查询 HTTP 接口测试。
// 覆盖权限矩阵（401/403/200）、任意 multipart 字段顺序、敏感密钥脱敏、SSRF 拦截、实时热生效、HA 一致性与流水落库。
package apigeo

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

type memManageStore struct {
	mu    sync.Mutex
	slots map[string]SlotConfig
	runs  []SyncRun
}

func newMemManageStore() *memManageStore {
	s := &memManageStore{slots: map[string]SlotConfig{}}
	for _, slot := range SlotOrder {
		spec := slotSpecs[slot]
		s.slots[slot] = SlotConfig{
			Slot:             slot,
			DisplayName:      spec.DisplayName,
			SourceMode:       SourceModeOfflineOnly,
			ActiveSourceType: SourceTypeBuiltin,
			LastStatus:       RunStatusIdle,
			UpdatedAt:        time.Now().UTC(),
		}
	}
	return s
}

func (m *memManageStore) ListSlotConfigs(context.Context) ([]SlotConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SlotConfig, 0, len(SlotOrder))
	for _, slot := range SlotOrder {
		if c, ok := m.slots[slot]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memManageStore) GetSlotConfig(_ context.Context, slot string) (*SlotConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.slots[slot]
	if !ok {
		return nil, ErrInvalidSlot
	}
	return &c, nil
}

func (m *memManageStore) UpdateSlotConfig(_ context.Context, u SlotConfigUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.slots[u.Slot]
	if !ok {
		return ErrInvalidSlot
	}
	if c.SourceMode != u.SourceMode || c.OfficialPreset != u.OfficialPreset || c.CustomURL != u.CustomURL {
		c.ETag = ""
		c.LastModified = ""
	}
	c.Enabled = u.Enabled
	c.SourceMode = u.SourceMode
	c.OfficialPreset = u.OfficialPreset
	c.CustomURL = u.CustomURL
	if !u.UpdatedAt.IsZero() {
		c.UpdatedAt = u.UpdatedAt
	}
	m.slots[u.Slot] = c
	return nil
}

func (m *memManageStore) UpdateSlotStatus(_ context.Context, u SlotActivationUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.slots[u.Slot]
	c.LastStatus = u.Status
	c.LastError = u.ErrorMessage
	c.UpdatedAt = u.UpdatedAt
	if u.ETag != "" {
		c.ETag = u.ETag
	}
	if u.LastModified != "" {
		c.LastModified = u.LastModified
	}
	if u.UpdateActiveFile {
		c.ActiveFilename = u.ActiveFilename
		c.ActiveSHA256 = u.ActiveSHA256
		c.ActiveSizeBytes = u.ActiveSizeBytes
		c.ActiveSourceType = u.ActiveSourceType
		t := u.UpdatedAt
		c.LastUpdatedAt = &t
	}
	m.slots[u.Slot] = c
	return nil
}

func (m *memManageStore) InsertSyncRun(_ context.Context, run *SyncRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *run
	if cp.ID == uuid.Nil {
		cp.ID = uuid.New()
	}
	m.runs = append([]SyncRun{cp}, m.runs...)
	return nil
}

func (m *memManageStore) ListSyncRuns(_ context.Context, f RunFilter) ([]SyncRun, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var filtered []SyncRun
	for _, r := range m.runs {
		if f.Slot != "" && r.Slot != f.Slot {
			continue
		}
		if f.TriggerType != "" && r.TriggerType != strings.ToUpper(f.TriggerType) {
			continue
		}
		if f.Status != "" && r.Status != strings.ToUpper(f.Status) {
			continue
		}
		filtered = append(filtered, r)
	}
	total := int64(len(filtered))
	page := f.Page
	if page <= 0 {
		page = 1
	}
	pageSize := f.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return []SyncRun{}, total, nil
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[start:end], total, nil
}

type fakeManageSettings struct {
	mu    sync.Mutex
	strs  map[string]string
	bools map[string]bool
}

func newFakeManageSettings() *fakeManageSettings {
	return &fakeManageSettings{
		strs:  map[string]string{},
		bools: map[string]bool{},
	}
}

func (f *fakeManageSettings) GetString(_ context.Context, g, k, def string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.strs[g+":"+k]; ok {
		return v
	}
	return def
}

func (f *fakeManageSettings) GetBool(_ context.Context, g, k string, def bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.bools[g+":"+k]; ok {
		return v
	}
	return def
}

func (f *fakeManageSettings) UpsertString(_ context.Context, g, k, v, _ string, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.strs[g+":"+k] = v
	return nil
}

func (f *fakeManageSettings) UpsertSensitiveString(_ context.Context, g, k, v, _ string, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.strs[g+":"+k] = v
	return nil
}

func (f *fakeManageSettings) UpsertBool(_ context.Context, g, k string, v bool, _ string, _ uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bools[g+":"+k] = v
	return nil
}

func buildMultipartUpload(t *testing.T, fileFirst bool, slot, filename string, fileContent []byte, expectedSHA string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	writeFile := func() {
		fw, err := w.CreateFormFile("file", filename)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := io.Copy(fw, bytes.NewReader(fileContent)); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}
	writeFields := func() {
		if slot != "" {
			_ = w.WriteField("slot", slot)
		}
		if expectedSHA != "" {
			_ = w.WriteField("expected_sha256", expectedSHA)
		}
	}
	if fileFirst {
		writeFile()
		writeFields()
	} else {
		writeFields()
		writeFile()
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	return &body, w.FormDataContentType()
}

func TestManageHandlerRBACAndLifecycle(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	tick := time.Date(2026, 11, 28, 15, 0, 0, 0, time.UTC)
	mgr.now = func() time.Time {
		tick = tick.Add(2 * time.Second)
		return tick
	}
	store := newMemManageStore()
	settings := &fakeManageSettings{
		strs: map[string]string{
			"geoip:schedule_cron":                 "0 3 2 * *",
			"geoip:maxmind_account_id":            "123456",
			"geoip:maxmind_license_key_encrypted": "enc:super-secret-do-not-leak",
		},
		bools: map[string]bool{
			"geoip:auto_update_enabled": false,
			"geoip:ha_sync_enabled":     true,
		},
	}
	h := NewManageHandler(mgr, store, settings, nil)

	// 1. 权限矩阵：未登录 401、只读账号写操作 403
	muxNoAuth := http.NewServeMux()
	RegisterManageRoutes(muxNoAuth, noPrincipal, h)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/geoip/status", nil)
	rec := httptest.NewRecorder()
	muxNoAuth.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rec.Code)
	}

	muxReadOnly := http.NewServeMux()
	RegisterManageRoutes(muxReadOnly, injectPrincipal(PermGeoIPRead), h)
	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/geoip/rollback", `{"slot":"ip2region_v4","backup_id":"x"}`},
		{http.MethodPut, "/api/v1/geoip/settings", `{}`},
		{http.MethodPost, "/api/v1/geoip/sync", `{}`},
		{http.MethodPost, "/api/v1/geoip/ha-resync", `{}`},
	} {
		req = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rec = httptest.NewRecorder()
		muxReadOnly.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("read-only %s %s = %d, want 403", tc.method, tc.path, rec.Code)
		}
	}

	// 2. 完整读写权限装配（同时挂载 lookup 路由验证端到端零重启生效）
	mux := http.NewServeMux()
	authzAll := injectPrincipal(PermGeoIPRead, PermGeoIPManage)
	RegisterManageRoutes(mux, authzAll, h)
	RegisterLookupRoutes(mux, authzAll, NewLookupHandler(eng))

	// 2a. 初始状态：geo_enabled=false，敏感密钥绝不回显，presets 包含全部 7 个官方源
	req = httptest.NewRequest(http.MethodGet, "/api/v1/geoip/status", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "super-secret-do-not-leak") {
		t.Fatal("maxmind encrypted key must never appear in status response")
	}
	var statusResp struct {
		Data StatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if statusResp.Data.GeoEnabled || len(statusResp.Data.Slots) != 5 || !statusResp.Data.Schedule.HasMaxMindLicenseKey ||
		len(statusResp.Data.Presets) != 7 || statusResp.Data.HANodes == nil {
		t.Fatalf("unexpected initial status: %+v", statusResp.Data)
	}

	// 2b. 上传 v1（故意把 file 放在 slot 前，验证流式顺序无关解析）
	v1 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "澳大利亚|悉尼|悉尼|APNIC|AU"}})
	body1, ct1 := buildMultipartUpload(t, true, SlotIP2RegionV4, "ip2region_v4.xdb", v1, sha256Hex(v1))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/geoip/upload", body1)
	req.Header.Set("Content-Type", ct1)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload v1 = %d: %s", rec.Code, rec.Body.String())
	}

	// 2c. 立即查 /api/v1/geoip/lookup?ip=1.1.1.1 → 零重启实时命中 AU
	req = httptest.NewRequest(http.MethodGet, "/api/v1/geoip/lookup?ip=1.1.1.1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lookup after v1 = %d: %s", rec.Code, rec.Body.String())
	}
	var lookupResp struct {
		Data lookupOneResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lookupResp); err != nil {
		t.Fatalf("decode lookup: %v", err)
	}
	if !lookupResp.Data.GeoEnabled || lookupResp.Data.Geo.CountryCode != "AU" {
		t.Fatalf("lookup after v1 = %+v, want geo_enabled=true AU", lookupResp.Data)
	}

	// 2d. 上传损坏文件 → 400 且记入 FAILED 流水，同时不影响当前 AU 查询
	badBody, badCT := buildMultipartUpload(t, false, SlotIP2RegionV4, "corrupt.xdb", []byte("not-an-xdb"), "")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/geoip/upload", badBody)
	req.Header.Set("Content-Type", badCT)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("corrupt upload = %d, want 400", rec.Code)
	}

	// 2e. 上传 v2 → 切换为 US 并生成 v1 备份
	v2 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "美国|加州|洛杉矶|Cloudflare|US"}})
	body2, ct2 := buildMultipartUpload(t, false, SlotIP2RegionV4, "ip2region_v4.xdb", v2, "")
	req = httptest.NewRequest(http.MethodPost, "/api/v1/geoip/upload", body2)
	req.Header.Set("Content-Type", ct2)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload v2 = %d: %s", rec.Code, rec.Body.String())
	}

	// 2f. 查状态取备份 ID，再调用回滚接口切回 AU
	req = httptest.NewRequest(http.MethodGet, "/api/v1/geoip/status", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode status2: %v", err)
	}
	var backupID string
	for _, s := range statusResp.Data.Slots {
		if s.Slot == SlotIP2RegionV4 && len(s.Backups) > 0 {
			backupID = s.Backups[0].BackupID
		}
	}
	if backupID == "" {
		t.Fatalf("expected backup after v2 upload, slots=%+v", statusResp.Data.Slots)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/geoip/rollback",
		strings.NewReader(`{"slot":"ip2region_v4","backup_id":"`+backupID+`"}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback = %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/geoip/lookup?ip=1.1.1.1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &lookupResp); err != nil {
		t.Fatalf("decode lookup after rollback: %v", err)
	}
	if lookupResp.Data.Geo.CountryCode != "AU" {
		t.Fatalf("lookup after rollback = %q, want AU", lookupResp.Data.Geo.CountryCode)
	}

	// 2g. 查不存在备份 → 404
	req = httptest.NewRequest(http.MethodPost, "/api/v1/geoip/rollback",
		strings.NewReader(`{"slot":"ip2region_v4","backup_id":"1700000000-000000000000.xdb"}`))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing backup rollback = %d, want 404", rec.Code)
	}

	// 2h. 查流水历史（共 5 条：v1 成功 + corrupt 失败 + v2 成功 + rollback 成功 + 缺失备份回滚失败）
	req = httptest.NewRequest(http.MethodGet, "/api/v1/geoip/runs?slot=ip2region_v4&page=1&page_size=10", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET runs = %d: %s", rec.Code, rec.Body.String())
	}
	var runsResp struct {
		Data struct {
			Items []SyncRun `json:"items"`
			Total int64     `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &runsResp); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if runsResp.Data.Total != 5 || len(runsResp.Data.Items) != 5 {
		t.Fatalf("runs total=%d len=%d, want 5", runsResp.Data.Total, len(runsResp.Data.Items))
	}
	if runsResp.Data.Items[0].TriggerType != TriggerRollback || runsResp.Data.Items[0].Status != RunStatusFailed {
		t.Fatalf("latest run = (%s, %s), want (ROLLBACK, FAILED)", runsResp.Data.Items[0].TriggerType, runsResp.Data.Items[0].Status)
	}
}

func TestManageHandlerSettingsSyncAndHAResyncEndpoints(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	store := newMemManageStore()
	settings := newFakeManageSettings()
	cipher := mustGeoTestCipher(t)

	v1 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "德国|黑森州|法兰克福|ISP|DE"}})

	dl := &fakeSlotDownloader{
		fetchFn: func(_ context.Context, _ iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
			return &iplibhttp.FetchResult{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(v1)),
				ETag:       `"de-v1"`,
				Filename:   "ip2region_v4.xdb",
			}, nil
		},
		valFn: func(_ context.Context, _, rawURL string) error {
			if strings.Contains(rawURL, "169.254.169.254") || strings.HasPrefix(rawURL, "http://") {
				return outboundhttp.ErrDenied
			}
			return nil
		},
	}

	peerSHA := ""
	ha := &fakeHAPusher{
		pushFn: func(_ context.Context, _, _, sha, _ string) ([]HANodeSyncResult, error) {
			peerSHA = sha
			return []HANodeSyncResult{{NodeID: "peer-1", NodeName: "standby-1", Status: "SUCCESS", SHA256: sha}}, nil
		},
		statusFn: func(_ context.Context) ([]HANodeGeoStatus, error) {
			slots := map[string]HANodeSlotDigest{}
			if peerSHA != "" {
				slots[SlotIP2RegionV4] = HANodeSlotDigest{Filename: "ip2region_v4.xdb", SHA256: peerSHA, SizeBytes: int64(len(v1))}
			}
			return []HANodeGeoStatus{{
				NodeID:     "peer-1",
				NodeName:   "standby-1",
				Reachable:  true,
				GeoIPReady: true,
				Revision:   "rev-1",
				Slots:      slots,
			}}, nil
		},
	}

	syncer := NewGeoSyncer(mgr, store, settings, dl, cipher).SetHAPusher(ha)
	h := NewManageHandler(mgr, store, settings, nil).SetSyncer(syncer).SetCipher(cipher)

	mux := http.NewServeMux()
	RegisterManageRoutes(mux, injectPrincipal(PermGeoIPRead, PermGeoIPManage), h)

	// 1. PUT /api/v1/geoip/settings 校验非法参数：坏 Cron、错误预置、缺少 MaxMind 凭据、SSRF URL
	for _, tc := range []struct {
		name string
		body string
	}{
		{"invalid cron", `{"schedule_cron":"not a cron"}`},
		{"mismatched preset", `{"slots":[{"slot":"ip2region_v4","enabled":true,"source_mode":"OFFICIAL","official_preset":"dbip_city_lite"}]}`},
		{"maxmind without creds", `{"slots":[{"slot":"dbip_city","enabled":true,"source_mode":"OFFICIAL","official_preset":"maxmind_geolite2_city"}]}`},
		{"custom url ssrf", `{"slots":[{"slot":"ip2region_v4","enabled":true,"source_mode":"CUSTOM_URL","custom_url":"https://169.254.169.254/a.xdb"}]}`},
		{"custom url http rejected", `{"slots":[{"slot":"ip2region_v4","enabled":true,"source_mode":"CUSTOM_URL","custom_url":"http://evil.com/a.xdb"}]}`},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/geoip/settings", strings.NewReader(tc.body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400 (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// 2. PUT /api/v1/geoip/settings 合法更新：开启定时 + 加密保存 MaxMind Key + 启用 ip2region_v4 官方源与 dbip_city MaxMind 源
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/geoip/settings", strings.NewReader(`{
		"auto_update_enabled": true,
		"schedule_cron": "30 4 1 * *",
		"ha_sync_enabled": true,
		"maxmind_account_id": "555666",
		"maxmind_license_key": "mm-top-secret-key",
		"slots": [
			{"slot": "ip2region_v4", "enabled": true, "source_mode": "OFFICIAL", "official_preset": "ip2region_v4"},
			{"slot": "dbip_city", "enabled": false, "source_mode": "OFFICIAL", "official_preset": "maxmind_geolite2_city"}
		]
	}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT settings valid = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "mm-top-secret-key") {
		t.Fatal("maxmind_license_key plaintext leaked in PUT settings response")
	}
	encMM := settings.strs[GeoIPSettingsGroup+":"+KeyMaxMindLicenseKeyEnc]
	if encMM == "" || strings.Contains(encMM, "mm-top-secret-key") {
		t.Fatalf("maxmind_license_key was not encrypted: %q", encMM)
	}
	if strings.Contains(rec.Body.String(), encMM) {
		t.Fatal("maxmind_license_key ciphertext leaked in PUT settings response")
	}

	// 3. POST /api/v1/geoip/sync 触发纯离线槽位返回 400
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/geoip/sync", strings.NewReader(`{"slot":"city_ipv6"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sync offline slot = %d, want 400", rec.Code)
	}

	// 4. POST /api/v1/geoip/sync 触发全部已启用槽位 -> 成功安装 DE 并自动推送备节点
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/geoip/sync", strings.NewReader(`{"slot":""}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST sync all = %d: %s", rec.Code, rec.Body.String())
	}
	var syncResp struct {
		Data SyncActionResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &syncResp); err != nil {
		t.Fatalf("decode sync resp: %v", err)
	}
	if syncResp.Data.Succeeded != 1 || len(syncResp.Data.Runs) != 1 {
		t.Fatalf("unexpected sync resp: %+v", syncResp.Data)
	}

	// 5. GET /api/v1/geoip/status 检查 ha_nodes 一致性为 true；模拟漂移后变为 false
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/geoip/status", nil))
	var stResp struct {
		Data StatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &stResp); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if len(stResp.Data.HANodes) != 1 || !stResp.Data.HANodes[0].Consistent {
		t.Fatalf("expected consistent HA node, got %+v", stResp.Data.HANodes)
	}

	peerSHA = "0000000000000000000000000000000000000000000000000000000000000000"
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/geoip/status", nil))
	_ = json.Unmarshal(rec.Body.Bytes(), &stResp)
	if len(stResp.Data.HANodes) != 1 || stResp.Data.HANodes[0].Consistent {
		t.Fatalf("expected drift (Consistent=false), got %+v", stResp.Data.HANodes)
	}

	// 6. POST /api/v1/geoip/ha-resync 恢复一致
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/geoip/ha-resync", strings.NewReader(`{}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST ha-resync = %d: %s", rec.Code, rec.Body.String())
	}
	if peerSHA != sha256Hex(v1) {
		t.Fatalf("peerSHA after ha-resync = %q, want %q", peerSHA, sha256Hex(v1))
	}

	// 7. clear_maxmind_license_key=true 清空密钥
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/geoip/settings", strings.NewReader(`{"clear_maxmind_license_key":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear maxmind key = %d: %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &stResp)
	if stResp.Data.Schedule.HasMaxMindLicenseKey {
		t.Fatal("expected HasMaxMindLicenseKey=false after clear")
	}

	// 8. 无 HA pusher 时 ha-resync 返回 503
	syncerNoHA := NewGeoSyncer(mgr, store, settings, dl, cipher)
	hNoHA := NewManageHandler(mgr, store, settings, nil).SetSyncer(syncerNoHA)
	muxNoHA := http.NewServeMux()
	RegisterManageRoutes(muxNoHA, injectPrincipal(PermGeoIPManage), hNoHA)
	rec = httptest.NewRecorder()
	muxNoHA.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/geoip/ha-resync", strings.NewReader(`{}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ha-resync without pusher = %d, want 503", rec.Code)
	}
}
