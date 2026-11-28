package apigeo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/iplibhttp"
)

type fakeSlotDownloader struct {
	mu       sync.Mutex
	requests []iplibhttp.FetchRequest
	fetchFn  func(ctx context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error)
	valFn    func(ctx context.Context, sourceMode, rawURL string) error
}

func (f *fakeSlotDownloader) Fetch(ctx context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	fn := f.fetchFn
	f.mu.Unlock()
	if fn == nil {
		return nil, errors.New("unexpected fetch")
	}
	return fn(ctx, req)
}

func (f *fakeSlotDownloader) ValidateTargetURL(ctx context.Context, sourceMode, rawURL string) error {
	if f.valFn != nil {
		return f.valFn(ctx, sourceMode, rawURL)
	}
	return nil
}

type fakeHAPusher struct {
	mu        sync.Mutex
	pushCalls []string
	pushFn    func(ctx context.Context, slot, filePath, sha256Hex, revision string) ([]HANodeSyncResult, error)
	statusFn  func(ctx context.Context) ([]HANodeGeoStatus, error)
}

func (f *fakeHAPusher) PushGeoIPSlot(ctx context.Context, slot, filePath, sha256Hex, revision string) ([]HANodeSyncResult, error) {
	f.mu.Lock()
	f.pushCalls = append(f.pushCalls, slot+":"+sha256Hex)
	fn := f.pushFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, slot, filePath, sha256Hex, revision)
	}
	return []HANodeSyncResult{{NodeName: "standby-1", Status: "SUCCESS", SHA256: sha256Hex}}, nil
}

func (f *fakeHAPusher) ListPeerGeoIPStatus(ctx context.Context) ([]HANodeGeoStatus, error) {
	if f.statusFn != nil {
		return f.statusFn(ctx)
	}
	return nil, nil
}

type capturedAlert struct {
	alertType string
	component string
	title     string
	message   string
}

func mustGeoTestCipher(t *testing.T) *encryption.Service {
	t.Helper()
	svc, err := encryption.NewWithKey(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	return svc
}

func TestCronParseMatchAndNextAfter(t *testing.T) {
	spec, err := ParseCron("0 3 2 * *")
	if err != nil {
		t.Fatalf("ParseCron default: %v", err)
	}
	if !spec.Match(time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC)) {
		t.Fatal("expected 2026-11-02 03:00 UTC to match 0 3 2 * *")
	}
	if spec.Match(time.Date(2026, 11, 2, 3, 1, 0, 0, time.UTC)) {
		t.Fatal("03:01 should not match")
	}

	// 宏与步进与周日 7 归一
	sunSpec, err := ParseCron("*/15 0-6/2 * * 7")
	if err != nil {
		t.Fatalf("ParseCron sunday: %v", err)
	}
	// 2026-11-29 is Sunday
	if !sunSpec.Match(time.Date(2026, 11, 29, 4, 30, 0, 0, time.UTC)) {
		t.Fatal("expected Sunday 04:30 to match */15 0-6/2 * * 7")
	}

	macroSpec, err := ParseCron("@daily")
	if err != nil {
		t.Fatalf("ParseCron @daily: %v", err)
	}
	next, err := macroSpec.NextAfter(time.Date(2026, 11, 28, 23, 59, 0, 0, time.UTC))
	if err != nil || !next.Equal(time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("NextAfter @daily = (%v, %v)", next, err)
	}

	// 非法与永不命中表达式
	for _, expr := range []string{"", "0 3 *", "60 3 * * *", "0 24 * * *", "0 0 32 * *", "0 0 1 13 *", "0 0 * * 8", "0 0 */0 * *"} {
		if _, err := ParseCron(expr); !errors.Is(err, ErrInvalidCron) {
			t.Errorf("ParseCron(%q) = %v, want ErrInvalidCron", expr, err)
		}
	}
	feb30, err := ParseCron("0 0 30 2 *")
	if err != nil {
		t.Fatalf("ParseCron feb30: %v", err)
	}
	if _, err := feb30.NextAfter(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalidCron) {
		t.Fatalf("Feb 30 NextAfter = %v, want ErrInvalidCron", err)
	}
}

func TestOfficialPresetsRegistry(t *testing.T) {
	presets := OfficialPresets()
	if len(presets) != 7 {
		t.Fatalf("presets count = %d, want 7", len(presets))
	}
	for _, id := range []string{
		PresetIP2RegionV4,
		PresetIP2RegionV6,
		PresetDBIPCityLite,
		PresetDBIPCountryLite,
		PresetGeoCountryMMDB,
		PresetMaxMindGeoLite2City,
		PresetMaxMindGeoLite2Country,
	} {
		if _, ok := LookupPreset(id); !ok {
			t.Errorf("missing official preset %q", id)
		}
	}
}

func TestGeoSyncerSyncSlotETagHAAndAlerts(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	store := newMemManageStore()
	settings := newFakeManageSettings()
	settings.bools[GeoIPSettingsGroup+":"+KeyGeoIPHASyncEnabled] = true

	v1 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "日本|东京都|东京|ISP|JP"}})

	if err := store.UpdateSlotConfig(context.Background(), SlotConfigUpdate{
		Slot:           SlotIP2RegionV4,
		Enabled:        true,
		SourceMode:     SourceModeOfficial,
		OfficialPreset: PresetIP2RegionV4,
	}); err != nil {
		t.Fatalf("UpdateSlotConfig: %v", err)
	}

	dl := &fakeSlotDownloader{
		fetchFn: func(_ context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
			if req.ETag == `"v1-etag"` {
				return &iplibhttp.FetchResult{StatusCode: http.StatusNotModified, NotModified: true, ETag: `"v1-etag"`}, nil
			}
			return &iplibhttp.FetchResult{
				StatusCode:   http.StatusOK,
				Body:         io.NopCloser(bytes.NewReader(v1)),
				ETag:         `"v1-etag"`,
				LastModified: "Sat, 28 Nov 2026 03:00:00 GMT",
				Filename:     "ip2region_v4.xdb",
			}, nil
		},
	}

	ha := &fakeHAPusher{}
	var alerts []capturedAlert
	syncer := NewGeoSyncer(mgr, store, settings, dl, nil).
		SetHAPusher(ha).
		SetAlertFunc(func(_ context.Context, alertType, component, title, message string) {
			alerts = append(alerts, capturedAlert{alertType, component, title, message})
		})

	// 1. 首次拉取成功：热加载 JP + 推送 HA + 记录 ETag
	opID := uuid.New()
	run1, err := syncer.SyncSlot(context.Background(), SlotIP2RegionV4, TriggerManual, &opID)
	if err != nil {
		t.Fatalf("SyncSlot v1: %v", err)
	}
	if run1.Status != RunStatusSuccess || run1.NewSHA256 != sha256Hex(v1) || len(run1.HAResults) != 1 {
		t.Fatalf("unexpected run1: %+v", run1)
	}
	if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "JP" {
		t.Fatalf("live lookup = (%q, %v), want JP", code, err)
	}
	cfg, _ := store.GetSlotConfig(context.Background(), SlotIP2RegionV4)
	if cfg.ETag != `"v1-etag"` || cfg.ActiveSHA256 != sha256Hex(v1) {
		t.Fatalf("slot config not updated: %+v", cfg)
	}

	// 2. 再次拉取携带 ETag 命中 304 -> SKIPPED_UNCHANGED
	run2, err := syncer.SyncSlot(context.Background(), SlotIP2RegionV4, TriggerManual, &opID)
	if err != nil {
		t.Fatalf("SyncSlot 304: %v", err)
	}
	if run2.Status != RunStatusSkippedUnchange {
		t.Fatalf("expected SKIPPED_UNCHANGED, got %+v", run2)
	}

	// 3. 新版本上传但 HA 备节点推送失败 -> 本地生效（SG），状态 PARTIAL_HA_FAILED，触发 GEOIP_NODE_DRIFT 告警
	v2 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "新加坡|新加坡|新加坡|ISP|SG"}})
	dl.fetchFn = func(_ context.Context, _ iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
		return &iplibhttp.FetchResult{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(v2)),
			ETag:       `"v2-etag"`,
			Filename:   "ip2region_v4.xdb",
		}, nil
	}
	ha.pushFn = func(_ context.Context, _, _, _, _ string) ([]HANodeSyncResult, error) {
		return []HANodeSyncResult{{NodeName: "standby-1", Status: "FAILED", Error: "connection refused"}}, nil
	}
	run3, err := syncer.SyncSlot(context.Background(), SlotIP2RegionV4, TriggerManual, &opID)
	if err != nil {
		t.Fatalf("SyncSlot HA partial failure should not error local install: %v", err)
	}
	if run3.Status != RunStatusPartialHAFailed {
		t.Fatalf("run3 status = %s, want PARTIAL_HA_FAILED", run3.Status)
	}
	if code, err := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); err != nil || code != "SG" {
		t.Fatalf("local engine should still activate SG despite HA drift: (%q, %v)", code, err)
	}
	if len(alerts) != 1 || alerts[0].alertType != AlertTypeGeoIPNodeDrift {
		t.Fatalf("expected GEOIP_NODE_DRIFT alert, got %+v", alerts)
	}

	// 4. 上游故障 -> 记录 FAILED 并触发 GEOIP_SYNC_FAILED 告警，不破坏当前 SG
	dl.fetchFn = func(_ context.Context, _ iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
		return nil, &iplibhttp.HTTPStatusError{StatusCode: http.StatusBadGateway, URL: "https://raw.githubusercontent.com/..."}
	}
	run4, err := syncer.SyncSlot(context.Background(), SlotIP2RegionV4, TriggerScheduled, nil)
	if err == nil || run4 == nil || run4.Status != RunStatusFailed {
		t.Fatalf("expected FAILED run on upstream 502, run=%+v err=%v", run4, err)
	}
	if len(alerts) != 2 || alerts[1].alertType != AlertTypeGeoIPSyncFailed {
		t.Fatalf("expected GEOIP_SYNC_FAILED alert, got %+v", alerts)
	}
	if code, _ := eng.LookupCountry(netip.MustParseAddr("1.1.1.1")); code != "SG" {
		t.Fatalf("existing SG DB should stay intact after failed pull, got %q", code)
	}

	// 5. HAResync 恢复备节点
	ha.pushFn = func(_ context.Context, _, _, sha, _ string) ([]HANodeSyncResult, error) {
		return []HANodeSyncResult{{NodeName: "standby-1", Status: "SUCCESS", SHA256: sha}}, nil
	}
	resyncRuns, err := syncer.HAResync(context.Background(), "", &opID)
	if err != nil || len(resyncRuns) != 1 || resyncRuns[0].Status != RunStatusSuccess || resyncRuns[0].TriggerType != TriggerHAResync {
		t.Fatalf("HAResync unexpected: runs=%+v err=%v", resyncRuns, err)
	}
}

func TestGeoSyncerDBIPMonthly404FallbackAndMaxMindBasicAuth(t *testing.T) {
	rawMMDB, err := os.ReadFile(realMMDBPath)
	if err != nil {
		t.Skipf("real mmdb fixture unavailable: %v", err)
	}
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	store := newMemManageStore()
	settings := newFakeManageSettings()
	cipher := mustGeoTestCipher(t)

	// 1. DB-IP Lite 月初 1 月 1 日 404 自动回退到去年 12 月
	_ = store.UpdateSlotConfig(context.Background(), SlotConfigUpdate{
		Slot:           SlotDBIPCity,
		Enabled:        true,
		SourceMode:     SourceModeOfficial,
		OfficialPreset: PresetDBIPCityLite,
	})
	var seenURLs []string
	dl := &fakeSlotDownloader{
		fetchFn: func(_ context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
			seenURLs = append(seenURLs, req.URL)
			if strings.Contains(req.URL, "2027-01") {
				return nil, &iplibhttp.HTTPStatusError{StatusCode: http.StatusNotFound, URL: req.URL}
			}
			return &iplibhttp.FetchResult{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(gzipBytes(t, rawMMDB))),
				Filename:   "dbip-city-lite-2026-12.mmdb.gz",
			}, nil
		},
	}
	syncer := NewGeoSyncer(mgr, store, settings, dl, cipher)
	syncer.now = func() time.Time { return time.Date(2027, 1, 1, 3, 0, 0, 0, time.UTC) }

	run, err := syncer.SyncSlot(context.Background(), SlotDBIPCity, TriggerManual, nil)
	if err != nil || run.Status != RunStatusSuccess {
		t.Fatalf("DB-IP fallback failed: run=%+v err=%v", run, err)
	}
	if len(seenURLs) != 2 ||
		!strings.Contains(seenURLs[0], "dbip-city-lite-2027-01.mmdb.gz") ||
		!strings.Contains(seenURLs[1], "dbip-city-lite-2026-12.mmdb.gz") {
		t.Fatalf("unexpected DB-IP fallback URLs: %v", seenURLs)
	}

	// 2. MaxMind GeoLite2 Country：使用解密后的 License Key 作为 Basic Auth 并流式解压 .tar.gz
	encKey, err := cipher.Encrypt("mm-license-secret-xyz")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	settings.strs[GeoIPSettingsGroup+":"+KeyMaxMindAccountID] = "987654"
	settings.strs[GeoIPSettingsGroup+":"+KeyMaxMindLicenseKeyEnc] = encKey
	_ = store.UpdateSlotConfig(context.Background(), SlotConfigUpdate{
		Slot:           SlotCountry,
		Enabled:        true,
		SourceMode:     SourceModeOfficial,
		OfficialPreset: PresetMaxMindGeoLite2Country,
	})

	tarPayload := tarGzBytes(t, []tarTestEntry{
		{name: "GeoLite2-Country_20261128/GeoLite2-Country.mmdb", body: rawMMDB},
	})
	var gotUser, gotPass, gotURL string
	dl.fetchFn = func(_ context.Context, req iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
		gotUser, gotPass, gotURL = req.BasicUser, req.BasicPass, req.URL
		return &iplibhttp.FetchResult{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(tarPayload)),
			Filename:   "GeoLite2-Country_20261128.tar.gz",
		}, nil
	}

	runMM, err := syncer.SyncSlot(context.Background(), SlotCountry, TriggerManual, nil)
	if err != nil || runMM.Status != RunStatusSuccess {
		t.Fatalf("MaxMind sync failed: run=%+v err=%v", runMM, err)
	}
	if gotUser != "987654" || gotPass != "mm-license-secret-xyz" ||
		gotURL != "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz" {
		t.Fatalf("unexpected MaxMind request: user=%q url=%q", gotUser, gotURL)
	}
}

func TestGeoSyncerSchedulerTickGateAndDedup(t *testing.T) {
	dir := t.TempDir()
	eng := NewReloadableEngine(dir)
	mgr := NewSlotManager(dir, eng, dir)
	store := newMemManageStore()
	settings := newFakeManageSettings()
	settings.strs[GeoIPSettingsGroup+":"+KeyGeoIPScheduleCron] = "0 3 2 * *"
	settings.bools[GeoIPSettingsGroup+":"+KeyGeoIPAutoUpdateEnabled] = false

	_ = store.UpdateSlotConfig(context.Background(), SlotConfigUpdate{
		Slot:           SlotIP2RegionV4,
		Enabled:        true,
		SourceMode:     SourceModeOfficial,
		OfficialPreset: PresetIP2RegionV4,
	})
	v1 := buildSyntheticXDBv4(3, []struct {
		start, end string
		region     string
	}{{"1.1.1.0", "1.1.1.255", "美国|加州|洛杉矶|ISP|US"}})

	dl := &fakeSlotDownloader{
		fetchFn: func(_ context.Context, _ iplibhttp.FetchRequest) (*iplibhttp.FetchResult, error) {
			return &iplibhttp.FetchResult{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(v1)),
				Filename:   "ip2region_v4.xdb",
			}, nil
		},
	}
	syncer := NewGeoSyncer(mgr, store, settings, dl, nil)
	dueTime := time.Date(2026, 12, 2, 3, 0, 10, 0, time.UTC)

	// 1. 开关关闭时即使到点也零外连
	_, fired, err := syncer.Tick(context.Background(), dueTime)
	if err != nil || fired || len(dl.requests) != 0 {
		t.Fatalf("auto_update_enabled=false should not fire: fired=%v reqs=%d err=%v", fired, len(dl.requests), err)
	}

	// 2. 开启开关后非匹配分钟不触发
	settings.bools[GeoIPSettingsGroup+":"+KeyGeoIPAutoUpdateEnabled] = true
	_, fired, err = syncer.Tick(context.Background(), dueTime.Add(time.Minute))
	if err != nil || fired {
		t.Fatalf("non-matching minute should not fire: fired=%v err=%v", fired, err)
	}

	// 3. 匹配分钟触发一次；同分钟重复 Tick 自动去重
	runs, fired, err := syncer.Tick(context.Background(), dueTime)
	if err != nil || !fired || len(runs) != 1 || runs[0].TriggerType != TriggerScheduled {
		t.Fatalf("expected scheduled run, fired=%v runs=%+v err=%v", fired, runs, err)
	}
	_, fired2, err := syncer.Tick(context.Background(), dueTime.Add(20*time.Second))
	if err != nil || fired2 {
		t.Fatalf("same-minute duplicate tick must be deduplicated: fired=%v err=%v", fired2, err)
	}
}
