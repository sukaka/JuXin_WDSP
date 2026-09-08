// risk_test.go 同身份批量下载判定（§107 子集）单测：
// 触发与未触发 / 阈值来源与非法回退 / 匿名豁免 / 窗口外豁免 / 物化字段形状。
package apifiles

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// fakeSettings 假设置（map 驱动，实现 SettingsReader）。
type fakeSettings map[string]int

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := f[group+":"+key]; ok {
		return v
	}
	return def
}

// fakeFindingSaver 捕获物化输入。
type fakeFindingSaver struct {
	batches [][]apiruntime.FindingInput
}

func (f *fakeFindingSaver) SaveFindings(_ context.Context, in []apiruntime.FindingInput) error {
	f.batches = append(f.batches, in)
	return nil
}

// addDownloads 为某身份造 n 个不同文件的下载资产行（近窗口）。
func addDownloads(store *MemStore, identity string, n int, age time.Duration) {
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		name := strings.Repeat("f", i+1) + ".csv"
		store.addAsset(FileAsset{
			ID: uuid.New(), EndpointKey: "GET /api/v1/files/{name}", Direction: DirectionDownload,
			FileName: name, Extension: "csv", MIME: "text/csv", SizeBytes: 10,
			IdentityFingerprint: identity, ClientIPMasked: "203.0.113.0",
			SensitiveTypes: []string{}, FirstSeen: now.Add(-age), LastSeen: now.Add(-age), TransferCount: 1,
		})
	}
}

// 触发：近 1h 同身份下载不同文件数 > 阈值 → FILE_BULK_DOWNLOAD finding 物化。
func TestBulkDownloadTriggered(t *testing.T) {
	store := NewMemStore()
	addDownloads(store, "auth:greedy", 4, 10*time.Minute)
	// 同名文件重复下载只计 1（DISTINCT filename 口径）
	addDownloads(store, "auth:greedy", 1, 5*time.Minute)
	saver := &fakeFindingSaver{}
	sweep := NewRiskSweeper(store, saver, fakeSettings{SettingsGroup + ":" + SettingsKeyBulkDownloadThreshold: 3})

	res, err := sweep.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Threshold != 3 || res.Candidates != 1 || res.Findings != 1 {
		t.Fatalf("result = %+v", res)
	}
	if len(saver.batches) != 1 || len(saver.batches[0]) != 1 {
		t.Fatalf("batches = %+v", saver.batches)
	}
	f := saver.batches[0][0]
	if f.FindingType != "FILE_BULK_DOWNLOAD" || f.Severity != "HIGH" || f.RiskLevel != "HIGH" {
		t.Fatalf("finding head = %+v", f)
	}
	if f.SubjectType != "IDENTITY" || f.SubjectID != "auth:greedy" {
		t.Fatalf("subject = %s/%s", f.SubjectType, f.SubjectID)
	}
	if f.EndpointKey != "" {
		t.Fatalf("identity-wide rule must not anchor endpoint, got %q", f.EndpointKey)
	}
	if f.Detail["distinct_files"] != int64(4) || f.Detail["threshold"] != 3 || f.Detail["rule_id"] != "file.bulk_download" {
		t.Fatalf("detail = %+v", f.Detail)
	}
	if f.Evidence["transfers"] != int64(5) {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
}

// 未触发：等于阈值（严格大于才触发）/ 匿名身份豁免 / 窗口外不计。
func TestBulkDownloadNotTriggered(t *testing.T) {
	store := NewMemStore()
	addDownloads(store, "auth:edge", 3, 10*time.Minute) // 等于阈值 3：不触发
	addDownloads(store, "", 10, 10*time.Minute)         // 匿名：不参与
	addDownloads(store, "auth:old", 9, 2*time.Hour)     // 窗口外：不计
	saver := &fakeFindingSaver{}
	sweep := NewRiskSweeper(store, saver, fakeSettings{SettingsGroup + ":" + SettingsKeyBulkDownloadThreshold: 3})

	res, err := sweep.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Candidates != 0 || res.Findings != 0 || len(saver.batches) != 0 {
		t.Fatalf("must not trigger: res=%+v batches=%+v", res, saver.batches)
	}
}

// 阈值：设置缺失回退默认；非法取值（≤0）回退默认。
func TestBulkDownloadThresholdFallback(t *testing.T) {
	store := NewMemStore()
	addDownloads(store, "auth:a", 2, time.Minute)

	// 无设置（nil reader）：默认 50 → 不触发
	res, err := NewRiskSweeper(store, &fakeFindingSaver{}, nil).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Threshold != DefaultBulkDownloadThreshold || res.Candidates != 0 {
		t.Fatalf("nil settings res = %+v", res)
	}
	// 非法取值 0 → 回退默认
	res, err = NewRiskSweeper(store, &fakeFindingSaver{},
		fakeSettings{SettingsGroup + ":" + SettingsKeyBulkDownloadThreshold: 0}).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Threshold != DefaultBulkDownloadThreshold {
		t.Fatalf("invalid threshold res = %+v", res)
	}
	// 显式阈值 1 → 触发
	res, err = NewRiskSweeper(store, &fakeFindingSaver{},
		fakeSettings{SettingsGroup + ":" + SettingsKeyBulkDownloadThreshold: 1}).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Threshold != 1 || res.Candidates != 1 {
		t.Fatalf("explicit threshold res = %+v", res)
	}
}

// findings saver 未注入：候选照常统计，物化跳过（装配降级形态）。
func TestBulkDownloadNilSaver(t *testing.T) {
	store := NewMemStore()
	addDownloads(store, "auth:a", 3, time.Minute)
	res, err := NewRiskSweeper(store, nil, fakeSettings{
		SettingsGroup + ":" + SettingsKeyBulkDownloadThreshold: 1,
	}).SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Candidates != 1 || res.Findings != 0 {
		t.Fatalf("nil saver res = %+v", res)
	}
}
