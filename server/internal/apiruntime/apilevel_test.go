// apilevel_test.go §8.2 四级识别标签（迁移 000149）采集与落库边界测试。
package apiruntime

import (
	"context"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 词表之外的 api_level 必须在入库前被拒绝（不落部分事件，CHECK 约束兜底）。
func TestSavePrimaryRejectsInvalidAPILevel(t *testing.T) {
	for _, bad := range []string{"SOME_API", "confirmed_api", "API", " CONFIRMED_API"} {
		db := &fakeBatchTx{}
		store := &Store{db: db}
		ev := ctxFieldEvent("req-lv-bad")
		ev.APILevel = bad
		err := store.SavePrimary(context.Background(), ev)
		if err == nil || !strings.Contains(err.Error(), "api_level") {
			t.Fatalf("api_level %q: SavePrimary error = %v, want vocabulary rejection", bad, err)
		}
		if len(db.ops) != 0 {
			t.Fatalf("api_level %q: database must not be called, ops = %v", bad, db.ops)
		}
	}
}

// 合法四级词表与空值（未上报）正常落库。
func TestSavePrimaryAcceptsAPILevelVocabulary(t *testing.T) {
	for _, lv := range []string{"", "CONFIRMED_API", "PROBABLE_API", "POSSIBLE_API", "NON_API"} {
		db := &fakeBatchTx{}
		store := &Store{db: db}
		ev := ctxFieldEvent("req-lv-ok")
		ev.APILevel = lv
		if err := store.SavePrimary(context.Background(), ev); err != nil {
			t.Fatalf("api_level %q: SavePrimary: %v", lv, err)
		}
		if got := db.countOp("exec:INSERT"); got != 1 {
			t.Fatalf("api_level %q: want primary INSERT, got %d (%v)", lv, got, db.ops)
		}
	}
}

// 采集解析：api_level 键按 JSON 名解析；旧版记录缺键为零值不报错。
func TestParseRecordLine_APILevel(t *testing.T) {
	rec, err := parseRecordLine([]byte(`{
		"request_id":"r-lv-1","endpoint_key":"GET /v1/users/{id}","api_level":"PROBABLE_API"
	}`))
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if rec.APILevel != "PROBABLE_API" {
		t.Fatalf("api_level = %q, want PROBABLE_API", rec.APILevel)
	}
	old, err := parseRecordLine([]byte(`{"request_id":"r-lv-2","endpoint_key":"GET /a"}`))
	if err != nil {
		t.Fatalf("legacy record rejected: %v", err)
	}
	if old.APILevel != "" {
		t.Fatalf("legacy record must keep zero api_level: %+v", old)
	}
}

// findings 冗余列：从主事件记录原样拷贝进 FindingInput（不重新计算）。
func TestRecordFindingsCopiesContextSnapshot(t *testing.T) {
	saver := &fakeFindingSaver{}
	c := NewCollector(nil, "test", "", "", "")
	c.SetFindingSaver(saver)
	devFP := strings.Repeat("b", 32)
	objHash := strings.Repeat("a", 32)
	c.recordFindings(context.Background(), &Record{
		RequestID:         "r-lv-f1",
		EndpointKey:       "GET /v1/orders/{id}",
		FinalAction:       "BLOCK",
		DeviceFingerprint: devFP,
		ObjectIdentifiers: []dsctx.ObjectIdentifier{
			{Source: "path", Param: "id", ValueHash: objHash},
		},
		Details: []dsctx.DetectorMatch{
			{Detector: "waf", RuleID: "942100", Severity: "HIGH", Message: "sqli"},
		},
	})
	if len(saver.batches) != 1 || len(saver.batches[0]) != 1 {
		t.Fatalf("want 1 finding batch of 1, got %+v", saver.batches)
	}
	f := saver.batches[0][0]
	if f.DeviceFingerprint != devFP {
		t.Fatalf("finding device_fingerprint = %q, want %q", f.DeviceFingerprint, devFP)
	}
	if len(f.ObjectIdentifiers) != 1 || f.ObjectIdentifiers[0].ValueHash != objHash {
		t.Fatalf("finding object_identifiers = %+v", f.ObjectIdentifiers)
	}
}

// findings 写入边界：明文/畸形指纹形态显式报错（与主事件同一纪律，不落库）。
func TestSaveFindingsRejectsInvalidContextSnapshot(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	base := FindingInput{
		EndpointKey: "GET /v1/orders/{id}", FindingType: "WAF_942100",
		Severity: "HIGH", Title: "sqli",
	}
	bad := base
	bad.DeviceFingerprint = "MacBook-Pro-张三"
	if err := store.SaveFindings(context.Background(), []FindingInput{bad}); err == nil {
		t.Fatal("non-hex finding device_fingerprint accepted")
	}
	bad = base
	bad.ObjectIdentifiers = []dsctx.ObjectIdentifier{
		{Source: "path", Param: "id", ValueHash: "order-123"},
	}
	if err := store.SaveFindings(context.Background(), []FindingInput{bad}); err == nil {
		t.Fatal("plaintext finding object identifier accepted")
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called, ops = %v", db.ops)
	}
}
