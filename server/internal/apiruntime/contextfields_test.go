// contextfields_test.go 统一上下文 §7 字段（迁移 000150）采集与落库边界测试。
package apiruntime

import (
	"context"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

func ctxFieldEvent(reqID string) *PrimaryEvent {
	return &PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:  reqID,
			OccurredAt: time.Now().UTC(),
		},
	}
}

// 明文/畸形 value_hash 必须在入库前被拒绝（不落部分事件）。
func TestSavePrimaryRejectsPlaintextObjectIdentifier(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := ctxFieldEvent("req-obj-raw")
	ev.ObjectIdentifiers = []dsctx.ObjectIdentifier{
		{Source: "path", Param: "id", ValueHash: "order-123"}, // 明文形态
	}
	err := store.SavePrimary(context.Background(), ev)
	if err == nil || !strings.Contains(err.Error(), "redacted") {
		t.Fatalf("SavePrimary error = %v, want redacted hash rejection", err)
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called for a plaintext object identifier, ops = %v", db.ops)
	}
}

func TestSavePrimaryRejectsInvalidObjectIdentifierShape(t *testing.T) {
	cases := []dsctx.ObjectIdentifier{
		{Source: "query", Param: "id", ValueHash: strings.Repeat("a", 32)}, // 非法 source
		{Source: "path", Param: "", ValueHash: strings.Repeat("a", 32)},    // 空 param
		{Source: "path", Param: "id", ValueHash: strings.Repeat("A", 32)},  // 大写 hex
		{Source: "path", Param: "id", ValueHash: strings.Repeat("a", 31)},  // 长度不符
	}
	for i, bad := range cases {
		db := &fakeBatchTx{}
		store := &Store{db: db}
		ev := ctxFieldEvent("req-obj-bad")
		ev.ObjectIdentifiers = []dsctx.ObjectIdentifier{bad}
		if err := store.SavePrimary(context.Background(), ev); err == nil {
			t.Fatalf("case %d: invalid identifier accepted: %+v", i, bad)
		}
		if len(db.ops) != 0 {
			t.Fatalf("case %d: database called despite invalid identifier", i)
		}
	}
	// 条数超上限
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := ctxFieldEvent("req-obj-many")
	for i := 0; i < dsctx.MaxObjectIdentifiers+1; i++ {
		ev.ObjectIdentifiers = append(ev.ObjectIdentifiers, dsctx.ObjectIdentifier{
			Source: "path", Param: "id", ValueHash: strings.Repeat("a", 32)})
	}
	if err := store.SavePrimary(context.Background(), ev); err == nil {
		t.Fatal("over-limit object identifiers accepted")
	}
}

func TestSavePrimaryRejectsInvalidDeviceFingerprint(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := ctxFieldEvent("req-devfp-bad")
	ev.DeviceFingerprint = "MacBook-Pro-张三" // 非哈希形态
	if err := store.SavePrimary(context.Background(), ev); err == nil {
		t.Fatal("non-hex device fingerprint accepted")
	}
	if len(db.ops) != 0 {
		t.Fatalf("database must not be called, ops = %v", db.ops)
	}
}

// 合法 §7 字段正常落库（INSERT 执行）。
func TestSavePrimaryAcceptsContextIdentifierFields(t *testing.T) {
	db := &fakeBatchTx{}
	store := &Store{db: db}
	ev := ctxFieldEvent("req-ctx-ok")
	ev.DeviceFingerprint = strings.Repeat("b", 32)
	ev.ObjectIdentifiers = []dsctx.ObjectIdentifier{
		{Source: "path", Param: "id", ValueHash: strings.Repeat("a", 32)},
		{Source: "body_json", Param: "meta.user_id", ValueHash: strings.Repeat("c", 32)},
	}
	if err := store.SavePrimary(context.Background(), ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	if got := db.countOp("exec:INSERT"); got != 1 {
		t.Fatalf("want primary INSERT, got %d (%v)", got, db.ops)
	}
}

// 采集解析：新键按 JSON 名解析；旧版记录缺键为零值不报错。
func TestParseRecordLine_ContextIdentifierFields(t *testing.T) {
	rec, err := parseRecordLine([]byte(`{
		"request_id":"r-cf-1","endpoint_key":"GET /v1/users/{id}",
		"device_fingerprint":"` + strings.Repeat("b", 32) + `",
		"object_identifiers":[{"source":"path","param":"id","value_hash":"` + strings.Repeat("a", 32) + `"}]
	}`))
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if len(rec.DeviceFingerprint) != 32 || len(rec.ObjectIdentifiers) != 1 ||
		rec.ObjectIdentifiers[0].Source != "path" || len(rec.ObjectIdentifiers[0].ValueHash) != 32 {
		t.Fatalf("§7 fields not parsed: %+v", rec)
	}
	old, err := parseRecordLine([]byte(`{"request_id":"r-cf-2","endpoint_key":"GET /a"}`))
	if err != nil {
		t.Fatalf("legacy record rejected: %v", err)
	}
	if old.DeviceFingerprint != "" || old.ObjectIdentifiers != nil {
		t.Fatalf("legacy record must keep zero values: %+v", old)
	}
}
