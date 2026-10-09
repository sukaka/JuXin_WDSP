// service_unit_test.go 五步校验链逐步正反测试（NG-AZ-01 §2 冻结顺序；无 DB 部分）。
// 第 3 步重放/原子切换/缺口/冲突/水位在 service_integration_test.go（真实 PG）。
package apiauthzauthority

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var testSourceID = uuid.MustParse("11111111-1111-1111-1111-111111111111")

func activeSource() *AuthoritySource {
	return &AuthoritySource{
		ID:     testSourceID,
		Name:   "crm-prod",
		Status: SourceStatusActive,
		Scopes: SourceScopes{TenantDomains: []string{"waf-s5.local"}, ObjectTypes: []string{"document"}},
	}
}

func signedBatch(t *testing.T, k *testKey, mode string, events ...ChangeEvent) ImportBatchPayload {
	t.Helper()
	p := ImportBatchPayload{
		BatchID: "batch-1", SourceID: testSourceID.String(), Mode: mode, KeyID: k.keyID,
	}
	for _, e := range events {
		p.Items = append(p.Items, k.signEvent(t, e))
	}
	return k.signBatch(t, p)
}

func payloadBody(t *testing.T, p ImportBatchPayload) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func svcNoDB() *Service { return NewService(nil) }

// ---------- 第 1 步：来源身份验签 ----------

func TestStep1Identity(t *testing.T) {
	k := newTestKey(t, "k1")
	src := activeSource()
	keys := []SourceKey{{KeyID: "k1", PublicKeyHex: k.pubHex(), Status: KeyStatusActive}}

	// 正：合法批次通过
	p := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	if fail := svcNoDB().verifyStep1Identity(src, keys, &p); fail != nil {
		t.Fatalf("合法批次应过第 1 步: %v", fail)
	}
	// 反1：来源停用
	disabled := *src
	disabled.Status = SourceStatusDisabled
	if fail := svcNoDB().verifyStep1Identity(&disabled, keys, &p); fail == nil || fail.step != 1 {
		t.Fatal("停用来源应第 1 步拒收")
	}
	// 反2：事件签名篡改
	bad := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	bad.Items[0].PrincipalRef = "subj:evil"
	bad = k.signBatch(t, bad) // 批次签名合法、事件签名失效——两级签名各司其职
	fail := svcNoDB().verifyStep1Identity(src, keys, &bad)
	if fail == nil || fail.step != 1 {
		t.Fatal("事件签名篡效应第 1 步拒收")
	}
	// 反3：批次签名失效
	badEnv := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	e2 := k.signEvent(t, baseEvent(testSourceID.String(), 2))
	badEnv.Items = append(badEnv.Items, e2)
	if fail := svcNoDB().verifyStep1Identity(src, keys, &badEnv); fail == nil || fail.step != 1 {
		t.Fatal("批次签名失效应第 1 步拒收")
	}
	// 反4：未知 key_id
	p2 := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	p2.Items[0].KeyID = "ghost"
	p2.Items[0] = k.signEvent(t, p2.Items[0])
	p2 = k.signBatch(t, p2)
	if fail := svcNoDB().verifyStep1Identity(src, keys, &p2); fail == nil || fail.step != 1 {
		t.Fatal("未知 key_id 应第 1 步拒收")
	}
	// 正：RETIRED 键窗口内事件验过
	retiredAt := time.Now().UTC().Add(-time.Hour)
	kr := newTestKey(t, "kr")
	oldEvent := baseEvent(testSourceID.String(), 1)
	oldEvent.KeyID = "kr"
	oldEvent.IssuedAt = retiredAt.Add(-2 * time.Hour).Format(time.RFC3339)
	oldEvent = kr.signEvent(t, oldEvent)
	pOld := ImportBatchPayload{BatchID: "b", SourceID: testSourceID.String(), Mode: ModeDelta, KeyID: "k1", Items: []ChangeEvent{oldEvent}}
	pOld = k.signBatch(t, pOld)
	keysWithRetired := append([]SourceKey{}, keys...)
	keysWithRetired = append(keysWithRetired, SourceKey{KeyID: "kr", PublicKeyHex: kr.pubHex(), Status: KeyStatusRetired, RetiredAt: &retiredAt})
	if fail := svcNoDB().verifyStep1Identity(src, keysWithRetired, &pOld); fail != nil {
		t.Fatalf("退役键窗口内事件应过: %v", fail)
	}
	// 反5：RETIRED 键窗口外事件（退役已久，超默认 24h 窗口）
	longRetired := retiredAt.Add(-48 * time.Hour)
	freshEvent := baseEvent(testSourceID.String(), 2)
	freshEvent.KeyID = "kr"
	freshEvent.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	freshEvent = kr.signEvent(t, freshEvent)
	pFresh := ImportBatchPayload{BatchID: "b2", SourceID: testSourceID.String(), Mode: ModeDelta, KeyID: "k1", Items: []ChangeEvent{freshEvent}}
	pFresh = k.signBatch(t, pFresh)
	keysLongRetired := append([]SourceKey{}, keys...)
	keysLongRetired = append(keysLongRetired, SourceKey{KeyID: "kr", PublicKeyHex: kr.pubHex(), Status: KeyStatusRetired, RetiredAt: &longRetired})
	if fail := svcNoDB().verifyStep1Identity(src, keysLongRetired, &pFresh); fail == nil || fail.step != 1 {
		t.Fatal("退役键窗口外事件应第 1 步拒收")
	}
}

// ---------- 第 2 步：范围权限 ----------

func TestStep2Scope(t *testing.T) {
	k := newTestKey(t, "k1")
	src := activeSource()
	// 范围内
	p := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	if fail := verifyStep2Scope(src, &p); fail != nil {
		t.Fatalf("范围内应过: %v", fail)
	}
	// 域外
	out := baseEvent(testSourceID.String(), 2)
	out.TenantDomain = "evil.example.com"
	p2 := signedBatch(t, k, ModeDelta, out)
	fail := verifyStep2Scope(src, &p2)
	if fail == nil || fail.step != 2 {
		t.Fatal("域外事件应第 2 步拒收")
	}
	// 类型外
	outType := baseEvent(testSourceID.String(), 3)
	outType.ObjectType = "database"
	p3 := signedBatch(t, k, ModeDelta, outType)
	if fail := verifyStep2Scope(src, &p3); fail == nil || fail.step != 2 {
		t.Fatal("类型外事件应第 2 步拒收")
	}
	// 空范围 = 不限
	open := *src
	open.Scopes = SourceScopes{}
	if fail := verifyStep2Scope(&open, &p2); fail != nil {
		t.Fatal("空范围授权应不限")
	}
}

// ---------- 第 4 步：大小与字段白名单 ----------

func TestStep4Shape(t *testing.T) {
	k := newTestKey(t, "k1")
	src := activeSource()
	_ = src

	// 正
	p := signedBatch(t, k, ModeDelta, baseEvent(testSourceID.String(), 1))
	if fail := verifyStep4Shape(payloadBody(t, p), &p); fail != nil {
		t.Fatalf("合法批次应过第 4 步: %v", fail)
	}
	// 反1：事件含未知字段（拒收不忽略）
	raw := map[string]any{}
	_ = json.Unmarshal(payloadBody(t, p), &raw)
	item := raw["items"].([]any)[0].(map[string]any)
	item["backdoor_field"] = "x"
	body2, _ := json.Marshal(raw)
	p2 := p
	if fail := verifyStep4Shape(body2, &p2); fail == nil || fail.step != 4 {
		t.Fatal("未知字段应第 4 步拒收（拒收不忽略）")
	}
	// 反2：信封未知字段
	raw2 := map[string]any{}
	_ = json.Unmarshal(payloadBody(t, p), &raw2)
	raw2["extra"] = 1
	body3, _ := json.Marshal(raw2)
	if fail := verifyStep4Shape(body3, &p); fail == nil || fail.step != 4 {
		t.Fatal("信封未知字段应第 4 步拒收")
	}
	// 反3：mode 非法
	p3 := signedBatch(t, k, "full", baseEvent(testSourceID.String(), 1))
	if fail := verifyStep4Shape(payloadBody(t, p3), &p3); fail == nil || fail.step != 4 {
		t.Fatal("非法 mode 应第 4 步拒收")
	}
	// 反4：sequence=0
	e0 := baseEvent(testSourceID.String(), 0)
	p4 := signedBatch(t, k, ModeDelta, e0)
	if fail := verifyStep4Shape(payloadBody(t, p4), &p4); fail == nil || fail.step != 4 {
		t.Fatal("sequence=0 应第 4 步拒收")
	}
	// 反5：超长批次
	var many []ChangeEvent
	for i := 0; i < MaxBatchItems+1; i++ {
		e := baseEvent(testSourceID.String(), uint64(i+1))
		e.EventID = fmt.Sprintf("evt-%d", i)
		many = append(many, e)
	}
	p5 := signedBatch(t, k, ModeDelta, many...)
	if fail := verifyStep4Shape(payloadBody(t, p5), &p5); fail == nil || fail.step != 4 {
		t.Fatal("超上限批次应第 4 步拒收")
	}
}

// ---------- 第 5 步：字段语义 ----------

func TestStep5Semantics(t *testing.T) {
	k := newTestKey(t, "k1")
	src := activeSource()
	now := time.Now().UTC()
	svc := svcNoDB()

	valid := baseEvent(testSourceID.String(), 1)
	valid.IssuedAt = now.Format(time.RFC3339)
	p := signedBatch(t, k, ModeDelta, valid)
	if fail := svc.verifyStep5Semantics(src, &p, now); fail != nil {
		t.Fatalf("合法事件应过第 5 步: %v", fail)
	}

	cases := []struct {
		name string
		mut  func(*ChangeEvent)
		want string
	}{
		{"relation 非 OWNER（不支持词表）", func(e *ChangeEvent) { e.Relation = "SHARED_WITH" }, "首批不支持"},
		{"relation 委托（不支持词表）", func(e *ChangeEvent) { e.Relation = "DELEGATED_TO" }, "首批不支持"},
		{"change_type 非法", func(e *ChangeEvent) { e.ChangeType = "TRANSFER" }, "change_type 非法"},
		{"object_ref 非 objref: 形态", func(e *ChangeEvent) { e.ObjectRef = "plain-id-123" }, "objref:"},
		{"valid_from 不早于 valid_until", func(e *ChangeEvent) {
			e.ValidFrom = "2026-10-05T00:00:00Z"
			e.ValidUntil = "2026-10-05T00:00:00Z"
		}, "早于 valid_until"},
		{"issued_at 未来超容忍", func(e *ChangeEvent) {
			e.IssuedAt = now.Add(time.Hour).Format(time.RFC3339)
		}, "超前当前时间"},
		{"事件陈旧超来源声明", func(e *ChangeEvent) {
			e.IssuedAt = now.Add(-48 * time.Hour).Format(time.RFC3339)
		}, "陈旧"},
		{"source_id 不一致", func(e *ChangeEvent) { e.SourceID = uuid.NewString() }, "source_id 与来源不一致"},
	}
	maxAge := int64(3600) // 来源声明最大年龄 1h
	srcWithAge := *src
	srcWithAge.MaxEventAgeSeconds = &maxAge
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := baseEvent(testSourceID.String(), 1)
			e.IssuedAt = now.Format(time.RFC3339)
			c.mut(&e)
			e = k.signEvent(t, e)
			pc := ImportBatchPayload{BatchID: "b", SourceID: testSourceID.String(), Mode: ModeDelta, KeyID: "k1", Items: []ChangeEvent{e}}
			pc = k.signBatch(t, pc)
			fail := svc.verifyStep5Semantics(&srcWithAge, &pc, now)
			if fail == nil || fail.step != 5 {
				t.Fatalf("%s 应第 5 步拒收", c.name)
			}
			if !strings.Contains(fail.summary(), c.want) {
				t.Fatalf("%s 原因应含 %q: %s", c.name, c.want, fail.summary())
			}
		})
	}

	// snapshot 含 REVOKE → 拒收
	rev := baseEvent(testSourceID.String(), 1)
	rev.ChangeType = "REVOKE"
	rev.IssuedAt = now.Format(time.RFC3339)
	ps := signedBatch(t, k, ModeSnapshot, rev)
	if fail := svc.verifyStep5Semantics(src, &ps, now); fail == nil || fail.step != 5 ||
		!strings.Contains(fail.summary(), "snapshot 批次仅接受 GRANT") {
		t.Fatal("snapshot 含 REVOKE 应第 5 步拒收")
	}
	// snapshot 全 GRANT → 通过
	gr := baseEvent(testSourceID.String(), 1)
	gr.IssuedAt = now.Format(time.RFC3339)
	ps2 := signedBatch(t, k, ModeSnapshot, gr)
	if fail := svc.verifyStep5Semantics(src, &ps2, now); fail != nil {
		t.Fatalf("snapshot 全 GRANT 应过: %v", fail)
	}
}
