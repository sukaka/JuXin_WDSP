// sweep_test.go SweepOnce 敏感证据清扫测试（内存仓储，语义同 SQL）。
package apidata

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// sensitiveDetails 构造运行时事件检测明细（镜像 dsctx.DetectorMatch JSON 形状）。
func sensitiveDetails(t *testing.T, details []map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func queryPhoneHit(field string) map[string]any {
	return map[string]any{
		"detector": "sensitive_data",
		"rule_id":  "sensitive.in_query",
		"evidence": map[string]string{"field": field, "data_type": "phone", "location": "query"},
	}
}

func jsonEmailHit(field string) map[string]any {
	return map[string]any{
		"detector": "sensitive_data",
		"rule_id":  "sensitive.field",
		"evidence": map[string]string{"field": field, "data_type": "email", "location": "json"},
	}
}

// TestSweepOnceUpsert 首次全量回填 upsert；连续清扫不重复计数（水位幂等）；
// 新事件到达后 occurrence_count 累加、last_seen 前移。
func TestSweepOnceUpsert(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "GET /orders/{id}"
	endpointID := store.addEndpoint(epKey)

	base := time.Now().UTC().Add(-time.Hour)
	// 事件1：query 命中 phone + json 命中 email
	store.addRuntimeEvent(epKey, base, sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"), jsonEmailHit("user.email"),
	}))
	// 事件2：仅 query 命中 phone（同字段再命中）
	store.addRuntimeEvent(epKey, base.Add(time.Minute), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"),
	}))
	// 事件3：非敏感明细（不产生字段行）
	store.addRuntimeEvent(epKey, base.Add(2*time.Minute), sensitiveDetails(t, []map[string]any{
		{"detector": "api_schema", "rule_id": "schema.type_mismatch"},
	}))

	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 2 || res.Hits != 3 || res.FieldsUpserted != 3 || res.SkippedNoEndpoint != 0 {
		t.Fatalf("result=%+v", res)
	}
	rows := store.fieldRows()
	if len(rows) != 2 {
		t.Fatalf("fields=%d rows=%+v", len(rows), rows)
	}
	byPath := map[string]sensitiveFieldRow{}
	for _, r := range rows {
		byPath[r.StructuredPath] = r
		if r.EndpointID != endpointID || r.DetectionSource != "RUNTIME" || r.Direction != "REQUEST" {
			t.Fatalf("row=%+v", r)
		}
	}
	phone := byPath["query.phone"]
	if phone.OccurrenceCount != 2 || !phone.LastSeen.Equal(base.Add(time.Minute)) || !phone.FirstSeen.Equal(base) {
		t.Fatalf("phone=%+v", phone)
	}
	email := byPath["json.user.email"]
	if email.OccurrenceCount != 1 || email.DataType != "email" {
		t.Fatalf("email=%+v", email)
	}

	// 连续清扫：水位已前移，无新事件 → 全零结果，计数不变（幂等）
	res2, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if res2.EventsScanned != 0 || res2.Hits != 0 || res2.HasMore {
		t.Fatalf("second sweep=%+v", res2)
	}
	rows = store.fieldRows()
	if byPath2 := rows[0]; len(rows) != 2 || byPath2.OccurrenceCount == 0 {
		t.Fatalf("after second sweep rows=%+v", rows)
	}
	for _, r := range store.fieldRows() {
		if r.StructuredPath == "query.phone" && r.OccurrenceCount != 2 {
			t.Fatalf("phone count changed after idle sweep: %+v", r)
		}
	}

	// 新事件（更晚时间）→ occurrence_count 累加
	store.addRuntimeEvent(epKey, base.Add(3*time.Minute), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"),
	}))
	res3, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep3: %v", err)
	}
	if res3.EventsScanned != 1 || res3.Hits != 1 {
		t.Fatalf("third sweep=%+v", res3)
	}
	for _, r := range store.fieldRows() {
		if r.StructuredPath == "query.phone" {
			if r.OccurrenceCount != 3 || !r.LastSeen.Equal(base.Add(3*time.Minute)) {
				t.Fatalf("phone after new event=%+v", r)
			}
		}
	}
}

// TestSweepOnceEmpty 空表/无命中安全。
func TestSweepOnceEmpty(t *testing.T) {
	store := NewMemStore()
	res, err := store.SweepOnce(context.Background())
	if err != nil || res.EventsScanned != 0 || res.Hits != 0 || res.Watermark != nil {
		t.Fatalf("empty sweep=%+v err=%v", res, err)
	}
	// 有事件但无敏感明细
	store.addEndpoint("GET /a")
	store.addRuntimeEvent("GET /a", time.Now().UTC(), sensitiveDetails(t, []map[string]any{
		{"detector": "auth", "rule_id": "auth.unauthenticated_api"},
	}))
	res, err = store.SweepOnce(context.Background())
	if err != nil || res.EventsScanned != 0 || res.Hits != 0 {
		t.Fatalf("no-hit sweep=%+v err=%v", res, err)
	}
	if len(store.fieldRows()) != 0 {
		t.Fatalf("fields=%+v", store.fieldRows())
	}
}

// TestSweepOnceUnknownEndpoint endpoint_key 未匹配资产的事件跳过并计数。
func TestSweepOnceUnknownEndpoint(t *testing.T) {
	store := NewMemStore()
	store.addRuntimeEvent("GET /ghost", time.Now().UTC(), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("mobile"),
	}))
	res, err := store.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 1 || res.SkippedNoEndpoint != 1 || res.FieldsUpserted != 0 {
		t.Fatalf("result=%+v", res)
	}
	if len(store.fieldRows()) != 0 {
		t.Fatalf("fields=%+v", store.fieldRows())
	}
}

// TestSweepOnceDirection 证据方向透传：RESPONSE 方向落 RESPONSE 行；缺省/非法方向归 REQUEST。
func TestSweepOnceDirection(t *testing.T) {
	store := NewMemStore()
	epKey := "POST /users"
	store.addEndpoint(epKey)
	store.addRuntimeEvent(epKey, time.Now().UTC(), sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{"field": "id_card", "data_type": "id_card", "location": "json", "direction": "RESPONSE"},
		},
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{"field": "mobile", "data_type": "phone", "location": "json", "direction": "SIDEWAYS"},
		},
	}))
	if _, err := store.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	dirs := map[string]string{}
	for _, r := range store.fieldRows() {
		dirs[r.StructuredPath] = r.Direction
	}
	if dirs["json.id_card"] != "RESPONSE" || dirs["json.mobile"] != "REQUEST" {
		t.Fatalf("dirs=%v", dirs)
	}
}

// TestSweepOnceConfidence 置信度口径：明细自带 confidence 透传；缺失/越界回落 0.8；
// 重复命中取 GREATEST（低置信度观测不降级）。
func TestSweepOnceConfidence(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "GET /conf"
	store.addEndpoint(epKey)
	base := time.Now().UTC().Add(-time.Hour)

	hit := func(field string, confidence any) map[string]any {
		m := map[string]any{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{"field": field, "data_type": "phone", "location": "query"},
		}
		if confidence != nil {
			m["confidence"] = confidence
		}
		return m
	}
	// 缺失 confidence → 0.8；显式 1.0 → 1.0；越界 1.5 → 0.8
	store.addRuntimeEvent(epKey, base, sensitiveDetails(t, []map[string]any{
		hit("f_default", nil), hit("f_value", 1.0), hit("f_oob", 1.5),
	}))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	conf := map[string]float64{}
	for _, r := range store.fieldRows() {
		conf[r.StructuredPath] = r.Confidence
	}
	if conf["query.f_default"] != 0.8 || conf["query.f_value"] != 1.0 || conf["query.f_oob"] != 0.8 {
		t.Fatalf("conf=%v", conf)
	}

	// 低置信度（0.8）再次命中已是 1.0 的字段 → 保持 1.0（GREATEST，不降级）
	store.addRuntimeEvent(epKey, base.Add(time.Minute), sensitiveDetails(t, []map[string]any{
		hit("f_value", 0.8),
	}))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	for _, r := range store.fieldRows() {
		if r.StructuredPath == "query.f_value" && r.Confidence != 1.0 {
			t.Fatalf("confidence must not downgrade: %+v", r)
		}
	}
}

// TestSweepOnceMaskedSample 脱敏样本保留策略：保留最新 1 条值级脱敏样本；
// 后续仅字段名命中（无 masked_sample）不清空既有脱敏样本；绝不读取原始 value 键。
func TestSweepOnceMaskedSample(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "POST /v1/profile"
	store.addEndpoint(epKey)
	base := time.Now().UTC().Add(-time.Hour)

	// 首次值级命中：写入 masked_sample = 138****8000
	store.addRuntimeEvent(epKey, base, sensitiveDetails(t, []map[string]any{
		{
			"detector":   "sensitive_data",
			"rule_id":    "sensitive.response_value",
			"confidence": 1.0,
			"evidence": map[string]string{
				"field":         "user.phone",
				"data_type":     "phone",
				"location":      "response_body",
				"direction":     "RESPONSE",
				"masked_sample": "138****8000",
			},
		},
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{
				"field":     "password",
				"data_type": "credential",
				"location":  "json",
				"value":     "must-never-be-copied",
			},
		},
	}))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep1: %v", err)
	}
	byPath := map[string]sensitiveFieldRow{}
	for _, r := range store.fieldRows() {
		byPath[r.StructuredPath] = r
	}
	if byPath["response_body.user.phone"].MaskedSample != "138****8000" {
		t.Fatalf("masked_sample = %q, want 138****8000", byPath["response_body.user.phone"].MaskedSample)
	}
	if byPath["json.password"].MaskedSample != "" {
		t.Fatalf("field-name hit must not copy raw value into masked_sample: %+v", byPath["json.password"])
	}

	// 新值级命中：更新为最新 1 条脱敏样本 139****5678
	store.addRuntimeEvent(epKey, base.Add(time.Minute), sensitiveDetails(t, []map[string]any{
		{
			"detector":   "sensitive_data",
			"rule_id":    "sensitive.response_value",
			"confidence": 1.0,
			"evidence": map[string]string{
				"field":         "user.phone",
				"data_type":     "phone",
				"location":      "response_body",
				"direction":     "RESPONSE",
				"masked_sample": "139****5678",
			},
		},
	}))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	for _, r := range store.fieldRows() {
		if r.StructuredPath == "response_body.user.phone" && r.MaskedSample != "139****5678" {
			t.Fatalf("newer value hit must update masked_sample to latest, got %q", r.MaskedSample)
		}
	}

	// 后续仅字段名命中（无 masked_sample）：不得覆盖清空已有值级脱敏样本
	store.addRuntimeEvent(epKey, base.Add(2*time.Minute), sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.response_field",
			"evidence": map[string]string{
				"field":     "user.phone",
				"data_type": "phone",
				"location":  "response_body",
				"direction": "RESPONSE",
				"value":     "13700000000",
			},
		},
	}))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep3: %v", err)
	}
	for _, r := range store.fieldRows() {
		if r.StructuredPath == "response_body.user.phone" && r.MaskedSample != "139****5678" {
			t.Fatalf("field-name-only hit must keep existing masked_sample, got %q", r.MaskedSample)
		}
	}
}

// TestSweepOnceIgnoresProtocolHeaderFieldNoise 历史事件中的标准浏览器协议头字段名误报
// （如 header.sec-ch-ua-mobile + sensitive.field）不得在清扫时重新回填到 api_sensitive_fields，
// 同时保留值级命中（sensitive.value）与自定义业务头（如 x-user-mobile）的正常记录。
func TestSweepOnceIgnoresProtocolHeaderFieldNoise(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	epKey := "GET /robots.txt"
	store.addEndpoint(epKey)
	base := time.Now().UTC().Add(-time.Hour)

	// 纯历史误报事件：sec-ch-ua-mobile 命中字段名规则 sensitive.field → 应完全跳过
	store.addRuntimeEvent(epKey, base, sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{
				"field":     "sec-ch-ua-mobile",
				"data_type": "phone",
				"location":  "header",
			},
		},
	}))
	// 混合事件：含 1 条历史误报 + 1 条值级命中 + 1 条自定义业务头字段名命中
	store.addRuntimeEvent(epKey, base.Add(time.Minute), sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{
				"field":     "sec-ch-ua-mobile",
				"data_type": "phone",
				"location":  "header",
			},
		},
		{
			"detector":   "sensitive_data",
			"rule_id":    "sensitive.value",
			"confidence": 1.0,
			"evidence": map[string]string{
				"field":         "user-agent",
				"data_type":     "phone",
				"location":      "header",
				"masked_sample": "138****8000",
			},
		},
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{
				"field":     "x-user-mobile",
				"data_type": "phone",
				"location":  "header",
			},
		},
	}))

	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 1 || res.Hits != 2 || res.FieldsUpserted != 2 {
		t.Fatalf("unexpected sweep result: %+v", res)
	}
	byPath := map[string]sensitiveFieldRow{}
	for _, r := range store.fieldRows() {
		byPath[r.StructuredPath] = r
	}
	if _, exists := byPath["header.sec-ch-ua-mobile"]; exists {
		t.Fatalf("sec-ch-ua-mobile field noise must not resurface: %+v", byPath)
	}
	if _, exists := byPath["header.user-agent"]; !exists {
		t.Fatalf("value-level header match must be kept: %+v", byPath)
	}
	if _, exists := byPath["header.x-user-mobile"]; !exists {
		t.Fatalf("custom business header match must be kept: %+v", byPath)
	}
}

func TestSweepOnceIgnoresPathFieldNoiseButKeepsPathValueHit(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	zipEP := "GET /mobile.zip"
	userEP := "GET /v1/users/{id}"
	store.addEndpoint(zipEP)
	store.addEndpoint(userEP)
	base := time.Now().UTC().Add(-time.Hour)

	// 历史路径字段名误报 + 响应体未完成检查诊断 → 均应忽略
	store.addRuntimeEvent(zipEP, base, sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{
				"field":     "mobile.zip",
				"data_type": "phone",
				"location":  "path",
			},
		},
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.response_body_unchecked",
			"evidence": map[string]string{
				"field":     "response_body",
				"location":  "response_body",
				"direction": "RESPONSE",
			},
		},
	}))
	// 路径实值命中（如 /v1/users/13800138000）→ 必须保留
	store.addRuntimeEvent(userEP, base.Add(time.Minute), sensitiveDetails(t, []map[string]any{
		{
			"detector":   "sensitive_data",
			"rule_id":    "sensitive.value",
			"confidence": 1.0,
			"evidence": map[string]string{
				"field":         "{id}",
				"data_type":     "phone",
				"location":      "path",
				"masked_sample": "138****8000",
			},
		},
	}))

	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsScanned != 1 || res.Hits != 1 || res.FieldsUpserted != 1 {
		t.Fatalf("unexpected sweep result: %+v", res)
	}
	rows := store.fieldRows()
	if len(rows) != 1 || rows[0].StructuredPath != "path.{id}" || rows[0].MaskedSample != "138****8000" {
		t.Fatalf("unexpected field rows: %+v", rows)
	}
}
