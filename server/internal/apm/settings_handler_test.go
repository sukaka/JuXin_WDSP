// settings_handler_test.go APM 设置专用接口单测（内存 fake 设置源 + 假 dialer +
// 审计 spy）：GET 不回显 DSN 原文、来源/连接状态字段、PUT 校验与清空语义、
// 高风险审计（摘要不含 DSN 值）、权限点。
package apm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// fakeAPMSettingsStore 内存实现 apmSettingsWriter + runtimeSettingsReader
// （记录敏感写入/删除供断言）。
type fakeAPMSettingsStore struct {
	fakeRuntimeSettings
	sensitiveWrites map[string]bool // 经 UpsertSensitiveString 写入的键
	deleted         []string
	upsertErr       error
}

func newFakeAPMSettingsStore() *fakeAPMSettingsStore {
	return &fakeAPMSettingsStore{
		fakeRuntimeSettings: fakeRuntimeSettings{bools: map[string]bool{}, strings: map[string]string{}},
		sensitiveWrites:     map[string]bool{},
	}
}

func (f *fakeAPMSettingsStore) UpsertBool(_ context.Context, group, key string, value bool, _ string, _ uuid.UUID) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.bools[group+":"+key] = value
	return nil
}

func (f *fakeAPMSettingsStore) UpsertSensitiveString(_ context.Context, group, key, value, _ string, _ uuid.UUID) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.strings[group+":"+key] = value
	f.sensitiveWrites[group+":"+key] = true
	return nil
}

func (f *fakeAPMSettingsStore) Delete(_ context.Context, group, key string) error {
	if f.upsertErr != nil {
		return f.upsertErr
	}
	delete(f.strings, group+":"+key)
	f.deleted = append(f.deleted, group+":"+key)
	return nil
}

// newAPMSettingsTestMux 装配设置接口测试 mux（假 dialer 防真实网络连接）。
func newAPMSettingsTestMux(store *fakeAPMSettingsStore, envEnabled bool, envDSN string,
	dialer *fakeDialer, spy *fakeAuditSpy, perms ...string) (*http.ServeMux, *SettingsHandler) {
	rc := NewRuntimeConfig(store, envEnabled, envDSN)
	m := NewCHManager(rc)
	m.dial = dialer.dial
	h := NewSettingsHandler(rc, store, m)
	if spy != nil {
		h.SetAudits(spy)
	}
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, injectPrincipal(perms...), h)
	return mux, h
}

func doAPMSettingsReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// decodeData 解包响应 data 字段。
func decodeData(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rr.Body.String())
	}
	return body.Data
}

// TestAPMSettingsGetMasksDSN GET 不回显 DSN 原文：只回 set 布尔与来源。
func TestAPMSettingsGetMasksDSN(t *testing.T) {
	store := newFakeAPMSettingsStore()
	store.strings["apm:clickhouse_dsn"] = "clickhouse://user:secret@h:9000/apm"
	store.bools["apm:enabled"] = true
	mux, _ := newAPMSettingsTestMux(store, false, "", &fakeDialer{}, nil, "system_settings.read")

	rr := doAPMSettingsReq(t, mux, "GET", "/api/v1/apm/settings", "")
	if rr.Code != 200 {
		t.Fatalf("get = %d, body %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret") || strings.Contains(rr.Body.String(), "clickhouse://") {
		t.Errorf("GET 响应泄露 DSN 原文: %s", rr.Body.String())
	}
	d := decodeData(t, rr)
	if d["enabled"] != true || d["enabled_source"] != sourceUI {
		t.Errorf("enabled/source = %v/%v, want true/%q", d["enabled"], d["enabled_source"], sourceUI)
	}
	if d["clickhouse_dsn_set"] != true || d["clickhouse_dsn_source"] != sourceUI {
		t.Errorf("dsn_set/source = %v/%v", d["clickhouse_dsn_set"], d["clickhouse_dsn_source"])
	}
	if d["ch_connected"] != true {
		t.Errorf("ch_connected = %v, want true（假 dialer 成功）", d["ch_connected"])
	}
}

// TestAPMSettingsGetEnvFallback DB 无行时如实报告 env 兜底与未配置。
func TestAPMSettingsGetEnvFallback(t *testing.T) {
	mux, _ := newAPMSettingsTestMux(newFakeAPMSettingsStore(), true, "clickhouse://env:9000/apm",
		&fakeDialer{}, nil, "system_settings.read")
	d := decodeData(t, doAPMSettingsReq(t, mux, "GET", "/api/v1/apm/settings", ""))
	if d["enabled"] != true || d["enabled_source"] != sourceEnv {
		t.Errorf("enabled/source = %v/%v, want true/%q", d["enabled"], d["enabled_source"], sourceEnv)
	}
	if d["clickhouse_dsn_set"] != true || d["clickhouse_dsn_source"] != sourceEnv {
		t.Errorf("dsn_set/source = %v/%v, want true/%q", d["clickhouse_dsn_set"], d["clickhouse_dsn_source"], sourceEnv)
	}

	mux, _ = newAPMSettingsTestMux(newFakeAPMSettingsStore(), false, "", &fakeDialer{}, nil, "system_settings.read")
	d = decodeData(t, doAPMSettingsReq(t, mux, "GET", "/api/v1/apm/settings", ""))
	if d["enabled"] != false || d["clickhouse_dsn_set"] != false || d["clickhouse_dsn_source"] != "" || d["ch_connected"] != false {
		t.Errorf("均未配置 = %+v, want 全关", d)
	}
}

// TestAPMSettingsUpdateValidation PUT 校验：非法 DSN 400、空 body 400、坏 JSON 400。
func TestAPMSettingsUpdateValidation(t *testing.T) {
	mux, _ := newAPMSettingsTestMux(newFakeAPMSettingsStore(), false, "", &fakeDialer{}, nil, "system_settings.update")
	for _, body := range []string{
		`{"clickhouse_dsn":"not-a-dsn"}`,
		`{}`,
		`not-json`,
	} {
		if rr := doAPMSettingsReq(t, mux, "PUT", "/api/v1/apm/settings", body); rr.Code != 400 {
			t.Errorf("put %s = %d, want 400", body, rr.Code)
		}
	}
}

// TestAPMSettingsUpdateEnabledAndAudit 开关写入 + 高风险审计 + 立即生效。
func TestAPMSettingsUpdateEnabledAndAudit(t *testing.T) {
	store := newFakeAPMSettingsStore()
	spy := &fakeAuditSpy{}
	mux, _ := newAPMSettingsTestMux(store, false, "", &fakeDialer{}, spy, "system_settings.update", "system_settings.read")

	rr := doAPMSettingsReq(t, mux, "PUT", "/api/v1/apm/settings", `{"enabled":true}`)
	if rr.Code != 200 {
		t.Fatalf("put enabled = %d, body %s", rr.Code, rr.Body.String())
	}
	if !store.bools["apm:enabled"] {
		t.Error("apm:enabled 行应写入 true")
	}
	// 立即生效：PUT 回执即反映新状态
	if d := decodeData(t, rr); d["enabled"] != true || d["enabled_source"] != sourceUI {
		t.Errorf("回执 enabled/source = %v/%v, want true/%q", d["enabled"], d["enabled_source"], sourceUI)
	}
	// 审计：module=apm、高风险、摘要不涉及 DSN 值
	if len(spy.inputs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(spy.inputs))
	}
	a := spy.inputs[0]
	if a.Module != "apm" || a.Action != "update" || a.RiskLevel != audits.RiskHigh || a.Result != audits.ResultSuccess {
		t.Errorf("audit = %+v", a)
	}
	if !strings.Contains(a.AfterSummary, `"enabled":true`) {
		t.Errorf("after 摘要应含 enabled: %q", a.AfterSummary)
	}
}

// TestAPMSettingsUpdateDSN DSN 写入走敏感通道 + 触发连接重建 + 审计只记 set。
func TestAPMSettingsUpdateDSN(t *testing.T) {
	store := newFakeAPMSettingsStore()
	spy := &fakeAuditSpy{}
	dialer := &fakeDialer{}
	mux, _ := newAPMSettingsTestMux(store, false, "", dialer, spy, "system_settings.update")

	dsn := "clickhouse://user:secret@h:9000/apm"
	rr := doAPMSettingsReq(t, mux, "PUT", "/api/v1/apm/settings", `{"clickhouse_dsn":"`+dsn+`"}`)
	if rr.Code != 200 {
		t.Fatalf("put dsn = %d, body %s", rr.Code, rr.Body.String())
	}
	if !store.sensitiveWrites["apm:clickhouse_dsn"] {
		t.Error("DSN 应经 UpsertSensitiveString 写入（is_sensitive=true）")
	}
	if dialer.calls != 1 || dialer.lastDSN != dsn {
		t.Errorf("写后应触发重建（dial 1 次新 DSN），got %d/%q", dialer.calls, dialer.lastDSN)
	}
	if len(spy.inputs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(spy.inputs))
	}
	if strings.Contains(spy.inputs[0].AfterSummary, "secret") || strings.Contains(spy.inputs[0].AfterSummary, "clickhouse://") {
		t.Errorf("审计摘要不得含 DSN 原文: %q", spy.inputs[0].AfterSummary)
	}
	if !strings.Contains(spy.inputs[0].AfterSummary, "set") {
		t.Errorf("审计摘要应记 set: %q", spy.inputs[0].AfterSummary)
	}
	// 响应不得回显 DSN 原文
	if strings.Contains(rr.Body.String(), "secret") {
		t.Errorf("PUT 响应泄露 DSN 原文: %s", rr.Body.String())
	}
}

// TestAPMSettingsClearDSN clickhouse_dsn="" = 清除界面覆盖（删除 DB 行，回退 env）。
func TestAPMSettingsClearDSN(t *testing.T) {
	store := newFakeAPMSettingsStore()
	store.strings["apm:clickhouse_dsn"] = "clickhouse://ui:9000/apm"
	dialer := &fakeDialer{}
	mux, _ := newAPMSettingsTestMux(store, false, "clickhouse://env:9000/apm", dialer, nil,
		"system_settings.update", "system_settings.read")

	rr := doAPMSettingsReq(t, mux, "PUT", "/api/v1/apm/settings", `{"clickhouse_dsn":""}`)
	if rr.Code != 200 {
		t.Fatalf("clear dsn = %d, body %s", rr.Code, rr.Body.String())
	}
	if len(store.deleted) != 1 || store.deleted[0] != "apm:clickhouse_dsn" {
		t.Errorf("应删除 DB 行，deleted = %v", store.deleted)
	}
	// 回退 env 兜底：重建按 env DSN
	if dialer.calls != 1 || dialer.lastDSN != "clickhouse://env:9000/apm" {
		t.Errorf("清空后应按 env DSN 重建，got %d/%q", dialer.calls, dialer.lastDSN)
	}
	d := decodeData(t, rr)
	if d["clickhouse_dsn_set"] != true || d["clickhouse_dsn_source"] != sourceEnv {
		t.Errorf("清空后来源应回退 env，got %v/%v", d["clickhouse_dsn_set"], d["clickhouse_dsn_source"])
	}
}

// TestAPMSettingsPermissions 权限点：读 system_settings.read、写 system_settings.update。
func TestAPMSettingsPermissions(t *testing.T) {
	store := newFakeAPMSettingsStore()
	h := NewSettingsHandler(NewRuntimeConfig(store, false, ""), store, NewCHManager(NewRuntimeConfig(store, false, "")))
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, injectPrincipal("system_settings.read"), h)
	if rr := doAPMSettingsReq(t, mux, "GET", "/api/v1/apm/settings", ""); rr.Code != 200 {
		t.Errorf("read perm get = %d, want 200", rr.Code)
	}
	if rr := doAPMSettingsReq(t, mux, "PUT", "/api/v1/apm/settings", `{"enabled":true}`); rr.Code != 403 {
		t.Errorf("read-only put = %d, want 403", rr.Code)
	}
	mux = http.NewServeMux()
	RegisterSettingsRoutes(mux, injectPrincipal(), h)
	if rr := doAPMSettingsReq(t, mux, "GET", "/api/v1/apm/settings", ""); rr.Code != 403 {
		t.Errorf("no perm get = %d, want 403", rr.Code)
	}
}
