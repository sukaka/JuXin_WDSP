// APM 数据面容量/健康告警集成测试（真实 PG/迁移/设置服务；ClickHouse 读数部分
// fake 注入引擎测试缝 SetIngestLag——环境无真实 CH，连接失败降级形态由
// TestAPMIngestLagDisabledForm 覆盖）。
//
// 覆盖：
//   - 迁移 000094 种子落库（apm_alert.ingest_lag_seconds=300）
//   - 设置键经系统设置 Update API 在线调整（settings 白名单登记生效）
//   - 告警链路：滞后超阈触发 APM_INGEST_LAG（MEDIUM / component=clickhouse）
//     → 重复评估合并去重 → 阈值调小后按新阈值判定 → 恢复正常 AutoRecover(RECOVERED)
//     → 读数失败中止不动既有告警
//   - 关闭形态（APM_ENABLED=false，读数源未注入）：评估空转零告警
package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// fakeIngestLagSource 是 systemalerts.IngestLagStatsStore 的可编程 fake（CH 读数替身）。
type fakeIngestLagSource struct {
	latest time.Time
	ok     bool
	err    error
}

func (f *fakeIngestLagSource) LatestIngestAt(context.Context) (time.Time, bool, error) {
	if f.err != nil {
		return time.Time{}, false, f.err
	}
	return f.latest, f.ok, nil
}

// apmAlertSettingVersion 读取 apm_alert 组指定键的当前版本号（Update API 乐观锁用）。
func apmAlertSettingVersion(t *testing.T, env *testEnv, cookies []*http.Cookie, key string) int {
	t.Helper()
	resp := env.get(t, "/api/v1/system-settings?group=apm_alert", cookies)
	defer resp.Body.Close()
	var list apiRespPage2
	readJSON(t, resp, &list)
	for _, item := range list.Data.Items {
		if item["setting_key"] == key {
			return int(item["version"].(float64))
		}
	}
	t.Fatalf("setting apm_alert/%s not found", key)
	return 0
}

// TestAPMIngestLagIntegration 采集滞后告警链路（种子/白名单/触发/合并/阈值热更/恢复/失败中止）。
func TestAPMIngestLagIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// 1. 迁移 000094 种子落库
	var value string
	if err := env.db.QueryRow(ctx,
		`SELECT setting_value #>> '{}' FROM system_settings WHERE setting_group = 'apm_alert' AND setting_key = 'ingest_lag_seconds'`).Scan(&value); err != nil {
		t.Fatalf("query seeded setting: %v", err)
	}
	if value != "300" {
		t.Errorf("seeded ingest_lag_seconds = %q, want 300", value)
	}

	// 2. 关闭形态（APM_ENABLED=false，读数源未注入）：评估空转，零告警
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("disabled-form evaluate: %v", err)
	}
	var n int
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_INGEST_LAG'`).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if n != 0 {
		t.Fatalf("disabled form must not raise APM_INGEST_LAG, got %d", n)
	}

	// 3. fake CH 读数注入：滞后 600s > 默认阈值 300s → 触发 MEDIUM/OPEN/clickhouse
	src := &fakeIngestLagSource{latest: time.Now().Add(-600 * time.Second), ok: true}
	env.app.AlertEngine().SetIngestLag(src)
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate raise: %v", err)
	}
	var severity, status, component string
	err := env.db.QueryRow(ctx, `
SELECT severity, status, component FROM system_alerts
WHERE alert_type = 'APM_INGEST_LAG'`).Scan(&severity, &status, &component)
	if err != nil {
		t.Fatalf("query ingest-lag alert: %v", err)
	}
	if severity != "MEDIUM" || status != "OPEN" || component != "clickhouse" {
		t.Errorf("alert = %s/%s/%s, want MEDIUM/OPEN/clickhouse", severity, status, component)
	}

	// 4. 重复评估仍超阈：合并去重（OPEN 总数 1）
	src.latest = time.Now().Add(-700 * time.Second)
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate merge: %v", err)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_INGEST_LAG' AND status = 'OPEN'`).Scan(&n); err != nil {
		t.Fatalf("count open: %v", err)
	}
	if n != 1 {
		t.Errorf("open count = %d, want 1（合并去重）", n)
	}

	// 5. 设置键经 Update API 在线调整（白名单生效）：阈值 300 → 60
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	ver := apmAlertSettingVersion(t, env, cookies, "ingest_lag_seconds")
	body := fmt.Sprintf(`{"setting_group":"apm_alert","setting_key":"ingest_lag_seconds","setting_value":60,"version":%d}`, ver)
	resp := env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update setting status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	resp.Body.Close()

	// 阈值 60：滞后 100s 仍超阈（合并）；滞后 30s 回落 → 自动恢复
	src.latest = time.Now().Add(-100 * time.Second)
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate with new threshold: %v", err)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_INGEST_LAG' AND status = 'OPEN'`).Scan(&n); err != nil {
		t.Fatalf("count open after threshold change: %v", err)
	}
	if n != 1 {
		t.Errorf("open count = %d, want 1（新阈值下仍超阈合并）", n)
	}
	src.latest = time.Now().Add(-30 * time.Second)
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate recover: %v", err)
	}
	var resolveType string
	if err := env.db.QueryRow(ctx, `
SELECT COALESCE(resolve_type, '') FROM system_alerts
WHERE alert_type = 'APM_INGEST_LAG' AND component = 'clickhouse'`).Scan(&resolveType); err != nil {
		t.Fatalf("query recovered alert: %v", err)
	}
	if resolveType != "RECOVERED" {
		t.Errorf("resolve_type = %s, want RECOVERED（阈值热更后按新口径恢复）", resolveType)
	}

	// 6. 读数失败中止：先再触发（阈值 60 下滞后 600s 超阈），再注入读数错误——
	// 既有 OPEN 告警不得被清动
	src.latest = time.Now().Add(-600 * time.Second)
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate re-raise: %v", err)
	}
	src.err = fmt.Errorf("clickhouse down")
	if err := env.app.AlertEngine().EvaluateIngestLag(ctx); err == nil {
		t.Fatal("want error on stats failure")
	}
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_INGEST_LAG' AND status = 'OPEN'`).Scan(&n); err != nil {
		t.Fatalf("count open after read error: %v", err)
	}
	if n != 1 {
		t.Errorf("open count = %d, want 1（读数失败不误恢复）", n)
	}

	// 7. 恢复阈值为默认 300（不影响其他用例；本测试库独立，仅为现场整洁）
	ver = apmAlertSettingVersion(t, env, cookies, "ingest_lag_seconds")
	body = fmt.Sprintf(`{"setting_group":"apm_alert","setting_key":"ingest_lag_seconds","setting_value":300,"version":%d}`, ver)
	resp = env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	resp.Body.Close()
}
