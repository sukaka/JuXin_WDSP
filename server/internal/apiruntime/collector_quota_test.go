// collector_quota_test.go 授权端点配额哨兵采集链路测试：发现 upsert 返回
// ErrLicenseQuotaExceeded 时——不阻断主事件落库、触发告警回调一次、不重试。
package apiruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// quotaDiscovery 发现 upsert 永远返回配额哨兵（采集链路哨兵捕获路径驱动）。
type quotaDiscovery struct{ calls int }

func (f *quotaDiscovery) UpsertDiscovery(_ context.Context, _ apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	f.calls++
	return nil, apiassets.ErrLicenseQuotaExceeded
}

func TestCollectOnce_LicenseQuotaExceeded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	// notable 记录（BLOCK）：主事件必须照常落库，不受发现配额拒绝影响
	rec := Record{
		RequestID: "r-quota-1", EndpointKey: "GET /v1/new-endpoint", Method: "GET",
		PathTemplate: "/v1/new-endpoint", IsAPI: true, APIConfidence: 0.8,
		FinalAction: "BLOCK", RiskLevel: "HIGH", RiskScore: 80,
		Details: []dsctx.DetectorMatch{{
			Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
			Severity: "HIGH", Message: "type mismatch", ScoreDelta: 80,
		}},
		OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	saver := &fakeSaver{}
	disc := &quotaDiscovery{}
	c := NewCollector(saver, "test-quota", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	var alerts []string
	c.SetQuotaAlertFunc(func(_ context.Context, endpointKey string) {
		alerts = append(alerts, endpointKey)
	})

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("配额拒绝不应使采集失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 processed line, got %d", n)
	}
	// 主事件照常落库（不阻断）
	if len(saver.saved) != 1 || saver.saved[0].RequestID != "r-quota-1" {
		t.Fatalf("主事件应照常落库: %+v", saver.saved)
	}
	// 告警回调按拒绝事件触发一次
	if len(alerts) != 1 || alerts[0] != "GET /v1/new-endpoint" {
		t.Fatalf("配额告警应触发一次且携带 endpoint_key: %+v", alerts)
	}
	// 断点照常前移：重复采集不重试（不产生重试风暴）
	n2, err := c.CollectOnce(context.Background())
	if err != nil || n2 != 0 {
		t.Fatalf("second CollectOnce want (0,nil), got (%d,%v)", n2, err)
	}
	if disc.calls != 1 {
		t.Fatalf("发现 upsert 不应重试，got %d calls", disc.calls)
	}
	if len(alerts) != 1 {
		t.Fatalf("告警不应重复触发，got %+v", alerts)
	}
}
