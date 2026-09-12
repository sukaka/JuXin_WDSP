// access_tools_test.go 访问控制与统计 Tool 组测试：
// rate_limit_statistics.get 的注册元数据、入参校验与 SQL 构造（不触库）。
package aitools

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRateLimitStatisticsMetadata rate_limit_statistics.get 注册成功，READ_ONLY 且权限点正确。
func TestRateLimitStatisticsMetadata(t *testing.T) {
	r := NewRegistry()
	NewAccessTools(r, nil)
	tl, ok := r.Get("rate_limit_statistics.get")
	if !ok {
		t.Fatal("缺少 Tool rate_limit_statistics.get")
	}
	if tl.RiskLevel() != RiskReadOnly {
		t.Errorf("risk = %s, want READ_ONLY", tl.RiskLevel())
	}
	if tl.RequiredPermission() != "rate_limits.read" {
		t.Errorf("permission = %s, want rate_limits.read", tl.RequiredPermission())
	}
	if tl.TimeoutSeconds() <= 0 || tl.MaxResults() <= 0 {
		t.Errorf("timeout=%d maxResults=%d 应均为正数", tl.TimeoutSeconds(), tl.MaxResults())
	}
	schema := tl.InputSchema()
	props, _ := schema["properties"].(map[string]interface{})
	for _, k := range []string{"start_time", "end_time", "application_id", "bucket"} {
		if _, ok := props[k]; !ok {
			t.Errorf("input_schema 缺少字段 %s", k)
		}
	}
}

// TestParseRateLimitStatsInput 入参解析：默认值、非法时间、超跨度、非法应用ID、分桶收敛。
func TestParseRateLimitStatsInput(t *testing.T) {
	// 默认：最近24小时，hour 分桶，无应用过滤
	start, end, appID, bucket, err := parseRateLimitStatsInput(map[string]interface{}{})
	if err != nil {
		t.Fatalf("默认入参 err = %v", err)
	}
	if appID != nil || bucket != "hour" {
		t.Errorf("默认 appID=%v bucket=%s", appID, bucket)
	}
	if d := end.Sub(start); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("默认跨度 = %v, want 约24小时", d)
	}

	// 显式时间 + day 分桶 + 合法应用ID
	id := uuid.New()
	_, _, appID, bucket, err = parseRateLimitStatsInput(map[string]interface{}{
		"start_time":     "2026-09-01T00:00:00Z",
		"end_time":       "2026-09-02T00:00:00Z",
		"bucket":         "day",
		"application_id": id.String(),
	})
	if err != nil {
		t.Fatalf("合法入参 err = %v", err)
	}
	if appID == nil || *appID != id || bucket != "day" {
		t.Errorf("appID=%v bucket=%s", appID, bucket)
	}

	cases := []struct {
		name string
		m    map[string]interface{}
	}{
		{"非法起始时间", map[string]interface{}{"start_time": "not-a-time"}},
		{"非法结束时间", map[string]interface{}{"end_time": "not-a-time"}},
		{"起止倒置", map[string]interface{}{
			"start_time": "2026-09-02T00:00:00Z", "end_time": "2026-09-01T00:00:00Z"}},
		{"超过90天", map[string]interface{}{
			"start_time": "2026-01-01T00:00:00Z", "end_time": "2026-09-01T00:00:00Z"}},
		{"非法应用ID", map[string]interface{}{"application_id": "not-a-uuid"}},
	}
	for _, c := range cases {
		if _, _, _, _, err := parseRateLimitStatsInput(c.m); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want ErrInvalidInput", c.name, err)
		}
	}

	// 非法分桶收敛为 hour
	if _, _, _, bucket, _ := parseRateLimitStatsInput(map[string]interface{}{"bucket": "minute"}); bucket != "hour" {
		t.Errorf("非法分桶应收敛为 hour, got %s", bucket)
	}
}

// TestRateLimitStatsWhere SQL 构造：占位符顺序、参数值与应用过滤。
func TestRateLimitStatsWhere(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

	where, args := rateLimitStatsWhere(start, end, nil)
	if !strings.Contains(where, "event_type LIKE 'CC%'") ||
		!strings.Contains(where, "occurred_at >= $1 AND occurred_at < $2") {
		t.Errorf("无应用过滤 where = %s", where)
	}
	if strings.Contains(where, "application_id") {
		t.Errorf("无应用过滤不应包含 application_id: %s", where)
	}
	if len(args) != 2 || !args[0].(time.Time).Equal(start) || !args[1].(time.Time).Equal(end) {
		t.Errorf("args = %v", args)
	}

	id := uuid.New()
	where, args = rateLimitStatsWhere(start, end, &id)
	if !strings.Contains(where, "AND application_id = $3") {
		t.Errorf("应用过滤 where = %s", where)
	}
	if len(args) != 3 || args[2].(uuid.UUID) != id {
		t.Errorf("args = %v", args)
	}
}
