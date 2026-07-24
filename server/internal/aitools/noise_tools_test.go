// noise_tools_test.go 降噪 Tool 测试：注册元数据、权限拒绝（DENIED 审计）、
// 输入校验与内存仓储 happy path。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/ainoise"
)

func seedNoiseCluster(t *testing.T, store *ainoise.MemStore) uuid.UUID {
	t.Helper()
	rule := 942100
	_, id, err := store.UpsertEvent(context.Background(), ainoise.EventInput{
		EventID: uuid.New(), Source: ainoise.SourceWAF, Host: "a.com", RawURI: "/search",
		RuleID: &rule, ClientIP: "1.2.3.4", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNoiseToolsRegistered(t *testing.T) {
	r := NewRegistry()
	NewNoiseTools(r, ainoise.NewMemStore())
	for _, code := range []string{"noise_cluster.search", "noise_cluster.get"} {
		tool, ok := r.Get(code)
		if !ok {
			t.Fatalf("tool %s not registered", code)
		}
		if tool.RiskLevel() != RiskReadOnly || tool.RequiredPermission() != "ai.noise_reduction.use" {
			t.Fatalf("tool %s meta: risk=%s perm=%s", code, tool.RiskLevel(), tool.RequiredPermission())
		}
	}
}

// TestNoiseToolDenied 无权限执行 → ErrPermission + DENIED 审计。
func TestNoiseToolDenied(t *testing.T) {
	r := NewRegistry()
	NewNoiseTools(r, ainoise.NewMemStore())
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal(), uuid.New(), nil,
		"noise_cluster.search", json.RawMessage(`{}`), aud)
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("err=%v want ErrPermission", err)
	}
	if len(aud.records) != 1 || aud.records[0].Status != "DENIED" || aud.records[0].ErrorCode != "PERMISSION_DENIED" {
		t.Fatalf("audit=%+v", aud.records)
	}
}

func TestNoiseClusterSearch(t *testing.T) {
	r := NewRegistry()
	store := ainoise.NewMemStore()
	seedNoiseCluster(t, store)
	NewNoiseTools(r, store)
	res, _, err := r.Execute(context.Background(), adminPrincipal("ai.noise_reduction.use"), uuid.New(), nil,
		"noise_cluster.search", json.RawMessage(`{"source":"WAF","status":"ACTIVE"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.(map[string]interface{})
	if out["total"].(int64) != 1 {
		t.Fatalf("total=%v", out["total"])
	}
}

func TestNoiseClusterSearchInvalidEnum(t *testing.T) {
	r := NewRegistry()
	NewNoiseTools(r, ainoise.NewMemStore())
	_, _, err := r.Execute(context.Background(), adminPrincipal("ai.noise_reduction.use"), uuid.New(), nil,
		"noise_cluster.search", json.RawMessage(`{"status":"BOGUS"}`), nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err=%v want ErrInvalidInput", err)
	}
}

func TestNoiseClusterGet(t *testing.T) {
	r := NewRegistry()
	store := ainoise.NewMemStore()
	id := seedNoiseCluster(t, store)
	NewNoiseTools(r, store)
	p := adminPrincipal("ai.noise_reduction.use")

	// 非法 UUID → 输入错误
	_, _, err := r.Execute(context.Background(), p, uuid.New(), nil,
		"noise_cluster.get", json.RawMessage(`{"cluster_id":"not-a-uuid"}`), nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err=%v want ErrInvalidInput", err)
	}
	// 不存在 → 业务错误
	_, _, err = r.Execute(context.Background(), p, uuid.New(), nil,
		"noise_cluster.get", json.RawMessage(`{"cluster_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil {
		t.Fatal("missing cluster should error")
	}
	// 正常详情（含代表事件）
	res, _, err := r.Execute(context.Background(), p, uuid.New(), nil,
		"noise_cluster.get", json.RawMessage(`{"cluster_id":"`+id.String()+`"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := res.(map[string]interface{})
	c := out["cluster"].(*ainoise.Cluster)
	if c.ID != id || c.EventCount != 1 {
		t.Fatalf("cluster=%+v", c)
	}
	events := out["events"].([]ainoise.ClusterEvent)
	if len(events) != 1 || !events[0].IsRepresentative {
		t.Fatalf("events=%+v", events)
	}
}
