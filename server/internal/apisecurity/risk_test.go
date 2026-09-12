// risk_test.go 风险中心领域测试：状态机迁移矩阵（合法/非法全组合）、内存仓储流转语义、
// 三视图降噪聚合、关联 request_id（不依赖数据库）。
package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRiskTransitionMatrix 状态机迁移矩阵：6 动作 × 7 状态全组合，合法迁移命中目标态，
// 表外组合一律非法。
func TestRiskTransitionMatrix(t *testing.T) {
	statuses := []string{
		RiskStatusNew, RiskStatusConfirmed, RiskStatusInProgress,
		RiskStatusFalsePositive, RiskStatusIgnored, RiskStatusResolved, RiskStatusArchived,
	}
	actions := []string{
		RiskActionConfirm, RiskActionStart, RiskActionResolve,
		RiskActionFalsePositive, RiskActionIgnore, RiskActionArchive,
	}
	// 合法迁移表（action, from）→ to
	legal := map[[3]string]bool{}
	for action, byFrom := range riskTransitions {
		for from, to := range byFrom {
			legal[[3]string{action, from, to}] = true
		}
	}
	legalCount := 0
	for _, action := range actions {
		for _, from := range statuses {
			to, ok := ResolveRiskTransition(action, from)
			if legal[[3]string{action, from, to}] {
				if !ok {
					t.Fatalf("legal transition %s from %s rejected", action, from)
				}
				legalCount++
				continue
			}
			if ok {
				t.Fatalf("illegal transition %s from %s accepted (-> %s)", action, from, to)
			}
		}
	}
	// 精确锚定合法迁移条目数（防状态机表被意外放宽）
	if legalCount != 13 {
		t.Fatalf("legal transitions=%d, want 13", legalCount)
	}
	// 未知动作/未知状态一律非法
	if _, ok := ResolveRiskTransition("DELETE", RiskStatusNew); ok {
		t.Fatal("unknown action accepted")
	}
	if _, ok := ResolveRiskTransition(RiskActionConfirm, "OPEN"); ok {
		t.Fatal("legacy status OPEN must not be a valid source")
	}
}

// TestRiskTransitionMatrixSpotCheck 关键路径点查（防迁移表整体错位）。
func TestRiskTransitionMatrixSpotCheck(t *testing.T) {
	cases := []struct{ action, from, to string }{
		{RiskActionConfirm, RiskStatusNew, RiskStatusConfirmed},
		{RiskActionStart, RiskStatusConfirmed, RiskStatusInProgress},
		{RiskActionResolve, RiskStatusInProgress, RiskStatusResolved},
		{RiskActionFalsePositive, RiskStatusNew, RiskStatusFalsePositive},
		{RiskActionIgnore, RiskStatusInProgress, RiskStatusIgnored},
		{RiskActionArchive, RiskStatusResolved, RiskStatusArchived},
	}
	for _, c := range cases {
		to, ok := ResolveRiskTransition(c.action, c.from)
		if !ok || to != c.to {
			t.Fatalf("%s from %s: to=%s ok=%v, want %s", c.action, c.from, to, ok, c.to)
		}
	}
	// 终态 ARCHIVED 任何动作非法；NEW 不能直接 start/resolve/archive
	for _, action := range []string{RiskActionConfirm, RiskActionStart, RiskActionResolve, RiskActionFalsePositive, RiskActionIgnore, RiskActionArchive} {
		if _, ok := ResolveRiskTransition(action, RiskStatusArchived); ok {
			t.Fatalf("ARCHIVED must be terminal, %s accepted", action)
		}
	}
	for _, action := range []string{RiskActionStart, RiskActionResolve, RiskActionArchive} {
		if _, ok := ResolveRiskTransition(action, RiskStatusNew); ok {
			t.Fatalf("NEW must not accept %s", action)
		}
	}
}

// TestRiskStatusHelpers 状态白名单与活动口径。
func TestRiskStatusHelpers(t *testing.T) {
	for _, s := range []string{"NEW", "CONFIRMED", "IN_PROGRESS", "FALSE_POSITIVE", "IGNORED", "RESOLVED", "ARCHIVED"} {
		if !IsValidRiskStatus(s) {
			t.Fatalf("%s must be valid", s)
		}
	}
	for _, s := range []string{"OPEN", "ACKNOWLEDGED", "", "new"} {
		if IsValidRiskStatus(s) {
			t.Fatalf("%s must be invalid", s)
		}
	}
	for _, s := range []string{"NEW", "CONFIRMED", "IN_PROGRESS"} {
		if !IsRiskActiveStatus(s) {
			t.Fatalf("%s must be active", s)
		}
	}
	for _, s := range []string{"FALSE_POSITIVE", "IGNORED", "RESOLVED", "ARCHIVED"} {
		if IsRiskActiveStatus(s) {
			t.Fatalf("%s must not be active", s)
		}
	}
}

// newSeededFinding 构造一条 NEW 状态风险（detail 带首次命中上下文）。
func newSeededFinding(endpointID *uuid.UUID) *RiskFinding {
	now := time.Now().UTC().Truncate(time.Second)
	return &RiskFinding{
		ID:          uuid.New(),
		EndpointID:  endpointID,
		RequestID:   "req-1",
		FindingType: "BOLA",
		Severity:    "HIGH",
		Status:      RiskStatusNew,
		Title:       "疑似越权访问",
		Detail:      json.RawMessage(`{"detector":"bola","rule_id":"resource.sequential_id"}`),
		Count:       3,
		Evidence:    json.RawMessage(`{"field":"id","type":"integer"}`),
		FirstSeenAt: now.Add(-time.Hour),
		LastSeenAt:  now,
		CreatedAt:   now.Add(-time.Hour),
	}
}

// TestRiskMemTransition 内存仓储流转：状态更新 + detail.handling 合并（保留原有键）+
// UpdatedAt；非法迁移 ErrInvalidRiskTransition；不存在 ErrNotFound。
func TestRiskMemTransition(t *testing.T) {
	ctx := context.Background()
	mem := NewRiskMemStore()
	f := newSeededFinding(nil)
	mem.SeedFinding(f)

	if _, err := mem.TransitionFinding(ctx, uuid.New(), RiskActionConfirm, RiskHandleInput{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing id err=%v, want ErrNotFound", err)
	}
	if _, err := mem.TransitionFinding(ctx, f.ID, RiskActionStart, RiskHandleInput{}); !errors.Is(err, ErrInvalidRiskTransition) {
		t.Fatalf("start from NEW err=%v, want ErrInvalidRiskTransition", err)
	}

	at := time.Now().UTC().Truncate(time.Second)
	updated, err := mem.TransitionFinding(ctx, f.ID, RiskActionConfirm, RiskHandleInput{Actor: "tester", Note: "确认是风险", Now: at})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != RiskStatusConfirmed || updated.UpdatedAt == nil || !updated.UpdatedAt.Equal(at) {
		t.Fatalf("updated: %+v", updated)
	}
	// detail.handling 合并且保留首次命中上下文
	var detail map[string]any
	if err := json.Unmarshal(updated.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail["rule_id"] != "resource.sequential_id" {
		t.Fatalf("detail original keys lost: %v", detail)
	}
	handling, ok := detail["handling"].(map[string]any)
	if !ok || handling["action"] != RiskActionConfirm || handling["actor"] != "tester" || handling["note"] != "确认是风险" {
		t.Fatalf("handling: %v", detail["handling"])
	}
	// 内存拷贝隔离：返回对象改动不影响仓储内状态
	updated.Status = "HACKED"
	again, err := mem.GetFinding(ctx, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Status != RiskStatusConfirmed {
		t.Fatalf("store mutated via returned pointer: %s", again.Status)
	}
}

// TestRiskMemSummary 三视图聚合：count/hits/max_severity/last_seen 与排序。
func TestRiskMemSummary(t *testing.T) {
	mem := NewRiskMemStore()
	epA := uuid.New()
	epB := uuid.New()
	mem.SetEndpointKey(epA, "GET /api/users/{id}")
	mem.SetEndpointKey(epB, "POST /api/orders")
	now := time.Now().UTC().Truncate(time.Second)
	mk := func(epID *uuid.UUID, subjType, subjID, ftype, sev string, count int, lastSeen time.Time) *RiskFinding {
		f := newSeededFinding(epID)
		f.ID = uuid.Nil // 由 SeedFinding 分配
		f.SubjectType, f.SubjectID = subjType, subjID
		f.FindingType, f.Severity, f.Count = ftype, sev, count
		f.LastSeenAt = lastSeen
		return f
	}
	// 主体 fp-1 两条（HIGH×3 + LOW×2），fp-2 一条（CRITICAL×1），匿名一条
	mem.SeedFinding(mk(&epA, "IDENTITY", "fp-1", "BOLA", "HIGH", 3, now))
	mem.SeedFinding(mk(&epA, "IDENTITY", "fp-1", "SCHEMA_DEVIATION", "LOW", 2, now.Add(-time.Hour)))
	mem.SeedFinding(mk(&epB, "IDENTITY", "fp-2", "SENSITIVE_LEAK", "CRITICAL", 1, now.Add(-30*time.Minute)))
	mem.SeedFinding(mk(nil, "", "", "SHADOW", "MEDIUM", 5, now.Add(-2*time.Hour)))

	sum, err := mem.SummarizeFindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 主体视图：3 桶（fp-1 / fp-2 / 匿名）；排序 max_severity DESC → CRITICAL(fp-2) 最前
	if len(sum.BySubject) != 3 {
		t.Fatalf("by_subject=%d, want 3", len(sum.BySubject))
	}
	first := sum.BySubject[0]
	if first.SubjectID != "fp-2" || first.MaxSeverity != "CRITICAL" || first.Count != 1 || first.Hits != 1 {
		t.Fatalf("by_subject[0]: %+v", first)
	}
	var fp1 *RiskSummaryBucket
	for i := range sum.BySubject {
		if sum.BySubject[i].SubjectID == "fp-1" {
			fp1 = &sum.BySubject[i]
		}
	}
	if fp1 == nil || fp1.Count != 2 || fp1.Hits != 5 || fp1.MaxSeverity != "HIGH" || !fp1.LastSeenAt.Equal(now) {
		t.Fatalf("fp-1 bucket: %+v", fp1)
	}
	// 端点视图：3 桶（epA / epB / NULL 端点）；epA 桶带出 endpoint_key
	if len(sum.ByEndpoint) != 3 {
		t.Fatalf("by_endpoint=%d, want 3", len(sum.ByEndpoint))
	}
	var epABucket *RiskSummaryBucket
	for i := range sum.ByEndpoint {
		if sum.ByEndpoint[i].EndpointID != nil && *sum.ByEndpoint[i].EndpointID == epA {
			epABucket = &sum.ByEndpoint[i]
		}
	}
	if epABucket == nil || epABucket.EndpointKey != "GET /api/users/{id}" || epABucket.Count != 2 || epABucket.Hits != 5 || epABucket.MaxSeverity != "HIGH" {
		t.Fatalf("epA bucket: %+v", epABucket)
	}
	// 类型视图：4 桶，各自计数
	if len(sum.ByFindingType) != 4 {
		t.Fatalf("by_finding_type=%d, want 4", len(sum.ByFindingType))
	}
	typeHits := map[string]int64{}
	for _, b := range sum.ByFindingType {
		typeHits[b.FindingType] = b.Hits
	}
	if typeHits["BOLA"] != 3 || typeHits["SCHEMA_DEVIATION"] != 2 || typeHits["SENSITIVE_LEAK"] != 1 || typeHits["SHADOW"] != 5 {
		t.Fatalf("type hits: %v", typeHits)
	}
}

// TestRiskMemRelatedRequestIDs 关联 request_id：同端点过滤、IDENTITY 主体指纹过滤、
// occurred_at 倒序、上限截断。
func TestRiskMemRelatedRequestIDs(t *testing.T) {
	mem := NewRiskMemStore()
	now := time.Now().UTC()
	mem.SeedEvent("GET /a", "fp-1", "rid-old", now.Add(-time.Hour))
	mem.SeedEvent("GET /a", "fp-2", "rid-other-identity", now) // 其他身份
	mem.SeedEvent("GET /a", "fp-1", "rid-new", now)
	mem.SeedEvent("GET /b", "fp-1", "rid-other-endpoint", now) // 其他端点

	// IDENTITY 主体：同端点 + 同身份指纹，倒序
	ids, err := mem.ListRelatedRequestIDs(context.Background(), "GET /a", "IDENTITY", "fp-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "rid-new" || ids[1] != "rid-old" {
		t.Fatalf("identity related: %v", ids)
	}
	// IP 主体：无身份过滤（事件表无来源指纹列），同端点全部
	ids, err = mem.ListRelatedRequestIDs(context.Background(), "GET /a", "IP", "src-fp", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("ip related: %v", ids)
	}
	// limit 截断
	ids, err = mem.ListRelatedRequestIDs(context.Background(), "GET /a", "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("limited related: %v", ids)
	}
	// 无匹配端点 → 空列表
	ids, err = mem.ListRelatedRequestIDs(context.Background(), "GET /none", "", "", 0)
	if err != nil || len(ids) != 0 {
		t.Fatalf("none related: %v err=%v", ids, err)
	}
}
