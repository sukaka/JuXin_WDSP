// readiness_test.go readiness 派生矩阵（D9：六态 + PROTECT_ACTIVE + reasons 全列）、
// 窗口词表、对象模型行选定、能力版本比较、确认文案。
package apiauthzwizard

import (
	"strings"
	"testing"
)

// 全绿基线（READY 形态输入）。
func readyInput() ReadinessInput {
	return ReadinessInput{
		Publishable: true, RequiredRelation: "OWNER", OwnerExclusive: true, EndpointConfirmed: true,
		HasEffectiveOwnerRelation: true,
	}
}

func TestDeriveReadinessMatrix(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*ReadinessInput)
		wantBadge   string
		wantReasons []string // 每组全部期望因子（reasons 全列，不漏首个以后）
	}{
		{"READY 全因子真", func(*ReadinessInput) {}, ReadinessReady, nil},
		{"NOT_PUBLISHABLE publishable=false", func(i *ReadinessInput) { i.Publishable = false },
			ReadinessNotPublishable, []string{"publishable=false"}},
		{"NOT_PUBLISHABLE 关系词非 OWNER", func(i *ReadinessInput) { i.RequiredRelation = "" },
			ReadinessNotPublishable, []string{"required_relation≠OWNER"}},
		{"NOT_PUBLISHABLE 排他未声明", func(i *ReadinessInput) { i.OwnerExclusive = false },
			ReadinessNotPublishable, []string{"owner_exclusive=false"}},
		{"NOT_PUBLISHABLE 端点未确认", func(i *ReadinessInput) { i.EndpointConfirmed = false },
			ReadinessNotPublishable, []string{"非 CONFIRMED"}},
		{"NOT_PUBLISHABLE 多因子全列", func(i *ReadinessInput) { i.Publishable = false; i.OwnerExclusive = false },
			ReadinessNotPublishable, []string{"publishable=false", "owner_exclusive=false"}},
		{"BLOCKED_BY_CONFLICT", func(i *ReadinessInput) { i.HasOpenConflict = true },
			ReadinessBlockedByConflict, []string{"OPEN 冲突"}},
		{"BLOCKED_BY_NO_RELATION", func(i *ReadinessInput) { i.HasEffectiveOwnerRelation = false },
			ReadinessBlockedByNoRelation, []string{"无有效 OWNER 关系"}},
		{"BLOCKED_BY_STALE 快照过期", func(i *ReadinessInput) { i.SnapshotExpired = true },
			ReadinessBlockedByStale, []string{"快照已过期"}},
		{"BLOCKED_BY_STALE 租约过期", func(i *ReadinessInput) { i.LeaseExpired = true },
			ReadinessBlockedByStale, []string{"租约已过期"}},
		{"BLOCKED_BY_STALE 时钟偏差", func(i *ReadinessInput) { i.ClockSkew = true },
			ReadinessBlockedByStale, []string{"时钟偏差"}},
		{"BLOCKED_BY_NODE ACK 非 FRESH", func(i *ReadinessInput) { i.NodeNotFresh = true },
			ReadinessBlockedByNode, []string{"ACK 非 FRESH"}},
		{"BLOCKED_BY_NODE 能力不足", func(i *ReadinessInput) { i.NodeCapabilityLow = true },
			ReadinessBlockedByNode, []string{"az/3"}},
		{"优先级：资格先于冲突", func(i *ReadinessInput) { i.Publishable = false; i.HasOpenConflict = true },
			ReadinessNotPublishable, []string{"publishable=false", "OPEN 冲突"}},
		{"优先级：冲突先于无关系", func(i *ReadinessInput) { i.HasOpenConflict = true; i.HasEffectiveOwnerRelation = false },
			ReadinessBlockedByConflict, []string{"OPEN 冲突", "无有效 OWNER 关系"}},
		{"优先级：时效先于节点", func(i *ReadinessInput) { i.LeaseExpired = true; i.NodeNotFresh = true },
			ReadinessBlockedByStale, []string{"租约已过期", "ACK 非 FRESH"}},
		{"PROTECT_ACTIVE 展示态覆盖", func(i *ReadinessInput) { i.Enforcement = "PROTECT"; i.HasOpenConflict = true },
			ReadinessProtectActive, []string{"OPEN 冲突"}},
		{"PROTECT_ACTIVE 全绿同样展示", func(i *ReadinessInput) { i.Enforcement = "protect" },
			ReadinessProtectActive, nil},
		{"节点状态明细原文随 reasons 带出", func(i *ReadinessInput) {
			i.NodeNotFresh = true
			i.NodeStateReasons = []string{"节点 gw-1：NEVER_ACKED（授权快照未达最新）"}
		}, ReadinessBlockedByNode, []string{"ACK 非 FRESH", "gw-1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := readyInput()
			c.mutate(&in)
			badge, reasons := DeriveReadiness(in)
			if badge != c.wantBadge {
				t.Fatalf("badge=%s want %s (reasons=%v)", badge, c.wantBadge, reasons)
			}
			for _, want := range c.wantReasons {
				found := false
				for _, r := range reasons {
					if strings.Contains(r, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("reasons 缺 %q: %v", want, reasons)
				}
			}
			if badge == ReadinessReady && len(reasons) != 0 {
				t.Fatalf("READY 不应带阻塞 reasons: %v", reasons)
			}
		})
	}
}

func TestValidateWindow(t *testing.T) {
	for _, d := range []int{1, 7, 30} {
		if msg := validateWindow(d); msg != "" {
			t.Fatalf("window_days=%d 应合法: %s", d, msg)
		}
	}
	for _, d := range []int{0, -1, 31, 365} {
		msg := validateWindow(d)
		if msg == "" || !strings.Contains(msg, "1~30") {
			t.Fatalf("window_days=%d 应词表外拒收: %q", d, msg)
		}
	}
}

func TestSelectModelRow(t *testing.T) {
	rowA := ObjectModelRow{ObjectSegment: "path:3"}
	rowB := ObjectModelRow{ObjectSegment: "query:account_id"}
	if _, msg := selectModelRow(nil, ""); msg == "" {
		t.Fatal("零行应提示无对象模型行")
	}
	if r, msg := selectModelRow([]ObjectModelRow{rowA}, ""); msg != "" || r.ObjectSegment != "path:3" {
		t.Fatalf("恰一行自动选定: %v %q", r, msg)
	}
	if _, msg := selectModelRow([]ObjectModelRow{rowA, rowB}, ""); msg == "" || !strings.Contains(msg, "path:3") || !strings.Contains(msg, "query:account_id") {
		t.Fatalf("多行未指定应列出候选: %q", msg)
	}
	if r, msg := selectModelRow([]ObjectModelRow{rowA, rowB}, "query:account_id"); msg != "" || r.ObjectSegment != "query:account_id" {
		t.Fatalf("多行指定选定: %v %q", r, msg)
	}
	if _, msg := selectModelRow([]ObjectModelRow{rowA}, "query:nope"); msg == "" {
		t.Fatal("指定不匹配应拒绝")
	}
}

func TestAzVersionAtLeast(t *testing.T) {
	cases := map[string]bool{"az/3": true, "az/10": true, "az/2": false, "az/1": false, "az": false, "": false, "grpc/3": false}
	for v, want := range cases {
		if got := azVersionAtLeast(v, 3); got != want {
			t.Fatalf("azVersionAtLeast(%q, 3)=%t want %t", v, got, want)
		}
	}
}

func TestConfirmTextV1(t *testing.T) {
	text := confirmTextV1(7, 12, 5, "zhang.lei")
	for _, want := range []string{"UNKNOWN 永不阻断", "近 7 天", "12 次", "5 个", "zhang.lei", "确认文案 v1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("确认文案缺 %q: %s", want, text)
		}
	}
}

func TestObjectTypeOf(t *testing.T) {
	cases := []struct{ path, segment, want string }{
		{"/v1/orders/{id}", "path:2", "orders"},
		{"/api/v1/tenants/{id}/projects/p002/items", "path:3", "tenants"},
		{"/v1/orders", "query:order_id", "order_id"},
		{"/v1/orders/{id}", "path:9", ""},
		{"/v1/orders", "header:X-Object", ""},
	}
	for _, c := range cases {
		if got := objectTypeOf(c.path, c.segment); got != c.want {
			t.Fatalf("objectTypeOf(%q, %q)=%q want %q", c.path, c.segment, got, c.want)
		}
	}
}

func TestEndpointKeyPattern(t *testing.T) {
	pattern := endpointKeyPattern("GET /api/v1/tenants/{id}/projects/p002/items")
	if pattern != `GET /api/v1/tenants/%/projects/p002/items` {
		t.Fatalf("pattern=%q", pattern)
	}
	// LIKE 特殊字符转义（%_ 与反斜杠）
	if got := endpointKeyPattern("GET /v1/a_b/c%d/{id}"); got != `GET /v1/a\_b/c\%d/%` {
		t.Fatalf("escape pattern=%q", got)
	}
	// 键族匹配语义：模板键（1001→{id} 归一恰等模板）与字面键（t001）同族
	for _, key := range []string{
		"GET /api/v1/tenants/{id}/projects/p002/items",
		"GET /api/v1/tenants/t001/projects/p002/items",
		"GET /api/v1/tenants/1001/projects/p002/items",
	} {
		if !likeMatch(pattern, key) {
			t.Fatalf("%q 应匹配键族模式 %q", key, pattern)
		}
	}
	if likeMatch(pattern, "GET /api/v1/tenants/t001/projects/p003/items") {
		t.Fatal("后缀不符不得匹配")
	}
}

// likeMatch 测试侧 LIKE 语义简化判定（% 通配单段任意字符含 {id} 字面）。
func likeMatch(pattern, s string) bool {
	pp, sp := strings.Split(pattern, "/"), strings.Split(s, "/")
	if len(pp) != len(sp) {
		return false
	}
	for i := range pp {
		if pp[i] == "%" {
			continue
		}
		if pp[i] != sp[i] {
			return false
		}
	}
	return true
}
