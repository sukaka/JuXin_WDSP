package sitediscovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleInput() DiscoveryInput {
	return DiscoveryInput{
		Node: "gw-1", Domain: "Example.COM ", IP: "10.0.0.5", Port: 443,
		Protocol: "HTTPS", SourceMode: "MIRROR", Hits: 10, ClientCount: 3,
		WindowStart: time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 8, 21, 4, 0, 30, 0, time.UTC),
	}
}

// Upsert 幂等/累加/不覆盖人工字段（MemStore 与 SQL 仓储共用同一语义契约）。
func TestUpsertAccumulateAndPreserve(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()

	d1, err := store.Upsert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	// domain 归一化（trim + 小写）
	if d1.Domain != "example.com" || d1.Status != StatusNew || d1.SeenCount != 10 || d1.ClientCount != 3 {
		t.Fatalf("first insert: %+v", d1)
	}
	if d1.FirstSeen != sampleInput().WindowStart || d1.LastSeen != sampleInput().WindowEnd {
		t.Fatalf("window times: %+v", d1)
	}

	// 命中：seen_count 累加，client_count/last_seen/gateway_node 覆盖
	in2 := sampleInput()
	in2.Hits = 5
	in2.ClientCount = 9
	in2.Node = "gw-2"
	in2.WindowEnd = in2.WindowEnd.Add(30 * time.Second)
	d2, err := store.Upsert(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.ID != d1.ID || d2.SeenCount != 15 || d2.ClientCount != 9 ||
		d2.GatewayNode != "gw-2" || !d2.LastSeen.Equal(in2.WindowEnd) {
		t.Fatalf("accumulate: %+v", d2)
	}
	if !d2.FirstSeen.Equal(d1.FirstSeen) {
		t.Fatalf("first_seen must keep first insert value: %+v", d2)
	}

	// 人工处置后命中：status/confirmed_by/confirmed_at 不覆盖
	if _, err := store.Confirm(ctx, d1.ID, "secadmin"); err != nil {
		t.Fatal(err)
	}
	d3, err := store.Upsert(ctx, in2)
	if err != nil {
		t.Fatal(err)
	}
	if d3.Status != StatusConfirmed || d3.ConfirmedBy != "secadmin" || d3.ConfirmedAt == nil {
		t.Fatalf("upsert must not overwrite manual fields: %+v", d3)
	}
	if d3.SeenCount != 20 {
		t.Fatalf("seen_count keep accumulating: %+v", d3)
	}
}

// Upsert 参数校验：非法 ip/port/protocol 返回 ErrInvalidInput。
func TestUpsertValidation(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	cases := []struct {
		name string
		mut  func(*DiscoveryInput)
	}{
		{"bad ip", func(in *DiscoveryInput) { in.IP = "not-an-ip" }},
		{"empty ip", func(in *DiscoveryInput) { in.IP = "" }},
		{"port zero", func(in *DiscoveryInput) { in.Port = 0 }},
		{"port too large", func(in *DiscoveryInput) { in.Port = 70000 }},
		{"bad protocol", func(in *DiscoveryInput) { in.Protocol = "FTP" }},
		{"bad source_mode", func(in *DiscoveryInput) { in.SourceMode = "SNIFF" }},
		{"negative hits", func(in *DiscoveryInput) { in.Hits = -1 }},
	}
	for _, tc := range cases {
		in := sampleInput()
		tc.mut(&in)
		if _, err := store.Upsert(ctx, in); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: err=%v, want ErrInvalidInput", tc.name, err)
		}
	}
	// window 缺零值：容错回落 now（不为 ErrInvalidInput）
	in := sampleInput()
	in.WindowStart, in.WindowEnd = time.Time{}, time.Time{}
	d, err := store.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("zero windows tolerated: %v", err)
	}
	if d.FirstSeen.IsZero() || d.LastSeen.IsZero() {
		t.Fatalf("zero windows must fall back to now: %+v", d)
	}
	// IPv6 合法
	in = sampleInput()
	in.IP = "2001:db8::1"
	in.Port = 80
	in.Protocol = "HTTP"
	if _, err := store.Upsert(ctx, in); err != nil {
		t.Fatalf("ipv6: %v", err)
	}
}

// List 过滤与分页（status/protocol/source_mode/keyword + last_seen DESC）。
func TestListFiltersAndPagination(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	base := time.Date(2026, 8, 21, 4, 0, 0, 0, time.UTC)
	mk := func(domain, ip string, port int, proto, mode string, end time.Time) {
		in := sampleInput()
		in.Domain, in.IP, in.Port, in.Protocol, in.SourceMode = domain, ip, port, proto, mode
		in.WindowStart, in.WindowEnd = end.Add(-30*time.Second), end
		if _, err := store.Upsert(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.example.com", "10.0.0.1", 443, "HTTPS", SourceModeMirror, base)
	mk("b.example.com", "10.0.0.2", 80, "HTTP", SourceModeRouted, base.Add(time.Minute))
	mk("", "10.0.0.3", 8443, "HTTPS", SourceModeTransparent, base.Add(2*time.Minute))

	// 默认排序 last_seen DESC
	list, total, err := store.List(ctx, ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 3 || len(list) != 3 {
		t.Fatalf("list all: total=%d len=%d err=%v", total, len(list), err)
	}
	if list[0].IP != "10.0.0.3" || list[2].IP != "10.0.0.1" {
		t.Fatalf("order: %+v", list)
	}
	// status 过滤
	if _, err := store.Ignore(ctx, list[0].ID, "op"); err != nil {
		t.Fatal(err)
	}
	list, total, _ = store.List(ctx, ListFilter{Status: StatusIgnored, Page: 1, PageSize: 20})
	if total != 1 || list[0].IP != "10.0.0.3" {
		t.Fatalf("status filter: total=%d %+v", total, list)
	}
	// protocol / source_mode 过滤
	_, total, _ = store.List(ctx, ListFilter{Protocol: ProtocolHTTP, Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("protocol filter total=%d", total)
	}
	_, total, _ = store.List(ctx, ListFilter{SourceMode: SourceModeMirror, Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("source_mode filter total=%d", total)
	}
	// keyword 命中 domain 与 ip
	_, total, _ = store.List(ctx, ListFilter{Keyword: "example.com", Page: 1, PageSize: 20})
	if total != 2 {
		t.Fatalf("keyword domain total=%d", total)
	}
	_, total, _ = store.List(ctx, ListFilter{Keyword: "10.0.0.2", Page: 1, PageSize: 20})
	if total != 1 {
		t.Fatalf("keyword ip total=%d", total)
	}
	// 分页
	list, total, _ = store.List(ctx, ListFilter{Page: 2, PageSize: 2})
	if total != 3 || len(list) != 1 {
		t.Fatalf("page 2: total=%d len=%d", total, len(list))
	}
	// page_size 超限回落默认 20
	list, _, _ = store.List(ctx, ListFilter{Page: 1, PageSize: 500})
	if len(list) != 3 {
		t.Fatalf("page_size clamp: len=%d", len(list))
	}
}

// 状态机流转：NEW→CONFIRMED→IGNORED→NEW；非法流转返回 ErrInvalidTransition。
func TestStateMachine(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	d, err := store.Upsert(ctx, sampleInput())
	if err != nil {
		t.Fatal(err)
	}

	// Confirm：写处置字段
	c, err := store.Confirm(ctx, d.ID, "secadmin")
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusConfirmed || c.ConfirmedBy != "secadmin" || c.ConfirmedAt == nil {
		t.Fatalf("confirm: %+v", c)
	}
	// Confirm 幂等（重复确认不报错）
	if _, err := store.Confirm(ctx, d.ID, "secadmin"); err != nil {
		t.Fatalf("confirm idempotent: %v", err)
	}
	// Ignore：CONFIRMED→IGNORED
	ig, err := store.Ignore(ctx, d.ID, "secadmin")
	if err != nil {
		t.Fatal(err)
	}
	if ig.Status != StatusIgnored {
		t.Fatalf("ignore: %+v", ig)
	}
	// Restore：清空处置字段回 NEW
	rs, err := store.Restore(ctx, d.ID, "secadmin")
	if err != nil {
		t.Fatal(err)
	}
	if rs.Status != StatusNew || rs.ConfirmedBy != "" || rs.ConfirmedAt != nil {
		t.Fatalf("restore: %+v", rs)
	}
	// Restore 源状态非法（NEW 不可恢复）
	if _, err := store.Restore(ctx, d.ID, "secadmin"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("restore from NEW: %v, want ErrInvalidTransition", err)
	}
	// Confirm 源状态非法（IGNORED 需先恢复）
	if _, err := store.Ignore(ctx, d.ID, "secadmin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm(ctx, d.ID, "secadmin"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("confirm from IGNORED: %v, want ErrInvalidTransition", err)
	}
	// 不存在：ErrNotFound
	if _, err := store.Confirm(ctx, uuid.New(), "secadmin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("confirm missing: %v, want ErrNotFound", err)
	}
	if _, err := store.Ignore(ctx, uuid.New(), "secadmin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ignore missing: %v, want ErrNotFound", err)
	}
	if _, err := store.Restore(ctx, uuid.New(), "secadmin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restore missing: %v, want ErrNotFound", err)
	}
	if _, err := store.GetByID(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v, want ErrNotFound", err)
	}
}
