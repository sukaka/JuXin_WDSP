package nodeinterfaces

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func snap(ifname, media string, speed int64) SnapshotItem {
	return SnapshotItem{
		NodeName: "gw-1", Ifname: ifname, MAC: "00:11:22:33:44:" + ifname[len(ifname)-1:],
		PCIPath: "0000:03:00." + ifname[len(ifname)-1:], Driver: "igb",
		MediaType: media, LinkSpeed: speed, Operstate: "up",
		CollectedAt: time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC),
	}
}

func listIfaces(t *testing.T, s *MemStore, node string) []Interface {
	t.Helper()
	groups, err := s.ListGrouped(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		return nil
	}
	return groups[0].Interfaces
}

// 首次快照：按快照顺序编 sort_order（1..N），全部 present。
func TestApplySnapshot_InitialOrder(t *testing.T) {
	s := NewMemStore()
	seen := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	if err := s.ApplySnapshot(context.Background(), "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "FIBRE", 10000)}, seen); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Ifname != "eth0" || list[0].SortOrder != 1 || list[1].Ifname != "eth1" || list[1].SortOrder != 2 {
		t.Fatalf("order = %+v", list)
	}
	if !list[0].Present || !list[1].Present {
		t.Fatal("initial snapshot must be present")
	}
	if list[0].MediaType != MediaTP || list[1].MediaType != MediaFibre {
		t.Fatalf("media = %s/%s", list[0].MediaType, list[1].MediaType)
	}
	if !list[0].FirstSeenAt.Equal(seen) || !list[0].LastSeenAt.Equal(seen) {
		t.Fatal("seen timestamps not applied")
	}
}

// 用户排序/角色在后续快照中保留；新口排末尾；快照乱序不影响已保存顺序。
func TestApplySnapshot_PreservesUserOrderAndRole(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	seen := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	if err := s.ApplySnapshot(ctx, "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "TP", 1000), snap("eth2", "FIBRE", 10000)}, seen); err != nil {
		t.Fatal(err)
	}
	// 用户整体替换排序：eth2 排第 1，eth0 排第 2，eth1 排第 3；并标记角色
	if err := s.ReplaceOrder(ctx, "gw-1", []OrderItem{
		{Ifname: "eth2", SortOrder: 1, Role: RoleTraffic},
		{Ifname: "eth0", SortOrder: 2},
		{Ifname: "eth1", SortOrder: 3},
	}); err != nil {
		t.Fatal(err)
	}
	// 第二轮快照：乱序 + 新口 eth3 + 采集字段变化
	later := seen.Add(time.Minute)
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{
		snap("eth2", "FIBRE", 10000), snap("eth3", "FIBRE", 25000),
		snap("eth0", "TP", 100), snap("eth1", "TP", 1000),
	}, later); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	if len(list) != 4 {
		t.Fatalf("len = %d, want 4", len(list))
	}
	got := []string{list[0].Ifname, list[1].Ifname, list[2].Ifname, list[3].Ifname}
	want := []string{"eth2", "eth0", "eth1", "eth3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	if list[0].Role != RoleTraffic {
		t.Fatalf("role = %q, want TRAFFIC", list[0].Role)
	}
	if list[3].SortOrder != 4 {
		t.Fatalf("new iface sort_order = %d, want 4（排末尾）", list[3].SortOrder)
	}
	// 采集字段刷新但 first_seen_at 保留（eth3 为本轮新发现，first_seen_at 即本轮时间）
	for _, it := range list {
		if it.Ifname == "eth3" {
			if !it.FirstSeenAt.Equal(later) {
				t.Fatalf("eth3 first_seen_at = %v, want 本轮发现时间", it.FirstSeenAt)
			}
			continue
		}
		if !it.FirstSeenAt.Equal(seen) {
			t.Fatalf("%s first_seen_at 被覆盖: %v", it.Ifname, it.FirstSeenAt)
		}
		if !it.LastSeenAt.Equal(later) {
			t.Fatalf("%s last_seen_at 未刷新: %v", it.Ifname, it.LastSeenAt)
		}
	}
	eth0 := list[1]
	if eth0.LinkSpeed != 100 {
		t.Fatalf("eth0 link_speed = %d, want 100（采集刷新）", eth0.LinkSpeed)
	}
}

// 快照中消失的口保留并置 present=false；重新出现恢复原位与用户设定。
func TestApplySnapshot_DisappearedAndReappear(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	seen := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	if err := s.ApplySnapshot(ctx, "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "FIBRE", 10000)}, seen); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceOrder(ctx, "gw-1", []OrderItem{{Ifname: "eth1", SortOrder: 0, Role: RoleMirror}}); err != nil {
		t.Fatal(err)
	}
	// eth1 消失（拔卡）
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{snap("eth0", "TP", 1000)}, seen.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2（消失口保留）", len(list))
	}
	byName := map[string]Interface{}
	for _, it := range list {
		byName[it.Ifname] = it
	}
	gone := byName["eth1"]
	if gone.Present {
		t.Fatalf("eth1 = %+v, want present=false", gone)
	}
	if gone.SortOrder != 0 || gone.Role != RoleMirror {
		t.Fatalf("消失口用户设定被改动: %+v", gone)
	}
	// eth1 重新出现：present 恢复，sort_order/role 不变
	if err := s.ApplySnapshot(ctx, "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "FIBRE", 10000)}, seen.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	list = listIfaces(t, s, "gw-1")
	byName = map[string]Interface{}
	for _, it := range list {
		byName[it.Ifname] = it
	}
	if !byName["eth1"].Present || byName["eth1"].SortOrder != 0 || byName["eth1"].Role != RoleMirror {
		t.Fatalf("reappeared eth1 = %+v", byName["eth1"])
	}
}

// 介质类型无法识别时归一化为 UNKNOWN。
func TestApplySnapshot_MediaNormalization(t *testing.T) {
	s := NewMemStore()
	it := snap("eth0", "twisted-pair-something", 1000)
	if err := s.ApplySnapshot(context.Background(), "gw-1", []SnapshotItem{it}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	if list[0].MediaType != MediaUnknown {
		t.Fatalf("media = %s, want UNKNOWN", list[0].MediaType)
	}
}

// 混合部署（gateway 无 ethtool 报 UNKNOWN，mirrorcap 有 ethtool 报 TP/FIBRE）：
// 已有明确 MediaType 不被后续 UNKNOWN/空值覆盖；明确介质变更与从 UNKNOWN 升级仍正常刷新。
func TestApplySnapshot_PreservesKnownMediaTypeAgainstUnknown(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	t0 := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)

	// 第 1 轮（mirrorcap 带 ethtool）：eth0=TP, eth1=FIBRE, eth2=UNKNOWN
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{
		snap("eth0", MediaTP, 1000),
		snap("eth1", MediaFibre, 10000),
		snap("eth2", MediaUnknown, 1000),
	}, t0); err != nil {
		t.Fatal(err)
	}

	// 第 2 轮（gateway 无 ethtool）：上报 UNKNOWN / 空串，同时更新 link_speed
	t1 := t0.Add(time.Minute)
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{
		snap("eth0", MediaUnknown, 2500),
		snap("eth1", "", 10000),
		snap("eth2", MediaUnknown, 1000),
		snap("eth3", "", 100),
	}, t1); err != nil {
		t.Fatal(err)
	}
	byName := map[string]Interface{}
	for _, it := range listIfaces(t, s, "gw-1") {
		byName[it.Ifname] = it
	}
	if byName["eth0"].MediaType != MediaTP || byName["eth0"].LinkSpeed != 2500 || !byName["eth0"].LastSeenAt.Equal(t1) {
		t.Fatalf("eth0 = %+v, want media=TP preserved with refreshed speed/last_seen_at", byName["eth0"])
	}
	if byName["eth1"].MediaType != MediaFibre {
		t.Fatalf("eth1 media = %q, want FIBRE preserved against empty", byName["eth1"].MediaType)
	}
	if byName["eth2"].MediaType != MediaUnknown || byName["eth3"].MediaType != MediaUnknown {
		t.Fatalf("eth2=%q eth3=%q, want UNKNOWN", byName["eth2"].MediaType, byName["eth3"].MediaType)
	}

	// 第 3 轮：明确介质可正常升级（UNKNOWN→TP）与切换（TP→FIBRE）
	t2 := t1.Add(time.Minute)
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{
		snap("eth0", MediaFibre, 10000),
		snap("eth1", MediaFibre, 10000),
		snap("eth2", MediaTP, 1000),
	}, t2); err != nil {
		t.Fatal(err)
	}
	byName = map[string]Interface{}
	for _, it := range listIfaces(t, s, "gw-1") {
		byName[it.Ifname] = it
	}
	if byName["eth0"].MediaType != MediaFibre || byName["eth2"].MediaType != MediaTP {
		t.Fatalf("upgraded/changed media: eth0=%q eth2=%q, want FIBRE/TP", byName["eth0"].MediaType, byName["eth2"].MediaType)
	}

	// 直接校验 reconcile：任意非空且非 UNKNOWN 的已有 MediaType 均在 UNKNOWN/空值输入下保留
	merged := reconcile("gw-1", []Interface{
		{NodeName: "gw-1", Ifname: "eth9", MediaType: "COPPER", SortOrder: 1},
	}, []SnapshotItem{
		snap("eth9", MediaUnknown, 1000),
	}, t2)
	if len(merged) != 1 || merged[0].MediaType != "COPPER" {
		t.Fatalf("reconcile preserved non-UNKNOWN = %+v", merged)
	}
}

// 同一快照内重复 ifname 不产生重复记录。
func TestApplySnapshot_DuplicateInSnapshot(t *testing.T) {
	s := NewMemStore()
	if err := s.ApplySnapshot(context.Background(), "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth0", "TP", 100)}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	if list[0].LinkSpeed != 100 {
		t.Fatalf("link_speed = %d, want 100（重复行按刷新处理）", list[0].LinkSpeed)
	}
}

// ReplaceOrder：引用不存在的接口返回 ErrUnknownInterface；role 恒传（空串 = 清除角色）。
func TestReplaceOrder_Validation(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	if err := s.ApplySnapshot(ctx, "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "TP", 1000)}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceOrder(ctx, "gw-1", []OrderItem{{Ifname: "eth0", SortOrder: 5, Role: RoleManagement}}); err != nil {
		t.Fatal(err)
	}
	// role 空串 → 清除角色
	if err := s.ReplaceOrder(ctx, "gw-1", []OrderItem{{Ifname: "eth0", SortOrder: 7, Role: ""}}); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	var eth0 *Interface
	for i := range list {
		if list[i].Ifname == "eth0" {
			eth0 = &list[i]
		}
	}
	if eth0 == nil || eth0.SortOrder != 7 || eth0.Role != "" {
		t.Fatalf("eth0 = %+v, want sort_order=7 role 已清除", eth0)
	}
	// 不存在的接口
	err := s.ReplaceOrder(ctx, "gw-1", []OrderItem{{Ifname: "eth9", SortOrder: 1}})
	if !errors.Is(err, ErrUnknownInterface) {
		t.Fatalf("err = %v, want ErrUnknownInterface", err)
	}
}

// ListGrouped：多节点分组 + 节点过滤。
func TestListGrouped_MultiNode(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	seen := time.Now().UTC()
	if err := s.ApplySnapshot(ctx, "gw-2", []SnapshotItem{snap("eth0", "TP", 1000)}, seen); err != nil {
		t.Fatal(err)
	}
	b := snap("eth0", "FIBRE", 10000)
	b.NodeName = "gw-1"
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{b}, seen); err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListGrouped(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0].NodeName != "gw-1" || groups[1].NodeName != "gw-2" {
		t.Fatalf("groups = %+v", groups)
	}
	groups, err = s.ListGrouped(ctx, "gw-2")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].NodeName != "gw-2" {
		t.Fatalf("filtered groups = %+v", groups)
	}
}

// IP 地址清洗、IPv4 优先排序、旧上报端省略时保留已有值、显式空数组清空。
func TestApplySnapshot_IPAddressesMergeAndNormalize(t *testing.T) {
	ctx := context.Background()
	s := NewMemStore()
	t0 := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)

	it0 := snap("eth0", MediaTP, 1000)
	it0.IPAddresses = []string{"2408:8207::10/64", "192.168.1.20/24", "10.0.0.5/24", "10.0.0.5/24", "bad-ip", " "}
	it1 := snap("eth1", MediaTP, 1000)
	// it1.IPAddresses == nil（旧版上报未带字段）
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{it0, it1}, t0); err != nil {
		t.Fatal(err)
	}
	list := listIfaces(t, s, "gw-1")
	want0 := []string{"10.0.0.5/24", "192.168.1.20/24", "2408:8207::10/64"}
	if !reflect.DeepEqual(list[0].IPAddresses, want0) {
		t.Fatalf("eth0 ip_addresses = %v, want %v", list[0].IPAddresses, want0)
	}
	if list[1].IPAddresses == nil || len(list[1].IPAddresses) != 0 {
		t.Fatalf("eth1 ip_addresses should be non-nil empty slice, got %#v", list[1].IPAddresses)
	}

	// 旧版上报（IPAddresses==nil）不清空已有 IP；新版显式上报 [] 会清空
	t1 := t0.Add(time.Minute)
	legacyEth0 := snap("eth0", MediaTP, 1000) // IPAddresses == nil
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{legacyEth0, it1}, t1); err != nil {
		t.Fatal(err)
	}
	list = listIfaces(t, s, "gw-1")
	if !reflect.DeepEqual(list[0].IPAddresses, want0) {
		t.Fatalf("eth0 ip_addresses overwritten by nil snapshot: %v", list[0].IPAddresses)
	}

	t2 := t1.Add(time.Minute)
	clearedEth0 := snap("eth0", MediaTP, 1000)
	clearedEth0.IPAddresses = []string{} // 显式空数组：表示网口已无 IP
	if err := s.ApplySnapshot(ctx, "gw-1", []SnapshotItem{clearedEth0, it1}, t2); err != nil {
		t.Fatal(err)
	}
	list = listIfaces(t, s, "gw-1")
	if list[0].IPAddresses == nil || len(list[0].IPAddresses) != 0 {
		t.Fatalf("eth0 ip_addresses should clear on explicit empty slice, got %#v", list[0].IPAddresses)
	}
}
