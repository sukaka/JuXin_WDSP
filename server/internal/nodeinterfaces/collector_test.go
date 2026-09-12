package nodeinterfaces

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 快照文件缺失：正常空转，不报错。
func TestCollectOnce_MissingFile(t *testing.T) {
	c := NewCollector(NewMemStore(), "test-01", filepath.Join(t.TempDir(), "node-interfaces.jsonl"))
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0/nil", n, err)
	}
}

// 全量快照采集：多节点分组入库；坏行进错误文件不静默丢弃。
func TestCollectOnce_Ingests(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "node-interfaces.jsonl")
	collected := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	lines := []string{
		`{"node_name":"gw-1","ifname":"eth0","mac":"00:11:22:33:44:00","pci_path":"0000:03:00.0","driver":"igb","media_type":"TP","link_speed":1000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"gw-1","ifname":"eth1","mac":"00:11:22:33:44:01","pci_path":"0000:03:00.1","driver":"ixgbe","media_type":"FIBRE","link_speed":10000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"gw-2","ifname":"enp3s0f0","mac":"00:11:22:33:44:10","pci_path":"0000:04:00.0","driver":"i40e","media_type":"FIBRE","link_speed":25000,"operstate":"down","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{bad json`,
		`{"node_name":"","ifname":"eth0"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	c := NewCollector(store, "test-01", logPath)
	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("n = %d, want 5", n)
	}

	groups, err := store.ListGrouped(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	gw1 := groups[0]
	if gw1.NodeName != "gw-1" || len(gw1.Interfaces) != 2 {
		t.Fatalf("gw-1 group = %+v", gw1)
	}
	if gw1.Interfaces[0].Ifname != "eth0" || gw1.Interfaces[0].SortOrder != 1 ||
		gw1.Interfaces[1].Ifname != "eth1" || gw1.Interfaces[1].SortOrder != 2 {
		t.Fatalf("gw-1 interfaces = %+v", gw1.Interfaces)
	}
	if !gw1.Interfaces[0].LastSeenAt.Equal(collected) {
		t.Fatalf("last_seen_at = %v, want collected_at", gw1.Interfaces[0].LastSeenAt)
	}
	if gw1.Interfaces[0].MediaType != MediaTP || gw1.Interfaces[1].MediaType != MediaFibre {
		t.Fatalf("media = %+v", gw1.Interfaces)
	}

	// 坏行写入 .errors 文件
	errData, err := os.ReadFile(logPath + ".errors")
	if err != nil {
		t.Fatalf("error file: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(errData)), "\n") + 1; got != 2 {
		t.Fatalf("error lines = %d, want 2 (%s)", got, errData)
	}
	m := c.Metrics()
	if m["failed_count"].(int64) != 2 || m["applied_count"].(int64) != 3 {
		t.Fatalf("metrics = %+v", m)
	}
}

// 第二轮快照：消失的口置 present=false，新口排末尾。
func TestCollectOnce_FullRebuild(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "node-interfaces.jsonl")
	mk := func(ifnames ...string) string {
		var lines []string
		for _, n := range ifnames {
			lines = append(lines, `{"node_name":"gw-1","ifname":"`+n+`","media_type":"TP","collected_at":"2026-08-17T10:00:00Z"}`)
		}
		return strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(logPath, []byte(mk("eth0", "eth1")), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewMemStore()
	c := NewCollector(store, "test-01", logPath)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 网关重写快照：eth1 消失，eth2 新出现
	if err := os.WriteFile(logPath, []byte(mk("eth0", "eth2")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	groups, _ := store.ListGrouped(context.Background(), "gw-1")
	list := groups[0].Interfaces
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	byName := map[string]Interface{}
	for _, it := range list {
		byName[it.Ifname] = it
	}
	if byName["eth1"].Present {
		t.Fatal("eth1 should be present=false")
	}
	if !byName["eth2"].Present || byName["eth2"].SortOrder != 3 {
		t.Fatalf("eth2 = %+v, want present 且排末尾", byName["eth2"])
	}
}
