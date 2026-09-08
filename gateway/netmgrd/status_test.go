package netmgrd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleStatus() Status {
	return Status{
		AppliedAt: "2026-08-19T06:00:00Z",
		OK:        true,
		Bridges:   []BridgeStatus{{Name: "br0", State: StateOK}},
		IPForward: StateOK,
		Routes:    []RouteStatus{{Dst: "10.9.0.0/24", Via: "192.168.50.254", State: StateOK}},
		Message:   "applied；路由只增不删（最小实现，期望外路由由运维清理）",
	}
}

func TestWriteStatusAtomicRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network-status.json")
	if err := WriteStatusAtomic(path, sampleStatus()); err != nil {
		t.Fatalf("写状态: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读状态: %v", err)
	}
	var got Status
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("状态应为完整 JSON: %v", err)
	}
	if !got.OK || got.IPForward != StateOK || len(got.Bridges) != 1 || got.Bridges[0].Name != "br0" ||
		len(got.Routes) != 1 || got.Routes[0].Via != "192.168.50.254" || got.AppliedAt == "" {
		t.Fatalf("回读内容不符: %+v", got)
	}
	// 契约字段名抽查（与发布端消费方对齐）
	for _, key := range []string{`"applied_at"`, `"ok"`, `"bridges"`, `"ip_forward"`, `"routes"`, `"message"`} {
		if !strings.Contains(string(data), key) {
			t.Fatalf("状态 JSON 缺契约字段 %s: %s", key, data)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("状态文件权限应为 0644: %v", fi.Mode().Perm())
	}
}

func TestWriteStatusAtomicEmptyArraysNotNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network-status.json")
	st := Status{AppliedAt: "t", OK: true, Bridges: make([]BridgeStatus, 0),
		IPForward: StateSkipped, Routes: make([]RouteStatus, 0), Message: "applied"}
	if err := WriteStatusAtomic(path, st); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"bridges":[]`) || !strings.Contains(string(data), `"routes":[]`) {
		t.Fatalf("空集合应序列化为 [] 而非 null: %s", data)
	}
}

func TestWriteStatusAtomicOverwriteNoTempLeft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network-status.json")
	first := sampleStatus()
	first.Message = "first"
	second := sampleStatus()
	second.Message = "second"
	if err := WriteStatusAtomic(path, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteStatusAtomic(path, second); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "second") {
		t.Fatalf("覆盖写未生效: %s", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "network-status.json" {
		t.Fatalf("临时文件应清理干净，目录内容: %v", entries)
	}
}

func TestWriteStatusAtomicMissingDir(t *testing.T) {
	err := WriteStatusAtomic(filepath.Join(t.TempDir(), "no/such/dir", "network-status.json"), sampleStatus())
	if err == nil {
		t.Fatal("目录不存在应显式报错（不得静默吞掉）")
	}
}
