package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	wantPorts := []int{80, 443, 8000, 8001, 8080, 8081, 8443, 8888, 9000, 9443}
	if !reflect.DeepEqual(p.Capture.Ports, wantPorts) {
		t.Fatalf("默认端口=%v", p.Capture.Ports)
	}
	if p.Capture.Direction != "both" {
		t.Fatalf("direction=%s", p.Capture.Direction)
	}
	if p.Output.Mode != "FLOW" {
		t.Fatalf("output=%s", p.Output.Mode)
	}
	if p.Limits.OutboundMbps != 100 {
		t.Fatalf("outbound_mbps=%v", p.Limits.OutboundMbps)
	}
	if p.Limits.CPUPercent != 20 || p.Limits.MemoryMB != 512 {
		t.Fatalf("limits=%+v", p.Limits)
	}
	if !p.Buffer.Enabled || p.Buffer.MaxSizeMB != 512 || p.Buffer.MaxAgeMinutes != 30 {
		t.Fatalf("buffer=%+v", p.Buffer)
	}
}

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "agent.json")
	cfg := Default()
	cfg.Server = "https://wdsp.example.com"
	cfg.AgentID = "a3c98f51-0000-0000-0000-000000000001"
	cfg.Credential = "wda_abc"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent.json 权限=%o, 应为 0600", fi.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server != cfg.Server || got.AgentID != cfg.AgentID || got.Credential != cfg.Credential {
		t.Fatalf("回读不一致: %+v", got)
	}
	if got.HeartbeatIntervalSeconds != 15 {
		t.Fatalf("heartbeat=%d", got.HeartbeatIntervalSeconds)
	}
}

func TestLoadMissingReturnsDefault(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("缺失文件应报错")
	}
	if cfg.HeartbeatIntervalSeconds != 15 || cfg.Limits.OutboundMbps != 100 {
		t.Fatalf("应返回默认配置: %+v", cfg)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://x","agent_id":"a","credential":"c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HeartbeatIntervalSeconds != 15 || cfg.Limits.CPUPercent != 20 || cfg.Buffer.MaxSizeMB != 512 {
		t.Fatalf("缺省字段未补齐: %+v", cfg)
	}
}

func TestEffectivePolicyFallback(t *testing.T) {
	cfg := Default()
	if cfg.EffectivePolicy().Name != "builtin-default" {
		t.Fatal("无策略快照应回退内置默认")
	}
	p := &Policy{Name: "prod"}
	cfg.Policy = p
	if cfg.EffectivePolicy() != p {
		t.Fatal("有策略快照应使用快照")
	}
}

// TestCertExpiresAtCompat Phase 2-B：旧 agent.json（无 cert_expires_at）照常加载
// （Bearer 模式）；新字段 omitempty 序列化往返且空值不出现在 JSON 中。
func TestCertExpiresAtCompat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://x","agent_id":"a","credential":"c"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertExpiresAt != "" {
		t.Fatalf("旧文件 cert_expires_at 应为空: %+v", cfg)
	}
	// 空值不序列化（omitempty），旧版 Agent 读新文件不受影响
	cfg.CertExpiresAt = "2026-12-01T00:00:00Z"
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertExpiresAt != "2026-12-01T00:00:00Z" {
		t.Fatalf("回读 cert_expires_at=%q", got.CertExpiresAt)
	}
	cfg.CertExpiresAt = ""
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "cert_expires_at") {
		t.Fatalf("空 cert_expires_at 不应序列化: %s", data)
	}
}
