package mirrorcap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func TestFileConfigRulesDirValidationAndOverlay(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "mirrorcap.json")
	goodJSON := `{"enabled":true,"node":"gw-01","interfaces":["eth2"],"ports":[80],"rules_dir":"/etc/caddy/rules/releases/20261201.1"}`
	if err := os.WriteFile(goodPath, []byte(goodJSON), 0o644); err != nil {
		t.Fatalf("write good mirrorcap.json: %v", err)
	}
	fc, err := LoadFileConfig(goodPath)
	if err != nil {
		t.Fatalf("LoadFileConfig valid rules_dir failed: %v", err)
	}
	cfg := fc.overlay(Config{RulesDir: defaultRulesDir})
	if cfg.RulesDir != "/etc/caddy/rules/releases/20261201.1" {
		t.Fatalf("overlay RulesDir = %q, want /etc/caddy/rules/releases/20261201.1", cfg.RulesDir)
	}

	// 拒绝含 .. 的非法路径穿越
	badPath := filepath.Join(dir, "bad.json")
	badJSON := `{"enabled":true,"node":"gw-01","interfaces":["eth2"],"ports":[80],"rules_dir":"/etc/caddy/rules/../../etc"}`
	if err := os.WriteFile(badPath, []byte(badJSON), 0o644); err != nil {
		t.Fatalf("write bad.json: %v", err)
	}
	if _, err := LoadFileConfig(badPath); err == nil || !strings.Contains(err.Error(), "rules_dir") {
		t.Fatalf("expected traversal rules_dir error, got %v", err)
	}
}

func TestSupervisorRebuildsDetectorWhenRulesDirChanges(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "mirrorcap.json")
	eventsPath := filepath.Join(dir, "events.log")

	var seenRulesDirs []string
	base := Config{
		RulesDir:  defaultRulesDir,
		EventsLog: eventsPath,
		AuditLog:  "off",
	}

	sup := NewSupervisor(
		base,
		os.ErrNotExist,
		cfgPath,
		time.Hour,
		&Stats{},
		func(p, node string) (*apievents.Logger, error) { return nil, nil },
		func(cfg Config, _ *apievents.Logger, _ *Stats) (RequestHandler, error) {
			seenRulesDirs = append(seenRulesDirs, cfg.RulesDir)
			return noopHandler{}, nil
		},
		func(_ Config, _ IfaceConsumer, _ *Stats) (Runner, error) {
			return newFakeRunner(), nil
		},
	)
	defer sup.Close()

	// 第一代规则包
	_ = os.WriteFile(cfgPath, []byte(`{"enabled":true,"node":"gw-01","interfaces":["eth2"],"ports":[80],"events_log":"`+eventsPath+`","audit_log":"off","rules_dir":"/etc/caddy/rules/releases/20261201.1"}`), 0o644)
	sup.tick()

	// 相同 rules_dir 重复 tick 不应重建检测器
	sup.tick()
	if len(seenRulesDirs) != 1 || seenRulesDirs[0] != "/etc/caddy/rules/releases/20261201.1" {
		t.Fatalf("unexpected detector builds after tick 1-2: %v", seenRulesDirs)
	}

	// 切换 rules_dir 到新版本规则包 → 触发在线重建检测器
	_ = os.WriteFile(cfgPath, []byte(`{"enabled":true,"node":"gw-01","interfaces":["eth2"],"ports":[80],"events_log":"`+eventsPath+`","audit_log":"off","rules_dir":"/etc/caddy/rules/releases/20261215.1"}`), 0o644)
	sup.tick()
	if len(seenRulesDirs) != 2 || seenRulesDirs[1] != "/etc/caddy/rules/releases/20261215.1" {
		t.Fatalf("expected detector rebuild on rules_dir change, got: %v", seenRulesDirs)
	}
}
