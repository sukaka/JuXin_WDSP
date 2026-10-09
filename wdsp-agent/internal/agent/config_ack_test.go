package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

func TestApplyServerConfigDoesNotAdvanceStateWhenSaveFails(t *testing.T) {
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPolicy := &config.Policy{Name: "old"}
	oldOverrides := []config.Override{{ID: "old"}}
	a := &Agent{
		cfg: &config.Config{
			Policy:                  oldPolicy,
			Overrides:               oldOverrides,
			AppliedConfigVersion:    3,
			PendingConfigAckVersion: 2,
		},
		cfgPath: filepath.Join(blockedParent, "agent.json"),
	}

	if err := a.applyServerConfig(&config.Policy{Name: "new"}, []config.Override{{ID: "new"}}, 4); err == nil {
		t.Fatal("配置写盘失败时应返回错误")
	}
	if a.cfg.Policy != oldPolicy || len(a.cfg.Overrides) != 1 || a.cfg.Overrides[0].ID != "old" ||
		a.cfg.AppliedConfigVersion != 3 || a.cfg.PendingConfigAckVersion != 2 {
		t.Fatalf("写盘失败不应推进内存配置: %+v", a.cfg)
	}
}
