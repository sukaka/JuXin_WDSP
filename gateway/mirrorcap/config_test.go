package mirrorcap

import (
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in      string
		want    []uint16
		wantErr bool
	}{
		{"80,8080", []uint16{80, 8080}, false},
		{" 80 , 443 ,80 ", []uint16{80, 443}, false}, // 空白与去重
		{"9000", []uint16{9000}, false},
		{"", nil, true},
		{"0", nil, true},
		{"65536", nil, true},
		{"abc", nil, true},
		{"80,,8080", []uint16{80, 8080}, false}, // 空段跳过
	}
	for _, c := range cases {
		got, err := parsePorts(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parsePorts(%q) 应报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePorts(%q) 意外错误: %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parsePorts(%q)=%v  want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parsePorts(%q)[%d]=%d want %d", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "eth1")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Iface != "eth1" {
		t.Errorf("Iface=%q want eth1", cfg.Iface)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 80 || cfg.Ports[1] != 8080 {
		t.Errorf("Ports=%v want [80 8080]", cfg.Ports)
	}
	if cfg.BodyMax != 65536 {
		t.Errorf("BodyMax=%d want 65536", cfg.BodyMax)
	}
	if cfg.EventsLog != defaultEventsLog {
		t.Errorf("EventsLog=%q want %q", cfg.EventsLog, defaultEventsLog)
	}
	if cfg.StatsInterval != 60*time.Second {
		t.Errorf("StatsInterval=%v want 60s", cfg.StatsInterval)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "eth2")
	t.Setenv("MIRROR_PORTS", "8081")
	t.Setenv("MIRROR_BODY_MAX", "1024")
	t.Setenv("MIRROR_EVENTS_LOG", "/tmp/ev.log")
	t.Setenv("GATEWAY_NODE_NAME", "node-a")
	t.Setenv("MIRROR_STATS_INTERVAL", "5")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.BodyMax != 1024 || cfg.EventsLog != "/tmp/ev.log" || cfg.NodeName != "node-a" || cfg.StatsInterval != 5*time.Second {
		t.Errorf("override 未生效: %+v", cfg)
	}
	if len(cfg.Ports) != 1 || cfg.Ports[0] != 8081 {
		t.Errorf("Ports=%v want [8081]", cfg.Ports)
	}
}

func TestFromEnvRequiresIface(t *testing.T) {
	// 清空可能继承的 MIRROR_IFACE
	t.Setenv("MIRROR_IFACE", "")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "MIRROR_IFACE") {
		t.Errorf("缺 MIRROR_IFACE 应报错并提示, got %v", err)
	}
}

func TestFromEnvRejectsBadNumbers(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "eth0")
	t.Setenv("MIRROR_BODY_MAX", "-1")
	if _, err := FromEnv(); err == nil {
		t.Error("MIRROR_BODY_MAX=-1 应报错")
	}
}

// 发现配置 env 兜底：默认值 + 显式覆盖 + 非法值报错。
func TestFromEnvDiscovery(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "eth0")
	// 默认：发现关闭
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Discovery.Enabled || len(cfg.Discovery.Ifaces) != 0 {
		t.Errorf("默认发现应关闭: %+v", cfg.Discovery)
	}
	if cfg.Discovery.Log != defaultDiscoveryLog || cfg.Discovery.FlushInterval != defaultDiscoveryFlushInterval {
		t.Errorf("发现默认值未生效: %+v", cfg.Discovery)
	}

	// 显式开启
	t.Setenv("SITE_DISCOVERY_ENABLED", "true")
	t.Setenv("SITE_DISCOVERY_IFACES", "eth2:MIRROR, eth0:routed ,eth2, eth1:transparent")
	t.Setenv("SITE_DISCOVERY_LOG", "/tmp/disc.jsonl")
	t.Setenv("SITE_DISCOVERY_FLUSH_INTERVAL", "10")
	cfg, err = FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if !cfg.Discovery.Enabled {
		t.Fatal("SITE_DISCOVERY_ENABLED=true 未生效")
	}
	want := []DiscoveryIface{{Name: "eth2", Mode: "MIRROR"}, {Name: "eth0", Mode: "ROUTED"}, {Name: "eth1", Mode: "TRANSPARENT"}}
	if len(cfg.Discovery.Ifaces) != 3 || cfg.Discovery.Ifaces[0] != want[0] || cfg.Discovery.Ifaces[1] != want[1] || cfg.Discovery.Ifaces[2] != want[2] {
		t.Errorf("Ifaces=%v want %v（mode 大写归一、去重保序）", cfg.Discovery.Ifaces, want)
	}
	if cfg.Discovery.Log != "/tmp/disc.jsonl" || cfg.Discovery.FlushInterval != 10*time.Second {
		t.Errorf("发现覆盖未生效: %+v", cfg.Discovery)
	}
}

func TestFromEnvDiscoveryInvalid(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "eth0")

	t.Setenv("SITE_DISCOVERY_ENABLED", "not-bool")
	if _, err := FromEnv(); err == nil {
		t.Error("SITE_DISCOVERY_ENABLED=not-bool 应报错")
	}

	t.Setenv("SITE_DISCOVERY_ENABLED", "true")
	if _, err := FromEnv(); err == nil {
		t.Error("发现开启但接口为空应报错")
	}

	t.Setenv("SITE_DISCOVERY_IFACES", "eth0:SNIFF")
	if _, err := FromEnv(); err == nil {
		t.Error("非法 mode 应报错")
	}

	t.Setenv("SITE_DISCOVERY_IFACES", "eth0")
	t.Setenv("SITE_DISCOVERY_FLUSH_INTERVAL", "-5")
	if _, err := FromEnv(); err == nil {
		t.Error("flush_interval 负数应报错")
	}
}

func TestParseEnvPreservesSettingsWithoutIface(t *testing.T) {
	t.Setenv("MIRROR_IFACE", "")
	t.Setenv("MIRROR_RULES_DIR", "/opt/jiuzhang/rules")
	t.Setenv("MIRROR_IDENTITY_SALT", "prod-salt")
	t.Setenv("MIRROR_AUDIT_LOG", "/opt/jiuzhang/logs/coraza-audit.log")
	t.Setenv("MIRROR_PORTS", "8081,8082")
	t.Setenv("MIRROR_BODY_MAX", "131072")

	cfg, err := ParseEnv()
	if err != nil {
		t.Fatalf("ParseEnv 不应因缺 MIRROR_IFACE 报错: %v", err)
	}
	if cfg.RulesDir != "/opt/jiuzhang/rules" || cfg.IdentitySalt != "prod-salt" ||
		cfg.AuditLog != "/opt/jiuzhang/logs/coraza-audit.log" || cfg.BodyMax != 131072 {
		t.Fatalf("ParseEnv 未保留运维环境变量: %+v", cfg)
	}
	if len(cfg.Ports) != 2 || cfg.Ports[0] != 8081 || cfg.Ports[1] != 8082 {
		t.Fatalf("ParseEnv Ports=%v want [8081 8082]", cfg.Ports)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("缺 MIRROR_IFACE 时 Validate 仍应报错")
	}
	if def := Defaults(); len(def.Ports) == 0 {
		t.Fatal("Defaults().Ports 不得为空")
	}
}
