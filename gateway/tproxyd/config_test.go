package tproxyd

import (
	"testing"
	"time"
)

func TestFromEnvDefaults(t *testing.T) {
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != "127.0.0.1:15000" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	if cfg.Target != "127.0.0.1:8080" {
		t.Fatalf("Target = %q", cfg.Target)
	}
	if cfg.MaxConns != 1024 {
		t.Fatalf("MaxConns = %d", cfg.MaxConns)
	}
	if cfg.StatsInterval != 60*time.Second {
		t.Fatalf("StatsInterval = %s", cfg.StatsInterval)
	}
	if cfg.DialTimeout != 10*time.Second || cfg.ShutdownGrace != 5*time.Second {
		t.Fatalf("DialTimeout=%s ShutdownGrace=%s", cfg.DialTimeout, cfg.ShutdownGrace)
	}
	if cfg.TargetTLS != "127.0.0.1:8443" || cfg.SniffTimeout != 3*time.Second {
		t.Fatalf("TargetTLS=%q SniffTimeout=%s", cfg.TargetTLS, cfg.SniffTimeout)
	}
	if cfg.RelayIdleTimeout != 300*time.Second {
		t.Fatalf("RelayIdleTimeout = %s", cfg.RelayIdleTimeout)
	}
	if len(cfg.ProtectHosts) != 0 || cfg.sniDispatchEnabled() {
		t.Fatalf("默认应关闭 SNI 分流: %v", cfg.ProtectHosts)
	}
}

func TestFromEnvSNIDispatch(t *testing.T) {
	t.Setenv("TPROXY_PROTECT_HOSTS", "Www.Test.COM., api.test.com")
	t.Setenv("TPROXY_PASSTHROUGH_ALLOWLIST", "Pass.Test.COM., other.test.com")
	t.Setenv("TPROXY_TARGET_TLS", "127.0.0.1:9443")
	t.Setenv("TPROXY_SNIFF_TIMEOUT", "5")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ProtectHosts) != 2 || cfg.ProtectHosts[0] != "www.test.com" || cfg.ProtectHosts[1] != "api.test.com" {
		t.Fatalf("ProtectHosts 归一化错误: %v", cfg.ProtectHosts)
	}
	if len(cfg.PassthroughAllowlist) != 2 || cfg.PassthroughAllowlist[0] != "pass.test.com" || cfg.PassthroughAllowlist[1] != "other.test.com" {
		t.Fatalf("PassthroughAllowlist 归一化错误: %v", cfg.PassthroughAllowlist)
	}
	if cfg.TargetTLS != "127.0.0.1:9443" || cfg.SniffTimeout != 5*time.Second {
		t.Fatalf("TargetTLS=%q SniffTimeout=%s", cfg.TargetTLS, cfg.SniffTimeout)
	}
	if !cfg.sniDispatchEnabled() {
		t.Fatal("清单非空应启用 SNI 分流")
	}
}

func TestFromEnvSNIDispatchRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"TPROXY_PROTECT_HOSTS":         "bad host.com",
		"TPROXY_PASSTHROUGH_ALLOWLIST": "*.evil.com",
		"TPROXY_TARGET_TLS":            "no-port",
		"TPROXY_SNIFF_TIMEOUT":         "0",
	}
	for key, val := range cases {
		t.Run(key, func(t *testing.T) {
			// 分流需开启才校验 TargetTLS/SniffTimeout，故统一带上合法清单
			if key != "TPROXY_PROTECT_HOSTS" {
				t.Setenv("TPROXY_PROTECT_HOSTS", "www.test.com")
			}
			t.Setenv(key, val)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("%s=%q 应报错", key, val)
			}
		})
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("TPROXY_LISTEN", "0.0.0.0:15000")
	t.Setenv("TPROXY_TARGET", "127.0.0.1:18080")
	t.Setenv("TPROXY_MAX_CONNS", "256")
	t.Setenv("TPROXY_STATS_INTERVAL", "5")
	t.Setenv("TPROXY_DIAL_TIMEOUT", "3")
	t.Setenv("TPROXY_SHUTDOWN_GRACE", "2")
	t.Setenv("TPROXY_RELAY_IDLE_TIMEOUT", "120")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != "0.0.0.0:15000" || cfg.Target != "127.0.0.1:18080" {
		t.Fatalf("Listen=%q Target=%q", cfg.Listen, cfg.Target)
	}
	if cfg.MaxConns != 256 || cfg.StatsInterval != 5*time.Second ||
		cfg.DialTimeout != 3*time.Second || cfg.ShutdownGrace != 2*time.Second ||
		cfg.RelayIdleTimeout != 120*time.Second {
		t.Fatalf("cfg=%+v", cfg)
	}
}

func TestFromEnvRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"TPROXY_LISTEN":             "no-port",
		"TPROXY_TARGET":             "127.0.0.1:notaport",
		"TPROXY_MAX_CONNS":          "0",
		"TPROXY_STATS_INTERVAL":     "abc",
		"TPROXY_DIAL_TIMEOUT":       "-1",
		"TPROXY_SHUTDOWN_GRACE":     "0",
		"TPROXY_RELAY_IDLE_TIMEOUT": "0",
	}
	for key, val := range cases {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, val)
			if _, err := FromEnv(); err == nil {
				t.Fatalf("%s=%q 应报错", key, val)
			}
		})
	}
}
