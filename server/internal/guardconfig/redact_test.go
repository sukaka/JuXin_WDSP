package guardconfig

import (
	"encoding/json"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestRedactGuardConfigStripsPassword(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{
		CounterBackend: "valkey",
		Valkey: &gatewayconfig.GuardValkey{
			Address:  "valkey:6379",
			Password: "super-secret",
			DB:       0,
		},
		AppRules: map[string]*gatewayconfig.GuardAppRules{
			"app1": {Allow: []gatewayconfig.GuardRule{{ID: "1", Address: "10.0.0.1/32"}}},
		},
	}
	red := RedactGuardConfig(cfg)
	if red.Valkey == nil || red.Valkey.Password != "***" {
		t.Fatalf("password not redacted: %+v", red.Valkey)
	}
	// 原配置不受影响
	if cfg.Valkey.Password != "super-secret" {
		t.Fatal("original config mutated")
	}
	data, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || containsStr(string(data), "super-secret") {
		t.Fatalf("marshaled redacted config still contains secret: %s", data)
	}
}

func TestInjectRuntimeSecrets(t *testing.T) {
	p := &Provider{valkeyAddr: "127.0.0.1:6379", valkeyPassword: "live-pass", valkeyDB: 2}
	cfg := &gatewayconfig.GuardConfig{
		Valkey: &gatewayconfig.GuardValkey{Address: "old", Password: "***", DB: 0},
	}
	p.InjectRuntimeSecrets(cfg)
	if cfg.Valkey.Password != "live-pass" || cfg.Valkey.Address != "127.0.0.1:6379" || cfg.Valkey.DB != 2 {
		t.Fatalf("inject failed: %+v", cfg.Valkey)
	}
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && containsIndex(s, sub)))
}

func containsIndex(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
