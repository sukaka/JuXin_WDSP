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

// TestRedactGuardConfigStripsTicketKey tls_session_ticket_key / tls_session_ticket_keys 为票据密钥明文，快照脱敏（同一纪律）。
func TestRedactGuardConfigStripsTicketKey(t *testing.T) {
	const k1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const k2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	cfg := &gatewayconfig.GuardConfig{
		TLSSessionTicketKey:  k1,
		TLSSessionTicketKeys: []string{k1, k2},
	}
	cp := RedactGuardConfig(cfg)
	if cp.TLSSessionTicketKey != "***" {
		t.Fatalf("票据键未脱敏: %q", cp.TLSSessionTicketKey)
	}
	if len(cp.TLSSessionTicketKeys) != 2 || cp.TLSSessionTicketKeys[0] != "***" || cp.TLSSessionTicketKeys[1] != "***" {
		t.Fatalf("票据多键未脱敏: %v", cp.TLSSessionTicketKeys)
	}
	if cfg.TLSSessionTicketKey != k1 || cfg.TLSSessionTicketKeys[0] != k1 || cfg.TLSSessionTicketKeys[1] != k2 {
		t.Fatal("原配置被改写")
	}
}

// TestRedactGuardConfigStripsIdentitySalt identity_salt 为敏感盐值，快照脱敏（与 valkey.password 同一纪律）。
func TestRedactGuardConfigStripsIdentitySalt(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{IdentitySalt: "live-salt"}
	red := RedactGuardConfig(cfg)
	if red.IdentitySalt != "***" {
		t.Fatalf("identity_salt not redacted: %q", red.IdentitySalt)
	}
	if cfg.IdentitySalt != "live-salt" {
		t.Fatal("original config mutated")
	}
}

// TestRedactGuardConfigStripsScanVerificationKey api_scan_verification.key_hex 为扫描签名
// 密钥明文，快照脱敏为占位（与 valkey.password/identity_salt 同一纪律）；
// 序列化产物不得含密钥明文，原配置不受影响。
func TestRedactGuardConfigStripsScanVerificationKey(t *testing.T) {
	const keyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := &gatewayconfig.GuardConfig{
		APIScanVerification: &gatewayconfig.GuardScanVerification{KeyHex: keyHex},
	}
	red := RedactGuardConfig(cfg)
	if red.APIScanVerification == nil || red.APIScanVerification.KeyHex != "***" {
		t.Fatalf("api_scan_verification.key_hex 未脱敏: %+v", red.APIScanVerification)
	}
	if cfg.APIScanVerification.KeyHex != keyHex {
		t.Fatal("原配置被改写")
	}
	data, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if containsStr(string(data), keyHex) {
		t.Fatalf("序列化快照仍含扫描签名密钥明文: %s", data)
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
