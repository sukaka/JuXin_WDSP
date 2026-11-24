// TLS 会话票据密钥下发测试（HA_ACTIVE_STANDBY_DESIGN §7.2）：
// 设置键解析（合法/非法）、Generate 产出 apps.tls.session_tickets、快照脱敏。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

const testTicketKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// Generate：配置票据密钥时产出 apps.tls.session_tickets（tls.stek.jiuzhang 静态键）；
// 未配置时无 apps.tls（保持 Go 标准库进程内随机键缺省）。
func TestGenerateTLSSessionTickets(t *testing.T) {
	g, err := Generate(GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       &GuardConfig{TLSSessionTicketKey: testTicketKey},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}
	tlsApp, ok := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("apps.tls 缺失: %s", g.JSON)
	}
	ks := tlsApp["session_tickets"].(map[string]interface{})["key_source"].(map[string]interface{})
	if ks["provider"] != "jiuzhang" {
		t.Fatalf("provider = %v", ks["provider"])
	}
	keys := ks["keys_hex"].([]interface{})
	if len(keys) != 1 || keys[0] != testTicketKey {
		t.Fatalf("keys_hex = %v", keys)
	}

	// 未配置密钥：无 apps.tls 块（回退缺省行为）
	g2, err := Generate(GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       &GuardConfig{},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg2 map[string]interface{}
	if err := json.Unmarshal([]byte(g2.JSON), &cfg2); err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg2["apps"].(map[string]interface{})["tls"]; ok {
		t.Fatal("未配置密钥不应产出 apps.tls")
	}
}

// 确定性：同输入（含密钥）两次生成逐字节一致（多节点扇出一致性的前提）。
func TestGenerateTLSSessionTicketsDeterministic(t *testing.T) {
	in := GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       &GuardConfig{TLSSessionTicketKey: testTicketKey},
	}
	g1, err1 := Generate(in)
	g2, err2 := Generate(in)
	if err1 != nil || err2 != nil {
		t.Fatalf("Generate: %v / %v", err1, err2)
	}
	if g1.JSON != g2.JSON || g1.Hash != g2.Hash {
		t.Fatal("同输入应产出逐字节一致配置")
	}
}

// GuardConfig 序列化：票据密钥随 GuardConfig 进出（快照前形态）；
// 脱敏纪律由 guardconfig.RedactGuardConfig 覆盖（见其测试）。
func TestGuardConfigTicketKeyJSON(t *testing.T) {
	g := GuardConfig{TLSSessionTicketKey: testTicketKey}
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), testTicketKey) {
		t.Fatalf("序列化应含票据键: %s", raw)
	}
}

// TestGenerateTLSSessionTicketsMultiKey 验证 2 键平滑轮换：
// apps.tls.session_tickets.key_source.keys_hex 按序输出全部密钥（首键加密、次键解密）。
func TestGenerateTLSSessionTicketsMultiKey(t *testing.T) {
	const key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	g, err := Generate(GenerateInput{
		Apps:        sampleApps(),
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard: &GuardConfig{
			TLSSessionTicketKey:  testTicketKey,
			TLSSessionTicketKeys: []string{testTicketKey, key2},
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(g.JSON), &cfg); err != nil {
		t.Fatalf("generated JSON invalid: %v", err)
	}
	tlsApp := cfg["apps"].(map[string]interface{})["tls"].(map[string]interface{})
	ks := tlsApp["session_tickets"].(map[string]interface{})["key_source"].(map[string]interface{})
	keys := ks["keys_hex"].([]interface{})
	if len(keys) != 2 || keys[0] != testTicketKey || keys[1] != key2 {
		t.Fatalf("keys_hex = %v, want [%s %s]", keys, testTicketKey, key2)
	}
}
