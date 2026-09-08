package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// newTestStore 创建仅带加密服务的 Store（不触 DB，仅测 config 加解密/脱敏纯逻辑）。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	enc, err := encryption.NewWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	return &Store{enc: enc}
}

// TestConfigEncryptDecryptRoundTrip 密值字段加密落库 → 解密还原；密文不明文泄露。
func TestConfigEncryptDecryptRoundTrip(t *testing.T) {
	s := newTestStore(t)
	cfg := map[string]interface{}{
		"webhook_url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=secret-key-1",
		"mention_all": true,
	}
	encCfg, err := s.encryptConfig(TypeWecom, cfg)
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	stored, _ := encCfg["webhook_url"].(string)
	if !strings.HasPrefix(stored, encPrefix) {
		t.Fatalf("密值应带 %s 前缀: %s", encPrefix, stored)
	}
	if strings.Contains(stored, "secret-key-1") {
		t.Fatalf("密文不应含明文片段: %s", stored)
	}
	if encCfg["mention_all"] != true {
		t.Errorf("非密值字段不应被改动: %v", encCfg["mention_all"])
	}

	decCfg, err := s.decryptConfig(TypeWecom, encCfg)
	if err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}
	if decCfg["webhook_url"] != cfg["webhook_url"] {
		t.Errorf("解密往返不一致: %v", decCfg["webhook_url"])
	}
}

// TestConfigDecryptCorrupted 密文损坏/密钥错误如实报错（不静默降级为空）。
func TestConfigDecryptCorrupted(t *testing.T) {
	s := newTestStore(t)
	cfg := map[string]interface{}{"webhook_url": encPrefix + "not-a-valid-ciphertext"}
	if _, err := s.decryptConfig(TypeWecom, cfg); err == nil {
		t.Fatal("损坏密文应报错")
	}
	other, _ := encryption.NewWithKey([]byte("abcdef0123456789abcdef0123456789"))
	s2 := &Store{enc: other}
	encCfg, err := s.encryptConfig(TypeFeishu, map[string]interface{}{
		"webhook_url": "https://open.feishu.cn/x", "secret": "s3"})
	if err != nil {
		t.Fatalf("encryptConfig: %v", err)
	}
	if _, err := s2.decryptConfig(TypeFeishu, encCfg); err == nil {
		t.Fatal("错误密钥解密应报错")
	}
}

// TestMaskConfig 接口读出脱敏：非空密值 → ********，空保持空，非密值不变。
func TestMaskConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"webhook_url": "https://open.feishu.cn/secret",
		"secret":      "",
	}
	masked := maskConfig(TypeFeishu, cfg)
	if masked["webhook_url"] != MaskedValue {
		t.Errorf("非空密值应脱敏, got %v", masked["webhook_url"])
	}
	if masked["secret"] != "" {
		t.Errorf("空密值不应脱敏, got %v", masked["secret"])
	}
	// smtp password 脱敏、host 不动
	m2 := maskConfig(TypeSMTP, map[string]interface{}{"host": "smtp.x.com", "password": "pw"})
	if m2["password"] != MaskedValue || m2["host"] != "smtp.x.com" {
		t.Errorf("smtp 脱敏错误: %v", m2)
	}
}

// TestResolveSecrets ******** 保留原值语义：新建拒绝、同类型更新保留、换类型拒绝。
func TestResolveSecrets(t *testing.T) {
	// 新建：密值写 ******** → 拒绝
	in := &channelInput{Type: TypeWecom, Config: map[string]interface{}{"webhook_url": MaskedValue}}
	if err := resolveSecrets(in, nil); err == nil {
		t.Fatal("新建渠道不应接受脱敏占位符")
	}
	// 同类型更新：******** → 替换为现有明文
	existing := &Channel{Type: TypeWecom, Config: map[string]interface{}{"webhook_url": "https://real-hook"}}
	in2 := &channelInput{Type: TypeWecom, Config: map[string]interface{}{"webhook_url": MaskedValue}}
	if err := resolveSecrets(in2, existing); err != nil {
		t.Fatalf("同类型更新保留原值失败: %v", err)
	}
	if in2.Config["webhook_url"] != "https://real-hook" {
		t.Errorf("应替换为现有明文, got %v", in2.Config["webhook_url"])
	}
	// 换类型更新：******** → 拒绝
	in3 := &channelInput{Type: TypeFeishu, Config: map[string]interface{}{"webhook_url": MaskedValue}}
	if err := resolveSecrets(in3, existing); err == nil {
		t.Fatal("更换渠道类型不应接受脱敏占位符")
	}
	// 真实新值不受影响
	in4 := &channelInput{Type: TypeWecom, Config: map[string]interface{}{"webhook_url": "https://new-hook"}}
	if err := resolveSecrets(in4, existing); err != nil {
		t.Fatalf("真实值不应被拒绝: %v", err)
	}
	if in4.Config["webhook_url"] != "https://new-hook" {
		t.Errorf("真实值不应被改动, got %v", in4.Config["webhook_url"])
	}
}

// TestValidateBasics 渠道基础字段校验。
func TestValidateBasics(t *testing.T) {
	cases := []struct {
		name    string
		in      channelInput
		wantErr string
	}{
		{"空名称", channelInput{Name: " ", Type: "wecom"}, "name"},
		{"非法类型", channelInput{Name: "x", Type: "dingtalk"}, "type"},
		{"非法级别", channelInput{Name: "x", Type: "wecom", MinSeverity: "URGENT"}, "min_severity"},
		{"未知类别", channelInput{Name: "x", Type: "wecom", Categories: []string{"unknown"}}, "categories"},
	}
	for _, c := range cases {
		if err := c.in.validateBasics(); err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: 应报 %q 相关错误, got %v", c.name, c.wantErr, err)
		}
	}
	// 正常：级别大小写规整 + 类别去重 + syslog 强制空 config
	ok := channelInput{
		Name: " 值班群 ", Type: "WeCom", MinSeverity: "high",
		Categories: []string{"infrastructure", "infrastructure", "ops"},
	}
	if err := ok.validateBasics(); err != nil {
		t.Fatalf("合法输入不应报错: %v", err)
	}
	if ok.Name != "值班群" || ok.Type != TypeWecom || ok.MinSeverity != SeverityHigh {
		t.Errorf("规整失败: %+v", ok)
	}
	if len(ok.Categories) != 2 {
		t.Errorf("类别应去重: %v", ok.Categories)
	}
	sys := channelInput{Name: "s", Type: "syslog", Config: map[string]interface{}{"junk": 1}}
	if err := sys.validateBasics(); err != nil {
		t.Fatalf("syslog 渠道不应报错: %v", err)
	}
	if len(sys.Config) != 0 {
		t.Errorf("syslog config 应强制为空: %v", sys.Config)
	}
}

// TestValidateConfigs 各渠道 config 校验（严格拒绝未知字段与非法值）。
func TestValidateConfigs(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		cfg     map[string]interface{}
		wantErr string
	}{
		{"wecom 正常", TypeWecom, map[string]interface{}{"webhook_url": "https://qyapi.weixin.qq.com/x", "mention_all": true}, ""},
		{"wecom 空地址", TypeWecom, map[string]interface{}{"webhook_url": ""}, "webhook_url"},
		{"wecom 非http", TypeWecom, map[string]interface{}{"webhook_url": "ftp://x"}, "webhook_url"},
		{"wecom 占位符", TypeWecom, map[string]interface{}{"webhook_url": MaskedValue}, "脱敏占位符"},
		{"wecom 未知字段", TypeWecom, map[string]interface{}{"webhook_url": "https://x.com/h", "foo": 1}, "config"},
		{"feishu 正常无签名", TypeFeishu, map[string]interface{}{"webhook_url": "https://open.feishu.cn/x"}, ""},
		{"feishu 正常带签名", TypeFeishu, map[string]interface{}{"webhook_url": "https://open.feishu.cn/x", "secret": "s"}, ""},
		{"smtp 正常", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(465), "security": "ssl",
			"username": "u", "password": "p", "from": "a@b.co", "to": []interface{}{"d@e.fg"}}, ""},
		{"smtp 非法端口", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(0), "security": "none", "from": "a@b.co", "to": []interface{}{"d@e.fg"}}, "port"},
		{"smtp 非法加密", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "tls12", "from": "a@b.co", "to": []interface{}{"d@e.fg"}}, "security"},
		{"smtp 空收件人", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none", "from": "a@b.co", "to": []interface{}{}}, "to"},
		{"smtp 非法发件人", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none", "from": "notanemail", "to": []interface{}{"d@e.fg"}}, "from"},
		// 审查 MED-16：仅校验包含 @ 过弱，须严格格式 + 显式拒绝控制字符
		{"smtp 发件人含 CRLF", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none",
			"from": "a@b.co\r\nBCC: evil@x.com", "to": []interface{}{"d@e.fg"}}, "from"},
		{"smtp 收件人含换行", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none",
			"from": "a@b.co", "to": []interface{}{"d@e.fg\nevil@x.com"}}, "to"},
		{"smtp 收件人缺 TLD", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none",
			"from": "a@b.co", "to": []interface{}{"d@e"}}, "to"},
		{"smtp 发件人带空格", TypeSMTP, map[string]interface{}{
			"host": "smtp.x.com", "port": float64(25), "security": "none",
			"from": "a b@b.co", "to": []interface{}{"d@e.fg"}}, "from"},
		{"syslog 任意 config", TypeSyslog, map[string]interface{}{}, ""},
	}
	for _, c := range cases {
		err := ValidateConfig(c.typ, c.cfg)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: 不应报错, got %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: 应报 %q 相关错误, got %v", c.name, c.wantErr, err)
		}
	}
}

// TestChannelNormalize JSON 输出稳定性：categories/config 不为 null。
func TestChannelNormalize(t *testing.T) {
	c := &Channel{ID: uuid.New(), Name: "x", Type: TypeSyslog, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	c.normalize()
	if c.Categories == nil || c.Config == nil {
		t.Errorf("normalize 后不应为 nil: %+v", c)
	}
}
