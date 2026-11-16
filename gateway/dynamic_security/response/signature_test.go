// signature_test.go 文件签名 v1 单测（W13-GW / P2-02）：
// 配置校验（kid/key_hex 必填与口径、未启用不强校验、错误信息不含密钥值）、
// token 生成可复算（同输入同 token；HMAC 消息字段边界）、文本/JSON/Markdown 嵌入形态、
// 文本族与 OOXML 类型能力边界、JSON 解析失败返回错误（调用方 FAIL_OPEN）、跳过情形。
package response

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sigTestKeyHex 测试用签名密钥（32 字节 hex）。
var sigTestKeyHex = hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

func sigTestConfig(t *testing.T) *FileSignatureConfig {
	t.Helper()
	cfg, err := NewFileSignatureConfig(true, "k2026", sigTestKeyHex)
	if err != nil {
		t.Fatalf("new signature config: %v", err)
	}
	return cfg
}

// TestNewFileSignatureConfig 配置校验：未启用不强校验（零行为）；启用时 kid/key_hex 必填、
// kid 字符集与长度口径、key_hex 须 32 字节 hex；错误信息不含密钥值。
func TestNewFileSignatureConfig(t *testing.T) {
	// 未启用：任意取值不强校验（网关零行为变化）
	cfg, err := NewFileSignatureConfig(false, "", "not-a-key")
	if err != nil || cfg == nil || cfg.Enabled {
		t.Fatalf("disabled must skip validation: %v %v", cfg, err)
	}
	if cfg.AllowsContentType("text/plain") {
		t.Fatal("disabled config must allow nothing")
	}
	// 合法配置
	cfg, err = NewFileSignatureConfig(true, " kid-1_01 ", sigTestKeyHex)
	if err != nil || cfg.KID != "kid-1_01" {
		t.Fatalf("valid config: %v %v", cfg, err)
	}
	// 非法配置：逐类报错
	bad := []struct {
		name string
		kid  string
		key  string
	}{
		{"kid 空", "", sigTestKeyHex},
		{"kid 含点（破坏 token 分段）", "k.1", sigTestKeyHex},
		{"kid 含竖线（破坏 HMAC 字段边界）", "k|1", sigTestKeyHex},
		{"kid 含空白", "k 1", sigTestKeyHex},
		{"kid 超长", strings.Repeat("k", 65), sigTestKeyHex},
		{"key 非 hex", "k1", "zz" + sigTestKeyHex[2:]},
		{"key 长度不足", "k1", sigTestKeyHex[:32]},
		{"key 空", "k1", ""},
	}
	for _, c := range bad {
		_, err := NewFileSignatureConfig(true, c.kid, c.key)
		if err == nil {
			t.Errorf("%s: must fail", c.name)
			continue
		}
		if strings.Contains(err.Error(), sigTestKeyHex) {
			t.Errorf("%s: error must not contain key material: %v", c.name, err)
		}
	}
}

// TestBuildFileSignatureTokenRecomputable token 可复算：按契约公式
// HMAC-SHA256(key, kid|filename|content_sha256_hex|unixts|identity_fp) 独立复算结果一致；
// 前缀/kid/时间戳分段符合 jzsig1.{kid}.{unixts}.{hmac_hex} 格式。
func TestBuildFileSignatureTokenRecomputable(t *testing.T) {
	cfg := sigTestConfig(t)
	body := []byte("order,amount\nA1,100\n")
	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])
	ts := int64(1780000000)
	token := BuildFileSignatureToken(cfg.key, cfg.KID, "orders.csv", sumHex, ts, "auth:abc123")

	// 格式分段
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "jzsig1" || parts[1] != "k2026" || parts[2] != strconv.FormatInt(ts, 10) {
		t.Fatalf("token format = %q", token)
	}
	if len(parts[3]) != 64 {
		t.Fatalf("hmac hex must be 64 chars: %q", parts[3])
	}
	// 独立复算（模拟管理面验证侧）
	mac := hmac.New(sha256.New, mustDecodeHex(t, sigTestKeyHex))
	mac.Write([]byte("k2026|orders.csv|" + sumHex + "|1780000000|auth:abc123"))
	if parts[3] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("token hmac not recomputable: %q", token)
	}
	// 任一字段变化即不同 token（字段边界不可混淆）
	other := BuildFileSignatureToken(cfg.key, cfg.KID, "orders.csv", sumHex, ts, "auth:abc124")
	if other == token {
		t.Fatal("identity_fp change must change token")
	}
}

// TestApplyFileSignatureText 文本下载：文件尾追加 "# jzsig1..." 注释行；内容哈希覆盖
// 传入 body（挂点侧水印后调用 → 签名盖最终交付内容）。
func TestApplyFileSignatureText(t *testing.T) {
	cfg := sigTestConfig(t)
	body := []byte("a,b\n1,2\n")
	now := time.Unix(1780000000, 0).UTC()
	out, token, applied, err := ApplyFileSignature(body, "text/csv; charset=utf-8", cfg, "orders.csv", "auth:fp", now)
	if err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	want := "a,b\n1,2\n# " + token
	if string(out) != want {
		t.Fatalf("signed body = %q, want %q", out, want)
	}
	// 体不以换行结尾时先补换行（与水印同一纪律）
	out2, _, applied2, err := ApplyFileSignature([]byte("no-newline"), "text/plain", cfg, "n.txt", "", now)
	if err != nil || !applied2 || !strings.HasPrefix(string(out2), "no-newline\n# jzsig1.") {
		t.Fatalf("no-newline body: %q applied=%v err=%v", out2, applied2, err)
	}
}

// TestApplyFileSignatureJSON JSON 下载：顶层加 "_sig" 字段；键已存在/顶层非对象跳过；
// 非法 JSON 返回错误（调用方 FAIL_OPEN 直通）。
func TestApplyFileSignatureJSON(t *testing.T) {
	cfg := sigTestConfig(t)
	now := time.Unix(1780000000, 0).UTC()
	out, token, applied, err := ApplyFileSignature([]byte(`{"ok":true}`), "application/json", cfg, "orders.json", "", now)
	if err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	s := string(out)
	if !strings.Contains(s, `"_sig":"`+token+`"`) || !strings.Contains(s, `"ok":true`) {
		t.Fatalf("json signed body = %s", s)
	}
	// 键已存在：跳过不改写（不覆盖既有数据）
	out, _, applied, err = ApplyFileSignature([]byte(`{"_sig":"existing"}`), "application/json", cfg, "orders.json", "", now)
	if err != nil || applied || string(out) != `{"_sig":"existing"}` {
		t.Fatalf("existing key must skip: %q applied=%v err=%v", out, applied, err)
	}
	// 顶层数组：无处加字段，跳过
	out, _, applied, err = ApplyFileSignature([]byte(`[1,2]`), "application/json", cfg, "orders.json", "", now)
	if err != nil || applied || string(out) != `[1,2]` {
		t.Fatalf("top-level array must skip: %q applied=%v err=%v", out, applied, err)
	}
	// 非法 JSON：返回错误（调用方 FAIL_OPEN）
	if _, _, _, err = ApplyFileSignature([]byte(`{bad`), "application/json", cfg, "orders.json", "", now); err == nil {
		t.Fatal("bad json must error (caller fail-open)")
	}
}

// TestApplyFileSignatureMarkdown Markdown/HTML 下载：HTML 注释行（渲染不可见）。
func TestApplyFileSignatureMarkdown(t *testing.T) {
	cfg := sigTestConfig(t)
	now := time.Unix(1780000000, 0).UTC()
	out, token, applied, err := ApplyFileSignature([]byte("# Readme"), "text/markdown", cfg, "readme.md", "", now)
	if err != nil || !applied {
		t.Fatalf("apply: %v applied=%v", err, applied)
	}
	if string(out) != "# Readme\n<!-- "+token+" -->" {
		t.Fatalf("markdown signed body = %q", out)
	}
}

// TestApplyFileSignatureSkips 跳过情形：nil/未启用/空体/超出 v1 文本族类型（application/pdf
// 等二进制需媒体库，不在 v1 范围）→ applied=false 且体逐字节不变、无错误。
func TestApplyFileSignatureSkips(t *testing.T) {
	cfg := sigTestConfig(t)
	now := time.Unix(1780000000, 0).UTC()
	body := []byte("FAKE-PDF-BYTES")
	for _, c := range []struct {
		name string
		cfg  *FileSignatureConfig
		ct   string
	}{
		{"nil 配置", nil, "text/plain"},
		{"未启用", &FileSignatureConfig{}, "text/plain"},
		{"pdf 二进制", cfg, "application/pdf"},
		{"图片二进制", cfg, "image/png"},
	} {
		out, token, applied, err := ApplyFileSignature(body, c.ct, c.cfg, "a.bin", "", now)
		if err != nil || applied || token != "" || string(out) != string(body) {
			t.Errorf("%s: must pass through: applied=%v err=%v", c.name, applied, err)
		}
	}
	// 空体跳过
	if _, _, applied, _ := ApplyFileSignature(nil, "text/plain", cfg, "a.txt", "", now); applied {
		t.Error("empty body must skip")
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
