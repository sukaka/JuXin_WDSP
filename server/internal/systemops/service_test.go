// service_test.go 标志文件共享密钥签名（HIGH-14 后续增强）单元测试：
// 规范化载荷稳定性、HMAC 黄金向量、密钥自举、写标志附带可验证签名。
package systemops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecret = "abababababababababababababababababababababababababababababababab"

func testCommand() Command {
	return Command{
		Action:       ActionReboot,
		RequestedBy:  "tester",
		UserID:       "uid-1",
		RequestID:    "r1",
		RequestedAt:  "2026-09-05T00:00:00Z",
		DelaySeconds: 3,
	}
}

func TestCanonicalPayloadStable(t *testing.T) {
	want := "v1\nreboot\ntester\nuid-1\nr1\n2026-09-05T00:00:00Z\n3"
	if got := CanonicalPayload(testCommand()); got != want {
		t.Fatalf("规范化载荷不符:\n got=%q\nwant=%q", got, want)
	}
}

// TestSignCommandGolden 黄金向量与 `openssl dgst -sha256 -hmac` 输出一致
// （hostctl-exec.sh 验签侧即用 openssl 计算，两端必须逐字节吻合）。
func TestSignCommandGolden(t *testing.T) {
	cmd := testCommand()
	SignCommand(&cmd, []byte(testSecret))
	const want = "6c57a25aad778fec340bfbf3b798e056126671e5054eef6e382cb479ef21c618"
	if cmd.HMAC != want {
		t.Fatalf("HMAC 黄金向量不符: got=%s want=%s", cmd.HMAC, want)
	}
}

func TestSignCommandCoversAllFields(t *testing.T) {
	base := testCommand()
	SignCommand(&base, []byte(testSecret))
	mutations := map[string]func(*Command){
		"action":       func(c *Command) { c.Action = ActionShutdown },
		"requestedBy":  func(c *Command) { c.RequestedBy = "root" },
		"userID":       func(c *Command) { c.UserID = "uid-2" },
		"requestID":    func(c *Command) { c.RequestID = "r2" },
		"requestedAt":  func(c *Command) { c.RequestedAt = "2026-09-05T00:00:01Z" },
		"delaySeconds": func(c *Command) { c.DelaySeconds = 60 },
	}
	for field, mutate := range mutations {
		m := testCommand()
		mutate(&m)
		SignCommand(&m, []byte(testSecret))
		if m.HMAC == base.HMAC {
			t.Fatalf("篡改字段 %s 后签名未变化（字段未被签名覆盖）", field)
		}
	}
}

func TestLoadOrCreateHostctlSecret(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateHostctlSecret(dir)
	if err != nil {
		t.Fatalf("首次自举密钥: %v", err)
	}
	if len(key) != 64 {
		t.Fatalf("密钥应为 64 字符 hex，实际 %d", len(key))
	}
	fi, err := os.Stat(filepath.Join(dir, HostctlSecretName))
	if err != nil {
		t.Fatalf("密钥文件未创建: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("密钥文件权限应为 0600，实际 %o", fi.Mode().Perm())
	}
	again, err := LoadOrCreateHostctlSecret(dir)
	if err != nil {
		t.Fatalf("二次读取密钥: %v", err)
	}
	if string(again) != string(key) {
		t.Fatal("二次读取密钥与首次自举不一致")
	}
}

func TestLoadOrCreateHostctlSecretMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, HostctlSecretName), []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatalf("写入非法密钥: %v", err)
	}
	if _, err := LoadOrCreateHostctlSecret(dir); err == nil {
		t.Fatal("格式非法的密钥应返回错误（fail-closed）")
	}
}

func TestWriteFlagFileSigns(t *testing.T) {
	dir := t.TempDir()
	cmd := testCommand()
	cmd.RequestedAt = "2026-09-05T08:00:00Z"
	final, err := WriteFlagFile(dir, cmd)
	if err != nil {
		t.Fatalf("写标志文件: %v", err)
	}
	raw, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("读标志文件: %v", err)
	}
	var got Command
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("标志文件非合法 JSON: %v", err)
	}
	if got.HMAC == "" {
		t.Fatal("写出的标志文件缺少 hmac 字段")
	}
	secret, err := LoadOrCreateHostctlSecret(dir)
	if err != nil {
		t.Fatalf("读取密钥: %v", err)
	}
	unsigned := got
	SignCommand(&unsigned, secret)
	if unsigned.HMAC != got.HMAC {
		t.Fatalf("写出的签名无法用目录内密钥复算: got=%s recomputed=%s", got.HMAC, unsigned.HMAC)
	}
	// 密钥文件应位于标志目录且不属于待处理标志（不以 .json 结尾）
	if strings.HasSuffix(HostctlSecretName, ".json") {
		t.Fatal("密钥文件名不得被 *.json 标志扫描命中")
	}
}

func TestWriteFlagFileSecretDirBlocked(t *testing.T) {
	// 目录路径被普通文件占用：MkdirAll/密钥自举/写标志全部失败（fail-closed）。
	blocker := filepath.Join(t.TempDir(), "hostctl")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("创建占用文件: %v", err)
	}
	if _, err := WriteFlagFile(blocker, testCommand()); err == nil {
		t.Fatal("目录不可写应返回错误")
	}
}
