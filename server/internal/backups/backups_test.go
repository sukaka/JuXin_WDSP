package backups

import (
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestBackupFileName 文件名固定模式。
func TestBackupFileName(t *testing.T) {
	id := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	name := BackupFileName(id)
	if name != "backup-123e4567-e89b-12d3-a456-426614174000.jzbk" {
		t.Errorf("unexpected name: %s", name)
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		t.Error("name must not contain path elements")
	}
}

// TestSafeJoin 路径穿越防御。
func TestSafeJoin(t *testing.T) {
	dir := "/var/lib/jiuzhang/backups"
	p, err := SafeJoin(dir, "backup-x.jzbk")
	if err != nil {
		t.Fatalf("normal name rejected: %v", err)
	}
	if p != dir+"/backup-x.jzbk" {
		t.Errorf("unexpected path: %s", p)
	}
	for _, bad := range []string{
		"../etc/passwd", "a/b", "/etc/passwd", "..", ".", "", "a/../../b",
		"backup-x.jzbk\x00", `./\..`,
	} {
		if _, err := SafeJoin(dir, bad); err == nil {
			t.Errorf("unsafe name accepted: %q", bad)
		}
	}
}

// TestBackupPath 备份完整路径在目录内。
func TestBackupPath(t *testing.T) {
	id := uuid.New()
	p, err := BackupPath("/data", id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "/data/backups/") {
		t.Errorf("path outside backup dir: %s", p)
	}
}

// TestValidType 类型二次校验。
func TestValidType(t *testing.T) {
	if !ValidType(TypeFull) || !ValidType(TypeConfigOnly) {
		t.Error("valid types rejected")
	}
	for _, bad := range []string{"", "PARTIAL", "full", "DATABASE_ONLY", "CERTIFICATE_ONLY"} {
		if ValidType(bad) {
			t.Errorf("invalid type accepted: %q", bad)
		}
	}
}

// TestEncryptionRoundtrip 使用 encryption 测试密钥的端到端加密往返（含清单校验）。
func TestEncryptionRoundtrip(t *testing.T) {
	enc := testEnc(t)
	dir := t.TempDir()
	ex := &Exporter{enc: enc, dataDir: dir}
	path, _ := buildTestBackup(t, enc, dir, map[string][]string{
		"roles": {`{"id":"r1","name":"admin"}`},
		"users": {`{"id":"u1"}`},
	})
	// 全文件哈希与大小
	sum, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 64 {
		t.Error("sha256 hex length")
	}
	// 解密读回全部行
	var lines []string
	err = ex.WalkSegments(path, func(*Manifest) error { return nil }, func(table string, r io.Reader) error {
		body, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		for _, ln := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			lines = append(lines, table+":"+ln)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	if lines[0] != `roles:{"id":"r1","name":"admin"}` || lines[1] != `users:{"id":"u1"}` {
		t.Errorf("content mismatch: %v", lines)
	}
}
