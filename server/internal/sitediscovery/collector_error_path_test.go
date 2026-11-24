package sitediscovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// 当 checkpoint 与日志位于不同目录（容器内日志卷只读、DataDir 可写）时，
// 坏行错误文件必须落入 checkpoint 同目录，而非只读日志卷。
func TestCollectorErrorFileUsesWritableCheckpointDir(t *testing.T) {
	logDir := t.TempDir()
	cpDir := t.TempDir()
	logPath := filepath.Join(logDir, "site-discovery.jsonl")
	cpPath := filepath.Join(cpDir, "site-discovery.checkpoint")

	if err := os.WriteFile(logPath, []byte("{corrupted-json\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
	c := NewCollector(NewMemStore(), "sd-err-dir", logPath, cpPath, "gw-1")
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	wantErr := filepath.Join(cpDir, "site-discovery.jsonl.errors")
	if _, err := os.Stat(wantErr); err != nil {
		t.Fatalf("expected error file in checkpoint dir %s: %v", wantErr, err)
	}
	if _, err := os.Stat(logPath + ".errors"); !os.IsNotExist(err) {
		t.Fatalf("error file should not be written into log dir")
	}
}
