package havipd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckHealth(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 24, 16, 30, 0, 0, time.UTC)

	// 1. 文件不存在 → 失败
	if err := checkHealthAt(filepath.Join(dir, "missing.json"), DefaultHealthMaxAge, now); err == nil {
		t.Fatal("缺失状态文件应健康检查失败")
	}

	// 2. 目录路径 → 失败
	if err := checkHealthAt(dir, DefaultHealthMaxAge, now); err == nil || !strings.Contains(err.Error(), "目录") {
		t.Fatalf("目录路径应失败: %v", err)
	}

	// 3. 合法新鲜状态文件（含自动创建不存在父目录）→ 通过
	nestedPath := filepath.Join(dir, "nested", "ha-vip-status.json")
	if err := WriteStatusAtomic(nestedPath, Status{
		Node:  "gw-a",
		State: StateStopped,
	}); err != nil {
		t.Fatalf("WriteStatusAtomic: %v", err)
	}
	fresh := now.Add(-10 * time.Second)
	if err := os.Chtimes(nestedPath, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if err := checkHealthAt(nestedPath, DefaultHealthMaxAge, now); err != nil {
		t.Fatalf("新鲜合法状态应健康: %v", err)
	}

	// 4. 各合法状态值均应通过
	for _, st := range []string{StateMaster, StateBackup, StateFault, StateDisabled, StateStopped} {
		p := filepath.Join(dir, "st-"+st+".json")
		if err := WriteStatusAtomic(p, Status{Node: "gw-a", State: st}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, fresh, fresh); err != nil {
			t.Fatal(err)
		}
		if err := checkHealthAt(p, DefaultHealthMaxAge, now); err != nil {
			t.Fatalf("状态 %s 应通过健康检查: %v", st, err)
		}
	}

	// 5. 状态文件过期（>30s）→ 失败
	stale := now.Add(-31 * time.Second)
	if err := os.Chtimes(nestedPath, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := checkHealthAt(nestedPath, DefaultHealthMaxAge, now); err == nil || !strings.Contains(err.Error(), "已过期") {
		t.Fatalf("过期状态文件应失败: %v", err)
	}

	// 6. 非法 JSON → 失败
	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte(`{"state":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(badJSON, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if err := checkHealthAt(badJSON, DefaultHealthMaxAge, now); err == nil || !strings.Contains(err.Error(), "JSON 非法") {
		t.Fatalf("损坏 JSON 应失败: %v", err)
	}

	// 7. 空/非法 state → 失败
	emptyState := filepath.Join(dir, "empty-state.json")
	if err := os.WriteFile(emptyState, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(emptyState, fresh, fresh); err != nil {
		t.Fatal(err)
	}
	if err := checkHealthAt(emptyState, DefaultHealthMaxAge, now); err == nil || !strings.Contains(err.Error(), "state 取值非法") {
		t.Fatalf("非法 state 应失败: %v", err)
	}
}
