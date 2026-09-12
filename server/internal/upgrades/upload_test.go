package upgrades

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// writeTmpPackage 写入临时升级包文件，返回路径与内容哈希。
func writeTmpPackage(t *testing.T, dir, content string) (string, string) {
	t.Helper()
	f, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return f.Name(), hex.EncodeToString(sum[:])
}

// TestFinalizeUpload 同名文件落盘语义：新建 rename、同哈希复用、异哈希冲突。
func TestFinalizeUpload(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(nil, nil, nil)
	target := filepath.Join(dir, "pkg.tar.gz")

	tmp1, hash1 := writeTmpPackage(t, dir, "content-v1")
	if err := h.finalizeUpload(target, tmp1, hash1); err != nil {
		t.Fatalf("首次落盘不应失败: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("目标文件应存在: %v", err)
	}

	// 同内容再传：复用现有文件，临时文件被清理
	tmp2, hash2 := writeTmpPackage(t, dir, "content-v1")
	if err := h.finalizeUpload(target, tmp2, hash2); err != nil {
		t.Fatalf("同哈希应复用: %v", err)
	}
	if _, err := os.Stat(tmp2); !os.IsNotExist(err) {
		t.Errorf("复用后临时文件应被删除")
	}

	// 不同内容同名：冲突
	tmp3, hash3 := writeTmpPackage(t, dir, "content-v2")
	if err := h.finalizeUpload(target, tmp3, hash3); !errors.Is(err, errUploadNameConflict) {
		t.Fatalf("异哈希同名应冲突, got %v", err)
	}
}

// TestFinalizeUploadConcurrent 回归（审查 LOW-S14）：同名并发上传（内容各异）在
// 互斥串行化下必须恰好一个成功、其余 409 冲突，且最终落盘文件哈希与胜出版本一致，
// 不得出现 check-then-rename 竞态导致的互相覆盖。
func TestFinalizeUploadConcurrent(t *testing.T) {
	dir := t.TempDir()
	h := NewHandler(nil, nil, nil)
	target := filepath.Join(dir, "pkg.tar.gz")

	const n = 8
	tmps := make([]string, n)
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		tmps[i], hashes[i] = writeTmpPackage(t, dir, string(rune('A'+i)))
	}

	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = h.finalizeUpload(target, tmps[i], hashes[i])
		}(i)
	}
	wg.Wait()

	var succeeded []int
	for i, err := range results {
		if err == nil {
			succeeded = append(succeeded, i)
			continue
		}
		if !errors.Is(err, errUploadNameConflict) {
			t.Errorf("上传 %d 出现意外错误: %v", i, err)
		}
	}
	// 恰好一个 rename 成功（其余同哈希复用不可能：内容互异，故均为冲突）
	if len(succeeded) != 1 {
		t.Fatalf("应恰好一个上传成功, got %d", len(succeeded))
	}
	finalHash, _, err := hashFileStreaming(target)
	if err != nil {
		t.Fatalf("读取最终文件失败: %v", err)
	}
	if finalHash != hashes[succeeded[0]] {
		t.Errorf("最终文件哈希应为胜出版本 %s, got %s（发生覆盖）", hashes[succeeded[0]], finalHash)
	}
}
