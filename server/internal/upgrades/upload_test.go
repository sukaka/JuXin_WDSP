package upgrades

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestResolveUploadVersions 版本来源优先级：包内 manifest 优先，表单交叉校验，
// 不一致报错，旧格式包须由表单提供。
func TestResolveUploadVersions(t *testing.T) {
	info := &packageManifestInfo{versionFrom: "2.0.0", versionTo: "2.1.0"}
	cases := []struct {
		name     string
		formFrom string
		formTo   string
		info     *packageManifestInfo
		wantFrom string
		wantTo   string
		wantErr  bool
	}{
		{"仅包内", "", "", info, "2.0.0", "2.1.0", false},
		{"仅表单（旧格式包）", "2.0.0", "2.1.0", nil, "2.0.0", "2.1.0", false},
		{"表单与包内一致", "2.0.0", "2.1.0", info, "2.0.0", "2.1.0", false},
		{"from 不一致", "1.9.9", "2.1.0", info, "", "", true},
		{"to 不一致", "2.0.0", "2.2.0", info, "", "", true},
		{"均无", "", "", nil, "", "", true},
		{"缺 to", "2.0.0", "", nil, "", "", true},
		{"包内仅部分字段+表单补齐", "2.0.0", "2.1.0", &packageManifestInfo{versionTo: "2.1.0"}, "2.0.0", "2.1.0", false},
	}
	for _, c := range cases {
		from, to, err := resolveUploadVersions(c.formFrom, c.formTo, c.info)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: 应报错", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: 意外报错: %v", c.name, err)
			continue
		}
		if from != c.wantFrom || to != c.wantTo {
			t.Errorf("%s: = %s -> %s, want %s -> %s", c.name, from, to, c.wantFrom, c.wantTo)
		}
	}
}

// TestMergeStoredManifest 登记 manifest 来源：包内 manifest.json 优先，
// 表单 manifest 字段仅覆盖 target_schema_version。
func TestMergeStoredManifest(t *testing.T) {
	raw := []byte(`{"product":"wdsp","version":"2.1.0","target_schema_version":9}`)
	info := &packageManifestInfo{raw: raw, targetSchema: 9}

	if got := mergeStoredManifest(info, ""); string(got) != string(raw) {
		t.Errorf("无表单时应保留包内 manifest: %s", got)
	}
	got := mergeStoredManifest(info, `{"target_schema_version":12}`)
	if ManifestTargetSchema(got) != 12 {
		t.Errorf("表单覆盖后 = %d, want 12", ManifestTargetSchema(got))
	}
	if !strings.Contains(string(got), `"version":"2.1.0"`) {
		t.Errorf("覆盖不应丢弃包内其他字段: %s", got)
	}
	// 包内不可解析（旧客户端）：沿用表单 manifest
	if got := mergeStoredManifest(nil, `{"target_schema_version":7}`); string(got) != `{"target_schema_version":7}` {
		t.Errorf("包内缺失时应沿用表单: %s", got)
	}
	// 表单非法 JSON：原样下传，由 buildPackage 拒绝
	if got := mergeStoredManifest(info, `{`); string(got) != `{` {
		t.Errorf("非法表单 manifest 应原样下传: %s", got)
	}
	// 表单不含 target_schema_version：保持包内值
	got = mergeStoredManifest(info, `{"note":"x"}`)
	if ManifestTargetSchema(got) != 9 {
		t.Errorf("未覆盖时应保持包内值 9, got %d", ManifestTargetSchema(got))
	}
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
