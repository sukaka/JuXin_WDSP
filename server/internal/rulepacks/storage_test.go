package rulepacks

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestStorageEnsureSeededAndRelativeSymlink(t *testing.T) {
	seedDir := makeMinimalRulesTree(t)
	storeDir := filepath.Join(t.TempDir(), "rules-store")
	archivesDir := filepath.Join(t.TempDir(), "archives")
	st := NewStorage(storeDir, archivesDir)

	if !st.Writable() {
		t.Fatal("expected storage to be writable")
	}

	seeded, activeVer, err := st.EnsureSeeded(seedDir, "builtin-1.19.1")
	if err != nil {
		t.Fatalf("EnsureSeeded: %v", err)
	}
	if !seeded || activeVer != "builtin-1.19.1" {
		t.Fatalf("seeded=%v activeVer=%q, want true / builtin-1.19.1", seeded, activeVer)
	}
	// 验证 current 为相对符号链接（跨容器/宿主机挂载通用）
	rawLink, err := os.Readlink(st.CurrentSymlinkPath())
	if err != nil {
		t.Fatalf("readlink current: %v", err)
	}
	if rawLink != filepath.Join("releases", "builtin-1.19.1") {
		t.Fatalf("current symlink = %q, want relative %q", rawLink, filepath.Join("releases", "builtin-1.19.1"))
	}

	// 落盘一个更新的客户规则包并切换 current 后，再次 EnsureSeeded 绝不能覆盖客户版本
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkgBytes := buildSignedRulePackFromDir(t, seedDir, "20261201.1", "4.28.0", "1.19.1", priv, nil)
	pkgPath := filepath.Join(t.TempDir(), "pkg.tar.gz")
	_ = os.WriteFile(pkgPath, pkgBytes, 0o600)

	if _, err := st.StageArchive(pkgPath, "20261201.1"); err != nil {
		t.Fatalf("StageArchive: %v", err)
	}
	if err := st.SwitchCurrentSymlink("20261201.1"); err != nil {
		t.Fatalf("SwitchCurrentSymlink: %v", err)
	}

	seeded2, activeVer2, err := st.EnsureSeeded(seedDir, "builtin-1.20.0")
	if err != nil {
		t.Fatalf("second EnsureSeeded: %v", err)
	}
	if seeded2 || activeVer2 != "20261201.1" {
		t.Fatalf("EnsureSeeded clobbered newer customer rulepack! seeded=%v activeVer=%q", seeded2, activeVer2)
	}
}

func TestStoragePruneReleasesProtectsActiveBuiltinAndConfigRefs(t *testing.T) {
	seedDir := makeMinimalRulesTree(t)
	storeDir := filepath.Join(t.TempDir(), "rules-store")
	st := NewStorage(storeDir, "")
	if _, _, err := st.EnsureSeeded(seedDir, "builtin-1.19.1"); err != nil {
		t.Fatalf("EnsureSeeded: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	versions := []string{"20261001.1", "20261015.1", "20261101.1", "20261115.1", "20261201.1"}
	for _, v := range versions {
		raw := buildSignedRulePackFromDir(t, seedDir, v, "4.28.0", "1.19.1", priv, nil)
		p := filepath.Join(t.TempDir(), v+".tar.gz")
		_ = os.WriteFile(p, raw, 0o600)
		if _, err := st.StageArchive(p, v); err != nil {
			t.Fatalf("stage %s: %v", v, err)
		}
	}

	// 保留 2 个最新（20261201.1, 20261115.1），但显式保护历史配置引用的 20261001.1
	protected := map[string]bool{
		"20261201.1": true,
		"20261001.1": true,
	}
	pruned, err := st.PruneReleases(2, protected)
	if err != nil {
		t.Fatalf("PruneReleases: %v", err)
	}
	if len(pruned) != 2 {
		t.Fatalf("pruned=%v, want 2 releases (20261101.1, 20261015.1)", pruned)
	}
	if !st.HasRelease("builtin-1.19.1") {
		t.Fatal("builtin baseline must never be pruned")
	}
	if !st.HasRelease("20261001.1") {
		t.Fatal("protected config-referenced release 20261001.1 must not be pruned")
	}
	if !st.HasRelease("20261201.1") || !st.HasRelease("20261115.1") {
		t.Fatal("newest retained releases must remain")
	}
	if st.HasRelease("20261101.1") || st.HasRelease("20261015.1") {
		t.Fatal("unprotected older releases should have been pruned")
	}
}
