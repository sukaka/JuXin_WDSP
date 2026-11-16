package wafrules

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// customPackDir 指向仓库内自建规则包目录（本包位于 server/internal/wafrules，
// 向上三级为仓库根目录）。
const customPackDir = "../../../gateway/rules/contrib/CUSTOM_PACK"

// TestCustomPackParses 解析 CUSTOM_PACK 全部规则文件，要求零失败且
// 规则 ID 全局唯一（防止各文件 ID 段漂移冲突）。
func TestCustomPackParses(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(customPackDir, "*.conf"))
	if err != nil {
		t.Fatalf("glob custom pack dir: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("no .conf files found in %s", customPackDir)
	}
	sort.Strings(files)

	seen := map[int]string{}
	total := 0
	for _, f := range files {
		rules, failed, err := ParseCRSFile(f, SourceCustomPack)
		if err != nil {
			t.Fatalf("ParseCRSFile(%s): %v", f, err)
		}
		for _, fail := range failed {
			t.Errorf("%s parse failure: %s", filepath.Base(f), fail)
		}
		for _, r := range rules {
			total++
			if prev, dup := seen[r.RuleID]; dup {
				t.Errorf("duplicate rule id %d in %s and %s", r.RuleID, prev, filepath.Base(f))
			}
			seen[r.RuleID] = filepath.Base(f)
			if r.RuleSource != SourceCustomPack {
				t.Errorf("rule %d source = %q, want CUSTOM_PACK", r.RuleID, r.RuleSource)
			}
			if r.Message == "" {
				t.Errorf("rule %d in %s has empty msg", r.RuleID, filepath.Base(f))
			}
			if r.Severity == "" {
				t.Errorf("rule %d in %s has empty severity", r.RuleID, filepath.Base(f))
			}
		}
	}
	t.Logf("parsed %d CUSTOM_PACK rules from %d files", total, len(files))
}

// TestCustomPackAttackCoverage 校验 attack-coverage.conf 的规则数量与 ID 段，
// 防止后续编辑意外丢规则或越段。
func TestCustomPackAttackCoverage(t *testing.T) {
	rules, failed, err := ParseCRSFile(filepath.Join(customPackDir, "attack-coverage.conf"), SourceCustomPack)
	if err != nil {
		t.Fatalf("ParseCRSFile: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("unexpected parse failures: %v", failed)
	}
	if len(rules) != 51 {
		t.Fatalf("parsed %d rules, want 51", len(rules))
	}
	for _, r := range rules {
		if r.RuleID < 1001100 || r.RuleID > 1001199 {
			t.Errorf("rule id %d out of range 1001100-1001199", r.RuleID)
		}
		if _, err := os.Stat(filepath.Join(customPackDir, "attack-coverage.conf")); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCustomPackPHP2Shell 校验 PHP2Shell 应急规则数量、ID 与阻断分层。
func TestCustomPackPHP2Shell(t *testing.T) {
	rules, failed, err := ParseCRSFile(filepath.Join(customPackDir, "cve-emergency.conf"), SourceCustomPack)
	if err != nil {
		t.Fatalf("ParseCRSFile: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("unexpected parse failures: %v", failed)
	}
	got := map[int]*Rule{}
	for _, r := range rules {
		if r.RuleID >= 1000043 && r.RuleID <= 1000047 {
			got[r.RuleID] = r
		}
	}
	if len(got) != 5 {
		t.Fatalf("PHP2Shell rules=%d want 5: %v", len(got), got)
	}
	for id := 1000043; id <= 1000046; id++ {
		r, ok := got[id]
		if !ok || r.Severity != "CRITICAL" || r.Message == "" {
			t.Errorf("rule %d invalid critical metadata: %+v", id, r)
		}
	}
	if r := got[1000047]; r.Severity != "WARNING" || r.Message == "" {
		t.Errorf("rule 1000047 invalid warning metadata: %+v", r)
	}
}

// TestCustomPackAttackVariantsEvasion 校验变种/绕过增强包数量与 ID 段。
func TestCustomPackAttackVariantsEvasion(t *testing.T) {
	rules, failed, err := ParseCRSFile(filepath.Join(customPackDir, "attack-variants-evasion.conf"), SourceCustomPack)
	if err != nil {
		t.Fatalf("ParseCRSFile: %v", err)
	}
	if len(failed) > 0 {
		t.Fatalf("unexpected parse failures: %v", failed)
	}
	if len(rules) != 99 {
		t.Fatalf("parsed %d rules, want 99", len(rules))
	}
	for _, r := range rules {
		if r.RuleID < 1001200 || r.RuleID > 1001299 {
			t.Errorf("rule id %d out of range 1001200-1001299", r.RuleID)
		}
		if r.Message == "" {
			t.Errorf("rule %d empty msg", r.RuleID)
		}
	}
}
