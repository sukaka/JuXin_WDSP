package apifiles

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type complianceSeedKey struct {
	direction  string
	matchType  string
	matchValue string
}

type reasonUpdateTuple struct {
	key       complianceSeedKey
	oldReason string
	newReason string
}

var (
	seedInsertBlockRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+api_file_compliance_rules\b[\s\S]*?;`)
	valuesBlockRe     = regexp.MustCompile(`(?is)FROM\s*\(\s*VALUES\b[\s\S]*?\)\s*AS\s+v\(`)
	fiveQuotedTupleRe = regexp.MustCompile(`\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\)`)
)

func parseSeedReasons(t *testing.T, path string) map[complianceSeedKey]struct {
	action string
	reason string
} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed migration %s: %v", path, err)
	}
	block := seedInsertBlockRe.FindString(string(raw))
	if block == "" {
		t.Fatalf("no INSERT INTO api_file_compliance_rules block found in %s", path)
	}
	matches := fiveQuotedTupleRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("no seed rows found in %s", path)
	}
	out := make(map[complianceSeedKey]struct {
		action string
		reason string
	}, len(matches))
	for _, m := range matches {
		key := complianceSeedKey{
			direction:  m[1],
			matchType:  m[2],
			matchValue: m[3],
		}
		if _, dup := out[key]; dup {
			t.Fatalf("duplicate seed key %+v in %s", key, path)
		}
		out[key] = struct {
			action string
			reason string
		}{action: m[4], reason: m[5]}
	}
	return out
}

func parseReasonUpdateTuples(t *testing.T, path string) map[complianceSeedKey]reasonUpdateTuple {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	block := valuesBlockRe.FindString(string(raw))
	if block == "" {
		t.Fatalf("no FROM (VALUES ...) AS v(...) block found in %s", path)
	}
	matches := fiveQuotedTupleRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("no update tuples found in %s", path)
	}
	out := make(map[complianceSeedKey]reasonUpdateTuple, len(matches))
	for _, m := range matches {
		key := complianceSeedKey{
			direction:  m[1],
			matchType:  m[2],
			matchValue: m[3],
		}
		if _, dup := out[key]; dup {
			t.Fatalf("duplicate update key %+v in %s", key, path)
		}
		out[key] = reasonUpdateTuple{
			key:       key,
			oldReason: m[4],
			newReason: m[5],
		}
	}
	return out
}

// TestComplianceReasonCopyMigrationContract 校验 000227 迁移与 000071/000081 内置种子精确对齐：
// 1) 18 条默认规则全部覆盖，old_reason 与原种子逐字符一致；
// 2) up/down 映射完全对称，且均通过 reason 精确条件保护手工修改不被覆盖；
// 3) 新文案通过 ComplianceRule.validate 且不含生硬研发术语。
func TestComplianceReasonCopyMigrationContract(t *testing.T) {
	migDir := filepath.Join("..", "..", "migrations")

	seeds := make(map[complianceSeedKey]struct {
		action string
		reason string
	})
	for _, name := range []string{
		"000071_api_file_compliance.up.sql",
		"000081_api_file_compliance_webshell_ext_seed.up.sql",
	} {
		for k, v := range parseSeedReasons(t, filepath.Join(migDir, name)) {
			if _, dup := seeds[k]; dup {
				t.Fatalf("overlapping seed key %+v across migrations", k)
			}
			seeds[k] = v
		}
	}
	if len(seeds) != 18 {
		t.Fatalf("expected 18 built-in seed rules across 000071+000081, got %d", len(seeds))
	}

	upPath := filepath.Join(migDir, "000227_api_file_compliance_reason_copy.up.sql")
	downPath := filepath.Join(migDir, "000227_api_file_compliance_reason_copy.down.sql")

	upRaw, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	downRaw, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}

	// 非侵入保护：up 仅覆盖 old_reason，down 仅回退 new_reason
	if !strings.Contains(string(upRaw), "SET reason     = v.new_reason") ||
		!strings.Contains(string(upRaw), "AND r.reason      = v.old_reason") {
		t.Fatalf("up migration must guard update with r.reason = v.old_reason")
	}
	if !strings.Contains(string(downRaw), "SET reason     = v.old_reason") ||
		!strings.Contains(string(downRaw), "AND r.reason      = v.new_reason") {
		t.Fatalf("down migration must guard rollback with r.reason = v.new_reason")
	}

	upTuples := parseReasonUpdateTuples(t, upPath)
	downTuples := parseReasonUpdateTuples(t, downPath)
	if len(upTuples) != len(seeds) {
		t.Fatalf("up migration tuple count = %d, want %d", len(upTuples), len(seeds))
	}
	if len(downTuples) != len(seeds) {
		t.Fatalf("down migration tuple count = %d, want %d", len(downTuples), len(seeds))
	}

	forbidden := []string{"投递面", "初始建议", "载荷"}
	for key, seed := range seeds {
		up, ok := upTuples[key]
		if !ok {
			t.Fatalf("up migration missing seed rule %+v", key)
		}
		if up.oldReason != seed.reason {
			t.Errorf("%+v old_reason mismatch:\n  got:  %q\n  want: %q", key, up.oldReason, seed.reason)
		}
		if up.newReason == "" || up.newReason == up.oldReason {
			t.Errorf("%+v invalid new_reason %q", key, up.newReason)
		}
		for _, bad := range forbidden {
			if strings.Contains(up.newReason, bad) {
				t.Errorf("%+v new_reason %q still contains %q", key, up.newReason, bad)
			}
		}

		rule := ComplianceRule{
			Direction:  key.direction,
			MatchType:  key.matchType,
			MatchValue: key.matchValue,
			Action:     seed.action,
			Reason:     up.newReason,
			Enabled:    true,
		}
		rule.normalize()
		if err := rule.validate(); err != nil {
			t.Errorf("%+v failed rule validation with new_reason %q: %v", key, up.newReason, err)
		}

		down, ok := downTuples[key]
		if !ok {
			t.Fatalf("down migration missing seed rule %+v", key)
		}
		if down != up {
			t.Errorf("%+v down tuple %+v != up tuple %+v", key, down, up)
		}
	}
}
