package apisecurity

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type taxonomySeedKey struct {
	dimension string
	value     string
}

type builtinDescUpdateTuple struct {
	code    string
	oldDesc string
	newDesc string
}

type taxonomyDescUpdateTuple struct {
	key     taxonomySeedKey
	oldDesc string
	newDesc string
}

var (
	builtinInsertBlockRe  = regexp.MustCompile(`(?is)INSERT\s+INTO\s+api_classifications\b[\s\S]*?;`)
	taxonomyInsertBlockRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+api_custom_taxonomies\b[\s\S]*?;`)
	builtinSeedRowRe      = regexp.MustCompile(`\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*TRUE\s*\)`)
	taxonomySeedRowRe     = regexp.MustCompile(`\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\)`)

	builtinUpdateBlockRe  = regexp.MustCompile(`(?is)UPDATE\s+api_classifications\s+AS\s+c[\s\S]*?;`)
	taxonomyUpdateBlockRe = regexp.MustCompile(`(?is)UPDATE\s+api_custom_taxonomies\s+AS\s+t[\s\S]*?;`)
	valuesSectionRe       = regexp.MustCompile(`(?is)FROM\s*\(\s*VALUES\b[\s\S]*?\)\s*AS\s+v\(`)
	threeQuotedTupleRe    = regexp.MustCompile(`\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\)`)
	fourQuotedTupleRe     = regexp.MustCompile(`\(\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*,\s*'([^']+)'\s*\)`)
	asciiLetterRe         = regexp.MustCompile(`[A-Za-z]`)
)

func parseBuiltinSeedDescriptions(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed migration %s: %v", path, err)
	}
	block := builtinInsertBlockRe.FindString(string(raw))
	if block == "" {
		t.Fatalf("no INSERT INTO api_classifications block found in %s", path)
	}
	matches := builtinSeedRowRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("no builtin seed rows found in %s", path)
	}
	out := make(map[string]string, len(matches))
	for _, m := range matches {
		code, desc := m[1], m[3]
		if _, dup := out[code]; dup {
			t.Fatalf("duplicate builtin code %q in %s", code, path)
		}
		out[code] = desc
	}
	return out
}

func parseTaxonomySeedDescriptions(t *testing.T, path string) map[taxonomySeedKey]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed migration %s: %v", path, err)
	}
	block := taxonomyInsertBlockRe.FindString(string(raw))
	if block == "" {
		t.Fatalf("no INSERT INTO api_custom_taxonomies block found in %s", path)
	}
	matches := taxonomySeedRowRe.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("no taxonomy seed rows found in %s", path)
	}
	out := make(map[taxonomySeedKey]string, len(matches))
	for _, m := range matches {
		key := taxonomySeedKey{dimension: m[1], value: m[2]}
		if _, dup := out[key]; dup {
			t.Fatalf("duplicate taxonomy key %+v in %s", key, path)
		}
		out[key] = m[3]
	}
	return out
}

func parseClassificationDescriptionMigration(t *testing.T, path string) (
	string,
	map[string]builtinDescUpdateTuple,
	map[taxonomySeedKey]taxonomyDescUpdateTuple,
) {
	t.Helper()
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	raw := string(rawBytes)

	builtinStmt := builtinUpdateBlockRe.FindString(raw)
	if builtinStmt == "" {
		t.Fatalf("no UPDATE api_classifications statement in %s", path)
	}
	builtinVals := valuesSectionRe.FindString(builtinStmt)
	if builtinVals == "" {
		t.Fatalf("no VALUES block in UPDATE api_classifications in %s", path)
	}
	builtinMatches := threeQuotedTupleRe.FindAllStringSubmatch(builtinVals, -1)
	if len(builtinMatches) == 0 {
		t.Fatalf("no builtin update tuples in %s", path)
	}
	builtinOut := make(map[string]builtinDescUpdateTuple, len(builtinMatches))
	for _, m := range builtinMatches {
		code := m[1]
		if _, dup := builtinOut[code]; dup {
			t.Fatalf("duplicate builtin update code %q in %s", code, path)
		}
		builtinOut[code] = builtinDescUpdateTuple{
			code:    code,
			oldDesc: m[2],
			newDesc: m[3],
		}
	}

	taxonomyStmt := taxonomyUpdateBlockRe.FindString(raw)
	if taxonomyStmt == "" {
		t.Fatalf("no UPDATE api_custom_taxonomies statement in %s", path)
	}
	taxonomyVals := valuesSectionRe.FindString(taxonomyStmt)
	if taxonomyVals == "" {
		t.Fatalf("no VALUES block in UPDATE api_custom_taxonomies in %s", path)
	}
	taxonomyMatches := fourQuotedTupleRe.FindAllStringSubmatch(taxonomyVals, -1)
	if len(taxonomyMatches) == 0 {
		t.Fatalf("no taxonomy update tuples in %s", path)
	}
	taxonomyOut := make(map[taxonomySeedKey]taxonomyDescUpdateTuple, len(taxonomyMatches))
	for _, m := range taxonomyMatches {
		key := taxonomySeedKey{dimension: m[1], value: m[2]}
		if _, dup := taxonomyOut[key]; dup {
			t.Fatalf("duplicate taxonomy update key %+v in %s", key, path)
		}
		taxonomyOut[key] = taxonomyDescUpdateTuple{
			key:     key,
			oldDesc: m[3],
			newDesc: m[4],
		}
	}

	return raw, builtinOut, taxonomyOut
}

// TestClassificationDescriptionCopyMigrationContract 校验 000230 迁移与全部内置用途分类及维度词表种子精确对齐：
// 1) 34 条 api_classifications 与 104 条 api_custom_taxonomies 种子在应用 000230 后均不含任何英文字母或内部启发式提示；
// 2) 每条 old_description 与原种子迁移逐字符一致；
// 3) up/down 完全对称，且均通过原/新 description 精确条件保护人工修订不被覆盖。
func TestClassificationDescriptionCopyMigrationContract(t *testing.T) {
	migDir := filepath.Join("..", "..", "migrations")

	builtinSeeds := make(map[string]string)
	for _, name := range []string{
		"000073_api_classifications_seed.up.sql",
		"000087_api_classifications_expansion.up.sql",
		"000096_api_classifications_builtin_backfill.up.sql",
	} {
		for code, desc := range parseBuiltinSeedDescriptions(t, filepath.Join(migDir, name)) {
			if _, dup := builtinSeeds[code]; dup {
				t.Fatalf("overlapping builtin seed code %q across migrations", code)
			}
			builtinSeeds[code] = desc
		}
	}
	if len(builtinSeeds) != 34 {
		t.Fatalf("expected 34 builtin classification seeds across 000073+000087+000096, got %d", len(builtinSeeds))
	}

	taxonomySeeds := make(map[taxonomySeedKey]string)
	for _, name := range []string{
		"000095_api_taxonomy_catalog_seed.up.sql",
		"000148_api_action_vocabulary_seed.up.sql",
	} {
		for key, desc := range parseTaxonomySeedDescriptions(t, filepath.Join(migDir, name)) {
			if _, dup := taxonomySeeds[key]; dup {
				t.Fatalf("overlapping taxonomy seed key %+v across migrations", key)
			}
			taxonomySeeds[key] = desc
		}
	}
	if len(taxonomySeeds) != 104 {
		t.Fatalf("expected 104 custom taxonomy seeds across 000095+000148, got %d", len(taxonomySeeds))
	}

	upPath := filepath.Join(migDir, "000230_api_classifications_description_copy.up.sql")
	downPath := filepath.Join(migDir, "000230_api_classifications_description_copy.down.sql")

	upRaw, upBuiltin, upTaxonomy := parseClassificationDescriptionMigration(t, upPath)
	downRaw, downBuiltin, downTaxonomy := parseClassificationDescriptionMigration(t, downPath)

	// 非侵入保护：up 仅覆盖 old_description，down 仅回退 new_description
	if !strings.Contains(upRaw, "SET description = v.new_description") ||
		!strings.Contains(upRaw, "AND c.description = v.old_description") ||
		!strings.Contains(upRaw, "AND t.description = v.old_description") {
		t.Fatalf("up migration must guard updates with c.description/t.description = v.old_description")
	}
	if !strings.Contains(downRaw, "SET description = v.old_description") ||
		!strings.Contains(downRaw, "AND c.description = v.new_description") ||
		!strings.Contains(downRaw, "AND t.description = v.new_description") {
		t.Fatalf("down migration must guard rollbacks with c.description/t.description = v.new_description")
	}

	if len(upBuiltin) != len(downBuiltin) {
		t.Fatalf("builtin tuple count mismatch: up=%d down=%d", len(upBuiltin), len(downBuiltin))
	}
	if len(upTaxonomy) != len(downTaxonomy) {
		t.Fatalf("taxonomy tuple count mismatch: up=%d down=%d", len(upTaxonomy), len(downTaxonomy))
	}

	for code, up := range upBuiltin {
		seedDesc, ok := builtinSeeds[code]
		if !ok {
			t.Fatalf("up migration references unknown builtin code %q", code)
		}
		if up.oldDesc != seedDesc {
			t.Errorf("builtin %s old_description mismatch:\n  got:  %q\n  want: %q", code, up.oldDesc, seedDesc)
		}
		if up.newDesc == "" || up.newDesc == up.oldDesc {
			t.Errorf("builtin %s invalid new_description %q", code, up.newDesc)
		}
		down, ok := downBuiltin[code]
		if !ok || down != up {
			t.Errorf("builtin %s down tuple %+v != up tuple %+v", code, down, up)
		}
		builtinSeeds[code] = up.newDesc
	}

	for key, up := range upTaxonomy {
		seedDesc, ok := taxonomySeeds[key]
		if !ok {
			t.Fatalf("up migration references unknown taxonomy key %+v", key)
		}
		if up.oldDesc != seedDesc {
			t.Errorf("taxonomy %+v old_description mismatch:\n  got:  %q\n  want: %q", key, up.oldDesc, seedDesc)
		}
		if up.newDesc == "" || up.newDesc == up.oldDesc {
			t.Errorf("taxonomy %+v invalid new_description %q", key, up.newDesc)
		}
		down, ok := downTaxonomy[key]
		if !ok || down != up {
			t.Errorf("taxonomy %+v down tuple %+v != up tuple %+v", key, down, up)
		}
		taxonomySeeds[key] = up.newDesc
	}

	// 应用 000230 后，全部内置分类与词表说明均不得含英文字母或内部启发式提示
	for code, desc := range builtinSeeds {
		if asciiLetterRe.MatchString(desc) || strings.Contains(desc, "启发式") {
			t.Errorf("builtin %s description still contains English or heuristic copy: %q", code, desc)
		}
	}
	for key, desc := range taxonomySeeds {
		if asciiLetterRe.MatchString(desc) || strings.Contains(desc, "启发式") {
			t.Errorf("taxonomy %+v description still contains English or heuristic copy: %q", key, desc)
		}
	}
}
