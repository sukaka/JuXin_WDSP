package tests

import (
	"strings"
	"testing"
)

func TestAuthzSharedRelationsMigration000216Static(t *testing.T) {
	up := readMigration(t, "000216_authz_shared_relations.up.sql")
	for _, fragment := range []string{
		"ADD COLUMN IF NOT EXISTS required_relations TEXT[]",
		"ck_api_object_models_required_relation",
		"required_relation IN ('OWNER', 'ANY_OF')",
		"ck_api_object_models_required_relations",
		"required_relation IS NULL AND required_relations IS NULL",
		"required_relations = '{}'::TEXT[]",
		"required_relations = ARRAY['OWNER', 'SHARED_WITH']::TEXT[]",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000216 up missing %q: %s", fragment, up)
		}
	}
	if strings.Contains(up, "DEFAULT '{OWNER") || strings.Contains(up, "UPDATE api_object_models SET required_relations") {
		t.Fatalf("000216 must not rewrite existing rows or default the nullable array: %s", up)
	}
	for _, unsupported := range []string{"DELEGATED_TO", "PARENT_OF"} {
		if strings.Contains(up, unsupported) {
			t.Fatalf("000216 must not introduce %s", unsupported)
		}
	}

	down := readMigration(t, "000216_authz_shared_relations.down.sql")
	for _, fragment := range []string{
		"DROP CONSTRAINT IF EXISTS ck_api_object_models_required_relations",
		"DROP COLUMN IF EXISTS required_relations",
		"required_relation IN ('OWNER')",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000216 down missing %q: %s", fragment, down)
		}
	}
	if strings.Contains(down, "UPDATE api_object_models") || strings.Contains(down, "DELETE FROM api_object_models") {
		t.Fatalf("000216 down must not silently rewrite or delete authorization models: %s", down)
	}
}
