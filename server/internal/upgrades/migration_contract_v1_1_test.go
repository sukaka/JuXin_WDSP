package upgrades

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIdentityBehaviorV11MigrationContract keeps the V1.1 schema contract
// reviewable without requiring a live database. Runtime migration tests can
// execute the same files against the supported PostgreSQL versions.
func TestIdentityBehaviorV11MigrationContract(t *testing.T) {
	root := filepath.Join("..", "..", "migrations")
	checks := map[string][]string{
		"000116_identity_contract_v1_1.up.sql": {
			"identity_confidence", "confidence_source", "behavior_statistics",
		},
		"000117_identity_behavior_v1_1_contract.up.sql": {
			"account_enum_threshold", "object_enum_threshold", "identity_evidence",
			"IF NOT EXISTS", "identity_behavior_events_identity_confidence_check",
		},
		"000118_rule_effect_stats_index.up.sql": {
			"idx_security_event_matches_effect_stats", "event_occurred_at",
		},
		"000119_rule_statistics_daily.up.sql": {
			"rule_statistics_daily", "confirmed_attack_count", "confirmed_false_positive_count",
		},
	}
	for name, needles := range checks {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		contents := string(data)
		for _, needle := range needles {
			if !strings.Contains(contents, needle) {
				t.Errorf("migration %s missing contract token %q", name, needle)
			}
		}
	}

	for _, name := range []string{
		"000116_identity_contract_v1_1.down.sql",
		"000117_identity_behavior_v1_1_contract.down.sql",
		"000118_rule_effect_stats_index.down.sql",
		"000119_rule_statistics_daily.down.sql",
	} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("missing rollback migration %s: %v", name, err)
		}
	}
}
