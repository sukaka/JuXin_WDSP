package tests

import (
	"context"
	"os"
	"testing"
)

// TestStage8AuthzMigration000136Replay verifies the AUTHZ-01 migration against
// PostgreSQL itself: replay must remain idempotent and the safety constraints
// must be present after the replay.
func TestStage8AuthzMigration000136Replay(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	raw, err := os.ReadFile("../migrations/000136_authz_observe_relations.up.sql")
	if err != nil {
		t.Fatalf("read 000136 up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("replay 000136 #%d: %v", i+1, err)
		}
	}

	for _, table := range []string{
		"api_object_relation_candidates",
		"api_authz_candidate_event_receipts",
		"api_object_relations",
		"api_authorization_decisions",
		"api_authz_migration_state",
	} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s count=%d want 1", table, n)
		}
	}

	if n := s8Count(t, env, `SELECT count(*) FROM api_authz_migration_state WHERE migration_key=$1`, "legacy_object_ownership_v1"); n != 1 {
		t.Fatalf("migration state rows=%d want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ($1,$2)`,
		"api_authorization.relation_manage", "api_authorization.evidence_read"); n != 2 {
		t.Fatalf("AUTHZ permission rows=%d want 2", n)
	}

	for _, constraint := range []string{
		"ck_authz_candidate_identity_domain",
		"ck_authz_relation_validity",
		"uq_authz_relation",
		"uq_api_authorization_decision",
	} {
		if n := s8Count(t, env, `SELECT count(*) FROM pg_constraint WHERE conname=$1`, constraint); n != 1 {
			t.Fatalf("constraint %s count=%d want 1", constraint, n)
		}
	}
}
