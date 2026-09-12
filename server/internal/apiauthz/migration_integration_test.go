package apiauthz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openAuthzPostgres(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping AUTHZ PG migration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

// TestAuthzMigrationPostgresContract validates 000136 against a disposable
// PostgreSQL database. The test is opt-in so local unit-test runs do not
// require a live database.
func TestAuthzMigrationPostgresContract(t *testing.T) {
	pool, ctx := openAuthzPostgres(t)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// A rerun must be a no-op, which protects deploy retries after a partial
	// control-plane restart.
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}

	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 136`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 136 records=%d, want 1", applied)
	}

	for _, table := range []string{
		"api_object_relation_candidates",
		"api_authz_candidate_event_receipts",
		"api_object_relations",
		"api_authorization_decisions",
		"api_authz_migration_state",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("table %s missing after migration", table)
		}
	}

	columns := map[string][]string{
		"api_role_baselines":             {"identity_assurance"},
		"api_object_models":              {"publishable", "required_relation", "owner_exclusive"},
		"api_object_relation_candidates": {"principal_id", "legacy_identity_fingerprint", "confidence_inputs"},
		"api_authorization_decisions":    {"decision_id", "checks", "evidence"},
	}
	for table, names := range columns {
		for _, name := range names {
			var exists bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
			)`, table, name).Scan(&exists); err != nil {
				t.Fatalf("check column %s.%s: %v", table, name, err)
			}
			if !exists {
				t.Fatalf("column %s.%s missing after migration", table, name)
			}
		}
	}

	for _, constraint := range []string{
		"ck_authz_candidate_identity_domain",
		"ck_authz_relation_validity",
		"uq_authz_relation",
		"uq_api_authorization_decision",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_constraint WHERE conname = $1
		)`, constraint).Scan(&exists); err != nil {
			t.Fatalf("check constraint %s: %v", constraint, err)
		}
		if !exists {
			t.Fatalf("constraint %s missing after migration", constraint)
		}
	}

	var permissionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM permissions
		WHERE code IN ('api_authorization.relation_manage', 'api_authorization.evidence_read')`).Scan(&permissionCount); err != nil {
		t.Fatalf("check AUTHZ permissions: %v", err)
	}
	if permissionCount != 2 {
		t.Fatalf("AUTHZ permissions=%d, want 2", permissionCount)
	}
}

// TestAuthzMigrationPostgresLegacyOwnershipContract verifies the AZ-01
// one-time bridge from the legacy ownership table. It is opt-in because it
// requires a disposable PostgreSQL database with the complete schema.
func TestAuthzMigrationPostgresLegacyOwnershipContract(t *testing.T) {
	pool, ctx := openAuthzPostgres(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// The migration state is process-wide in the schema. Reset it so this
	// opt-in contract remains repeatable against a reused disposable database.
	if _, err := pool.Exec(ctx, `UPDATE api_authz_migration_state
		SET status='PENDING',rows_migrated=0,last_error='',updated_at=now()
		WHERE migration_key='legacy_object_ownership_v1'`); err != nil {
		t.Fatalf("reset legacy migration state: %v", err)
	}

	var applicationID, endpointID string
	code := fmt.Sprintf("authz-migration-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&applicationID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	endpointKey := fmt.Sprintf("%s:GET:/orders/{id}", code)
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key) VALUES ($1,'GET','/orders/{id}',$2) RETURNING id`, applicationID, endpointKey).Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_object_ownership WHERE endpoint_id=$1`, endpointID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
	})

	legacyFingerprint := "legacy-fp-" + code
	objectID := "42"
	if _, err := pool.Exec(ctx, `INSERT INTO api_object_ownership(endpoint_id,identity_fingerprint,object_type,object_id,access_count) VALUES ($1,$2,'order',$3,7)`, endpointID, legacyFingerprint, objectID); err != nil {
		t.Fatalf("insert legacy ownership: %v", err)
	}
	keyHex := strings.Repeat("ab", 32)
	store := NewStore(pool)
	migrated, err := store.MigrateLegacyOwnershipOnce(ctx, keyHex)
	if err != nil {
		t.Fatalf("migrate legacy ownership: %v", err)
	}
	if migrated != 1 {
		t.Fatalf("migrated rows=%d, want 1", migrated)
	}

	var objectRef, legacyFP, source, status, evidenceRef string
	var sourceCount int
	var observationCount int64
	var confidence []byte
	if err := pool.QueryRow(ctx, `SELECT object_ref,legacy_identity_fingerprint,source,status,source_count,observation_count,confidence_inputs,evidence_ref
		FROM api_object_relation_candidates WHERE application_id=$1`, applicationID).Scan(&objectRef, &legacyFP, &source, &status, &sourceCount, &observationCount, &confidence, &evidenceRef); err != nil {
		t.Fatalf("read migrated candidate: %v", err)
	}
	if objectRef != objectReference(mustDecodeKey(t, keyHex), objectID) || legacyFP != legacyFingerprint {
		t.Fatalf("candidate identity = (%q,%q), want (%q,%q)", objectRef, legacyFP, objectReference(mustDecodeKey(t, keyHex), objectID), legacyFingerprint)
	}
	if source != "OBSERVED_ACCESS" || status != "FROZEN" || sourceCount != 1 || observationCount != 7 || evidenceRef != "legacy_object_ownership_v1" {
		t.Fatalf("candidate metadata = source %q status %q source_count %d observation_count %d evidence_ref %q", source, status, sourceCount, observationCount, evidenceRef)
	}
	var principalNull bool
	if err := pool.QueryRow(ctx, `SELECT principal_id IS NULL FROM api_object_relation_candidates WHERE application_id=$1`, applicationID).Scan(&principalNull); err != nil {
		t.Fatalf("check principal null: %v", err)
	}
	var confidenceFields map[string]any
	if err := json.Unmarshal(confidence, &confidenceFields); err != nil {
		t.Fatalf("decode confidence inputs: %v", err)
	}
	if !principalNull || confidenceFields["identity_assurance"] != "LEGACY_UNVERIFIED" || confidenceFields["confirmable"] != false {
		t.Fatalf("candidate trust fields principal_null=%v confidence=%s", principalNull, confidence)
	}

	var relations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_object_relations WHERE application_id=$1`, applicationID).Scan(&relations); err != nil {
		t.Fatalf("check trusted relations: %v", err)
	}
	if relations != 0 {
		t.Fatalf("trusted relations=%d, want 0", relations)
	}
	if migrated, err = store.MigrateLegacyOwnershipOnce(ctx, keyHex); err != nil {
		t.Fatalf("rerun legacy migration: %v", err)
	} else if migrated != 0 {
		t.Fatalf("rerun migrated rows=%d, want 0", migrated)
	}
	var state string
	var rowsMigrated int64
	if err := pool.QueryRow(ctx, `SELECT status,rows_migrated FROM api_authz_migration_state WHERE migration_key='legacy_object_ownership_v1'`).Scan(&state, &rowsMigrated); err != nil {
		t.Fatalf("read migration state: %v", err)
	}
	if state != "COMPLETED" || rowsMigrated != 1 {
		t.Fatalf("migration state=(%s,%d), want (COMPLETED,1)", state, rowsMigrated)
	}
}

// TestAuthzCandidateSweepPostgresConcurrentContract verifies that concurrent
// sweep workers claim one runtime event exactly once via row locking and the
// candidate-event receipt table.
func TestAuthzCandidateSweepPostgresConcurrentContract(t *testing.T) {
	pool, ctx := openAuthzPostgres(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	code := fmt.Sprintf("authz-sweep-%d", time.Now().UnixNano())
	var applicationID, endpointID, eventID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&applicationID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	endpointKey := fmt.Sprintf("%s:GET:/orders/{id}", code)
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key) VALUES ($1,'GET','/orders/{id}',$2) RETURNING id`, applicationID, endpointKey).Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_runtime_events(id,request_id,endpoint_key,raw_path,occurred_at,jwt_verification) VALUES (gen_random_uuid(),$1,$2,'/orders/42',now(),$3::jsonb) RETURNING id`, code, endpointKey, `{"status":"VERIFIED","verified_principal_id":"principal-1","verified_tenant_id":"tenant-1","verified_identity_type":"HUMAN"}`).Scan(&eventID); err != nil {
		t.Fatalf("insert runtime event: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_runtime_events WHERE id=$1`, eventID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_endpoints WHERE id=$1`, endpointID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, applicationID)
	})

	keyHex := strings.Repeat("cd", 32)
	failedCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := NewStore(pool).SweepRelationCandidatesOnce(failedCtx, keyHex); err == nil {
		t.Fatal("canceled candidate sweep succeeded")
	}
	var receiptsAfterFailure int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_authz_candidate_event_receipts WHERE event_id=$1`, eventID).Scan(&receiptsAfterFailure); err != nil {
		t.Fatalf("check receipt after failed sweep: %v", err)
	}
	if receiptsAfterFailure != 0 {
		t.Fatalf("receipts after failed sweep=%d, want 0", receiptsAfterFailure)
	}
	start := make(chan struct{})
	results := make(chan *CandidateSweepResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := NewStore(pool).SweepRelationCandidatesOnce(ctx, keyHex)
			results <- result
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent candidate sweep: %v", err)
		}
	}
	var scanned, upserted int
	for result := range results {
		scanned += result.EventsScanned
		upserted += result.CandidatesUpserted
	}
	if scanned != 1 || upserted != 1 {
		t.Fatalf("concurrent sweep totals scanned=%d upserted=%d, want 1/1", scanned, upserted)
	}

	var receipts, candidates, observations int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_authz_candidate_event_receipts WHERE event_id=$1`, eventID).Scan(&receipts); err != nil {
		t.Fatalf("count candidate receipts: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*),COALESCE(sum(observation_count),0) FROM api_object_relation_candidates WHERE application_id=$1 AND principal_id='principal-1'`, applicationID).Scan(&candidates, &observations); err != nil {
		t.Fatalf("count candidates: %v", err)
	}
	if receipts != 1 || candidates != 1 || observations != 1 {
		t.Fatalf("candidate exactly-once state receipts=%d candidates=%d observations=%d, want 1/1/1", receipts, candidates, observations)
	}
}

func mustDecodeKey(t *testing.T, keyHex string) []byte {
	t.Helper()
	key, err := decodeObjectHMACKey(keyHex)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	return key
}

// TestAuthzMigrationPostgresConcurrentContract requires a real PostgreSQL
// instance. It starts two independent migration runners against the same
// database and verifies that the migration record is inserted exactly once.
// This is intentionally opt-in: a local unit-test run must not claim
// cross-process or PostgreSQL coverage without AUTHZ_TEST_PG_DSN.
func TestAuthzMigrationPostgresConcurrentContract(t *testing.T) {
	pool, ctx := openAuthzPostgres(t)

	version := 900000 + int(time.Now().UnixNano()%9999)
	table := fmt.Sprintf("authz_migration_lock_probe_%d", version)
	dir := t.TempDir()
	name := fmt.Sprintf("%06d_authz_migration_lock_probe", version)
	upSQL := fmt.Sprintf("CREATE TABLE %s (id INTEGER NOT NULL); SELECT pg_sleep(0.05);", table)
	if err := os.WriteFile(filepath.Join(dir, name+".up.sql"), []byte(upSQL), 0o600); err != nil {
		t.Fatalf("write probe migration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table)
		_, _ = pool.Exec(context.Background(), "DELETE FROM schema_migrations WHERE version=$1", version)
	})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- database.Migrate(ctx, pool, dir, "up")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}

	var records int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, version).Scan(&records); err != nil {
		t.Fatalf("check concurrent migration record: %v", err)
	}
	if records != 1 {
		t.Fatalf("concurrent migration records=%d, want 1", records)
	}
	var tableExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&tableExists); err != nil {
		t.Fatalf("check probe table: %v", err)
	}
	if !tableExists {
		t.Fatalf("probe table %s missing after concurrent migration", table)
	}
}

// TestAuthzMigrationPostgresFailureRetryContract requires a real PostgreSQL
// instance. It verifies that a failed migration leaves neither its DDL nor a
// schema_migrations completion row, then verifies that fixing the migration
// can be retried successfully and remains idempotent on a second run.
// This covers transaction failure recovery; it does not claim a process-kill
// or machine-crash simulation.
func TestAuthzMigrationPostgresFailureRetryContract(t *testing.T) {
	pool, ctx := openAuthzPostgres(t)

	version := 900000 + int(time.Now().UnixNano()%9999)
	table := fmt.Sprintf("authz_migration_recovery_probe_%d", version)
	dir := t.TempDir()
	name := fmt.Sprintf("%06d_authz_migration_recovery_probe", version)
	path := filepath.Join(dir, name+".up.sql")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP TABLE IF EXISTS "+table)
		_, _ = pool.Exec(context.Background(), "DELETE FROM schema_migrations WHERE version=$1", version)
	})

	// The table creation must be rolled back together with the failing
	// statement. The migration runner must not record a completed version.
	failingSQL := fmt.Sprintf("CREATE TABLE %s (id INTEGER NOT NULL); SELECT 1/0;", table)
	if err := os.WriteFile(path, []byte(failingSQL), 0o600); err != nil {
		t.Fatalf("write failing probe migration: %v", err)
	}
	if err := database.Migrate(ctx, pool, dir, "up"); err == nil {
		t.Fatal("failing migration succeeded")
	}

	var records int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, version).Scan(&records); err != nil {
		t.Fatalf("check failed migration record: %v", err)
	}
	if records != 0 {
		t.Fatalf("failed migration records=%d, want 0", records)
	}
	var tableExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&tableExists); err != nil {
		t.Fatalf("check rolled-back probe table: %v", err)
	}
	if tableExists {
		t.Fatalf("probe table %s survived failed migration", table)
	}

	if err := os.WriteFile(path, []byte(fmt.Sprintf("CREATE TABLE %s (id INTEGER NOT NULL);", table)), 0o600); err != nil {
		t.Fatalf("write fixed probe migration: %v", err)
	}
	if err := database.Migrate(ctx, pool, dir, "up"); err != nil {
		t.Fatalf("retry migration: %v", err)
	}
	if err := database.Migrate(ctx, pool, dir, "up"); err != nil {
		t.Fatalf("idempotent migration rerun: %v", err)
	}

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, version).Scan(&records); err != nil {
		t.Fatalf("check successful migration record: %v", err)
	}
	if records != 1 {
		t.Fatalf("successful migration records=%d, want 1", records)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&tableExists); err != nil {
		t.Fatalf("check retried probe table: %v", err)
	}
	if !tableExists {
		t.Fatalf("probe table %s missing after retry", table)
	}
}
