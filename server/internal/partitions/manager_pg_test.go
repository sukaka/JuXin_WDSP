package partitions

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func requirePartitionsTestPool(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("PARTITIONS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("PARTITIONS_TEST_PG_DSN not set, skipping PG integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, dsn
}

func replaceDSNDatabase(dsn, dbName string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func copyMigrationsUpTo(t *testing.T, srcDir, dstDir string, maxVersion int) {
	t.Helper()
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read migrations dir %s: %v", srcDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if len(name) < 6 {
			continue
		}
		var ver int
		if _, err := fmt.Sscanf(name[:6], "%d", &ver); err != nil {
			continue
		}
		if ver > maxVersion {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), raw, 0o600); err != nil {
			t.Fatalf("write migration %s: %v", name, err)
		}
	}
}

func TestMigration000243DefaultSplitAndReversibilityPG(t *testing.T) {
	adminPool, baseDSN := requirePartitionsTestPool(t)
	ctx := context.Background()

	// Create an isolated temporary database so we can test 000001 -> 000242 -> seed -> 000243 cleanly.
	dbName := "part_m31_0243_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, pgxIdentifier(dbName))); err != nil {
		t.Fatalf("create isolated test database %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, pgxIdentifier(dbName)))
	})

	isoDSN, err := replaceDSNDatabase(baseDSN, dbName)
	if err != nil {
		t.Fatalf("replaceDSNDatabase: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(isoDSN)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// Run with non-UTC session TimeZone to prove 000243 UTC boundaries are timezone-invariant.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["TimeZone"] = "Asia/Shanghai"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	// Step 1: Migrate 000001 -> 000242 only.
	migDir242 := t.TempDir()
	copyMigrationsUpTo(t, "../../migrations", migDir242, 242)
	if err := database.Migrate(ctx, pool, migDir242, "up"); err != nil {
		t.Fatalf("migrate up to 000242: %v", err)
	}

	// Step 2: Seed multi-month rows into security_events (landing in security_events_default)
	// and access_control_events (landing in access_control_events_default + 2026_07 + 2026_08).
	shanghai := time.FixedZone("Asia/Shanghai", 8*3600)
	nowUTC := time.Now().UTC()

	secSeeds := []struct {
		id         uuid.UUID
		occurredAt time.Time
		reqID      string
	}{
		{uuid.New(), time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC), "sec-2026-05"},
		{uuid.New(), time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC), "sec-2026-08-end"},
		// 2026-09-01 00:00:00+08 is 2026-08-31 16:00:00 UTC -> MUST route to security_events_2026_08!
		{uuid.New(), time.Date(2026, 9, 1, 0, 0, 0, 0, shanghai), "sec-2026-09-shanghai-is-aug-utc"},
		{uuid.New(), time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC), "sec-2026-09"},
		{uuid.New(), nowUTC, "sec-now"},
	}
	for _, s := range secSeeds {
		if _, err := pool.Exec(ctx, `
INSERT INTO security_events (id, request_id, occurred_at, domain, request_uri)
VALUES ($1, $2, $3, 'example.com', '/api/test')`,
			s.id, s.reqID, s.occurredAt); err != nil {
			t.Fatalf("seed security_events (%s): %v", s.reqID, err)
		}
	}

	acSeeds := []struct {
		id         uuid.UUID
		occurredAt time.Time
		reqID      string
	}{
		{uuid.New(), time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC), "ac-2026-06"},
		{uuid.New(), time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC), "ac-2026-07"},
		{uuid.New(), time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC), "ac-2026-08"},
		{uuid.New(), time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC), "ac-2026-09"},
		{uuid.New(), nowUTC, "ac-now"},
	}
	for _, a := range acSeeds {
		if _, err := pool.Exec(ctx, `
INSERT INTO access_control_events (id, request_id, occurred_at, client_ip, event_type)
VALUES ($1, $2, $3, '192.0.2.10', 'IP_BLACKLIST')`,
			a.id, a.reqID, a.occurredAt); err != nil {
			t.Fatalf("seed access_control_events (%s): %v", a.reqID, err)
		}
	}

	// Confirm rows are in *_default before 000243.
	var secDefBefore, acDefBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events_default`).Scan(&secDefBefore); err != nil {
		t.Fatalf("count security_events_default before: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_control_events_default`).Scan(&acDefBefore); err != nil {
		t.Fatalf("count access_control_events_default before: %v", err)
	}
	if secDefBefore != 5 || acDefBefore != 3 {
		t.Fatalf("unexpected pre-000243 default counts: sec=%d (want 5), ac=%d (want 3)", secDefBefore, acDefBefore)
	}

	// Step 3: Apply 000243 up (isolated up to 000243 so 000244+ does not interfere with 000243 down).
	migDir243 := t.TempDir()
	copyMigrationsUpTo(t, "../../migrations", migDir243, 243)
	if err := database.Migrate(ctx, pool, migDir243, "up"); err != nil {
		t.Fatalf("migrate 000243 up: %v", err)
	}

	// Verify *_default partitions are gone.
	for _, defName := range []string{"security_events_default", "access_control_events_default"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, defName).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", defName, err)
		}
		if exists {
			t.Fatalf("%s still exists after 000243 up", defName)
		}
	}

	// Verify total counts and specific routing (2026-09-01+08 landed in security_events_2026_08).
	var secTotal, acTotal, secAugCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events`).Scan(&secTotal); err != nil {
		t.Fatalf("count security_events: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_control_events`).Scan(&acTotal); err != nil {
		t.Fatalf("count access_control_events: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events_2026_08`).Scan(&secAugCount); err != nil {
		t.Fatalf("count security_events_2026_08: %v", err)
	}
	if secTotal != 5 || acTotal != 5 || secAugCount != 2 {
		t.Fatalf("counts mismatch after 000243 up: secTotal=%d acTotal=%d secAugCount=%d", secTotal, acTotal, secAugCount)
	}

	// Verify pre-created [now-2m .. now+3m] UTC partitions exist with exact UTC bounds.
	mgr := NewManager(pool, nil)
	baseMonth := bucketStartUTC(nowUTC, GranularityMonthly)
	for _, parent := range []string{"security_events", "access_control_events"} {
		children, err := mgr.listPartitions(ctx, "public", parent)
		if err != nil {
			t.Fatalf("listPartitions %s: %v", parent, err)
		}
		byName := map[string]partitionBound{}
		for _, c := range children {
			b, err := parsePartitionBound(c.BoundExpr)
			if err != nil {
				t.Fatalf("parsePartitionBound(%s): %v", c.Name, err)
			}
			if b.IsDefault {
				t.Fatalf("unexpected DEFAULT partition %s on %s", c.Name, parent)
			}
			byName[c.Name] = b
		}
		for offset := -2; offset <= 3; offset++ {
			s, e := bucketRangeUTC(baseMonth, GranularityMonthly, offset)
			pName, _ := partitionName(parent, GranularityMonthly, s)
			b, ok := byName[pName]
			if !ok {
				t.Fatalf("missing pre-created partition %s", pName)
			}
			if !b.Lower.Equal(s) || !b.Upper.Equal(e) {
				t.Fatalf("partition %s bounds [%v, %v), want [%v, %v)", pName, b.Lower, b.Upper, s, e)
			}
		}
	}

	// Verify DETACH PARTITION CONCURRENTLY works directly on security_events_2026_05 now that *_default is gone.
	if _, err := pool.Exec(ctx, `ALTER TABLE security_events DETACH PARTITION security_events_2026_05 CONCURRENTLY`); err != nil {
		t.Fatalf("DETACH PARTITION CONCURRENTLY failed after 000243 up: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE security_events ATTACH PARTITION security_events_2026_05 FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00')`); err != nil {
		t.Fatalf("re-ATTACH PARTITION failed: %v", err)
	}

	// Step 4: Roll back 000243 (down) and verify *_default restored and 2026_07/2026_08 preserved.
	if err := database.Migrate(ctx, pool, migDir243, "down"); err != nil {
		t.Fatalf("migrate 000243 down: %v", err)
	}

	for _, defName := range []string{"security_events_default", "access_control_events_default"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, defName).Scan(&exists); err != nil {
			t.Fatalf("check %s after down: %v", defName, err)
		}
		if !exists {
			t.Fatalf("%s missing after 000243 down", defName)
		}
	}
	for _, keep := range []string{"access_control_events_2026_07", "access_control_events_2026_08"} {
		var cnt int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, keep)).Scan(&cnt); err != nil {
			t.Fatalf("query preserved partition %s: %v", keep, err)
		}
		if cnt != 1 {
			t.Fatalf("preserved partition %s count = %d, want 1", keep, cnt)
		}
	}

	var secDefAfterDown, acDefAfterDown int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events_default`).Scan(&secDefAfterDown); err != nil {
		t.Fatalf("count security_events_default after down: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_control_events_default`).Scan(&acDefAfterDown); err != nil {
		t.Fatalf("count access_control_events_default after down: %v", err)
	}
	if secDefAfterDown != 5 || acDefAfterDown != 3 {
		t.Fatalf("restored default counts mismatch: sec=%d (want 5), ac=%d (want 3)", secDefAfterDown, acDefAfterDown)
	}

	// Step 5: Re-apply 000243 up, then execute up.sql directly a second time to verify idempotency.
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("re-migrate 000243 up: %v", err)
	}
	upSQL, err := os.ReadFile("../../migrations/000243_partition_default_split.up.sql")
	if err != nil {
		t.Fatalf("read 000243 up sql: %v", err)
	}
	if _, err := pool.Exec(ctx, string(upSQL)); err != nil {
		t.Fatalf("idempotent re-execution of 000243 up sql failed: %v", err)
	}
}

func TestManagerEnsureAndDropExpiredPartitionsPG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	monthlyTbl := "part_m_test_" + suffix
	dailyTbl := "part_d_test_" + suffix
	plainTbl := "part_plain_test_" + suffix

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s (id UUID PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL);
`, monthlyTbl, dailyTbl, plainTbl)); err != nil {
		t.Fatalf("create test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s, %s, %s CASCADE`, monthlyTbl, dailyTbl, plainTbl))
	})

	// Pre-create one expired monthly partition and one expired daily partition.
	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s_2025_01 PARTITION OF %s FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00');
CREATE TABLE %s_2026_01_01 PARTITION OF %s FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-01-02 00:00:00+00');
`, monthlyTbl, monthlyTbl, dailyTbl, dailyTbl)); err != nil {
		t.Fatalf("create expired partitions: %v", err)
	}

	fixedNow := func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }
	policies := []PartitionPolicy{
		{ParentTable: monthlyTbl, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, PastBuckets: 1, FutureBuckets: 2, Enabled: true},
		{ParentTable: dailyTbl, TimeColumn: "occurred_at", Granularity: GranularityDaily, RetentionDays: 14, PastBuckets: 1, FutureBuckets: 2, Enabled: true},
		{ParentTable: plainTbl, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, PastBuckets: 1, FutureBuckets: 1, Enabled: true},
		{ParentTable: "nonexistent_" + suffix, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, PastBuckets: 1, FutureBuckets: 1, Enabled: true},
	}

	mgr := NewManager(pool, nil, WithNowFunc(fixedNow), WithPartitionPolicies(policies))

	created, err := mgr.EnsurePartitions(ctx)
	if err != nil {
		t.Fatalf("EnsurePartitions: %v", err)
	}
	// Monthly: 2026_10, 2026_11, 2026_12, 2027_01 (4); Daily: 11_14, 11_15, 11_16, 11_17 (4) -> 8.
	if created != 8 {
		t.Fatalf("created = %d, want 8", created)
	}

	// Steady-state second run should create 0.
	createdAgain, err := mgr.EnsurePartitions(ctx)
	if err != nil || createdAgain != 0 {
		t.Fatalf("second EnsurePartitions = (%d, %v), want (0, nil)", createdAgain, err)
	}

	finalized, dropped, err := mgr.DropExpiredPartitions(ctx)
	if err != nil {
		t.Fatalf("DropExpiredPartitions: %v", err)
	}
	if finalized != 0 || dropped != 2 {
		t.Fatalf("finalized=%d dropped=%d, want 0 and 2", finalized, dropped)
	}

	// Verify expired dropped and active preserved.
	for _, gone := range []string{monthlyTbl + "_2025_01", dailyTbl + "_2026_01_01"} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, gone).Scan(&exists)
		if exists {
			t.Fatalf("expired partition %s still exists", gone)
		}
	}
	for _, kept := range []string{monthlyTbl + "_2026_11", dailyTbl + "_2026_11_15"} {
		var exists bool
		_ = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, kept).Scan(&exists)
		if !exists {
			t.Fatalf("active partition %s was unexpectedly dropped", kept)
		}
	}
}

func TestManagerFinalizeRecoveryPG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	parent := "part_fin_test_" + suffix
	expiredChild := parent + "_2024_01"
	activeChild := parent + "_2026_11"

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-02-01 00:00:00+00');
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
`, parent, expiredChild, parent, activeChild, parent)); err != nil {
		t.Fatalf("create finalize test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s, %s CASCADE`, parent, expiredChild))
	})

	// Hold an open REPEATABLE READ snapshot in tx2 so DETACH CONCURRENTLY phase 1 commits
	// (setting inhdetachpending = true) and phase 2 blocks waiting for tx2's snapshot until
	// server-side statement_timeout fires on conn1 (deterministic before tx2 commits).
	conn2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire conn2: %v", err)
	}
	tx2, err := conn2.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		conn2.Release()
		t.Fatalf("begin tx2: %v", err)
	}
	var cnt int
	if err := tx2.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, parent)).Scan(&cnt); err != nil {
		_ = tx2.Rollback(ctx)
		conn2.Release()
		t.Fatalf("snapshot query in tx2: %v", err)
	}

	conn1, err := pool.Acquire(ctx)
	if err != nil {
		_ = tx2.Rollback(ctx)
		conn2.Release()
		t.Fatalf("acquire conn1: %v", err)
	}
	if _, err := conn1.Exec(ctx, `SET statement_timeout = '200ms'`); err != nil {
		conn1.Release()
		_ = tx2.Rollback(ctx)
		conn2.Release()
		t.Fatalf("set statement_timeout on conn1: %v", err)
	}
	_, detachErr := conn1.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s DETACH PARTITION %s CONCURRENTLY`, parent, expiredChild))
	_, _ = conn1.Exec(ctx, `RESET statement_timeout`)
	conn1.Release()
	if detachErr == nil {
		_ = tx2.Rollback(ctx)
		conn2.Release()
		t.Fatalf("expected DETACH CONCURRENTLY to fail with statement_timeout while tx2 held snapshot")
	}

	// Release snapshot only AFTER PostgreSQL itself canceled phase 2 and returned error.
	if err := tx2.Commit(ctx); err != nil {
		conn2.Release()
		t.Fatalf("commit tx2: %v", err)
	}
	conn2.Release()

	// Confirm inhdetachpending = true in pg_inherits.
	var pending bool
	if err := pool.QueryRow(ctx, `
SELECT i.inhdetachpending
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
WHERE c.relname = $1`, expiredChild).Scan(&pending); err != nil {
		t.Fatalf("query inhdetachpending (detachErr was %v): %v", detachErr, err)
	}
	if !pending {
		t.Fatalf("expected inhdetachpending = true on %s", expiredChild)
	}

	// Run DropExpiredPartitions -> must FINALIZE + DROP expiredChild while keeping activeChild.
	mgr := NewManager(pool, nil,
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }),
		WithPartitionPolicies([]PartitionPolicy{
			{ParentTable: parent, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, Enabled: true},
		}),
	)
	finalized, dropped, err := mgr.DropExpiredPartitions(ctx)
	if err != nil {
		t.Fatalf("DropExpiredPartitions after pending detach: %v", err)
	}
	if finalized != 1 || dropped != 1 {
		t.Fatalf("finalized=%d dropped=%d, want 1 and 1", finalized, dropped)
	}

	var gone bool
	_ = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NULL`, expiredChild).Scan(&gone)
	if !gone {
		t.Fatalf("expected %s to be dropped after FINALIZE recovery", expiredChild)
	}
}

func TestManagerDefaultPartitionFallbackPG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	parent := "part_def_fb_" + suffix
	expiredChild := parent + "_2024_01"
	defChild := parent + "_default"

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s PARTITION OF %s DEFAULT;
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-02-01 00:00:00+00');
`, parent, defChild, parent, expiredChild, parent)); err != nil {
		t.Fatalf("create default fallback test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s CASCADE`, parent))
	})

	mgr := NewManager(pool, nil,
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }),
		WithPartitionPolicies([]PartitionPolicy{
			{ParentTable: parent, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, Enabled: true},
		}),
	)
	_, dropped, err := mgr.DropExpiredPartitions(ctx)
	if err != nil {
		t.Fatalf("DropExpiredPartitions with DEFAULT fallback failed: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}

	var defExists, expExists bool
	_ = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, defChild).Scan(&defExists)
	_ = pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, expiredChild).Scan(&expExists)
	if !defExists || expExists {
		t.Fatalf("defExists=%v expExists=%v, want true/false", defExists, expExists)
	}
}

func TestManagerTimezoneRobustnessPG(t *testing.T) {
	_, baseDSN := requirePartitionsTestPool(t)
	ctx := context.Background()

	cfg, err := pgxpool.ParseConfig(baseDSN)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["TimeZone"] = "Asia/Shanghai"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	parent := "part_tz_test_" + suffix
	expired := parent + "_2025_01"

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00');
`, parent, expired, parent)); err != nil {
		t.Fatalf("create tz test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s CASCADE`, parent))
	})

	mgr := NewManager(pool, nil,
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }),
		WithPartitionPolicies([]PartitionPolicy{
			{ParentTable: parent, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, PastBuckets: 0, FutureBuckets: 1, Enabled: true},
		}),
	)

	created, err := mgr.EnsurePartitions(ctx)
	if err != nil || created != 2 {
		t.Fatalf("EnsurePartitions under Asia/Shanghai = (%d, %v), want (2, nil)", created, err)
	}
	_, dropped, err := mgr.DropExpiredPartitions(ctx)
	if err != nil || dropped != 1 {
		t.Fatalf("DropExpiredPartitions under Asia/Shanghai = (%d, %v), want (1, nil)", dropped, err)
	}
}

func TestManagerCleanupExpiredRowsPG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	pkTbl := "cleanup_pk_test_" + suffix
	ctidTbl := "cleanup_ctid_test_" + suffix

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL);
CREATE TABLE %s (tenant_id INT NOT NULL, item_key TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (tenant_id, item_key));
`, pkTbl, ctidTbl)); err != nil {
		t.Fatalf("create cleanup test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s, %s CASCADE`, pkTbl, ctidTbl))
	})

	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	oldTS := now.Add(-10 * 24 * time.Hour)
	recentTS := now.Add(-1 * 24 * time.Hour)

	for i := 0; i < 7; i++ {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (id, created_at) VALUES ($1, $2)`, pkTbl), uuid.New(), oldTS); err != nil {
			t.Fatalf("seed old pk row: %v", err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (tenant_id, item_key, created_at) VALUES ($1, $2, $3)`, ctidTbl), 1, fmt.Sprintf("old-%d", i), oldTS); err != nil {
			t.Fatalf("seed old ctid row: %v", err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (id, created_at) VALUES ($1, $2)`, pkTbl), uuid.New(), recentTS); err != nil {
			t.Fatalf("seed recent pk row: %v", err)
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (tenant_id, item_key, created_at) VALUES ($1, $2, $3)`, ctidTbl), 1, fmt.Sprintf("new-%d", i), recentTS); err != nil {
			t.Fatalf("seed recent ctid row: %v", err)
		}
	}

	mgr := NewManager(pool, nil,
		WithNowFunc(func() time.Time { return now }),
		WithBatchSleep(0),
		WithCleanupPolicies([]CleanupPolicy{
			{Table: pkTbl, TimeColumn: "created_at", PKColumn: "id", RetentionDays: 7, BatchSize: 3, MaxBatches: 10, Enabled: true},
			{Table: ctidTbl, TimeColumn: "created_at", PKColumn: "", RetentionDays: 7, BatchSize: 3, MaxBatches: 10, Enabled: true},
		}),
	)

	cleaned, err := mgr.CleanupExpiredRows(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredRows: %v", err)
	}
	if cleaned != 14 {
		t.Fatalf("cleaned = %d, want 14", cleaned)
	}

	var remPK, remCTID int
	_ = pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, pkTbl)).Scan(&remPK)
	_ = pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, ctidTbl)).Scan(&remCTID)
	if remPK != 2 || remCTID != 2 {
		t.Fatalf("remaining rows = (%d, %d), want (2, 2)", remPK, remCTID)
	}
}

func TestManagerExtremeRetentionDaysPG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	parent := "part_ext_ret_" + suffix
	activeChild := parent + "_2026_11"
	cleanupTbl := "cleanup_ext_ret_" + suffix

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (id UUID NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
CREATE TABLE %s (id UUID PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL);
`, parent, activeChild, parent, cleanupTbl)); err != nil {
		t.Fatalf("create extreme retention test tables: %v", err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (id, created_at) VALUES ($1, $2)`, cleanupTbl),
		uuid.New(), time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed extreme retention cleanup row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s, %s CASCADE`, parent, cleanupTbl))
	})

	fixedNow := func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }
	for _, days := range []int{110000, 999999, 2000000} {
		mgr := NewManager(pool, nil,
			WithNowFunc(fixedNow),
			WithBatchSleep(0),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: parent, TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: days, PastBuckets: 0, FutureBuckets: 1, Enabled: true},
			}),
			WithCleanupPolicies([]CleanupPolicy{
				{Table: cleanupTbl, TimeColumn: "created_at", PKColumn: "id", RetentionDays: days, BatchSize: 10, MaxBatches: 5, Enabled: true},
			}),
		)

		res, err := mgr.RunOnce(ctx)
		if err != nil {
			t.Fatalf("days=%d RunOnce failed: %v", days, err)
		}
		if res.PartitionsDropped != 0 || res.RowsCleaned != 0 {
			t.Fatalf("days=%d unexpected drops/cleanups: %+v", days, res)
		}

		var activeExists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, activeChild).Scan(&activeExists); err != nil || !activeExists {
			t.Fatalf("days=%d active partition %s missing (exists=%v err=%v)", days, activeChild, activeExists, err)
		}
		var rowCount int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, cleanupTbl)).Scan(&rowCount); err != nil || rowCount != 1 {
			t.Fatalf("days=%d cleanupTbl rows=%d (err=%v), want 1", days, rowCount, err)
		}
	}
}

func TestManagerCleanupCTIDOnPartitionedTablePG(t *testing.T) {
	pool, _ := requirePartitionsTestPool(t)
	ctx := context.Background()

	suffix := strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	parent := "cleanup_part_ctid_" + suffix
	oldPart := parent + "_2025_01"
	newPart := parent + "_2026_11"

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
CREATE TABLE %s (label TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL) PARTITION BY RANGE (created_at);
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00');
CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
`, parent, oldPart, parent, newPart, parent)); err != nil {
		t.Fatalf("create partitioned ctid test tables: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TABLE IF EXISTS %s CASCADE`, parent))
	})

	if _, err := pool.Exec(ctx, fmt.Sprintf(`
INSERT INTO %s (label, created_at) VALUES ('expired-row', '2025-01-15 00:00:00+00');
INSERT INTO %s (label, created_at) VALUES ('active-row', '2026-11-14 00:00:00+00');
`, parent, parent)); err != nil {
		t.Fatalf("insert partitioned rows: %v", err)
	}

	var oldCTID, newCTID string
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT ctid::text FROM %s WHERE label = 'expired-row'`, oldPart)).Scan(&oldCTID); err != nil {
		t.Fatalf("scan oldCTID: %v", err)
	}
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT ctid::text FROM %s WHERE label = 'active-row'`, newPart)).Scan(&newCTID); err != nil {
		t.Fatalf("scan newCTID: %v", err)
	}
	if oldCTID != "(0,1)" || newCTID != "(0,1)" {
		t.Fatalf("expected both partition rows at ctid=(0,1), got old=%s new=%s", oldCTID, newCTID)
	}

	mgr := NewManager(pool, nil,
		WithNowFunc(func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }),
		WithBatchSleep(0),
		WithCleanupPolicies([]CleanupPolicy{
			{Table: parent, TimeColumn: "created_at", PKColumn: "", RetentionDays: 30, BatchSize: 10, MaxBatches: 5, Enabled: true},
		}),
	)

	cleaned, err := mgr.CleanupExpiredRows(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredRows on partitioned table: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}

	var remOld, remNew int
	var activeLabel string
	_ = pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, oldPart)).Scan(&remOld)
	_ = pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, newPart)).Scan(&remNew)
	if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT label FROM %s LIMIT 1`, newPart)).Scan(&activeLabel); err != nil {
		t.Fatalf("read preserved active row: %v", err)
	}
	if remOld != 0 || remNew != 1 || activeLabel != "active-row" {
		t.Fatalf("unexpected post-cleanup state: remOld=%d remNew=%d activeLabel=%q", remOld, remNew, activeLabel)
	}
}

func pgxIdentifier(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}
