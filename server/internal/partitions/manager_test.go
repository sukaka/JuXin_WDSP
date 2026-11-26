package partitions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestParsePartitionBound(t *testing.T) {
	t.Parallel()

	july1UTC := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	aug1UTC := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expr      string
		wantDef   bool
		wantLower *time.Time
		wantUpper *time.Time
		wantErr   bool
	}{
		{
			name:    "default uppercase",
			expr:    "DEFAULT",
			wantDef: true,
		},
		{
			name:    "default lowercase with whitespace",
			expr:    "  default  ",
			wantDef: true,
		},
		{
			name:      "UTC +00",
			expr:      "FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-08-01 00:00:00+00')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "Asia/Shanghai +08",
			expr:      "FOR VALUES FROM ('2026-07-01 08:00:00+08') TO ('2026-08-01 08:00:00+08')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "Asia/Kolkata +05:30",
			expr:      "FOR VALUES FROM ('2026-07-01 05:30:00+05:30') TO ('2026-08-01 05:30:00+05:30')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "America/New_York -04",
			expr:      "FOR VALUES FROM ('2026-06-30 20:00:00-04') TO ('2026-07-31 20:00:00-04')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "MINVALUE lower",
			expr:      "FOR VALUES FROM (MINVALUE) TO ('2026-07-01 00:00:00+00')",
			wantLower: nil,
			wantUpper: &july1UTC,
		},
		{
			name:      "MAXVALUE upper",
			expr:      "FOR VALUES FROM ('2026-08-01 00:00:00+00') TO (MAXVALUE)",
			wantLower: &aug1UTC,
			wantUpper: nil,
		},
		{
			name:      "fractional seconds and cast suffix",
			expr:      "FOR VALUES FROM ('2026-07-01 00:00:00+00'::timestamp with time zone) TO ('2026-08-01 00:00:00.000000+00'::timestamptz)",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "RFC3339",
			expr:      "FOR VALUES FROM ('2026-07-01T00:00:00Z') TO ('2026-08-01T00:00:00Z')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:      "no timezone treated as UTC",
			expr:      "FOR VALUES FROM ('2026-07-01 00:00:00') TO ('2026-08-01 00:00:00')",
			wantLower: &july1UTC,
			wantUpper: &aug1UTC,
		},
		{
			name:    "empty",
			expr:    "",
			wantErr: true,
		},
		{
			name:    "malformed expression",
			expr:    "FOR VALUES IN ('a')",
			wantErr: true,
		},
		{
			name:    "malformed timestamp",
			expr:    "FOR VALUES FROM ('not-a-date') TO ('2026-08-01 00:00:00+00')",
			wantErr: true,
		},
		{
			name:    "invalid MAXVALUE lower",
			expr:    "FOR VALUES FROM (MAXVALUE) TO ('2026-08-01 00:00:00+00')",
			wantErr: true,
		},
		{
			name:    "invalid MINVALUE upper",
			expr:    "FOR VALUES FROM ('2026-07-01 00:00:00+00') TO (MINVALUE)",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parsePartitionBound(tc.expr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %+v", tc.expr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.expr, err)
			}
			if got.IsDefault != tc.wantDef {
				t.Fatalf("IsDefault = %v, want %v", got.IsDefault, tc.wantDef)
			}
			if tc.wantLower == nil {
				if got.HasLower {
					t.Fatalf("expected HasLower=false, got %v", got.Lower)
				}
			} else if !got.HasLower || !got.Lower.Equal(*tc.wantLower) {
				t.Fatalf("Lower = (%v, %v), want %v", got.HasLower, got.Lower, *tc.wantLower)
			}
			if tc.wantUpper == nil {
				if got.HasUpper {
					t.Fatalf("expected HasUpper=false, got %v", got.Upper)
				}
			} else if !got.HasUpper || !got.Upper.Equal(*tc.wantUpper) {
				t.Fatalf("Upper = (%v, %v), want %v", got.HasUpper, got.Upper, *tc.wantUpper)
			}
		})
	}
}

func TestBucketMathAndNaming(t *testing.T) {
	t.Parallel()

	// Non-UTC input crossing UTC month/year boundary: 2026-12-31 20:00-05 -> 2027-01-01 01:00 UTC.
	est := time.FixedZone("EST", -5*3600)
	nowEST := time.Date(2026, 12, 31, 20, 0, 0, 0, est)
	mBase := bucketStartUTC(nowEST, GranularityMonthly)
	if !mBase.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("monthly base = %v, want 2027-01-01 UTC", mBase)
	}
	prevStart, prevEnd := bucketRangeUTC(mBase, GranularityMonthly, -1)
	if !prevStart.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) ||
		!prevEnd.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("prev monthly range = [%v, %v)", prevStart, prevEnd)
	}

	// Leap year daily rollover: 2024-02-28 -> 2024-02-29 -> 2024-03-01.
	feb28 := time.Date(2024, 2, 28, 15, 30, 0, 0, time.UTC)
	dBase := bucketStartUTC(feb28, GranularityDaily)
	leapStart, leapEnd := bucketRangeUTC(dBase, GranularityDaily, 1)
	if !leapStart.Equal(time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC)) ||
		!leapEnd.Equal(time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("leap daily range = [%v, %v)", leapStart, leapEnd)
	}

	// Partition naming and 63-byte validation.
	mName, err := partitionName("security_events", GranularityMonthly, prevStart)
	if err != nil || mName != "security_events_2026_12" {
		t.Fatalf("monthly name = (%q, %v)", mName, err)
	}
	dName, err := partitionName("access_logs", GranularityDaily, leapStart)
	if err != nil || dName != "access_logs_2024_02_29" {
		t.Fatalf("daily name = (%q, %v)", dName, err)
	}

	longParent := strings.Repeat("a", 55)
	if _, err := partitionName(longParent, GranularityDaily, leapStart); err == nil {
		t.Fatal("expected error when partition name exceeds 63 bytes")
	}
}

func TestPolicyValidation(t *testing.T) {
	t.Parallel()

	policies := DefaultPartitionPolicies()
	if len(policies) != 13 {
		t.Fatalf("DefaultPartitionPolicies len = %d, want 13", len(policies))
	}

	seenPart := make(map[string]PartitionPolicy, len(policies))
	var monthlyCount, dailyCount int
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			t.Fatalf("default policy %s invalid: %v", p.ParentTable, err)
		}
		if !p.Enabled {
			t.Fatalf("default policy %s should be enabled", p.ParentTable)
		}
		if p.ParentTable == "operation_audits" {
			t.Fatal("operation_audits must NEVER be in DefaultPartitionPolicies")
		}
		if _, dup := seenPart[p.ParentTable]; dup {
			t.Fatalf("duplicate ParentTable %s", p.ParentTable)
		}
		seenPart[p.ParentTable] = p

		switch p.Granularity {
		case GranularityMonthly:
			monthlyCount++
			if p.PastBuckets < 2 || p.FutureBuckets < 3 {
				t.Fatalf("unexpected monthly bucket window for %s: %+v", p.ParentTable, p)
			}
		case GranularityDaily:
			dailyCount++
			if p.PastBuckets < 2 || p.FutureBuckets < 14 {
				t.Fatalf("unexpected daily bucket window for %s: %+v", p.ParentTable, p)
			}
		}
	}
	if monthlyCount != 6 || dailyCount != 7 {
		t.Fatalf("monthly=%d daily=%d, want 6 and 7", monthlyCount, dailyCount)
	}
	apiRuntimePolicy, ok := seenPart["api_runtime_events"]
	if !ok || apiRuntimePolicy.Granularity != GranularityMonthly {
		t.Fatalf("api_runtime_events must use monthly granularity: %+v", apiRuntimePolicy)
	}

	cleanup := DefaultCleanupPolicies()
	if len(cleanup) != 5 {
		t.Fatalf("DefaultCleanupPolicies len = %d, want 5", len(cleanup))
	}
	seenCleanup := make(map[string]CleanupPolicy, len(cleanup))
	for _, c := range cleanup {
		if err := c.Validate(); err != nil {
			t.Fatalf("default cleanup policy %s invalid: %v", c.Table, err)
		}
		if !c.Enabled {
			t.Fatalf("default cleanup policy %s should be enabled", c.Table)
		}
		if c.Table == "operation_audits" {
			t.Fatal("operation_audits must NEVER be in DefaultCleanupPolicies")
		}
		if _, dup := seenCleanup[c.Table]; dup {
			t.Fatalf("duplicate cleanup Table %s", c.Table)
		}
		seenCleanup[c.Table] = c
	}
	if got := seenCleanup["agent_api_observation_asset_events"].PKColumn; got != "" {
		t.Fatalf("agent_api_observation_asset_events PKColumn = %q, want empty for (tableoid, ctid)", got)
	}
	receipts := seenCleanup["api_authz_candidate_event_receipts"]
	if receipts.PKColumn != "event_id" || receipts.RetentionDays < apiRuntimePolicy.RetentionDays+31 {
		t.Fatalf("api_authz_candidate_event_receipts policy unsafe relative to api_runtime_events: %+v", receipts)
	}

	bad := PartitionPolicy{
		ParentTable:   "bad-table;drop",
		TimeColumn:    "occurred_at",
		Granularity:   GranularityMonthly,
		RetentionDays: 30,
	}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid table identifier error")
	}
}

func TestSQLBuilders(t *testing.T) {
	t.Parallel()

	s := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	e := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)

	createSQL := buildCreatePartitionSQL("public", "security_events", "security_events_2026_11", s, e)
	if strings.Contains(createSQL, ";") ||
		!strings.Contains(createSQL, `"public"."security_events_2026_11"`) ||
		!strings.Contains(createSQL, `FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')`) {
		t.Fatalf("unexpected createSQL: %s", createSQL)
	}

	detachConc := buildDetachPartitionConcurrentlySQL("public", "security_events", "public", "security_events_2026_01")
	if detachConc != `ALTER TABLE "public"."security_events" DETACH PARTITION "public"."security_events_2026_01" CONCURRENTLY` {
		t.Fatalf("unexpected detachConc: %s", detachConc)
	}

	detachFin := buildDetachPartitionFinalizeSQL("public", "security_events", "public", "security_events_2026_01")
	if detachFin != `ALTER TABLE "public"."security_events" DETACH PARTITION "public"."security_events_2026_01" FINALIZE` {
		t.Fatalf("unexpected detachFin: %s", detachFin)
	}

	delPK := buildBatchedDeleteSQL("public", "my_tbl", "created_at", "id")
	if !strings.Contains(delPK, `WHERE "id" IN (SELECT "id" FROM "public"."my_tbl" WHERE "created_at" < $1 LIMIT $2)`) {
		t.Fatalf("unexpected delPK: %s", delPK)
	}
	delCTID := buildBatchedDeleteSQL("public", "my_tbl", "created_at", "")
	if !strings.Contains(delCTID, `WHERE (tableoid, ctid) IN (SELECT tableoid, ctid FROM "public"."my_tbl" WHERE "created_at" < $1 LIMIT $2)`) {
		t.Fatalf("unexpected delCTID: %s", delCTID)
	}
}

func TestRetentionCutoffNoOverflow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

	if got, want := retentionCutoff(now, 180), now.AddDate(0, 0, -180); !got.Equal(want) {
		t.Fatalf("180d cutoff = %v, want %v", got, want)
	}
	if got := retentionCutoff(now, 0); !got.Equal(now) {
		t.Fatalf("0d cutoff = %v, want %v", got, now)
	}
	for _, days := range []int{106752, 110000, 999999, maxRetentionDays + 500000} {
		got := retentionCutoff(now, days)
		if !got.Before(now) {
			t.Fatalf("retentionCutoff(now, %d) = %v, expected strictly before %v (overflow!)", days, got, now)
		}
		if got.Year() >= 2000 {
			t.Fatalf("retentionCutoff(now, %d) = %v, expected centuries in the past", days, got)
		}
	}
	if got, want := retentionCutoff(now, maxRetentionDays+1), retentionCutoff(now, maxRetentionDays); !got.Equal(want) {
		t.Fatalf("clamped cutoff = %v, want %v", got, want)
	}
}

func TestNewManagerTypedNilSafety(t *testing.T) {
	t.Parallel()

	mgr := NewManager(nil, nil)
	if mgr == nil {
		t.Fatal("NewManager(nil, nil) returned nil")
	}
	if _, err := mgr.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when db is nil")
	}
	if days := mgr.resolveRetentionDays(context.Background(), "logging", "retention_days", 180); days != 180 {
		t.Fatalf("resolveRetentionDays = %d, want 180", days)
	}
}

// --- Mock DBExecutor & IntSettingGetter ---

type mockRow struct {
	scanFn func(dest ...any) error
}

func (r mockRow) Scan(dest ...any) error {
	return r.scanFn(dest...)
}

type mockRows struct {
	data [][]any
	idx  int
	err  error
}

func (r *mockRows) Close()                        {}
func (r *mockRows) Err() error                    { return r.err }
func (r *mockRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }
func (r *mockRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (r *mockRows) Next() bool {
	if r.idx < len(r.data) {
		r.idx++
		return true
	}
	return false
}
func (r *mockRows) Scan(dest ...any) error {
	row := r.data[r.idx-1]
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = row[i].(string)
		case *bool:
			*d = row[i].(bool)
		default:
			return fmt.Errorf("unsupported mock scan type %T", dest[i])
		}
	}
	return nil
}
func (r *mockRows) Values() ([]any, error) { return nil, nil }
func (r *mockRows) RawValues() [][]byte    { return nil }
func (r *mockRows) Conn() *pgx.Conn        { return nil }

type mockDB struct {
	relkinds     map[string]string // table -> relkind
	children     map[string][]partitionEntry
	execCalls    []string
	execHandler  func(sql string, args ...any) (pgconn.CommandTag, error)
	queryErr     error
}

func (m *mockDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	m.execCalls = append(m.execCalls, sql)
	if m.execHandler != nil {
		return m.execHandler(sql, args...)
	}
	return pgconn.NewCommandTag("OK 0"), nil
}

func (m *mockDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	if strings.Contains(sql, "FROM pg_inherits") && len(args) >= 2 {
		parent := args[1].(string)
		entries := m.children[parent]
		data := make([][]any, 0, len(entries))
		for _, e := range entries {
			data = append(data, []any{e.Schema, e.Name, e.DetachPending, e.BoundExpr})
		}
		return &mockRows{data: data}, nil
	}
	return &mockRows{}, nil
}

func (m *mockDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "FROM pg_class") && len(args) >= 1 {
		tbl := args[0].(string)
		rk, ok := m.relkinds[tbl]
		if !ok {
			return mockRow{scanFn: func(_ ...any) error { return pgx.ErrNoRows }}
		}
		return mockRow{scanFn: func(dest ...any) error {
			*(dest[0].(*string)) = "public"
			*(dest[1].(*string)) = rk
			return nil
		}}
	}
	return mockRow{scanFn: func(_ ...any) error { return pgx.ErrNoRows }}
}

type mockSettings struct {
	values map[string]int
}

func (s *mockSettings) GetInt(_ context.Context, group, key string, def int) int {
	if s.values == nil {
		return def
	}
	if v, ok := s.values[group+"."+key]; ok {
		return v
	}
	return def
}

func TestManagerMockEnsurePartitions(t *testing.T) {
	t.Parallel()

	fixedNow := func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }

	t.Run("missing parent and relkind r skipped cleanly", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{
				"plain_table": "r",
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "missing_table", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, PastBuckets: 1, FutureBuckets: 1, Enabled: true},
				{ParentTable: "plain_table", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, PastBuckets: 1, FutureBuckets: 1, Enabled: true},
			}),
		)
		created, err := mgr.EnsurePartitions(context.Background())
		if err != nil || created != 0 {
			t.Fatalf("got (%d, %v), want (0, nil)", created, err)
		}
		if len(db.execCalls) != 0 {
			t.Fatalf("expected 0 DDL execs, got %v", db.execCalls)
		}
	})

	t.Run("steady state executes zero DDL and skips expired buckets", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					{Schema: "public", Name: "events_2026_11", BoundExpr: "FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')"},
					{Schema: "public", Name: "events_2026_12", BoundExpr: "FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00')"},
				},
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				// Retention 20 days -> cutoff 2026-10-26, so M-1 (2026-10, end 2026-11-01 > cutoff) is created;
				// M-2 (2026-09, end 2026-10-01 <= cutoff) is skipped!
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 20, PastBuckets: 2, FutureBuckets: 1, Enabled: true},
			}),
		)
		created, err := mgr.EnsurePartitions(context.Background())
		if err != nil {
			t.Fatalf("EnsurePartitions err: %v", err)
		}
		if created != 1 {
			t.Fatalf("created = %d, want 1 (only 2026_10)", created)
		}
		if len(db.execCalls) != 1 || !strings.Contains(db.execCalls[0], "events_2026_10") {
			t.Fatalf("unexpected DDL calls: %v", db.execCalls)
		}
	})

	t.Run("42P07 duplicate_table treated idempotently", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{},
			execHandler: func(_ string, _ ...any) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, &pgconn.PgError{Code: "42P07", Message: "relation already exists"}
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, PastBuckets: 0, FutureBuckets: 0, Enabled: true},
			}),
		)
		created, err := mgr.EnsurePartitions(context.Background())
		if err != nil || created != 0 {
			t.Fatalf("got (%d, %v), want (0, nil)", created, err)
		}
	})

	t.Run("extreme retention >= 106752 days does not overflow cutoff and creates partitions", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{},
		}
		mgr := NewManagerWithDeps(db, &mockSettings{values: map[string]int{"logging.retention_days": 110000}},
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, SettingsGroup: "logging", SettingsKey: "retention_days", PastBuckets: 1, FutureBuckets: 1, Enabled: true},
			}),
		)
		created, err := mgr.EnsurePartitions(context.Background())
		if err != nil || created != 3 {
			t.Fatalf("got (%d, %v), want (3, nil)", created, err)
		}
	})
}

func TestManagerMockDropExpiredPartitions(t *testing.T) {
	t.Parallel()

	fixedNow := func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }

	t.Run("FINALIZE recovery, CONCURRENTLY detach, keeps active and MAXVALUE", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"security_events": "p"},
			children: map[string][]partitionEntry{
				"security_events": {
					// Pending expired -> FINALIZE + DROP
					{Schema: "public", Name: "security_events_2026_01", DetachPending: true, BoundExpr: "FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00')"},
					// Normal expired -> DETACH CONCURRENTLY + DROP
					{Schema: "public", Name: "security_events_2026_02", DetachPending: false, BoundExpr: "FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00')"},
					// Active -> KEEP
					{Schema: "public", Name: "security_events_2026_11", DetachPending: false, BoundExpr: "FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')"},
					// Unbounded upper -> KEEP
					{Schema: "public", Name: "security_events_future", DetachPending: false, BoundExpr: "FOR VALUES FROM ('2026-12-01 00:00:00+00') TO (MAXVALUE)"},
				},
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "security_events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, Enabled: true},
			}),
		)
		finalized, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err != nil {
			t.Fatalf("DropExpiredPartitions err: %v", err)
		}
		if finalized != 1 || dropped != 2 {
			t.Fatalf("got finalized=%d dropped=%d, want 1 and 2", finalized, dropped)
		}
		wantCalls := []string{
			`ALTER TABLE "public"."security_events" DETACH PARTITION "public"."security_events_2026_01" FINALIZE`,
			`DROP TABLE IF EXISTS "public"."security_events_2026_01"`,
			`ALTER TABLE "public"."security_events" DETACH PARTITION "public"."security_events_2026_02" CONCURRENTLY`,
			`DROP TABLE IF EXISTS "public"."security_events_2026_02"`,
		}
		if len(db.execCalls) != len(wantCalls) {
			t.Fatalf("execCalls = %v, want %v", db.execCalls, wantCalls)
		}
		for i, want := range wantCalls {
			if db.execCalls[i] != want {
				t.Fatalf("execCalls[%d] = %q, want %q", i, db.execCalls[i], want)
			}
		}
	})

	t.Run("hasDefault uses non-concurrent DETACH and preserves DEFAULT", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					{Schema: "public", Name: "events_default", BoundExpr: "DEFAULT"},
					{Schema: "public", Name: "events_2025_01", BoundExpr: "FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00')"},
				},
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
			}),
		)
		_, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err != nil || dropped != 1 {
			t.Fatalf("got (%d, %v), want (1, nil)", dropped, err)
		}
		if db.execCalls[0] != `ALTER TABLE "public"."events" DETACH PARTITION "public"."events_2025_01"` {
			t.Fatalf("expected non-concurrent detach, got %q", db.execCalls[0])
		}
	})

	t.Run("55000 concurrent detach fallback to non-concurrent DETACH", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					{Schema: "public", Name: "events_2025_01", BoundExpr: "FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00')"},
				},
			},
			execHandler: func(sql string, _ ...any) (pgconn.CommandTag, error) {
				if strings.HasSuffix(sql, "CONCURRENTLY") {
					return pgconn.CommandTag{}, &pgconn.PgError{
						Code:    "55000",
						Message: "cannot detach partitions concurrently when a default partition exists",
					}
				}
				return pgconn.NewCommandTag("OK 0"), nil
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
			}),
		)
		_, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err != nil || dropped != 1 {
			t.Fatalf("got (%d, %v), want (1, nil)", dropped, err)
		}
		if len(db.execCalls) != 3 {
			t.Fatalf("expected 3 calls (CONCURRENTLY, fallback DETACH, DROP), got %v", db.execCalls)
		}
	})

	t.Run("42P01 and 42704 idempotency without aborting loop", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					{Schema: "public", Name: "events_2025_01", BoundExpr: "FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00')"},
					{Schema: "public", Name: "events_2025_02", BoundExpr: "FOR VALUES FROM ('2025-02-01 00:00:00+00') TO ('2025-03-01 00:00:00+00')"},
				},
			},
			execHandler: func(sql string, _ ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "events_2025_01") && strings.Contains(sql, "DETACH") {
					return pgconn.CommandTag{}, &pgconn.PgError{Code: "42704", Message: "partition not found"}
				}
				if strings.Contains(sql, "events_2025_01") && strings.Contains(sql, "DROP") {
					return pgconn.CommandTag{}, &pgconn.PgError{Code: "42P01", Message: "undefined table"}
				}
				return pgconn.NewCommandTag("OK 0"), nil
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
			}),
		)
		_, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err != nil || dropped != 2 {
			t.Fatalf("got (%d, %v), want (2, nil)", dropped, err)
		}
	})

	t.Run("settings clamp <= 0 falls back to policy RetentionDays", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					// Upper 2026-10-01: under 180d fallback (cutoff ~2026-05-19) this must NOT be dropped!
					{Schema: "public", Name: "events_2026_09", BoundExpr: "FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00')"},
				},
			},
		}
		mgr := NewManagerWithDeps(db, &mockSettings{values: map[string]int{"logging.retention_days": 0}},
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, SettingsGroup: "logging", SettingsKey: "retention_days", Enabled: true},
			}),
		)
		_, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err != nil || dropped != 0 {
			t.Fatalf("got (%d, %v), want (0, nil)", dropped, err)
		}
	})

	t.Run("unparseable bound returns error and does not drop", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{"events": "p"},
			children: map[string][]partitionEntry{
				"events": {
					{Schema: "public", Name: "events_weird", BoundExpr: "FOR VALUES WITH (MODULUS 4, REMAINDER 0)"},
				},
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
			}),
		)
		_, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err == nil || dropped != 0 {
			t.Fatalf("expected error and 0 dropped, got (%d, %v)", dropped, err)
		}
		if len(db.execCalls) != 0 {
			t.Fatalf("expected no DDL on unparseable bound, got %v", db.execCalls)
		}
	})

	t.Run("extreme retention 110000 and 999999 days keep active partitions", func(t *testing.T) {
		for _, extremeDays := range []int{110000, 999999} {
			db := &mockDB{
				relkinds: map[string]string{"events": "p"},
				children: map[string][]partitionEntry{
					"events": {
						{Schema: "public", Name: "events_2025_01", BoundExpr: "FOR VALUES FROM ('2025-01-01 00:00:00+00') TO ('2025-02-01 00:00:00+00')"},
						{Schema: "public", Name: "events_2026_11", BoundExpr: "FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00')"},
					},
				},
			}
			mgr := NewManagerWithDeps(db, &mockSettings{values: map[string]int{"logging.retention_days": extremeDays}},
				WithNowFunc(fixedNow),
				WithPartitionPolicies([]PartitionPolicy{
					{ParentTable: "events", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 180, SettingsGroup: "logging", SettingsKey: "retention_days", Enabled: true},
				}),
			)
			_, dropped, err := mgr.DropExpiredPartitions(context.Background())
			if err != nil || dropped != 0 {
				t.Fatalf("days=%d got dropped=%d err=%v, want (0, nil)", extremeDays, dropped, err)
			}
			if len(db.execCalls) != 0 {
				t.Fatalf("days=%d expected 0 execs, got %v", extremeDays, db.execCalls)
			}
		}
	})

	t.Run("skips phase B on parent when phase A FINALIZE fails while other parent proceeds", func(t *testing.T) {
		db := &mockDB{
			relkinds: map[string]string{
				"events_a": "p",
				"events_b": "p",
			},
			children: map[string][]partitionEntry{
				"events_a": {
					{Schema: "public", Name: "events_a_2024_01", DetachPending: true, BoundExpr: "FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-02-01 00:00:00+00')"},
					{Schema: "public", Name: "events_a_2024_02", DetachPending: false, BoundExpr: "FOR VALUES FROM ('2024-02-01 00:00:00+00') TO ('2024-03-01 00:00:00+00')"},
				},
				"events_b": {
					{Schema: "public", Name: "events_b_2024_01", DetachPending: false, BoundExpr: "FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-02-01 00:00:00+00')"},
				},
			},
			execHandler: func(sql string, _ ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "events_a_2024_01") && strings.Contains(sql, "FINALIZE") {
					return pgconn.CommandTag{}, context.DeadlineExceeded
				}
				return pgconn.NewCommandTag("OK 0"), nil
			},
		}
		mgr := NewManagerWithDeps(db, nil,
			WithNowFunc(fixedNow),
			WithPartitionPolicies([]PartitionPolicy{
				{ParentTable: "events_a", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
				{ParentTable: "events_b", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
			}),
		)
		finalized, dropped, err := mgr.DropExpiredPartitions(context.Background())
		if err == nil {
			t.Fatal("expected Phase A FINALIZE error, got nil")
		}
		if finalized != 0 || dropped != 1 {
			t.Fatalf("got finalized=%d dropped=%d, want (0, 1)", finalized, dropped)
		}
		for _, call := range db.execCalls {
			if strings.Contains(call, "events_a_2024_02") {
				t.Fatalf("unexpected Phase B call on events_a after Phase A FINALIZE failure: %v", db.execCalls)
			}
		}
		wantCalls := []string{
			`ALTER TABLE "public"."events_a" DETACH PARTITION "public"."events_a_2024_01" FINALIZE`,
			`ALTER TABLE "public"."events_b" DETACH PARTITION "public"."events_b_2024_01" CONCURRENTLY`,
			`DROP TABLE IF EXISTS "public"."events_b_2024_01"`,
		}
		if len(db.execCalls) != len(wantCalls) {
			t.Fatalf("execCalls = %v, want %v", db.execCalls, wantCalls)
		}
		for i, want := range wantCalls {
			if db.execCalls[i] != want {
				t.Fatalf("execCalls[%d] = %q, want %q", i, db.execCalls[i], want)
			}
		}
	})
}

func TestManagerMockCleanupExpiredRows(t *testing.T) {
	t.Parallel()

	fixedNow := func() time.Time { return time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC) }

	var batchCalls int
	db := &mockDB{
		relkinds: map[string]string{"health_records": "r"},
		execHandler: func(_ string, _ ...any) (pgconn.CommandTag, error) {
			batchCalls++
			if batchCalls < 3 {
				return pgconn.NewCommandTag("DELETE 10"), nil
			}
			return pgconn.NewCommandTag("DELETE 4"), nil
		},
	}

	mgr := NewManagerWithDeps(db, nil,
		WithNowFunc(fixedNow),
		WithBatchSleep(0),
		WithCleanupPolicies([]CleanupPolicy{
			{Table: "missing_cleanup_tbl", TimeColumn: "created_at", RetentionDays: 7, BatchSize: 10, MaxBatches: 5, Enabled: true},
			{Table: "health_records", TimeColumn: "created_at", PKColumn: "id", RetentionDays: 7, BatchSize: 10, MaxBatches: 5, Enabled: true},
		}),
	)

	deleted, err := mgr.CleanupExpiredRows(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpiredRows err: %v", err)
	}
	if deleted != 24 || batchCalls != 3 {
		t.Fatalf("deleted=%d batches=%d, want 24 and 3", deleted, batchCalls)
	}

	// Verify MaxBatches cap stops early.
	batchCalls = 0
	db.execHandler = func(_ string, _ ...any) (pgconn.CommandTag, error) {
		batchCalls++
		return pgconn.NewCommandTag("DELETE 10"), nil
	}
	mgrCap := NewManagerWithDeps(db, nil,
		WithNowFunc(fixedNow),
		WithBatchSleep(0),
		WithCleanupPolicies([]CleanupPolicy{
			{Table: "health_records", TimeColumn: "created_at", RetentionDays: 7, BatchSize: 10, MaxBatches: 2, Enabled: true},
		}),
	)
	deleted, err = mgrCap.CleanupExpiredRows(context.Background())
	if err != nil || deleted != 20 || batchCalls != 2 {
		t.Fatalf("cap test got deleted=%d batches=%d err=%v, want 20/2/nil", deleted, batchCalls, err)
	}

	// Verify extreme RetentionDays passes a past cutoff (not overflowed into the future).
	var gotCutoff time.Time
	dbCutoff := &mockDB{
		relkinds: map[string]string{"health_records": "r"},
		execHandler: func(_ string, args ...any) (pgconn.CommandTag, error) {
			gotCutoff = args[0].(time.Time)
			return pgconn.NewCommandTag("DELETE 0"), nil
		},
	}
	mgrExtreme := NewManagerWithDeps(dbCutoff, nil,
		WithNowFunc(fixedNow),
		WithBatchSleep(0),
		WithCleanupPolicies([]CleanupPolicy{
			{Table: "health_records", TimeColumn: "created_at", RetentionDays: 110000, BatchSize: 10, MaxBatches: 1, Enabled: true},
		}),
	)
	if _, err := mgrExtreme.CleanupExpiredRows(context.Background()); err != nil {
		t.Fatalf("extreme cleanup err: %v", err)
	}
	if !gotCutoff.Before(fixedNow()) || gotCutoff.Year() >= 1800 {
		t.Fatalf("extreme cleanup cutoff = %v, expected < 1800", gotCutoff)
	}
}

func TestManagerStartCancellation(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	db := &mockDB{
		relkinds: map[string]string{},
		queryErr: errors.New("unexpected query"),
	}
	mgr := NewManagerWithDeps(db, nil,
		WithInterval(10*time.Millisecond),
		WithPartitionPolicies([]PartitionPolicy{
			{ParentTable: "t1", TimeColumn: "occurred_at", Granularity: GranularityMonthly, RetentionDays: 30, Enabled: true},
		}),
	)
	db.relkinds = map[string]string{} // missing -> 0 queries to pg_inherits, 1 QueryRow to pg_class
	db.queryErr = nil

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Wrap QueryRow observation via RunOnce count isn't needed; just verify Start exits cleanly.
		calls.Add(1)
		mgr.Start(ctx)
	}()

	time.Sleep(35 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not exit promptly on context cancellation")
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected call count %d", calls.Load())
	}
}
