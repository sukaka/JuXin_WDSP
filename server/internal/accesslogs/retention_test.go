package accesslogs

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mockRelkindRow struct {
	relkind string
	err     error
}

func (r mockRelkindRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.relkind
	return nil
}

type mockRetentionDB struct {
	relkind   string
	queryErr  error
	nilRow    bool
	execSQLs  []string
	execCount int64
}

func (m *mockRetentionDB) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	m.execSQLs = append(m.execSQLs, sql)
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", m.execCount)), nil
}

func (m *mockRetentionDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockRetentionDB) QueryRow(context.Context, string, ...any) pgx.Row {
	if m.nilRow {
		return nil
	}
	return mockRelkindRow{relkind: m.relkind, err: m.queryErr}
}

type stubRetentionSettings struct{ days int }

func (s stubRetentionSettings) GetInt(context.Context, string, string, int) int { return s.days }

func TestRetentionCleanerSkipsPartitionedTable(t *testing.T) {
	db := &mockRetentionDB{relkind: "p", execCount: 10}
	rc := &RetentionCleaner{db: db, settings: stubRetentionSettings{days: 7}}

	n, err := rc.CleanOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted = %d, want 0 when relkind='p'", n)
	}
	if len(db.execSQLs) != 0 {
		t.Fatalf("expected 0 DELETE executions when relkind='p', got %v", db.execSQLs)
	}
}

func TestRetentionCleanerFallsBackOnRegularTableAndNilRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		db   *mockRetentionDB
	}{
		{name: "relkind_r", db: &mockRetentionDB{relkind: "r", execCount: 15}},
		{name: "nil_row_mock", db: &mockRetentionDB{nilRow: true, execCount: 15}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := &RetentionCleaner{db: tc.db, settings: stubRetentionSettings{days: 7}}
			n, err := rc.CleanOnce(context.Background())
			if err != nil {
				t.Fatalf("CleanOnce: %v", err)
			}
			if n != 15 {
				t.Fatalf("deleted = %d, want 15", n)
			}
			if len(tc.db.execSQLs) != 1 || !strings.Contains(tc.db.execSQLs[0], "DELETE FROM access_logs") {
				t.Fatalf("unexpected execSQLs: %v", tc.db.execSQLs)
			}
		})
	}
}

func TestNewRetentionCleanerTypedNilSafe(t *testing.T) {
	rc := NewRetentionCleaner(nil, nil)
	n, err := rc.CleanOnce(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("got (%d, %v), want (0, nil)", n, err)
	}
}
