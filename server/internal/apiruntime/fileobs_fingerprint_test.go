package apiruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fingerprintRow struct{}

func (fingerprintRow) Scan(...any) error { return pgx.ErrNoRows }

type fingerprintDB struct {
	query string
	args  []any
}

func (db *fingerprintDB) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	db.query = query
	db.args = append([]any(nil), args...)
	return pgconn.NewCommandTag("INSERT 1"), nil
}

func (db *fingerprintDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (db *fingerprintDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return fingerprintRow{}
}

func TestFileObsStoreFingerprintUpsert(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	db := &fingerprintDB{}
	store := NewFileObsStore(nil).WithDB(db)
	rec := &Record{
		RequestID: "fingerprint-1", EndpointKey: "POST /api/v1/files/upload", OccurredAt: time.Now().UTC(),
		FileObservations: []FileObservation{{
			Direction: "UPLOAD", FileName: "report.txt", Extension: "txt", MIME: "text/plain", Size: 12,
			ContentSHA256: strings.ToUpper(hash),
		}},
	}
	if err := store.RecordFileObservations(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	value, ok := db.args[7].(*string)
	if !ok || value == nil || *value != hash {
		t.Fatalf("sha256 upsert value = %#v", db.args[7])
	}
	if !strings.Contains(db.query, "sha256") || !strings.Contains(db.query, "COALESCE(EXCLUDED.sha256, api_file_assets.sha256)") {
		t.Fatalf("sha256 must preserve history when no new fingerprint exists: %s", db.query)
	}

	rec.FileObservations[0].ContentSHA256 = ""
	if err := store.RecordFileObservations(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	if value, ok := db.args[7].(*string); !ok || value != nil {
		t.Fatalf("unknown fingerprint must remain NULL: %#v", db.args[7])
	}
}

func TestNormalizedFileSHA256(t *testing.T) {
	if got := normalizedFileSHA256(strings.Repeat("CD", 32)); got == nil || *got != strings.Repeat("cd", 32) {
		t.Fatalf("valid fingerprint normalization failed: %#v", got)
	}
	for _, value := range []string{"", "short", strings.Repeat("x", 64), strings.Repeat("a", 63)} {
		if got := normalizedFileSHA256(value); got != nil {
			t.Fatalf("invalid fingerprint %q must be omitted: %#v", value, got)
		}
	}
}
