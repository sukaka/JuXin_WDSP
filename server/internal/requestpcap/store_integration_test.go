package requestpcap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestRequestPCAPStoreIntegration(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real PostgreSQL test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) {
			t.Fatalf("migrate through 000218: %v detail=%q where=%q hint=%q", err, pgError.Detail, pgError.Where, pgError.Hint)
		}
		t.Fatalf("migrate through 000218: %v", err)
	}
	store := NewStore(pool)
	artifact := validTestArtifact(t)
	keyPair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plainDEK := bytes.Repeat([]byte{9}, 32)
	artifact.WrappedDEK, artifact.KeyID, err = evidencekey.WrapDEK(keyPair.PublicKey, plainDEK)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetArtifact(ctx, artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "HOT" || stored.StorageTier != "HOT" || stored.PlaintextSHA256 != artifact.PlaintextSHA256 {
		t.Fatalf("unexpected stored artifact: %+v", stored)
	}
	unwrapped, err := evidencekey.UnwrapDEK(keyPair.PrivateKey, stored.KeyID, stored.WrappedDEK)
	if err != nil || !bytes.Equal(unwrapped, plainDEK) {
		t.Fatalf("stored key envelope did not unwrap correctly: %v", err)
	}
	clear(unwrapped)
	if err := store.BeginMigration(ctx, artifact.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteMigration(ctx, artifact.ID, strings.Repeat("f", 64)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("migration accepted wrong hash: %v", err)
	}
	if err := store.CompleteMigration(ctx, artifact.ID, artifact.CiphertextSHA256); err != nil {
		t.Fatal(err)
	}

	first, last := int64(1), int64(2)
	link := RequestLink{
		ArtifactID: artifact.ID, RequestID: "req-pcap-integration", TraceID: "0123456789abcdef0123456789abcdef",
		MatchStatus: "MATCHED", MatchBasis: "CONNECTION_EPOCH", Coverage: "CONNECTION",
		CandidateCount: 1, FirstPacketNo: &first, LastPacketNo: &last, ExpiresAt: artifact.ExpiresAt,
	}
	if err := store.LinkRequest(ctx, link); err != nil {
		t.Fatal(err)
	}
	if err := store.LinkRequest(ctx, link); err != nil {
		t.Fatalf("idempotent link replay failed: %v", err)
	}
	conflicting := link
	conflicting.FirstPacketNo = &last
	if err := store.LinkRequest(ctx, conflicting); err == nil {
		t.Fatal("conflicting packet range was silently accepted as an idempotent replay")
	}
	links, err := store.ListRequestLinks(ctx, link.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].ArtifactID != artifact.ID || links[0].TraceID != link.TraceID || links[0].MatchStatus != "MATCHED" {
		t.Fatalf("unexpected request links: %+v", links)
	}
	if err := store.BeginExpiry(ctx, artifact.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteExpiry(ctx, artifact.ID); err != nil {
		t.Fatal(err)
	}
	stored, err = store.GetArtifact(ctx, artifact.ID)
	if err != nil || stored.State != "EXPIRED" {
		t.Fatalf("expiry tombstone missing: state=%s err=%v", stored.State, err)
	}
	if err := store.MarkUnavailable(ctx, artifact.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expired artifact was incorrectly reopened: %v", err)
	}
	if _, err := store.GetArtifact(ctx, uuid.New()); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("unknown artifact error=%v", err)
	}
	for i := 0; i < 5; i++ {
		if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
			t.Fatalf("rollback request PCAP migration %d: %v", 222-i, err)
		}
	}
	var schemaVersion int
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != 217 {
		t.Fatalf("rollback stopped at migration %d, want 217", schemaVersion)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("restore request PCAP migrations: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != 222 {
		t.Fatalf("restore stopped at migration %d, want 222", schemaVersion)
	}
}
