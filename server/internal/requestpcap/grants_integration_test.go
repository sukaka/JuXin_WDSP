package requestpcap

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestDownloadGrantAndVerificationIntegration(t *testing.T) {
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
		t.Fatal(err)
	}
	store := NewStore(pool)
	artifact := validTestArtifact(t)
	if err := store.CreateArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetArtifact(ctx, artifact.ID)
	if err != nil || stored.IntegrityStatus != "UNVERIFIED" || stored.LastVerifiedAt != nil {
		t.Fatalf("unexpected initial verification status: %+v err=%v", stored, err)
	}
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := store.SetVerification(ctx, artifact.ID, "PASS", "", verifiedAt); err != nil {
		t.Fatal(err)
	}
	stored, err = store.GetArtifact(ctx, artifact.ID)
	if err != nil || stored.IntegrityStatus != "PASS" || stored.LastVerifiedAt == nil || !stored.LastVerifiedAt.Equal(verifiedAt) {
		t.Fatalf("verification status was not persisted: %+v err=%v", stored, err)
	}
	if err := store.SetVerification(ctx, artifact.ID, "FAILED", "DECRYPTION_FAILED", verifiedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.SetVerification(ctx, artifact.ID, "PASS", "DECRYPTION_FAILED", verifiedAt); err == nil {
		t.Fatal("successful verification accepted an error code")
	}
	if err := store.SetVerification(ctx, uuid.New(), "PASS", "", verifiedAt); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("missing artifact verification error=%v", err)
	}
	hot, err := store.ListHotArtifacts(ctx, artifact.NodeID, time.Now().Add(time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range hot {
		if candidate.ID == artifact.ID {
			found = candidate.IntegrityStatus == "FAILED" && candidate.VerificationErrorCode == "DECRYPTION_FAILED"
		}
	}
	if !found {
		t.Fatal("lifecycle query did not return verification state")
	}

	newGrant := func(id, userID uuid.UUID, sessionID string, expiresAt time.Time) DownloadGrant {
		return DownloadGrant{ID: id, ArtifactID: artifact.ID, RequestID: "req-grant", UserID: userID,
			SessionID: sessionID, Reason: "安全事件溯源", SourceIP: "192.0.2.15", ExpiresAt: expiresAt}
	}
	userID := uuid.New()
	grantID := uuid.New()
	if err := store.CreateDownloadGrant(ctx, newGrant(grantID, userID, "session-a", time.Now().Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeDownloadGrant(ctx, grantID, uuid.New(), "session-a", time.Now()); !errors.Is(err, ErrGrantNotAvailable) {
		t.Fatalf("cross-user grant consumption error=%v", err)
	}
	if _, err := store.ConsumeDownloadGrant(ctx, grantID, userID, "session-b", time.Now()); !errors.Is(err, ErrGrantNotAvailable) {
		t.Fatalf("cross-session grant consumption error=%v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.ConsumeDownloadGrant(ctx, grantID, userID, "session-a", time.Now())
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrGrantNotAvailable) {
			t.Fatalf("atomic grant consumption error=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("single-use grant consumed %d times", successes)
	}
	expiredID := uuid.New()
	if err := store.CreateDownloadGrant(ctx, newGrant(expiredID, userID, "session-a", time.Now().Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeDownloadGrant(ctx, expiredID, userID, "session-a", time.Now().Add(2*time.Second)); !errors.Is(err, ErrGrantNotAvailable) {
		t.Fatalf("expired grant consumption error=%v", err)
	}
	if err := store.CreateDownloadGrant(ctx, newGrant(uuid.New(), userID, "session-a", time.Now().Add(-time.Second))); err == nil {
		t.Fatal("expired grant was created")
	}
}
