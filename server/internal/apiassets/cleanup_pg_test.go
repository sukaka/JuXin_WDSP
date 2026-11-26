package apiassets

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestNoiseCleanupPGIntegration(t *testing.T) {
	dsn := os.Getenv("APIASSETS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("APIASSETS_TEST_PG_DSN not set, skipping PG integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	appID := uuid.New()
	appCode := "noise-cleanup-" + appID.String()[:8]
	if _, err := pool.Exec(ctx, `
INSERT INTO applications (id, code, name)
VALUES ($1, $2, $3)`, appID, appCode, "Noise Cleanup Test App"); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_endpoints WHERE application_id = $1`, appID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM applications WHERE id = $1`, appID)
	})

	store := NewStore(pool)

	noiseStatic, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		ApplicationID: &appID,
		Host:          "noise-cleanup.test.local",
		Method:        "GET",
		PathTemplate:  "/static/logo.png",
		Confidence:    0.4,
		IsAPI:         true,
	})
	if err != nil {
		t.Fatalf("insert noiseStatic: %v", err)
	}

	noiseNonAPI, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		ApplicationID: &appID,
		Host:          "noise-cleanup.test.local",
		Method:        "GET",
		PathTemplate:  "/portal/home",
		Confidence:    0.1,
		IsAPI:         false,
	})
	if err != nil {
		t.Fatalf("insert noiseNonAPI: %v", err)
	}

	protectedByModel, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		ApplicationID: &appID,
		Host:          "noise-cleanup.test.local",
		Method:        "GET",
		PathTemplate:  "/static/protected.png",
		Confidence:    0.6,
		IsAPI:         true,
	})
	if err != nil {
		t.Fatalf("insert protectedByModel: %v", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO api_model_versions (api_endpoint_id, endpoint_key, status, content_hash)
VALUES ($1, $2, 'CANDIDATE', 'sha256:test-protected')`,
		protectedByModel.ID, protectedByModel.EndpointKey); err != nil {
		t.Fatalf("insert api_model_versions: %v", err)
	}

	realAPI, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		ApplicationID: &appID,
		Host:          "noise-cleanup.test.local",
		Method:        "GET",
		PathTemplate:  "/api/v1/orders",
		Confidence:    0.95,
		IsAPI:         true,
	})
	if err != nil {
		t.Fatalf("insert realAPI: %v", err)
	}

	cfg := DefaultDiscoveryFilterConfig()
	filter := NoiseCleanupFilter{ApplicationID: &appID}

	preview, err := store.PreviewNoiseCleanup(ctx, cfg, filter)
	if err != nil {
		t.Fatalf("PreviewNoiseCleanup: %v", err)
	}
	if preview.Total != 2 || preview.ProtectedSkipped != 1 {
		t.Fatalf("PreviewNoiseCleanup = total:%d protected_skipped:%d, want total:2 protected_skipped:1",
			preview.Total, preview.ProtectedSkipped)
	}

	// IGNORE 模式：指定 noiseStatic 与 protectedByModel，后者必须受 api_model_versions 保护而跳过
	ignoreRes, err := store.ExecuteNoiseCleanup(ctx, cfg, NoiseCleanupFilter{
		ApplicationID: &appID,
		IDs:           []uuid.UUID{noiseStatic.ID, protectedByModel.ID},
	}, NoiseCleanupActionIgnore, "stage1-tester")
	if err != nil {
		t.Fatalf("ExecuteNoiseCleanup(IGNORE): %v", err)
	}
	if ignoreRes.Action != NoiseCleanupActionIgnore || ignoreRes.Affected != 1 || ignoreRes.ProtectedSkipped != 1 {
		t.Fatalf("ExecuteNoiseCleanup(IGNORE) = %+v, want affected=1 protected_skipped=1", ignoreRes)
	}

	afterIgnore, err := store.GetByID(ctx, noiseStatic.ID)
	if err != nil || afterIgnore.AssetStatus != "IGNORED" {
		t.Fatalf("noiseStatic after IGNORE = %+v err=%v, want IGNORED", afterIgnore, err)
	}
	afterProtected, err := store.GetByID(ctx, protectedByModel.ID)
	if err != nil || afterProtected.AssetStatus != "DISCOVERED" {
		t.Fatalf("protectedByModel should stay DISCOVERED, got %+v err=%v", afterProtected, err)
	}

	// DELETE 模式（含已 IGNORE 行）：删除 noiseStatic + noiseNonAPI，保留 protectedByModel 与 realAPI
	delRes, err := store.ExecuteNoiseCleanup(ctx, cfg, NoiseCleanupFilter{
		ApplicationID:  &appID,
		IncludeIgnored: true,
	}, NoiseCleanupActionDelete, "stage1-tester")
	if err != nil {
		t.Fatalf("ExecuteNoiseCleanup(DELETE): %v", err)
	}
	if delRes.Action != NoiseCleanupActionDelete || delRes.Affected != 2 || delRes.ProtectedSkipped != 1 {
		t.Fatalf("ExecuteNoiseCleanup(DELETE) = %+v, want affected=2 protected_skipped=1", delRes)
	}

	for _, deletedID := range []uuid.UUID{noiseStatic.ID, noiseNonAPI.ID} {
		if _, err := store.GetByID(ctx, deletedID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected deleted endpoint %s to return ErrNotFound, got %v", deletedID, err)
		}
	}
	for _, keptID := range []uuid.UUID{protectedByModel.ID, realAPI.ID} {
		if _, err := store.GetByID(ctx, keptID); err != nil {
			t.Fatalf("expected kept endpoint %s to remain, got err=%v", keptID, err)
		}
	}
}
