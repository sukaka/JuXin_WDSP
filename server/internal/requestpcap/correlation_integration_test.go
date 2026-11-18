package requestpcap

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestCapturedRequestCorrelationIntegration(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real correlation test")
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
	// 同一分片重放不能重复创建或覆盖证据。
	if err := store.CreateArtifact(ctx, artifact); err != nil {
		t.Fatalf("artifact replay is not idempotent: %v", err)
	}
	applicationID := uuid.New()
	traceID := "0123456789abcdef0123456789abcdef"
	logEntry := &accesslogs.LogEntry{
		OccurredAt: time.Now().UTC(), RequestID: "req-captured-1", ApplicationID: applicationID.String(),
		RequestMethod: "POST", RequestPath: "/v1/login", TraceID: traceID,
		RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{},
	}
	if _, err := accesslogs.NewStore(pool).Insert(ctx, logEntry); err != nil {
		t.Fatal(err)
	}
	evidence := CapturedRequest{
		RequestID: logEntry.RequestID, TraceID: traceID, ConnectionID: strings.Repeat("a", 64),
		ObservedAt: time.Now().UTC(), CapturePoint: "GATEWAY_EGRESS", Method: "POST", Path: "/v1/login", Host: "shop.internal",
		FirstPacketNo: 1, LastPacketNo: 2,
	}
	if err := store.RecordCapturedRequest(ctx, artifact.ID, evidence); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCapturedRequest(ctx, artifact.ID, evidence); err != nil {
		t.Fatalf("request evidence replay failed: %v", err)
	}
	links, err := store.ListRequestLinks(ctx, evidence.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].MatchBasis != "HTTP1_REQUEST_ID" || links[0].Coverage != "CONNECTION" ||
		links[0].ApplicationID == nil || *links[0].ApplicationID != applicationID || links[0].TraceID != traceID {
		t.Fatalf("unexpected captured request link: %+v", links)
	}

	for name, mutate := range map[string]func(*CapturedRequest){
		"path":            func(e *CapturedRequest) { e.Path = "/v1/other" },
		"trace":           func(e *CapturedRequest) { e.TraceID = "abcdef0123456789abcdef0123456789" },
		"untrusted point": func(e *CapturedRequest) { e.CapturePoint = "MIRROR" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := evidence
			mutate(&invalid)
			if err := store.RecordCapturedRequest(ctx, artifact.ID, invalid); err == nil {
				t.Fatal("mismatched request evidence was accepted")
			}
		})
	}
	unknown := evidence
	unknown.RequestID = "req-not-in-access-logs"
	if err := store.RecordCapturedRequest(ctx, artifact.ID, unknown); !errors.Is(err, ErrRequestAuditNotFound) {
		t.Fatalf("unknown request error=%v", err)
	}
	links, err = store.ListRequestLinks(ctx, evidence.RequestID)
	if err != nil || len(links) != 1 {
		t.Fatalf("negative correlation cases contaminated links: %+v err=%v", links, err)
	}
	manager, err := NewStorageManager(store, t.TempDir(), t.TempDir(), "another-node")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.MigrateOne(ctx, artifact.ID); err == nil {
		t.Fatal("storage manager accepted another node's artifact")
	}
}
