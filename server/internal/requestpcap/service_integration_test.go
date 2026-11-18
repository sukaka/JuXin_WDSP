package requestpcap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

func TestRealDatabaseAndHTTPDerivedDownload(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real PostgreSQL download test")
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
	seed, oldService, _ := newServiceFixture(t)
	hotRoot, warmRoot := t.TempDir(), t.TempDir()
	content, err := os.ReadFile(filepath.Join(oldService.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	if err := store.CreateArtifact(ctx, seed.artifact); err != nil {
		t.Fatal(err)
	}
	if err := store.LinkRequest(ctx, seed.link); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, oldService.keys, hotRoot, warmRoot)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	hash, err := security.HashPassword(handlerTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	spy := &requestAuditSpy{}
	handler := NewHandler(service, &requestUserStub{user: &users.User{ID: userID, Status: users.StatusActive, PasswordHash: hash}}, spy)
	mux := http.NewServeMux()
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), &authz.Principal{UserID: userID, Username: "integration-auditor", SessionID: "session-integration",
				PermsSet: map[string]bool{PermissionRead: true, PermissionVerify: true, PermissionDownload: true}})))
		})
	}
	handler.RegisterRoutes(mux, auth, func(next http.Handler) http.Handler { return next })

	artifactID := seed.artifact.ID.String()
	requestID := seed.link.RequestID
	response := requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/artifacts/"+artifactID+"/verify", map[string]string{"request_id": requestID, "reason": "真实数据库核验"})
	if response.Code != http.StatusOK {
		t.Fatalf("real verify HTTP response: %d %s", response.Code, response.Body.String())
	}
	response = requestJSON(t, mux, http.MethodPost, "/api/v1/request-pcap/artifacts/"+artifactID+"/download-grants", map[string]string{"request_id": requestID, "reason": "安全事件取证", "password": handlerTestPassword})
	if response.Code != http.StatusCreated {
		t.Fatalf("real grant HTTP response: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			GrantID uuid.UUID `json:"grant_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/request-pcap/artifacts/%s/download?request_id=%s&grant_id=%s", artifactID, requestID, body.Data.GrantID)
	response = requestJSON(t, mux, http.MethodGet, path, nil)
	if response.Code != http.StatusOK || response.Body.Len() != 104 {
		t.Fatalf("real download HTTP response: %d %s", response.Code, response.Body.String())
	}
	response = requestJSON(t, mux, http.MethodGet, path, nil)
	if response.Code != http.StatusForbidden {
		t.Fatalf("real grant replay response: %d %s", response.Code, response.Body.String())
	}
	if spy.last().Result != audits.ResultFailure || spy.last().ObjectType != "request_pcap" {
		t.Fatalf("real replay audit missing: %+v", spy.last())
	}
}
