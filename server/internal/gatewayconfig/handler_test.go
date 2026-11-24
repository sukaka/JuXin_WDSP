// handler_test.go CurrentConfig 错误处理回归（审查修复）：
// GetCurrentVersion 上抛真实查询错误时必须 500，不得渲染成 has_current:false。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// TestCurrentConfigDBErrorReturns500 数据库不可用时：GetCurrentVersion 返回非 ErrNoRows
// 错误，CurrentConfig 应返回 500 INTERNAL_ERROR，而非把故障渲染成"无当前版本"。
func TestCurrentConfigDBErrorReturns500(t *testing.T) {
	// 惰性连接池指向不可用端口：查询必然立即失败，无需真实数据库。
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/gatewayconfig_test?connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	h := NewHandler(NewPublisher(pool, nil, nil, nil, "", t.TempDir(), nil, nil), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/gateway-configs/current", nil)
	rec := httptest.NewRecorder()
	h.CurrentConfig(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("CurrentConfig status = %d, want 500", rec.Code)
	}
	var body response.Body
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != response.CodeInternalError {
		t.Errorf("body code = %q, want %q", body.Code, response.CodeInternalError)
	}
	if data, ok := body.Data.(map[string]interface{}); ok {
		if hasCurrent, exists := data["has_current"]; exists && hasCurrent == false {
			t.Error("错误被渲染成 has_current:false")
		}
	}
}

func TestVersionItemIncludesValidationResult(t *testing.T) {
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	for _, vr := range []string{"SMOKE_PASS", "SMOKE_FAIL", "SMOKE_SKIPPED", ""} {
		v := &ConfigVersion{
			ID:                uuid.New(),
			VersionNumber:     "V20261120.090000.000-12345678",
			ConfigurationHash: "1234567890abcdef",
			BusinessSnapshot:  "{}",
			ChangeSummary:     "test",
			PublishResult:     "SUCCESS",
			ValidationResult:  vr,
			IsCurrent:         true,
			CreatedAt:         now,
			PublishedAt:       &now,
		}
		item := versionItem(v)
		got, exists := item["validation_result"]
		if !exists {
			t.Fatalf("versionItem(%q) missing validation_result key", vr)
		}
		if got != vr {
			t.Fatalf("versionItem(%q)[validation_result] = %v, want %q", vr, got, vr)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/config-versions", nil)
		response.Page(rec, req, []map[string]interface{}{item}, 1, 1, 20)
		var env struct {
			Data struct {
				Items []struct {
					ValidationResult *string `json:"validation_result"`
				} `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(env.Data.Items) != 1 || env.Data.Items[0].ValidationResult == nil || *env.Data.Items[0].ValidationResult != vr {
			t.Fatalf("serialized validation_result mismatch for %q: %+v", vr, env.Data.Items)
		}
	}
}

func TestRetryNodeSyncHandler(t *testing.T) {
	fakeB := &fakeCaddyAdmin{}
	srvB := httptest.NewServer(fakeB.handler())
	defer srvB.Close()
	fakeC := &fakeCaddyAdmin{}
	srvC := httptest.NewServer(fakeC.handler())
	defer srvC.Close()

	versionID := uuid.New()
	unpublishedID := uuid.New()
	primaryID := uuid.New()
	nodeBID := uuid.New()
	nodeCID := uuid.New()

	baseStore := &fakeNodeSyncStore{targets: []SyncTarget{
		{NodeID: primaryID, NodeName: "gw-a", AdminAddr: "/var/run/caddy/admin.sock"},
		{NodeID: nodeBID, NodeName: "gw-b", AdminAddr: srvB.URL},
		{NodeID: nodeCID, NodeName: "gw-c", AdminAddr: srvC.URL},
	}}
	store := &failedTargetNodeSyncStore{
		fakeNodeSyncStore: baseStore,
		failedTargets:     []SyncTarget{{NodeID: nodeBID, NodeName: "gw-b", AdminAddr: srvB.URL}},
	}
	pub := &Publisher{
		caddy: NewCaddyClient("/var/run/caddy/admin.sock"),
		loadVersionFn: func(_ context.Context, id uuid.UUID) (*ConfigVersion, error) {
			switch id {
			case versionID:
				return &ConfigVersion{ID: versionID, ConfigurationJSON: fanoutTestConfig, PublishResult: TaskSuccess}, nil
			case unpublishedID:
				return &ConfigVersion{ID: unpublishedID, ConfigurationJSON: fanoutTestConfig, PublishResult: TaskFailed}, nil
			default:
				return nil, ErrVersionNotFound
			}
		},
	}
	pub.SetLocalNodeName("gw-a")
	pub.SetNodeSyncStore(store)
	h := NewHandler(pub, nil, nil)

	doReq := func(pathID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/publish/versions/"+pathID+"/retry-sync", strings.NewReader(body))
		req.SetPathValue("id", pathID)
		req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{UserID: uuid.New(), Username: "admin"}))
		rec := httptest.NewRecorder()
		h.RetryNodeSync(rec, req)
		return rec
	}

	t.Run("invalid version id returns 400", func(t *testing.T) {
		if rec := doReq("not-a-uuid", ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("invalid json body returns 400", func(t *testing.T) {
		if rec := doReq(versionID.String(), "{bad"); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("invalid node_id returns 400", func(t *testing.T) {
		if rec := doReq(versionID.String(), `{"node_id":"bad"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("missing version returns 404", func(t *testing.T) {
		if rec := doReq(uuid.NewString(), ""); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
	t.Run("unpublished version returns 400", func(t *testing.T) {
		if rec := doReq(unpublishedID.String(), ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("missing target node returns 404", func(t *testing.T) {
		if rec := doReq(versionID.String(), `{"node_id":"`+uuid.NewString()+`"}`); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
	t.Run("local primary target returns 400", func(t *testing.T) {
		if rec := doReq(versionID.String(), `{"node_id":"`+primaryID.String()+`"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("empty body retries failed targets for version", func(t *testing.T) {
		rec := doReq(versionID.String(), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data NodeSyncRetryResult `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if env.Data.VersionID != versionID || env.Data.Attempted != 1 || env.Data.Succeeded != 1 || env.Data.Failed != 0 {
			t.Fatalf("retry result = %+v", env.Data)
		}
		if len(fakeB.loadCalls()) != 1 || len(fakeC.loadCalls()) != 0 {
			t.Fatalf("loads: B=%d C=%d, want 1/0", len(fakeB.loadCalls()), len(fakeC.loadCalls()))
		}
	})
	t.Run("targeted node_id retries only specified node", func(t *testing.T) {
		rec := doReq(versionID.String(), `{"node_id":"`+nodeCID.String()+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var env struct {
			Data NodeSyncRetryResult `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if env.Data.NodeID != nodeCID.String() || env.Data.Attempted != 1 || env.Data.Succeeded != 1 {
			t.Fatalf("targeted retry result = %+v", env.Data)
		}
		if len(fakeC.loadCalls()) != 1 {
			t.Fatalf("gw-c loads = %d, want 1", len(fakeC.loadCalls()))
		}
	})
}
