// handler_test.go CurrentConfig 错误处理回归（审查修复）：
// GetCurrentVersion 上抛真实查询错误时必须 500，不得渲染成 has_current:false。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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
