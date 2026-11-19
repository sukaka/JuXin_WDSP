// handler_sync_test.go W18-SYNC 节点同步登记接口（PATCH /nodes/{id}）单测：
// 权限矩阵（匿名 401 / 无权限 403 / api_policy.publish 200）/ 参数与地址校验 /
// 404 / 登记更新落库 / 操作审计 before-after。仓储用 sweeper_test.go 的 fakeNodeStore。
package apinodes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// spyAudits 审计间谍（记录每次 Record 输入）。
type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// syncTestNode 构造一个待登记节点行。
func syncTestNode() Node {
	return Node{ID: uuid.New(), NodeName: "gw-reg", Status: StatusActive}
}

func newSyncMux(h *Handler, inject func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, inject, h)
	return mux
}

func syncInjectAnon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}

func syncInjectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "w18sync-it", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "w18sync-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func doPatch(t *testing.T, mux http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestUpdateNodePermissionMatrix 权限矩阵：匿名 401 / 无权限 403 /
// api_runtime.read 仅只读权限不足 / api_policy.publish 放行。
func TestUpdateNodePermissionMatrix(t *testing.T) {
	node := syncTestNode()
	path := "/api/v1/api-security/nodes/" + node.ID.String()
	body := `{"sync_enabled":false}`

	cases := []struct {
		name   string
		inject func(http.Handler) http.Handler
		want   int
	}{
		{"匿名 401", syncInjectAnon, http.StatusUnauthorized},
		{"无任何权限 403", syncInjectPerms(), http.StatusForbidden},
		{"仅只读权限 403", syncInjectPerms(PermRuntimeRead), http.StatusForbidden},
		{"发布权限 200", syncInjectPerms(PermPolicyPublish), http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := &fakeNodeStore{nodes: []Node{node}}
			h := NewHandler(store)
			rr := doPatch(t, newSyncMux(h, c.inject), path, body)
			if rr.Code != c.want {
				t.Fatalf("status = %d, want %d (body=%s)", rr.Code, c.want, rr.Body.String())
			}
		})
	}
}

// TestUpdateNodeValidation 参数校验：非法 ID / 不存在节点 / 空变更 / 地址非法。
func TestUpdateNodeValidation(t *testing.T) {
	node := syncTestNode()
	base := "/api/v1/api-security/nodes/"

	newHandler := func() (*Handler, *fakeNodeStore) {
		store := &fakeNodeStore{nodes: []Node{node}}
		return NewHandler(store), store
	}

	t.Run("非法节点ID 400", func(t *testing.T) {
		h, _ := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+"not-a-uuid", `{"sync_enabled":true}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("节点不存在 404", func(t *testing.T) {
		h, _ := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+uuid.NewString(), `{"sync_enabled":true}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})

	t.Run("空变更 400", func(t *testing.T) {
		h, _ := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+node.ID.String(), `{}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("请求体非法 400", func(t *testing.T) {
		h, _ := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+node.ID.String(), `{"admin_addr":123}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("公网地址拦截 400", func(t *testing.T) {
		h, store := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+node.ID.String(),
			`{"admin_addr":"http://8.8.8.8:2019"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body=%s)", rr.Code, rr.Body.String())
		}
		if store.nodes[0].AdminAddr != "" {
			t.Fatalf("store mutated on rejected addr: %+v", store.nodes[0])
		}
	})

	t.Run("非 http 方案拦截 400", func(t *testing.T) {
		h, _ := newHandler()
		rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+node.ID.String(),
			`{"admin_addr":"ftp://10.0.0.1:2019"}`)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("非白名单 unix socket 与元数据地址拦截 400", func(t *testing.T) {
		for _, addr := range []string{
			"/var/run/docker.sock",
			"/run/caddy/../docker.sock",
			"http://169.254.169.254:80",
			"http://[fd00:ec2::254]:80",
		} {
			h, _ := newHandler()
			rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)), base+node.ID.String(),
				`{"admin_addr":"`+addr+`"}`)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("addr %q: status = %d, want 400", addr, rr.Code)
			}
		}
	})
}

// TestUpdateNodeSuccessAndAudit 登记成功：admin_addr/sync_enabled 落库（未提供字段保持原值），
// 响应带出更新后节点，审计记录 before/after 与对象要素。
func TestUpdateNodeSuccessAndAudit(t *testing.T) {
	node := syncTestNode()
	node.AdminAddr = "/run/old-admin.sock"
	node.SyncEnabled = false
	store := &fakeNodeStore{nodes: []Node{node}}
	spy := &spyAudits{}
	h := NewHandler(store).SetAudits(spy)
	mux := newSyncMux(h, syncInjectPerms(PermPolicyPublish))
	path := "/api/v1/api-security/nodes/" + node.ID.String()

	// 部分更新：仅改 admin_addr（sync_enabled 保持 false）
	rr := doPatch(t, mux, path, `{"admin_addr":"http://10.0.0.5:2019"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if store.nodes[0].AdminAddr != "http://10.0.0.5:2019" || store.nodes[0].SyncEnabled {
		t.Fatalf("store = %+v, want addr updated / sync_enabled unchanged", store.nodes[0])
	}
	var resp struct {
		Data struct {
			AdminAddr   string `json:"admin_addr"`
			SyncEnabled bool   `json:"sync_enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if resp.Data.AdminAddr != "http://10.0.0.5:2019" || resp.Data.SyncEnabled {
		t.Fatalf("response = %+v", resp.Data)
	}

	// 开启扇出（admin_addr 保持）
	rr = doPatch(t, mux, path, `{"sync_enabled":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !store.nodes[0].SyncEnabled || store.nodes[0].AdminAddr != "http://10.0.0.5:2019" {
		t.Fatalf("store after enable = %+v", store.nodes[0])
	}

	// 审计：两次成功更新，before/after 如实
	if len(spy.entries) != 2 {
		t.Fatalf("audit entries = %+v", spy.entries)
	}
	first, second := spy.entries[0], spy.entries[1]
	if first.Action != "update" || first.ObjectType != "api_gateway_node" ||
		first.ObjectID != node.ID.String() || first.ObjectName != "gw-reg" ||
		first.Result != audits.ResultSuccess || first.RiskLevel != audits.RiskMedium {
		t.Fatalf("first audit = %+v", first)
	}
	if !strings.Contains(first.BeforeSummary, "/run/old-admin.sock") ||
		!strings.Contains(first.AfterSummary, "http://10.0.0.5:2019") ||
		!strings.Contains(first.AfterSummary, `"sync_enabled":false`) {
		t.Fatalf("first audit before/after = %q -> %q", first.BeforeSummary, first.AfterSummary)
	}
	if !strings.Contains(second.BeforeSummary, `"sync_enabled":false`) ||
		!strings.Contains(second.AfterSummary, `"sync_enabled":true`) {
		t.Fatalf("second audit before/after = %q -> %q", second.BeforeSummary, second.AfterSummary)
	}
}

// TestUpdateNodeClearAddr 清除登记（admin_addr 置空串）放行并落库。
func TestUpdateNodeClearAddr(t *testing.T) {
	node := syncTestNode()
	node.AdminAddr = "http://10.0.0.5:2019"
	node.SyncEnabled = true
	store := &fakeNodeStore{nodes: []Node{node}}
	h := NewHandler(store).SetAudits(&spyAudits{})
	rr := doPatch(t, newSyncMux(h, syncInjectPerms(PermPolicyPublish)),
		"/api/v1/api-security/nodes/"+node.ID.String(), `{"admin_addr":"","sync_enabled":false}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if store.nodes[0].AdminAddr != "" || store.nodes[0].SyncEnabled {
		t.Fatalf("store = %+v, want cleared", store.nodes[0])
	}
}
