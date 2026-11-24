package nodeinterfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

var ifacePerms = []string{"system_health.read", "system_settings.update"}

// injectPrincipal 模拟认证链：注入持有网口管理权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range ifacePerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newTestMux(h *Handler, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeData(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var env struct {
		Code string         `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, rr.Body.String())
	}
	return env.Data
}

// 未登录 401、无权限 403（读/写两个端点）。
func TestRoutesPermission(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)

	muxNoAuth := newTestMux(h, func(next http.Handler) http.Handler { return next })
	rr := doJSON(t, muxNoAuth, http.MethodGet, "/api/v1/gateway/interfaces", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth GET status=%d", rr.Code)
	}
	rr = doJSON(t, muxNoAuth, http.MethodPut, "/api/v1/gateway/interfaces/order",
		map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": "eth0", "sort_order": 1}}})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth PUT status=%d", rr.Code)
	}

	muxNoPerm := newTestMux(h, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	})
	rr = doJSON(t, muxNoPerm, http.MethodGet, "/api/v1/gateway/interfaces", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm GET status=%d", rr.Code)
	}
	rr = doJSON(t, muxNoPerm, http.MethodPut, "/api/v1/gateway/interfaces/order",
		map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": "eth0", "sort_order": 1}}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm PUT status=%d", rr.Code)
	}
}

// List：按节点分组返回，node_name 过滤生效，空库返回空数组而非 null。
func TestListGrouped(t *testing.T) {
	store := NewMemStore()
	seen := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	eth1 := snap("eth1", "FIBRE", 10000)
	eth1.IPAddresses = []string{"10.0.1.10/24", "2408:8207::10/64"}
	eth0 := snap("eth0", "TP", 1000)
	if err := store.ApplySnapshot(context.Background(), "gw-1",
		[]SnapshotItem{eth1, eth0}, seen); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, nil)
	mux := newTestMux(h, injectPrincipal)

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/gateway/interfaces", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	nodes, _ := data["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes = %v", nodes)
	}
	ifaces, _ := nodes[0].(map[string]any)["interfaces"].([]any)
	// 快照按 eth1,eth0 顺序上报：eth1 sort_order=1 排前（验证按 sort_order 而非 ifname 排序）
	if len(ifaces) != 2 || ifaces[0].(map[string]any)["ifname"] != "eth1" {
		t.Fatalf("interfaces not sorted by sort_order: %v", ifaces)
	}
	if ifaces[0].(map[string]any)["present"] != true {
		t.Fatalf("present = %v", ifaces[0])
	}
	ips0, ok0 := ifaces[0].(map[string]any)["ip_addresses"].([]any)
	if !ok0 || len(ips0) != 2 || ips0[0] != "10.0.1.10/24" || ips0[1] != "2408:8207::10/64" {
		t.Fatalf("eth1 ip_addresses = %#v", ifaces[0].(map[string]any)["ip_addresses"])
	}
	ips1, ok1 := ifaces[1].(map[string]any)["ip_addresses"].([]any)
	if !ok1 || len(ips1) != 0 {
		t.Fatalf("eth0 ip_addresses should be JSON empty array [], got %#v", ifaces[1].(map[string]any)["ip_addresses"])
	}

	rr = doJSON(t, mux, http.MethodGet, "/api/v1/gateway/interfaces?node_name=gw-x", nil)
	data = decodeData(t, rr)
	nodes, _ = data["nodes"].([]any)
	if len(nodes) != 0 {
		t.Fatalf("filtered nodes = %v, want empty", nodes)
	}
}

// UpdateOrder 参数校验：各类非法输入一律 400。
func TestUpdateOrderValidation(t *testing.T) {
	store := NewMemStore()
	if err := store.ApplySnapshot(context.Background(), "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "TP", 1000)}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, nil)
	mux := newTestMux(h, injectPrincipal)

	cases := []struct {
		name string
		body any
	}{
		{"missing node_name", map[string]any{"items": []any{map[string]any{"ifname": "eth0", "sort_order": 1, "role": ""}}}},
		{"empty items", map[string]any{"node_name": "gw-1", "items": []any{}}},
		{"blank ifname", map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": " ", "sort_order": 1, "role": ""}}}},
		{"dup ifname", map[string]any{"node_name": "gw-1", "items": []any{
			map[string]any{"ifname": "eth0", "sort_order": 1, "role": ""},
			map[string]any{"ifname": "eth0", "sort_order": 2, "role": ""}}}},
		{"negative sort_order", map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": "eth0", "sort_order": -1, "role": ""}}}},
		{"invalid role", map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": "eth0", "sort_order": 1, "role": "admin"}}}},
		{"unknown ifname", map[string]any{"node_name": "gw-1", "items": []any{map[string]any{"ifname": "eth9", "sort_order": 1, "role": ""}}}},
	}
	for _, tc := range cases {
		rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", tc.name, rr.Code, rr.Body.String())
		}
	}
	// 非 JSON 请求体
	req := httptest.NewRequest(http.MethodPut, "/api/v1/gateway/interfaces/order", bytes.NewReader([]byte("{oops")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
}

// UpdateOrder 成功路径：整体替换排序与角色（role 恒传，空串 = 清除），响应返回更新后分组。
func TestUpdateOrderSuccess(t *testing.T) {
	store := NewMemStore()
	if err := store.ApplySnapshot(context.Background(), "gw-1",
		[]SnapshotItem{snap("eth0", "TP", 1000), snap("eth1", "FIBRE", 10000)}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, nil) // 审计服务为 nil：不应 panic
	mux := newTestMux(h, injectPrincipal)

	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", map[string]any{
		"node_name": "gw-1",
		"items": []any{
			map[string]any{"ifname": "eth1", "sort_order": 1, "role": "TRAFFIC"},
			map[string]any{"ifname": "eth0", "sort_order": 2, "role": "MANAGEMENT"},
		},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	nodes, _ := data["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes = %v", nodes)
	}
	ifaces, _ := nodes[0].(map[string]any)["interfaces"].([]any)
	if ifaces[0].(map[string]any)["ifname"] != "eth1" ||
		ifaces[0].(map[string]any)["role"] != "TRAFFIC" ||
		ifaces[1].(map[string]any)["ifname"] != "eth0" {
		t.Fatalf("interfaces = %v", ifaces)
	}
	// 再保存一次 role 空串：角色清除（前端契约：role 恒传，空串 = 未分配）
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", map[string]any{
		"node_name": "gw-1",
		"items":     []any{map[string]any{"ifname": "eth1", "sort_order": 1, "role": ""}},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	list, err := store.ListGrouped(context.Background(), "gw-1")
	if err != nil {
		t.Fatal(err)
	}
	// 排序后 eth1（sort_order=1）在前
	if list[0].Interfaces[0].Ifname != "eth1" || list[0].Interfaces[0].Role != "" {
		t.Fatalf("eth1 = %+v, want role 已清除", list[0].Interfaces[0])
	}
	if list[0].Interfaces[1].Role != "MANAGEMENT" {
		t.Fatalf("eth0 = %+v, want role=MANAGEMENT（未被本次提交触及）", list[0].Interfaces[1])
	}
}

func TestHandlerUpdateOrderTriggersOnChangeCallback(t *testing.T) {
	store := NewMemStore()
	_ = store.ApplySnapshot(context.Background(), "gw-1", []SnapshotItem{
		{NodeName: "gw-1", Ifname: "eth2", MAC: "00:11:22:33:44:55"},
	}, time.Now())
	called := 0
	h := NewHandler(store, nil).SetOnChange(func(context.Context) { called++ })
	mux := newTestMux(h, injectPrincipal)

	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", map[string]any{
		"node_name": "gw-1",
		"items":     []any{map[string]any{"ifname": "eth2", "sort_order": 1, "role": "MIRROR"}},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if called != 1 {
		t.Fatalf("onChange called = %d, want 1", called)
	}
}

func TestHandlerUpdateOrderRejectsManagementOrMirrorOnBridgedPort(t *testing.T) {
	store := NewMemStore()
	_ = store.ApplySnapshot(context.Background(), "gw-1", []SnapshotItem{
		{NodeName: "gw-1", Ifname: "eth2", MAC: "00:11:22:33:44:55"},
		{NodeName: "gw-1", Ifname: "eth3", MAC: "00:11:22:33:44:56"},
	}, time.Now())
	h := NewHandler(store, nil).SetBridgePortChecker(func(_ context.Context, nodeName, ifname string) (string, error) {
		if nodeName == "gw-1" && ifname == "eth2" {
			return "br0", nil
		}
		return "", nil
	})
	mux := newTestMux(h, injectPrincipal)

	for _, forbiddenRole := range []string{RoleManagement, RoleMirror} {
		rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", map[string]any{
			"node_name": "gw-1",
			"items":     []any{map[string]any{"ifname": "eth2", "sort_order": 1, "role": forbiddenRole}},
		})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("setting %s on bridged port status=%d body=%s, want 400", forbiddenRole, rr.Code, rr.Body.String())
		}
	}
	// 设为 TRAFFIC 或空串允许
	for _, allowedRole := range []string{RoleTraffic, ""} {
		rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/interfaces/order", map[string]any{
			"node_name": "gw-1",
			"items":     []any{map[string]any{"ifname": "eth2", "sort_order": 1, "role": allowedRole}},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("setting %q on bridged port status=%d body=%s, want 200", allowedRole, rr.Code, rr.Body.String())
		}
	}
}
