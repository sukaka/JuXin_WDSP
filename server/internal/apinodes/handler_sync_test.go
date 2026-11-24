// handler_sync_test.go W18-SYNC 节点同步登记接口（PATCH /nodes/{id}）单测：
// 权限矩阵（匿名 401 / 无权限 403 / api_policy.publish 200）/ 参数与地址校验 /
// 404 / 登记更新落库 / 操作审计 before-after。仓储用 sweeper_test.go 的 fakeNodeStore。
package apinodes

import (
	"context"
	"encoding/json"
	"errors"
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

type fakeEncryptor struct{}

func (fakeEncryptor) Encrypt(plain string) (string, error) {
	return "enc:" + plain, nil
}

func doReq(t *testing.T, mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestNodeHAPermissions 验证纯 WAF/HA 权限（ha.read / ha.manage）可执行节点列表、创建、编辑、测试、删除。
func TestNodeHAPermissions(t *testing.T) {
	node := syncTestNode()
	store := &fakeNodeStore{nodes: []Node{node}}
	h := NewHandler(store).SetEncryptor(fakeEncryptor{})

	// ha.read 可读 GET /nodes 与 GET /nodes/consistency，不能写
	readMux := newSyncMux(h, syncInjectPerms(PermHARead))
	if rr := doReq(t, readMux, http.MethodGet, "/api/v1/api-security/nodes", ""); rr.Code != http.StatusOK {
		t.Fatalf("ha.read GET /nodes = %d", rr.Code)
	}
	if rr := doReq(t, readMux, http.MethodGet, "/api/v1/api-security/nodes/consistency", ""); rr.Code != http.StatusOK {
		t.Fatalf("ha.read GET /consistency = %d", rr.Code)
	}
	if rr := doReq(t, readMux, http.MethodPost, "/api/v1/api-security/nodes", `{"node_name":"gw-new"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("ha.read POST /nodes = %d, want 403", rr.Code)
	}

	// ha.manage 可执行 POST/PATCH/POST test/DELETE
	writeMux := newSyncMux(h, syncInjectPerms(PermHAManage))
	if rr := doPatch(t, writeMux, "/api/v1/api-security/nodes/"+node.ID.String(), `{"sync_enabled":true}`); rr.Code != http.StatusOK {
		t.Fatalf("ha.manage PATCH = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, writeMux, http.MethodPost, "/api/v1/api-security/nodes/"+node.ID.String()+"/test", ""); rr.Code != http.StatusOK {
		t.Fatalf("ha.manage POST /test = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, writeMux, http.MethodDelete, "/api/v1/api-security/nodes/"+node.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("ha.manage DELETE = %d body=%s", rr.Code, rr.Body.String())
	}
}

// TestCreateUpdateDeleteNodeWithSyncSecret 验证节点创建/编辑/删除、密钥加密落库与脱敏、HA 组引用拦截 409。
func TestCreateUpdateDeleteNodeWithSyncSecret(t *testing.T) {
	validSecret := strings.Repeat("a1", 32) // 64 hex chars
	newSecret := strings.Repeat("b2", 32)

	store := &fakeNodeStore{}
	spy := &spyAudits{}
	h := NewHandler(store).SetAudits(spy).SetEncryptor(fakeEncryptor{})
	mux := newSyncMux(h, syncInjectPerms(PermHAManage))

	// 1. 非法输入校验：非法节点名 / 公网 sync_agent_addr / 短密钥
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes", `{"node_name":"../bad"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad node_name = %d, want 400", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes", `{"node_name":"gw-b","sync_agent_addr":"https://8.8.8.8:18443"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("public sync_agent_addr = %d, want 400", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes", `{"node_name":"gw-b","sync_secret":"deadbeef"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("short sync_secret = %d, want 400", rr.Code)
	}

	// 未装配加密服务时设置 sync_secret 必须 fail-closed（不落明文）
	noEncMux := newSyncMux(NewHandler(store), syncInjectPerms(PermHAManage))
	if rr := doReq(t, noEncMux, http.MethodPost, "/api/v1/api-security/nodes",
		`{"node_name":"gw-noenc","sync_agent_addr":"https://10.0.0.2:18443","sync_secret":"`+validSecret+`"}`); rr.Code != http.StatusInternalServerError {
		t.Fatalf("missing encryptor = %d, want 500", rr.Code)
	}

	// 2. 创建成功：201，返回 has_sync_secret=true，响应体与审计均不含明文/密文
	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes",
		`{"node_name":"gw-b","sync_agent_addr":"https://10.0.0.2:18443","sync_secret":"`+validSecret+`","sync_enabled":true}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), validSecret) || strings.Contains(rr.Body.String(), "enc:") {
		t.Fatalf("response leaked secret: %s", rr.Body.String())
	}
	var createResp struct {
		Data Node `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	nodeID := createResp.Data.ID
	if createResp.Data.NodeName != "gw-b" || createResp.Data.SyncAgentAddr != "https://10.0.0.2:18443" || !createResp.Data.HasSyncSecret || !createResp.Data.SyncEnabled {
		t.Fatalf("created node = %+v", createResp.Data)
	}
	if store.secrets[nodeID] != "enc:"+validSecret {
		t.Fatalf("stored ciphertext = %q", store.secrets[nodeID])
	}
	// 审计不包含密钥明文或密文
	if len(spy.entries) != 1 || strings.Contains(spy.entries[0].AfterSummary, validSecret) {
		t.Fatalf("create audit invalid or leaked secret: %+v", spy.entries)
	}

	// 3. 重名冲突 409
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes", `{"node_name":"gw-b"}`); rr.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409", rr.Code)
	}

	// 4. PATCH 省略 sync_secret：保持原密文不变
	path := "/api/v1/api-security/nodes/" + nodeID.String()
	if rr := doPatch(t, mux, path, `{"sync_agent_addr":"https://10.0.0.3:18443"}`); rr.Code != http.StatusOK {
		t.Fatalf("patch addr = %d body=%s", rr.Code, rr.Body.String())
	}
	if store.secrets[nodeID] != "enc:"+validSecret || !store.nodes[0].HasSyncSecret {
		t.Fatalf("omitted sync_secret must preserve existing secret: %q", store.secrets[nodeID])
	}

	// 5. PATCH 替换 sync_secret
	rr = doPatch(t, mux, path, `{"sync_secret":"`+newSecret+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch secret = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), newSecret) {
		t.Fatalf("patch response leaked secret")
	}
	if store.secrets[nodeID] != "enc:"+newSecret {
		t.Fatalf("stored ciphertext after rotate = %q", store.secrets[nodeID])
	}

	// 6. PATCH 传空串 "" 清除 sync_secret
	rr = doPatch(t, mux, path, `{"sync_secret":""}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear secret = %d body=%s", rr.Code, rr.Body.String())
	}
	if store.secrets[nodeID] != "" || store.nodes[0].HasSyncSecret {
		t.Fatalf("empty sync_secret must clear secret: %q has=%v", store.secrets[nodeID], store.nodes[0].HasSyncSecret)
	}

	// 7. DELETE 在 HA 组中被引用 → 409
	store.inHAGroup = map[uuid.UUID]bool{nodeID: true}
	if rr := doReq(t, mux, http.MethodDelete, path, ""); rr.Code != http.StatusConflict {
		t.Fatalf("delete in ha group = %d, want 409 (body=%s)", rr.Code, rr.Body.String())
	}

	// 8. 移出 HA 组后 DELETE → 200
	store.inHAGroup[nodeID] = false
	if rr := doReq(t, mux, http.MethodDelete, path, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete free node = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(store.nodes) != 0 {
		t.Fatalf("nodes remaining after delete: %+v", store.nodes)
	}
}

// TestTestNodeChannels 验证 POST /nodes/{id}/test 的 hasyncd / caddy_admin / none 三条通道分支。
func TestTestNodeChannels(t *testing.T) {
	nodeHasync := Node{ID: uuid.New(), NodeName: "gw-sync", SyncAgentAddr: "https://10.0.0.2:18443"}
	nodeCaddy := Node{ID: uuid.New(), NodeName: "gw-caddy", AdminAddr: "http://10.0.0.3:2019"}
	nodeNone := Node{ID: uuid.New(), NodeName: "gw-none"}
	store := &fakeNodeStore{nodes: []Node{nodeHasync, nodeCaddy, nodeNone}}

	trueVal := true
	h := NewHandler(store).
		SetNodeTester(func(_ context.Context, id uuid.UUID) (*NodeTestResult, error) {
			if id != nodeHasync.ID {
				return nil, errors.New("unexpected id")
			}
			return &NodeTestResult{
				OK:             true,
				Channel:        "hasyncd",
				LatencyMs:      12,
				Version:        "1.12.0",
				CaddyReachable: &trueVal,
				HostctlReady:   &trueVal,
				UpgradeReady:   &trueVal,
			}, nil
		}).
		SetCaddyPinger(func(_ context.Context, addr string) error {
			if addr != "http://10.0.0.3:2019" {
				return errors.New("unexpected addr")
			}
			return nil
		})
	mux := newSyncMux(h, syncInjectPerms(PermHAManage))

	// 1. hasyncd 通道
	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes/"+nodeHasync.ID.String()+"/test", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("hasyncd test status = %d", rr.Code)
	}
	var res struct {
		Data NodeTestResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Data.OK || res.Data.Channel != "hasyncd" || res.Data.Version != "1.12.0" ||
		res.Data.CaddyReachable == nil || !*res.Data.CaddyReachable ||
		res.Data.HostctlReady == nil || !*res.Data.HostctlReady ||
		res.Data.UpgradeReady == nil || !*res.Data.UpgradeReady {
		t.Fatalf("hasyncd test data = %+v", res.Data)
	}

	// 2. caddy_admin 通道
	rr = doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes/"+nodeCaddy.ID.String()+"/test", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("caddy_admin test status = %d", rr.Code)
	}
	res.Data = NodeTestResult{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Data.OK || res.Data.Channel != "caddy_admin" || res.Data.CaddyReachable == nil || !*res.Data.CaddyReachable {
		t.Fatalf("caddy_admin test data = %+v", res.Data)
	}

	// 3. 未配置通道 → ok=false, channel=none
	rr = doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes/"+nodeNone.ID.String()+"/test", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("none test status = %d", rr.Code)
	}
	res.Data = NodeTestResult{}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Data.OK || res.Data.Channel != "none" || res.Data.Error == "" {
		t.Fatalf("none test data = %+v", res.Data)
	}
}

// TestTestNodeDefaultHTTPCaddyAdminPing 验证默认 caddyPing 通过 NewCaddyClientForAdminAddr 真实探测 HTTP Caddy Admin。
func TestTestNodeDefaultHTTPCaddyAdminPing(t *testing.T) {
	var hitConfig bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			hitConfig = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	node := Node{ID: uuid.New(), NodeName: "gw-http-caddy", AdminAddr: srv.URL}
	store := &fakeNodeStore{nodes: []Node{node}}
	h := NewHandler(store) // 不覆盖 caddyPing，走默认 NewCaddyClientForAdminAddr
	mux := newSyncMux(h, syncInjectPerms(PermHAManage))

	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/nodes/"+node.ID.String()+"/test", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("http caddy test status = %d body=%s", rr.Code, rr.Body.String())
	}
	var res struct {
		Data NodeTestResult `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !hitConfig || !res.Data.OK || res.Data.Channel != "caddy_admin" ||
		res.Data.CaddyReachable == nil || !*res.Data.CaddyReachable {
		t.Fatalf("default HTTP caddy ping failed: hitConfig=%v data=%+v", hitConfig, res.Data)
	}
}
