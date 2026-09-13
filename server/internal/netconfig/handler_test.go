package netconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
	"github.com/jiuzhang-waf/server/internal/response"
)

var netPerms = []string{"system_health.read", "system_settings.update"}

// fakeLister 提供固定网口清单（PUT 校验数据源）。
type fakeLister struct{ ifaces []nodeinterfaces.Interface }

func (f fakeLister) ListGrouped(_ context.Context, nodeName string) ([]nodeinterfaces.NodeInterfaces, error) {
	return []nodeinterfaces.NodeInterfaces{{NodeName: nodeName, Interfaces: f.ifaces}}, nil
}

// injectPrincipal 模拟认证链：注入持有网络配置权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range netPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// newTestHandler 装配测试处理器：内存仓储 + 固定清单 + 临时边车目录（默认节点 gw-1）。
func newTestHandler(t *testing.T) (*Handler, *MemStore, string) {
	t.Helper()
	store := NewMemStore()
	h := NewHandler(store, fakeLister{ifaces: testIfaces()}, nil, "gw-1")
	dir := t.TempDir()
	h.SetSidecarDir(dir)
	return h, store, dir
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

func validBody() map[string]any {
	return map[string]any{
		"bridges":    []any{map[string]any{"name": "br0", "ports": []any{"eth2", "eth3"}}},
		"ip_forward": true,
		"routes":     []any{map[string]any{"dst": "10.9.0.0/24", "via": "192.168.50.1"}},
	}
}

// 未登录 401、无权限 403（读/写两个端点）。
func TestRoutesPermission(t *testing.T) {
	h, _, _ := newTestHandler(t)

	muxNoAuth := newTestMux(h, func(next http.Handler) http.Handler { return next })
	if rr := doJSON(t, muxNoAuth, http.MethodGet, "/api/v1/gateway/network-config", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth GET status=%d", rr.Code)
	}
	if rr := doJSON(t, muxNoAuth, http.MethodPut, "/api/v1/gateway/network-config", validBody()); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth PUT status=%d", rr.Code)
	}

	muxNoPerm := newTestMux(h, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	})
	if rr := doJSON(t, muxNoPerm, http.MethodGet, "/api/v1/gateway/network-config", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm GET status=%d", rr.Code)
	}
	if rr := doJSON(t, muxNoPerm, http.MethodPut, "/api/v1/gateway/network-config", validBody()); rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm PUT status=%d", rr.Code)
	}
}

// Get：无记录返回空配置（bridges/routes 为空数组而非 null、updated_at 为 null、status 为 null）。
func TestGetDefaultEmpty(t *testing.T) {
	h, _, _ := newTestHandler(t)
	mux := newTestMux(h, injectPrincipal)

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/gateway/network-config", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	desired, _ := data["desired"].(map[string]any)
	if desired == nil {
		t.Fatalf("desired missing: %v", data)
	}
	if desired["updated_at"] != nil {
		t.Fatalf("updated_at = %v, want null", desired["updated_at"])
	}
	if desired["ip_forward"] != false {
		t.Fatalf("ip_forward = %v", desired["ip_forward"])
	}
	bridges, ok := desired["bridges"].([]any)
	if !ok || bridges == nil || len(bridges) != 0 {
		t.Fatalf("bridges = %v, want 空数组", desired["bridges"])
	}
	routes, ok := desired["routes"].([]any)
	if !ok || routes == nil || len(routes) != 0 {
		t.Fatalf("routes = %v, want 空数组", desired["routes"])
	}
	if data["status"] != nil {
		t.Fatalf("status = %v, want null", data["status"])
	}
}

// Get status 透传：合法 network-status.json 原样返回；解析失败降级 null；
// 查询非默认节点时即使状态文件存在也为 null（状态属于本网关节点）。
func TestGetStatusPassthrough(t *testing.T) {
	h, store, dir := newTestHandler(t)
	if err := store.Save(context.Background(), "gw-1", validConfig()); err != nil {
		t.Fatal(err)
	}
	mux := newTestMux(h, injectPrincipal)

	statusRaw := `{"applied_at":"2026-08-19T10:00:00Z","ok":true,"bridges":[{"name":"br0","state":"ok","message":""}],"ip_forward":"ok","routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1","state":"ok","message":""}],"message":""}`
	if err := os.WriteFile(filepath.Join(dir, "network-status.json"), []byte(statusRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/gateway/network-config", nil)
	data := decodeData(t, rr)
	status, _ := data["status"].(map[string]any)
	if status == nil || status["ok"] != true || status["ip_forward"] != "ok" {
		t.Fatalf("status = %v", data["status"])
	}
	// updated_at 来自保存时间（非 null）
	if data["desired"].(map[string]any)["updated_at"] == nil {
		t.Fatal("保存后 updated_at 不应为 null")
	}
	// 非默认节点：status 为 null
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/gateway/network-config?node_name=gw-other", nil)
	data = decodeData(t, rr)
	if data["status"] != nil {
		t.Fatalf("非默认节点 status = %v, want null", data["status"])
	}
	// 解析失败：status 降级 null（不报错）
	if err := os.WriteFile(filepath.Join(dir, "network-status.json"), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/gateway/network-config", nil)
	data = decodeData(t, rr)
	if data["status"] != nil {
		t.Fatalf("损坏状态文件 status = %v, want null", data["status"])
	}
}

// Update 成功路径：保存 DB + 原子写 network.json（契约字段齐全）+ 返回 desired/status。
func TestUpdateSuccess(t *testing.T) {
	h, store, dir := newTestHandler(t)
	mux := newTestMux(h, injectPrincipal) // 审计服务为 nil：不应 panic

	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	desired := data["desired"].(map[string]any)
	if desired["updated_at"] == nil || desired["ip_forward"] != true {
		t.Fatalf("desired = %v", desired)
	}

	// DB（内存仓储）已保存
	cfg, _, found, err := store.Get(context.Background(), "gw-1")
	if err != nil || !found {
		t.Fatalf("saved found=%v err=%v", found, err)
	}
	if len(cfg.Bridges) != 1 || cfg.Bridges[0].Name != "br0" || !cfg.IPForward || len(cfg.Routes) != 1 {
		t.Fatalf("saved cfg = %+v", cfg)
	}

	// network.json 契约：bridges/ip_forward/routes/updated_at
	raw, err := os.ReadFile(filepath.Join(dir, "network.json"))
	if err != nil {
		t.Fatalf("network.json 未写出: %v", err)
	}
	var file struct {
		Bridges []struct {
			Name  string   `json:"name"`
			Ports []string `json:"ports"`
		} `json:"bridges"`
		IPForward bool `json:"ip_forward"`
		Routes    []struct {
			Dst string `json:"dst"`
			Via string `json:"via"`
		} `json:"routes"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("network.json 解析: %v raw=%s", err, raw)
	}
	if len(file.Bridges) != 1 || file.Bridges[0].Name != "br0" ||
		len(file.Bridges[0].Ports) != 2 || file.Bridges[0].Ports[0] != "eth2" {
		t.Fatalf("file bridges = %+v", file.Bridges)
	}
	if !file.IPForward || len(file.Routes) != 1 ||
		file.Routes[0].Dst != "10.9.0.0/24" || file.Routes[0].Via != "192.168.50.1" {
		t.Fatalf("file = %+v", file)
	}
	if file.UpdatedAt == "" {
		t.Fatal("file updated_at 为空")
	}
}

// Update 合并系统设置 DNS/NTP 服务器：network.json 与响应 desired 含
// dns_servers/ntp_servers；空设置字段缺省不出现；设置读取失败降级为空不阻断保存；
// 非法设置原文防御性忽略。
func TestUpdateMergesServersSettings(t *testing.T) {
	readFileMap := func(t *testing.T, dir string) map[string]any {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "network.json"))
		if err != nil {
			t.Fatalf("network.json 未写出: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("network.json 解析: %v raw=%s", err, raw)
		}
		return m
	}

	// 设置非空：字段合并下发
	h, store, dir := newTestHandler(t)
	store.SetServers("223.5.5.5, 8.8.8.8", "pool.ntp.org,ntp.aliyun.com")
	mux := newTestMux(h, injectPrincipal)
	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	file := readFileMap(t, dir)
	dns, _ := file["dns_servers"].([]any)
	if len(dns) != 2 || dns[0] != "223.5.5.5" || dns[1] != "8.8.8.8" {
		t.Fatalf("file dns_servers = %v", file["dns_servers"])
	}
	ntp, _ := file["ntp_servers"].([]any)
	if len(ntp) != 2 || ntp[0] != "pool.ntp.org" || ntp[1] != "ntp.aliyun.com" {
		t.Fatalf("file ntp_servers = %v", file["ntp_servers"])
	}
	data := decodeData(t, rr)
	desired := data["desired"].(map[string]any)
	if desired["dns_servers"] == nil || desired["ntp_servers"] == nil {
		t.Fatalf("desired 缺少下发字段: %v", desired)
	}

	// dns 空串（继承宿主机）：dns_servers 不出现，ntp_servers 正常下发
	store.SetServers("", "pool.ntp.org")
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	file = readFileMap(t, dir)
	if _, ok := file["dns_servers"]; ok {
		t.Fatalf("空 dns 设置不应出现 dns_servers 字段: %v", file)
	}
	if ntp, _ := file["ntp_servers"].([]any); len(ntp) != 1 || ntp[0] != "pool.ntp.org" {
		t.Fatalf("file ntp_servers = %v", file["ntp_servers"])
	}

	// 两键均空：两字段均不出现
	store.SetServers("", "")
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	file = readFileMap(t, dir)
	if _, ok := file["dns_servers"]; ok {
		t.Fatalf("空设置不应出现 dns_servers 字段: %v", file)
	}
	if _, ok := file["ntp_servers"]; ok {
		t.Fatalf("空设置不应出现 ntp_servers 字段: %v", file)
	}

	// 设置读取失败：记日志降级，保存与下发不阻断（字段缺省）
	store.SetServers("223.5.5.5", "pool.ntp.org")
	store.SetServersErr(errors.New("db down"))
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("读取失败不应阻断保存 status=%d body=%s", rr.Code, rr.Body.String())
	}
	file = readFileMap(t, dir)
	if _, ok := file["dns_servers"]; ok {
		t.Fatalf("读取失败降级后不应出现 dns_servers 字段: %v", file)
	}

	// 设置原文非法（绕过入库校验的脏数据）：防御性忽略该键，保存成功
	store.SetServers("8.8.8.8; rm -rf /", "pool.ntp.org")
	rr = doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("非法设置原文不应阻断保存 status=%d body=%s", rr.Code, rr.Body.String())
	}
	file = readFileMap(t, dir)
	if _, ok := file["dns_servers"]; ok {
		t.Fatalf("非法 dns 原文不应下发: %v", file)
	}
	if ntp, _ := file["ntp_servers"].([]any); len(ntp) != 1 || ntp[0] != "pool.ntp.org" {
		t.Fatalf("file ntp_servers = %v", file["ntp_servers"])
	}
}

// Update 参数校验：各类非法输入一律 400（含非默认节点与未知字段）。
func TestUpdateValidation(t *testing.T) {
	h, _, _ := newTestHandler(t)
	mux := newTestMux(h, injectPrincipal)

	withMut := func(mut func(m map[string]any)) map[string]any {
		m := validBody()
		mut(m)
		return m
	}
	cases := []struct {
		name string
		body any
	}{
		{"bad bridge name", withMut(func(m map[string]any) {
			m["bridges"] = []any{map[string]any{"name": "bridge0", "ports": []any{"eth2", "eth3"}}}
		})},
		{"too few ports", withMut(func(m map[string]any) {
			m["bridges"] = []any{map[string]any{"name": "br0", "ports": []any{"eth2"}}}
		})},
		{"management port", withMut(func(m map[string]any) {
			m["bridges"] = []any{map[string]any{"name": "br0", "ports": []any{"eth0", "eth2"}}}
		})},
		{"not present port", withMut(func(m map[string]any) {
			m["bridges"] = []any{map[string]any{"name": "br0", "ports": []any{"eth1", "eth2"}}}
		})},
		{"unknown port", withMut(func(m map[string]any) {
			m["bridges"] = []any{map[string]any{"name": "br0", "ports": []any{"eth2", "eth9"}}}
		})},
		{"port in two bridges", withMut(func(m map[string]any) {
			m["bridges"] = []any{
				map[string]any{"name": "br0", "ports": []any{"eth2", "eth3"}},
				map[string]any{"name": "br1", "ports": []any{"eth3", "eth4"}},
			}
		})},
		{"bad dst", withMut(func(m map[string]any) {
			m["routes"] = []any{map[string]any{"dst": "10.9.0.0/33", "via": "192.168.50.1"}}
		})},
		{"bad via", withMut(func(m map[string]any) {
			m["routes"] = []any{map[string]any{"dst": "10.9.0.0/24", "via": "not-an-ip"}}
		})},
		{"dup dst", withMut(func(m map[string]any) {
			m["routes"] = []any{
				map[string]any{"dst": "10.9.0.0/24", "via": "192.168.50.1"},
				map[string]any{"dst": "10.9.0.0/24", "via": "192.168.50.2"},
			}
		})},
		{"non-default node", withMut(func(m map[string]any) { m["node_name"] = "gw-other" })},
		{"client updated_at rejected", withMut(func(m map[string]any) { m["updated_at"] = "2026-08-19T00:00:00Z" })},
		// dns/ntp 来源 system_settings，不接受客户端经本接口直传（未知字段 400）
		{"client dns_servers rejected", withMut(func(m map[string]any) { m["dns_servers"] = []any{"8.8.8.8"} })},
	}
	for _, tc := range cases {
		rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", tc.name, rr.Code, rr.Body.String())
		}
	}
	// 非 JSON 请求体
	req := httptest.NewRequest(http.MethodPut, "/api/v1/gateway/network-config", bytes.NewReader([]byte("{oops")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
}

// Update 边车写入失败：返回 500（DB 已保存不隐瞒），不静默吞掉。
func TestUpdateSidecarWriteFailure(t *testing.T) {
	h, store, _ := newTestHandler(t)
	// 边车目录指向常规文件之下：MkdirAll 必然失败
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.SetSidecarDir(filepath.Join(blocker, "sub"))
	mux := newTestMux(h, injectPrincipal)

	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", validBody())
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rr.Code, rr.Body.String())
	}
	// DB 已保存（响应错误信息已注明「配置已保存」）
	if _, _, found, err := store.Get(context.Background(), "gw-1"); err != nil || !found {
		t.Fatalf("失败路径 DB 未保存 found=%v err=%v", found, err)
	}
}
