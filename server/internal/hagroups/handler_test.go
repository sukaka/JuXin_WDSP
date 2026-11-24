// 主备高可用接口测试：创建/校验/更新/回切/删除全链路 + 边车契约 + 认证串纪律。
package hagroups

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeNodes 已登记网关节点集合（node-a/node-b/node-c）。
type fakeNodes map[string]bool

func (f fakeNodes) Exists(_ context.Context, nodeID string) (bool, error) { return f[nodeID], nil }

func (f fakeNodes) Names(_ context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	for _, id := range ids {
		if f[id] {
			out[id] = id // 测试环境节点名即节点 ID
		}
	}
	return out, nil
}

// fakeEnc 测试加解密（前缀可逆模拟）。
type fakeEnc struct{}

func (fakeEnc) Encrypt(p string) (string, error) { return "enc:" + p, nil }
func (fakeEnc) Decrypt(c string) (string, error) { return strings.TrimPrefix(c, "enc:"), nil }

var haPerms = []string{"ha.read", "ha.manage"}

func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range haPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newTestHandler(t *testing.T, enc Encryptor) (*Handler, *MemStore, string) {
	t.Helper()
	store := NewMemStore()
	h := NewHandler(store, fakeNodes{"node-a": true, "node-b": true, "node-c": true}, enc, nil)
	dir := t.TempDir()
	h.SetSidecarDir(dir)
	return h, store, dir
}

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal, h)
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

func validBody() map[string]any {
	return map[string]any{
		"name": "ha-main", "state": "ENABLED", "vrid": 51, "iface": "eth0",
		"vips": []string{"192.168.31.100/24"}, "preempt": false, "advert_int_ms": 1000,
		"unicast": false, "members": []map[string]any{
			{"node_id": "node-a", "priority": 120},
			{"node_id": "node-b", "priority": 100},
		},
	}
}

func readHaVipFile(t *testing.T, dir string) haVipFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "ha-vip.json"))
	if err != nil {
		t.Fatalf("ha-vip.json 未写出: %v", err)
	}
	var f haVipFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("ha-vip.json 解析: %v", err)
	}
	return f
}

// 创建全链路：DB + ha-vip.json（认证串明文下发、文件 0600）+ 响应不含明文。
func TestCreateEndToEnd(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	body := validBody()
	pass := "v1psecr8"
	body["auth_pass"] = pass
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 响应不含认证串明文
	if strings.Contains(rr.Body.String(), pass) {
		t.Fatal("响应不得包含认证串明文")
	}

	// ha-vip.json 契约：members(node+priority) + vrrp 段 + auth_pass 解密下发
	f := readHaVipFile(t, dir)
	if f.Group != "ha-main" || f.State != "ENABLED" || len(f.Members) != 2 ||
		f.VRRP.VRID != 51 || f.VRRP.VIPs[0] != "192.168.31.100/24" || f.VRRP.AuthPass != pass {
		t.Fatalf("ha-vip.json 契约不符: %+v", f)
	}
	nodeSet := map[string]int{}
	for _, m := range f.Members {
		nodeSet[m.Node] = m.Priority
	}
	if nodeSet["node-a"] != 120 || nodeSet["node-b"] != 100 {
		t.Fatalf("members 不符: %+v", f.Members)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ha-vip.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("含认证串下发文件必须 0600: %v", fi.Mode())
	}
}

// 校验：各类非法输入一律 400 且不下发。
func TestCreateValidation(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"vip 非 CIDR", func(b map[string]any) { b["vips"] = []string{"192.168.31.100"} }},
		{"成员 3 个", func(b map[string]any) {
			b["members"] = append(b["members"].([]map[string]any), map[string]any{"node_id": "node-c", "priority": 80})
		}},
		{"成员节点未登记", func(b map[string]any) {
			b["members"] = []map[string]any{{"node_id": "node-x", "priority": 120}, {"node_id": "node-b", "priority": 100}}
		}},
		{"优先级重复", func(b map[string]any) {
			b["members"] = []map[string]any{{"node_id": "node-a", "priority": 120}, {"node_id": "node-b", "priority": 120}}
		}},
		{"单播无对端地址", func(b map[string]any) { b["unicast"] = true }},
		{"认证串超长", func(b map[string]any) { b["auth_pass"] = "123456789" }},
		{"vrid 越界", func(b map[string]any) { b["vrid"] = 999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := validBody()
			tc.mutate(body)
			rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "ha-vip.json")); !os.IsNotExist(err) {
				t.Fatal("非法输入不应写 ha-vip.json")
			}
		})
	}
}

// 未装配加密服务时设置认证串 → 400（不出现明文落库）。
func TestCreateAuthWithoutEncryptor(t *testing.T) {
	h, _, _ := newTestHandler(t, nil)
	mux := newTestMux(h)
	body := validBody()
	body["auth_pass"] = "v1psecr8"
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "加密服务") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// 更新：版本冲突 409；正常更新后 ha-vip.json 跟随。
func TestUpdateAndVersionConflict(t *testing.T) {
	h, store, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %s", rr.Body.String())
	}
	groups, _ := store.List(context.Background())
	g := groups[0]

	// 过期版本 → 409
	body := validBody()
	body["version"] = g.Version + 9
	rr = doJSON(t, mux, http.MethodPatch, fmt.Sprintf("/api/v1/ha/groups/%s", g.ID), body)
	if rr.Code != http.StatusConflict {
		t.Fatalf("版本冲突应 409: %d %s", rr.Code, rr.Body.String())
	}

	// 正确版本 + 改 VIP → 下发跟随
	body["version"] = g.Version
	body["vips"] = []string{"192.168.31.200/24"}
	rr = doJSON(t, mux, http.MethodPatch, fmt.Sprintf("/api/v1/ha/groups/%s", g.ID), body)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	f := readHaVipFile(t, dir)
	if f.VRRP.VIPs[0] != "192.168.31.200/24" {
		t.Fatalf("下发未跟随: %+v", f.VRRP)
	}
}

// 人工回切：交换优先级并重新下发。
func TestFailback(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	// 从 List 接口拿组 ID
	rrList := doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups", nil)
	var rr *httptest.ResponseRecorder
	var env struct {
		Data struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rrList.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	id := env.Data.Items[0].ID

	rr = doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-b"})
	if rr.Code != http.StatusOK {
		t.Fatalf("failback: %d %s", rr.Code, rr.Body.String())
	}
	f := readHaVipFile(t, dir)
	prio := map[string]int{}
	for _, m := range f.Members {
		prio[m.Node] = m.Priority
	}
	if prio["node-b"] != 120 || prio["node-a"] != 100 {
		t.Fatalf("回切后优先级未交换: %+v", f.Members)
	}

	// 持有方未知（无状态文件）且目标已是高优先级 → 保守不变更（防重复点击漂移优先级）
	rr = doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-b"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "未做变更") {
		t.Fatalf("持有方未知时应不变更: %d %s", rr.Code, rr.Body.String())
	}
	f = readHaVipFile(t, dir)
	for _, m := range f.Members {
		if (m.Node == "node-b" && m.Priority != 120) || (m.Node == "node-a" && m.Priority != 100) {
			t.Fatalf("持有方未知时优先级不应变化: %+v", f.Members)
		}
	}
}

// writeHaVipStatus 写 havipd 运行状态文件（模拟本节点 havipd 回写）。
func writeHaVipStatus(t *testing.T, dir string, body map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ha-vip-status.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func haGroupID(t *testing.T, mux http.Handler) string {
	t.Helper()
	rrList := doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups", nil)
	var env struct {
		Data struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rrList.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Data.Items) == 0 {
		t.Fatal("无主备组")
	}
	return env.Data.Items[0].ID
}

// nopreempt 故障转移回归（MED-29）：配置 node-a=120 > node-b=100，VIP 实际在
// node-b（本节点状态 MASTER=node-b）。回切到 node-a（已是高优先级但未持有 VIP）
// 必须可执行：下调 node-b 优先级强制其重载让位，node-a 保持全组最高。
func TestFailbackNopreemptAfterFailover(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	id := haGroupID(t, mux)
	writeHaVipStatus(t, dir, map[string]any{
		"group": "ha-main", "node": "node-b", "state": "MASTER",
		"keepalived_running": true, "vips_present": []string{"192.168.31.100/24"},
	})

	// 回切到原主 node-a：可执行，node-a 保持 120，node-b 100→99（强制重载让位）
	rr := doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-a"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "强制其重载让位") {
		t.Fatalf("nopreempt 回切应可执行: %d %s", rr.Code, rr.Body.String())
	}
	f := readHaVipFile(t, dir)
	prio := map[string]int{}
	for _, m := range f.Members {
		prio[m.Node] = m.Priority
	}
	if prio["node-a"] != 120 || prio["node-b"] != 99 {
		t.Fatalf("回切后应保持目标最高、对端下调: %+v", f.Members)
	}

	// 回切到当前持有方 node-b → 幂等提示，优先级不再变化
	rr = doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-b"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "已持有 VIP，无需回切") {
		t.Fatalf("目标已持有 VIP 应幂等: %d %s", rr.Code, rr.Body.String())
	}
	f = readHaVipFile(t, dir)
	for _, m := range f.Members {
		if (m.Node == "node-a" && m.Priority != 120) || (m.Node == "node-b" && m.Priority != 99) {
			t.Fatalf("幂等回切不应变更优先级: %+v", f.Members)
		}
	}
}

// 本节点 BACKUP 且 keepalived 存活 → 推断对端持有 VIP（2 节点组健康推断）：
// 回切到本节点（已是高优先级）应可执行。
func TestFailbackHolderInferredFromLocalBackup(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	id := haGroupID(t, mux)
	writeHaVipStatus(t, dir, map[string]any{
		"group": "ha-main", "node": "node-a", "state": "BACKUP",
		"keepalived_running": true, "vips_present": []string{},
	})

	rr := doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-a"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "强制其重载让位") {
		t.Fatalf("BACKUP 推断持有方后回切应可执行: %d %s", rr.Code, rr.Body.String())
	}
	f := readHaVipFile(t, dir)
	prio := map[string]int{}
	for _, m := range f.Members {
		prio[m.Node] = m.Priority
	}
	if prio["node-a"] != 120 || prio["node-b"] != 99 {
		t.Fatalf("回切后应保持目标最高、对端下调: %+v", f.Members)
	}
}

// 状态文件过期（havipd 疑似停止）→ 持有方未知：目标已是高优先级时不变更。
func TestFailbackStaleStatusUntrusted(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	id := haGroupID(t, mux)
	writeHaVipStatus(t, dir, map[string]any{
		"group": "ha-main", "node": "node-b", "state": "MASTER",
		"keepalived_running": true, "vips_present": []string{"192.168.31.100/24"},
	})
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "ha-vip-status.json"), stale, stale); err != nil {
		t.Fatal(err)
	}

	rr := doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-a"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "未做变更") {
		t.Fatalf("状态过期应按持有方未知处理: %d %s", rr.Code, rr.Body.String())
	}
}

// 删除：ha-vip.json 删除（收回释放 VIP）+ DB 删除。
func TestDelete(t *testing.T) {
	h, store, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	groups, _ := store.List(context.Background())
	id := groups[0].ID

	rr := doJSON(t, mux, http.MethodDelete, fmt.Sprintf("/api/v1/ha/groups/%s", id), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "ha-vip.json")); !os.IsNotExist(err) {
		t.Fatal("删除组应同步删除 ha-vip.json（收回释放 VIP）")
	}
	if _, err := store.Get(context.Background(), id); err == nil {
		t.Fatal("DB 应已删除")
	}
}

func TestCreateAndUpdateRejectBridgedVRRPIface(t *testing.T) {
	h, _, _ := newTestHandler(t, fakeEnc{})
	h.SetBridgePortChecker(func(_ context.Context, nodeNames []string, iface string) (string, string, error) {
		if iface == "eth2" {
			return "node-a", "br0", nil
		}
		return "", "", nil
	})
	mux := newTestMux(h)

	// 1. 创建时使用网桥成员口 eth2 → 400
	body := validBody()
	body["iface"] = "eth2"
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("create with bridged iface status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}

	// 2. 使用非桥接口 eth0 创建成功
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create with non-bridged iface status=%d body=%s", rr.Code, rr.Body.String())
	}
	id := haGroupID(t, mux)

	// 3. 更新为网桥成员口 eth2 → 400
	upd := validBody()
	upd["iface"] = "eth2"
	upd["version"] = 1
	rr = doJSON(t, mux, http.MethodPatch, fmt.Sprintf("/api/v1/ha/groups/%s", id), upd)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("update to bridged iface status=%d body=%s, want 400", rr.Code, rr.Body.String())
	}
}
