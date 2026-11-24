// 主备高可用接口测试：创建/校验/更新/回切/删除全链路 + 边车契约 + 认证串纪律 +
// 节点互斥 + 远端同步钩子 + 脑裂判定 + 持久化事件接口。
package hagroups

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// fakeNodes 已登记网关节点集合（node-a/node-b/node-c/node-d）。
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

// fakeRemoteSyncer 记录推送/删除调用并可按节点注入失败。
type fakeRemoteSyncer struct {
	pushed  map[string][]byte
	deleted []string
	pushErr map[string]error
	delErr  map[string]error
}

func newFakeRemoteSyncer() *fakeRemoteSyncer {
	return &fakeRemoteSyncer{
		pushed:  map[string][]byte{},
		pushErr: map[string]error{},
		delErr:  map[string]error{},
	}
}

func (f *fakeRemoteSyncer) PushHaVip(_ context.Context, nodeName string, payload []byte) error {
	if err := f.pushErr[nodeName]; err != nil {
		return err
	}
	f.pushed[nodeName] = append([]byte(nil), payload...)
	return nil
}

func (f *fakeRemoteSyncer) DeleteHaVip(_ context.Context, nodeName string) error {
	if err := f.delErr[nodeName]; err != nil {
		return err
	}
	f.deleted = append(f.deleted, nodeName)
	return nil
}

// fakeStatusProvider 模拟全量节点状态汇聚提供者。
type fakeStatusProvider struct {
	statuses map[string]NodeRuntimeStatus
	err      error
}

func (f *fakeStatusProvider) GetNodeHaVipStatuses(_ context.Context, nodeNames []string) (map[string]NodeRuntimeStatus, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]NodeRuntimeStatus{}
	for _, n := range nodeNames {
		if st, ok := f.statuses[n]; ok {
			out[n] = st
		}
	}
	return out, nil
}

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
	h := NewHandler(store, fakeNodes{"node-a": true, "node-b": true, "node-c": true, "node-d": true}, enc, nil)
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

// 创建全链路：DB + ha-vip.json（认证串明文下发、文件 0640、track_interfaces 透传）+ 响应不含明文、切片不为 null。
func TestCreateEndToEnd(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	body := validBody()
	pass := "v1p._:@+"
	body["auth_pass"] = pass
	body["track_interfaces"] = []string{"eth2", " eth3 ", "eth2"}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 响应不含认证串明文
	if strings.Contains(rr.Body.String(), pass) {
		t.Fatal("响应不得包含认证串明文")
	}
	// 非 null 切片校验（unicast_peers 未传也应输出 []）
	if !strings.Contains(rr.Body.String(), `"unicast_peers":[]`) {
		t.Fatalf("unicast_peers 应为 [] 而非 null: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"track_interfaces":["eth2","eth3"]`) {
		t.Fatalf("track_interfaces 应去重保序返回: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"sync_results":[`) {
		t.Fatalf("响应应包含 sync_results: %s", rr.Body.String())
	}

	// ha-vip.json 契约：members(node+priority) + vrrp 段 + auth_pass 解密下发 + track_interfaces
	f := readHaVipFile(t, dir)
	if f.Group != "ha-main" || f.State != "ENABLED" || len(f.Members) != 2 ||
		f.VRRP.VRID != 51 || f.VRRP.VIPs[0] != "192.168.31.100/24" || f.VRRP.AuthPass != pass {
		t.Fatalf("ha-vip.json 契约不符: %+v", f)
	}
	if len(f.VRRP.TrackInterfaces) != 2 || f.VRRP.TrackInterfaces[0] != "eth2" || f.VRRP.TrackInterfaces[1] != "eth3" {
		t.Fatalf("ha-vip.json track_interfaces 不符: %+v", f.VRRP.TrackInterfaces)
	}
	nodeSet := map[string]int{}
	for _, m := range f.Members {
		nodeSet[m.Node] = m.Priority
	}
	if nodeSet["node-a"] != 120 || nodeSet["node-b"] != 100 {
		t.Fatalf("members 不符: %+v", f.Members)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ha-vip.json")); fi.Mode().Perm() != 0o640 {
		t.Fatalf("含认证串下发文件必须 0640（同组 1000 可读，other 无权限）: %v", fi.Mode())
	}
}

// 校验：各类非法输入一律 400 且不下发。
func TestCreateValidation(t *testing.T) {
	h, _, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	tooManyTracks := make([]string, 17)
	for i := range tooManyTracks {
		tooManyTracks[i] = fmt.Sprintf("eth%d", i+1)
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"vip 非 CIDR", func(b map[string]any) { b["vips"] = []string{"192.168.31.100"} }},
		{"vip IPv6 拒绝", func(b map[string]any) { b["vips"] = []string{"fd00::1/64"} }},
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
		{"认证串含空格", func(b map[string]any) { b["auth_pass"] = "ab cd" }},
		{"认证串含换行", func(b map[string]any) { b["auth_pass"] = "ab\ncd" }},
		{"认证串含大括号", func(b map[string]any) { b["auth_pass"] = "ab{cd}" }},
		{"认证串含井号注释符", func(b map[string]any) { b["auth_pass"] = "ab#cd" }},
		{"认证串含感叹号", func(b map[string]any) { b["auth_pass"] = "ab!cd" }},
		{"认证串含引号", func(b map[string]any) { b["auth_pass"] = `ab"cd` }},
		{"认证串含反斜杠", func(b map[string]any) { b["auth_pass"] = `ab\cd` }},
		{"advert_int_ms 小于 1000", func(b map[string]any) { b["advert_int_ms"] = 500 }},
		{"advert_int_ms 非整秒", func(b map[string]any) { b["advert_int_ms"] = 1500 }},
		{"advert_int_ms 超过 10000", func(b map[string]any) { b["advert_int_ms"] = 11000 }},
		{"vrid 越界", func(b map[string]any) { b["vrid"] = 999 }},
		{"track_interfaces 与 iface 相同", func(b map[string]any) { b["track_interfaces"] = []string{"eth0"} }},
		{"track_interfaces 非法接口名", func(b map[string]any) { b["track_interfaces"] = []string{"eth2\nprio"} }},
		{"track_interfaces 超上限 16", func(b map[string]any) { b["track_interfaces"] = tooManyTracks }},
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

func TestMarshalStringSliceNeverNull(t *testing.T) {
	raw, err := marshalStringSlice(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("nil 切片应序列化为 [], got %s", string(raw))
	}
}

func TestIsNodeUniqueViolation(t *testing.T) {
	if !isNodeUniqueViolation(&pgconn.PgError{Code: "23505", ConstraintName: "uq_ha_group_members_node_id"}) {
		t.Fatal("应识别 uq_ha_group_members_node_id 唯一约束冲突")
	}
	if !isNodeUniqueViolation(&pgconn.PgError{Code: "23505", Detail: "Key (node_id)=(xxx) already exists."}) {
		t.Fatal("应识别 (node_id) Detail 唯一冲突")
	}
	if isNodeUniqueViolation(&pgconn.PgError{Code: "23505", ConstraintName: "ha_groups_name_key"}) {
		t.Fatal("组名唯一冲突不应误判为节点冲突")
	}
	if isNodeUniqueViolation(errors.New("other error")) {
		t.Fatal("普通错误不应匹配")
	}
}

// 节点互斥校验：同一节点归属第二组 → 409 Conflict（创建与更新路径均拦截）。
func TestMemberNodeExclusivityConflict(t *testing.T) {
	h, _, _ := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create group1: %d %s", rr.Code, rr.Body.String())
	}

	// 创建第二组复用 node-b → 409
	body2 := validBody()
	body2["name"] = "ha-second"
	body2["vrid"] = 52
	body2["members"] = []map[string]any{
		{"node_id": "node-b", "priority": 120},
		{"node_id": "node-c", "priority": 100},
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body2)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "已归属其他主备组") {
		t.Fatalf("节点互斥应返回 409: %d %s", rr.Code, rr.Body.String())
	}

	// 使用不重叠的 [node-c, node-d] 创建成功
	body2["members"] = []map[string]any{
		{"node_id": "node-c", "priority": 120},
		{"node_id": "node-d", "priority": 100},
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body2)
	if rr.Code != http.StatusOK {
		t.Fatalf("create group2 with disjoint nodes: %d %s", rr.Code, rr.Body.String())
	}
	var env struct {
		Data struct {
			Group struct {
				ID string `json:"id"`
			} `json:"group"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}

	// 更新第二组试图抢占 node-a → 409
	body2["version"] = 1
	body2["members"] = []map[string]any{
		{"node_id": "node-a", "priority": 120},
		{"node_id": "node-d", "priority": 100},
	}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/ha/groups/"+env.Data.Group.ID, body2)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "已归属其他主备组") {
		t.Fatalf("更新抢占节点应返回 409: %d %s", rr.Code, rr.Body.String())
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

// 人工回切：交换优先级并重新下发，且落库 FAILBACK 事件。
func TestFailback(t *testing.T) {
	h, store, dir := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	id := haGroupID(t, mux)

	rr := doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
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
	evs, total, err := store.ListEvents(context.Background(), EventFilter{EventType: EventTypeFailback})
	if err != nil || total != 1 || evs[0].GroupID != id || evs[0].NodeName != "node-b" {
		t.Fatalf("回切应落库 FAILBACK 事件: total=%d evs=%+v err=%v", total, evs, err)
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

// 远端状态汇聚 + 独立管理面节点场景：无本机状态文件时仍可精准识别 VIP 持有方并完成回切与远端下发。
func TestFailbackViaNodeStatusProviderAndRemoteSyncer(t *testing.T) {
	h, store, dir := newTestHandler(t, fakeEnc{})
	syncer := newFakeRemoteSyncer()
	now := time.Now().UTC()
	freshAt := now.Add(-2 * time.Second)
	provider := &fakeStatusProvider{
		statuses: map[string]NodeRuntimeStatus{
			"node-a": {
				NodeName:  "node-a",
				Status:    json.RawMessage(`{"group":"ha-main","node":"node-a","state":"BACKUP","keepalived_running":true,"vips_present":[]}`),
				UpdatedAt: &freshAt,
			},
			"node-b": {
				NodeName:  "node-b",
				Status:    json.RawMessage(`{"group":"ha-main","node":"node-b","state":"MASTER","keepalived_running":true,"vips_present":["192.168.31.100/24"]}`),
				UpdatedAt: &freshAt,
			},
		},
	}
	h.SetLocalNodeName("mgmt-node").SetRemoteSyncer(syncer).SetNodeStatusProvider(provider)
	h.now = func() time.Time { return now }
	mux := newTestMux(h)

	// 创建：mgmt-node 不是成员 → 不写本机 ha-vip.json，只推送远端 node-a 与 node-b
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "ha-vip.json")); !os.IsNotExist(err) {
		t.Fatal("管理面非组成员时不应写本机 ha-vip.json")
	}
	if len(syncer.pushed["node-a"]) == 0 || len(syncer.pushed["node-b"]) == 0 {
		t.Fatalf("应推送全部远端成员: pushed=%v", syncer.pushed)
	}

	id := haGroupID(t, mux)
	// 回切到 node-a：虽无本机状态文件，但 provider 确认 node-b 持有 VIP → 触发微调 100→99
	rr = doJSON(t, mux, http.MethodPost, fmt.Sprintf("/api/v1/ha/groups/%s/failback", id),
		map[string]string{"node_id": "node-a"})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "强制其重载让位") {
		t.Fatalf("远端状态汇聚回切失败: %d %s", rr.Code, rr.Body.String())
	}
	var pushed haVipFile
	if err := json.Unmarshal(syncer.pushed["node-b"], &pushed); err != nil {
		t.Fatal(err)
	}
	prio := map[string]int{}
	for _, m := range pushed.Members {
		prio[m.Node] = m.Priority
	}
	if prio["node-a"] != 120 || prio["node-b"] != 99 {
		t.Fatalf("远端下发优先级不符: %+v", pushed.Members)
	}
	evs, total, _ := store.ListEvents(context.Background(), EventFilter{GroupID: id, EventType: EventTypeFailback})
	if total != 1 || evs[0].Detail["previous_holder"] != "node-b" {
		t.Fatalf("FAILBACK 事件应记录原持有方: total=%d evs=%+v", total, evs)
	}
}

// 远端同步与防误删：本机属于 group1 时，创建/删除 group2 不得影响本机 ha-vip.json；远端失败记录 SYNC_FAILED。
func TestRemoteSyncAndSafeDelete(t *testing.T) {
	h, store, dir := newTestHandler(t, fakeEnc{})
	syncer := newFakeRemoteSyncer()
	h.SetLocalNodeName("node-a").SetRemoteSyncer(syncer)
	mux := newTestMux(h)

	// 1. 创建 group1 [node-a, node-b]：写本机 + 推 node-b（不重复推本机 node-a）
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create group1: %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := syncer.pushed["node-a"]; ok {
		t.Fatal("本机节点不应重复经 RemoteSyncer 推送")
	}
	if len(syncer.pushed["node-b"]) == 0 {
		t.Fatal("远端节点 node-b 应收到推送")
	}

	// 2. 创建 group2 [node-c, node-d]（node-d 注入失败）：不得覆写本机 ha-vip.json，返回 sync_results 且落库 SYNC_FAILED
	syncer.pushErr["node-d"] = errors.New("dial tcp timeout")
	body2 := validBody()
	body2["name"] = "ha-second"
	body2["vrid"] = 52
	body2["members"] = []map[string]any{
		{"node_id": "node-c", "priority": 120},
		{"node_id": "node-d", "priority": 100},
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", body2)
	if rr.Code != http.StatusOK {
		t.Fatalf("create group2: %d %s", rr.Code, rr.Body.String())
	}
	f := readHaVipFile(t, dir)
	if f.Group != "ha-main" {
		t.Fatalf("本机 ha-vip.json 不得被无关组覆写: got %s", f.Group)
	}
	if !strings.Contains(rr.Body.String(), `"status":"FAILED"`) || !strings.Contains(rr.Body.String(), "dial tcp timeout") {
		t.Fatalf("响应 sync_results 应报告远端失败详情: %s", rr.Body.String())
	}
	evs, total, _ := store.ListEvents(context.Background(), EventFilter{NodeName: "node-d", EventType: EventTypeSyncFailed})
	if total != 1 || evs[0].GroupName != "ha-second" {
		t.Fatalf("远端同步失败应落库 SYNC_FAILED 事件: total=%d evs=%+v", total, evs)
	}

	// 3. 删除 group2：不得误删本机 ha-vip.json，同时通知远端 node-c / node-d 删除
	var env2 struct {
		Data struct {
			Group struct {
				ID string `json:"id"`
			} `json:"group"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env2); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/ha/groups/"+env2.Data.Group.ID, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete group2: %d %s", rr.Code, rr.Body.String())
	}
	if f := readHaVipFile(t, dir); f.Group != "ha-main" {
		t.Fatalf("删除无关组后本机 ha-vip.json 必须完好: got %s", f.Group)
	}
	deletedSet := map[string]bool{}
	for _, n := range syncer.deleted {
		deletedSet[n] = true
	}
	if !deletedSet["node-c"] || !deletedSet["node-d"] {
		t.Fatalf("删除 group2 应通知远端成员收回: deleted=%v", syncer.deleted)
	}

	// 4. 更新 group1 把成员从 node-b 换成 node-c：应收回旧成员 node-b 的远端 ha-vip.json
	groups, _ := store.List(context.Background())
	g1 := groups[0]
	upd := validBody()
	upd["version"] = g1.Version
	upd["members"] = []map[string]any{
		{"node_id": "node-a", "priority": 120},
		{"node_id": "node-c", "priority": 100},
	}
	syncer.deleted = nil
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/ha/groups/"+g1.ID, upd)
	if rr.Code != http.StatusOK {
		t.Fatalf("update group1: %d %s", rr.Code, rr.Body.String())
	}
	if len(syncer.deleted) != 1 || syncer.deleted[0] != "node-b" {
		t.Fatalf("更新移除旧成员 node-b 时应调用 DeleteHaVip 收回: deleted=%v", syncer.deleted)
	}
}

// List/Get 返回 node_statuses 与 split_brain（双 MASTER / 双持 VIP 触发，过期状态不误报）。
func TestListAndGetSplitBrainDetection(t *testing.T) {
	h, _, _ := newTestHandler(t, fakeEnc{})
	now := time.Now().UTC()
	freshAt := now.Add(-5 * time.Second)
	staleAt := now.Add(-2 * time.Minute)
	provider := &fakeStatusProvider{statuses: map[string]NodeRuntimeStatus{}}
	h.SetNodeStatusProvider(provider)
	h.now = func() time.Time { return now }
	mux := newTestMux(h)

	doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", validBody())
	id := haGroupID(t, mux)

	// 1. 正常一主一备 → split_brain=false
	provider.statuses["node-a"] = NodeRuntimeStatus{
		NodeName:  "node-a",
		Status:    json.RawMessage(`{"group":"ha-main","node":"node-a","state":"MASTER","keepalived_running":true,"vips_present":["192.168.31.100/24"]}`),
		UpdatedAt: &freshAt,
	}
	provider.statuses["node-b"] = NodeRuntimeStatus{
		NodeName:  "node-b",
		Status:    json.RawMessage(`{"group":"ha-main","node":"node-b","state":"BACKUP","keepalived_running":true,"vips_present":[]}`),
		UpdatedAt: &freshAt,
	}
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups/"+id, nil)
	var getEnv struct {
		Data struct {
			NodeStatuses map[string]NodeRuntimeStatus `json:"node_statuses"`
			SplitBrain   bool                         `json:"split_brain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &getEnv); err != nil {
		t.Fatal(err)
	}
	if getEnv.Data.SplitBrain || len(getEnv.Data.NodeStatuses) != 2 || !getEnv.Data.NodeStatuses["node-a"].Fresh {
		t.Fatalf("正常主备不应报脑裂: %+v", getEnv.Data)
	}

	// 2. 双节点新鲜 MASTER → Get 与 List 均返回 split_brain=true
	provider.statuses["node-b"] = NodeRuntimeStatus{
		NodeName:  "node-b",
		Status:    json.RawMessage(`{"group":"ha-main","node":"node-b","state":"MASTER","keepalived_running":true,"vips_present":["192.168.31.100/24"]}`),
		UpdatedAt: &freshAt,
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups/"+id, nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &getEnv); err != nil {
		t.Fatal(err)
	}
	if !getEnv.Data.SplitBrain {
		t.Fatalf("双 MASTER 应返回 split_brain=true: %s", rr.Body.String())
	}
	rrList := doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups", nil)
	if !strings.Contains(rrList.Body.String(), `"split_brain":true`) {
		t.Fatalf("List 双 MASTER 应返回 split_brain=true: %s", rrList.Body.String())
	}

	// 3. 其中一节点状态过期（>30s）→ split_brain=false
	provider.statuses["node-b"] = NodeRuntimeStatus{
		NodeName:  "node-b",
		Status:    json.RawMessage(`{"group":"ha-main","node":"node-b","state":"MASTER","keepalived_running":true,"vips_present":["192.168.31.100/24"]}`),
		UpdatedAt: &staleAt,
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/ha/groups/"+id, nil)
	if err := json.Unmarshal(rr.Body.Bytes(), &getEnv); err != nil {
		t.Fatal(err)
	}
	if getEnv.Data.SplitBrain || getEnv.Data.NodeStatuses["node-b"].Fresh {
		t.Fatalf("过期状态不应触发脑裂: %+v", getEnv.Data)
	}
}

// GET /api/v1/ha/events 分页与多条件筛选测试。
func TestListEventsEndpoint(t *testing.T) {
	h, store, _ := newTestHandler(t, fakeEnc{})
	mux := newTestMux(h)

	gid1 := uuid.New().String()
	gid2 := uuid.New().String()
	t0 := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	_ = store.RecordEvent(context.Background(), HaEvent{GroupID: gid1, GroupName: "g1", NodeName: "node-a", EventType: EventTypeVIPTransition, Detail: map[string]any{"to": "MASTER"}, OccurredAt: t0})
	_ = store.RecordEvent(context.Background(), HaEvent{GroupID: gid1, GroupName: "g1", NodeName: "node-b", EventType: EventTypeFailback, Detail: map[string]any{"op": "swap"}, OccurredAt: t0.Add(time.Minute)})
	_ = store.RecordEvent(context.Background(), HaEvent{GroupID: gid2, GroupName: "g2", NodeName: "node-c", EventType: EventTypeSplitBrain, Detail: map[string]any{"nodes": 2}, OccurredAt: t0.Add(2 * time.Minute)})

	// 全量分页查询（倒序，page_size=2）
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/ha/events?page=1&page_size=2", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list events: %d %s", rr.Code, rr.Body.String())
	}
	var pageEnv struct {
		Data struct {
			Items    []HaEvent `json:"items"`
			Page     int       `json:"page"`
			PageSize int       `json:"page_size"`
			Total    int64     `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pageEnv); err != nil {
		t.Fatal(err)
	}
	if pageEnv.Data.Total != 3 || len(pageEnv.Data.Items) != 2 || pageEnv.Data.Items[0].EventType != EventTypeSplitBrain {
		t.Fatalf("分页/倒序结果不符: %+v", pageEnv.Data)
	}

	// 按 group_id + node_name + event_type 精确过滤
	rr = doJSON(t, mux, http.MethodGet, fmt.Sprintf("/api/v1/ha/events?group_id=%s&node_name=node-b&event_type=%s", gid1, EventTypeFailback), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("filter events: %d %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pageEnv); err != nil {
		t.Fatal(err)
	}
	if pageEnv.Data.Total != 1 || len(pageEnv.Data.Items) != 1 || pageEnv.Data.Items[0].NodeName != "node-b" {
		t.Fatalf("过滤结果不符: %+v", pageEnv.Data)
	}

	// 非法 group_id / 非法 page → 400
	if rr := doJSON(t, mux, http.MethodGet, "/api/v1/ha/events?group_id=not-a-uuid", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 group_id 应 400: %d", rr.Code)
	}
	if rr := doJSON(t, mux, http.MethodGet, "/api/v1/ha/events?page=0", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 page 应 400: %d", rr.Code)
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

	// 2. 使用非桥接口 eth0 创建成功（且允许将网桥口 eth2 放入 track_interfaces）
	okBody := validBody()
	okBody["track_interfaces"] = []string{"eth2"}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/ha/groups", okBody)
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
