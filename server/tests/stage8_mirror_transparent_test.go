// 镜像/透明部署模式产品化（server 侧）集成测试
// （docs/NETWORK_MODES_DESIGN.md §4.2/§4.3，迁移 000064）。
//
// 覆盖：
//   - API 创建/详情/列表的 MIRROR/TRANSPARENT deployment_mode 往返与落库；
//   - CHECK 约束放行 MIRROR/TRANSPARENT、拦截词表外取值（绕过应用层直写验证）；
//   - 生成器链路（与发布同一 Generate 入口）：MIRROR 应用不产生内联站点路由，
//     TRANSPARENT/REVERSE_PROXY 应用照常；
//   - mirrorcap 边车配置接口来源：nodeinterfaces ListMirrorInterfaces 仅返回
//     该节点 role=MIRROR 且 present 的接口名（sort_order 升序）。
//
// 边车配置文件内容（mirrorcap.json/tproxyd.json 的 enabled 翻转、端口来源、原子写）
// 由 server/internal/gatewayconfig/sidecars_test.go 单测覆盖；完整发布到活网关的
// 端到端验证需 docker compose 实验室环境，不在本 Go 集成测试范围。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8MirrorTransparent -count=1
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

func TestStage8MirrorTransparent(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8mt", "SECURITY_ADMIN")
	kw := "s8mt" + s5Rand()

	// ---------- 创建 MIRROR / TRANSPARENT 应用：放行且落库 ----------
	resp := env.post(t, "/api/v1/applications",
		`{"code":"`+kw+`-mir","name":"镜像旁路","deployment_mode":"MIRROR"}`, cookies, csrf)
	result := s5OK(t, resp, "create MIRROR app")
	if got := result.Data["deployment_mode"]; got != "MIRROR" {
		t.Fatalf("create MIRROR deployment_mode = %v", got)
	}
	mirID, _ := result.Data["id"].(string)

	resp = env.post(t, "/api/v1/applications",
		`{"code":"`+kw+`-tpx","name":"透明串接","deployment_mode":"TRANSPARENT"}`, cookies, csrf)
	result = s5OK(t, resp, "create TRANSPARENT app")
	if got := result.Data["deployment_mode"]; got != "TRANSPARENT" {
		t.Fatalf("create TRANSPARENT deployment_mode = %v", got)
	}
	tpxID, _ := result.Data["id"].(string)

	for id, mode := range map[string]string{mirID: "MIRROR", tpxID: "TRANSPARENT"} {
		if n := s8Count(t, env,
			`SELECT count(*) FROM applications WHERE id = $1 AND deployment_mode = $2`, id, mode); n != 1 {
			t.Fatalf("%s 未落库", mode)
		}
		// 详情回读
		result = s5OK(t, env.get(t, "/api/v1/applications/"+id, cookies), "get "+mode+" app")
		if got := result.Data["deployment_mode"]; got != mode {
			t.Fatalf("detail deployment_mode = %v, want %s", got, mode)
		}
	}

	// ---------- 列表携带两种新模式 ----------
	result = s5OK(t, env.get(t, "/api/v1/applications?keyword="+kw, cookies), "list apps")
	items, _ := result.Data["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("list items = %d, want 2", len(items))
	}
	for _, it := range items {
		m := it.(map[string]interface{})
		code, _ := m["code"].(string)
		want := "MIRROR"
		if strings.HasSuffix(code, "-tpx") {
			want = "TRANSPARENT"
		}
		if got := m["deployment_mode"]; got != want {
			t.Fatalf("list item %s deployment_mode = %v, want %s", code, got, want)
		}
	}

	// ---------- CHECK 约束（000064）：词表内直写放行、词表外拦截 ----------
	if _, err := env.db.Exec(context.Background(),
		`UPDATE applications SET deployment_mode = 'ROUTED' WHERE id = $1`, mirID); err != nil {
		t.Fatalf("CHECK 约束应放行词表内取值: %v", err)
	}
	if _, err := env.db.Exec(context.Background(),
		`UPDATE applications SET deployment_mode = 'MIRROR' WHERE id = $1`, mirID); err != nil {
		t.Fatalf("CHECK 约束应放行 MIRROR: %v", err)
	}
	if _, err := env.db.Exec(context.Background(),
		`UPDATE applications SET deployment_mode = 'BRIDGE' WHERE id = $1`, mirID); err == nil {
		t.Fatal("CHECK 约束未拦截词表外 deployment_mode")
	}

	// ---------- 域名挂载（镜像口 8081 / 透明口 8082） ----------
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", mirID),
		`{"hostname":"`+kw+`-mir.example.com","is_primary":true,"http_enabled":true,"http_port":8081}`, cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "add MIRROR app domain")
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", tpxID),
		`{"hostname":"`+kw+`-tpx.example.com","is_primary":true,"http_enabled":true,"http_port":8082}`, cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "add TRANSPARENT app domain")

	// ---------- 生成器链路（发布同一 Generate 入口）：MIRROR 无内联路由、TRANSPARENT 照常 ----------
	appStore := applications.NewStore(env.db)
	buildAppData := func(id string) gatewayconfig.AppData {
		uid, err := uuid.Parse(id)
		if err != nil {
			t.Fatal(err)
		}
		a, err := appStore.GetByID(context.Background(), uid)
		if err != nil {
			t.Fatal(err)
		}
		domains, err := appStore.ListDomains(context.Background(), uid)
		if err != nil {
			t.Fatal(err)
		}
		upstreams, err := appStore.ListUpstreams(context.Background(), uid)
		if err != nil {
			t.Fatal(err)
		}
		return gatewayconfig.AppData{
			AppID: a.ID.String(), Code: a.Code, ProtectionMode: a.ProtectionMode,
			DeploymentMode: a.DeploymentMode, Domains: domains, Upstreams: upstreams,
		}
	}
	gen, err := gatewayconfig.Generate(gatewayconfig.GenerateInput{
		Apps:        []gatewayconfig.AppData{buildAppData(mirID), buildAppData(tpxID)},
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(gen.JSON, kw+"-mir.example.com") {
		t.Fatal("MIRROR 应用不应生成内联站点路由")
	}
	if !strings.Contains(gen.JSON, kw+"-tpx.example.com") {
		t.Fatal("TRANSPARENT 应用应照常生成内联站点路由")
	}

	// ---------- mirrorcap 边车接口来源：仅 role=MIRROR 且 present，按 sort_order ----------
	ifaceStore := nodeinterfaces.NewStore(env.db)
	node := "gw-" + kw
	seenAt := time.Now().UTC()
	if err := ifaceStore.ApplySnapshot(context.Background(), node, []nodeinterfaces.SnapshotItem{
		s8IfSnapshot(node, "eth0", "TP", 1000),
		s8IfSnapshot(node, "eth1", "FIBRE", 10000),
		s8IfSnapshot(node, "eth2", "FIBRE", 25000),
	}, seenAt); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if err := ifaceStore.ReplaceOrder(context.Background(), node, []nodeinterfaces.OrderItem{
		{Ifname: "eth2", SortOrder: 1, Role: "MIRROR"},
		{Ifname: "eth0", SortOrder: 2, Role: "TRAFFIC"},
		{Ifname: "eth1", SortOrder: 3, Role: "MIRROR"},
	}); err != nil {
		t.Fatalf("ReplaceOrder: %v", err)
	}
	// eth1 在下一轮快照中消失（present=false），不得再作为镜像口来源
	if err := ifaceStore.ApplySnapshot(context.Background(), node, []nodeinterfaces.SnapshotItem{
		s8IfSnapshot(node, "eth0", "TP", 1000),
		s8IfSnapshot(node, "eth2", "FIBRE", 25000),
	}, seenAt.Add(time.Minute)); err != nil {
		t.Fatalf("ApplySnapshot round2: %v", err)
	}
	ifaces, err := ifaceStore.ListMirrorInterfaces(context.Background(), node)
	if err != nil {
		t.Fatalf("ListMirrorInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0] != "eth2" {
		t.Fatalf("ListMirrorInterfaces = %v, want [eth2]（eth1 已消失、eth0 非 MIRROR）", ifaces)
	}
}
