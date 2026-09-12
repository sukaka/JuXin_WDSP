// WDSP 阶段A 网口管理（server 侧）集成测试。
//
// 覆盖：采集器经快照文件 → 真实 PG UPSERT 入库（含消失口 present=false、新口排末尾、
// 用户 sort_order/role 保留）、GET 分组查询与 node_name 过滤、PUT 排序/角色整体替换、
// 参数校验 400、审计落库（module=system / risk_level=LOW）、权限矩阵
// （SYSTEM_ADMIN 读写放行，SECURITY_ADMIN 读写均 403）。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8NodeInterfaces -count=1
package tests

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

// s8IfSnapshot 造一条快照行（字段与网关 node-interfaces.jsonl 输出一致）。
func s8IfSnapshot(node, ifname, media string, speed int64) nodeinterfaces.SnapshotItem {
	return nodeinterfaces.SnapshotItem{
		NodeName: node, Ifname: ifname, MAC: "00:11:22:33:44:" + ifname[len(ifname)-1:],
		PCIPath: "0000:03:00." + ifname[len(ifname)-1:], Driver: "igb",
		MediaType: media, LinkSpeed: speed, Operstate: "up",
		CollectedAt: time.Now().UTC(),
	}
}

func TestStage8NodeInterfaces(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8ifc", "SYSTEM_ADMIN")
	kw := "s8n" + s5Rand()
	node := "gw-" + kw

	// ---------- 采集链路：快照文件 → collector → 真实 PG ----------
	logPath := filepath.Join(t.TempDir(), "node-interfaces.jsonl")
	collected := time.Date(2026, 8, 17, 10, 0, 0, 0, time.UTC)
	snapshot := strings.Join([]string{
		`{"node_name":"` + node + `","ifname":"eth0","mac":"00:11:22:33:44:00","pci_path":"0000:03:00.0","driver":"igb","media_type":"TP","link_speed":1000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"` + node + `","ifname":"eth1","mac":"00:11:22:33:44:01","pci_path":"0000:03:00.1","driver":"ixgbe","media_type":"FIBRE","link_speed":10000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"` + node + `","ifname":"eth2","mac":"00:11:22:33:44:02","pci_path":"0000:03:00.2","driver":"ixgbe","media_type":"FIBRE","link_speed":10000,"operstate":"down","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(snapshot), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := nodeinterfaces.NewCollector(nodeinterfaces.NewStore(env.db), "it-iface-01", logPath)
	if _, err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM gateway_node_interfaces WHERE node_name = $1 AND present`, node); n != 3 {
		t.Fatalf("collected rows = %d, want 3", n)
	}

	// ---------- GET 分组查询 + 排序 ----------
	result := s5OK(t, env.get(t, "/api/v1/gateway/interfaces?node_name="+node, cookies), "list interfaces")
	nodes, _ := result.Data["nodes"].([]interface{})
	if len(nodes) != 1 {
		t.Fatalf("nodes = %v", nodes)
	}
	ifaces, _ := nodes[0].(map[string]interface{})["interfaces"].([]interface{})
	if len(ifaces) != 3 {
		t.Fatalf("interfaces = %v", ifaces)
	}
	for i, want := range []string{"eth0", "eth1", "eth2"} {
		if ifaces[i].(map[string]interface{})["ifname"] != want {
			t.Fatalf("interfaces[%d] = %v, want %s", i, ifaces[i], want)
		}
	}
	if ifaces[0].(map[string]interface{})["media_type"] != "TP" ||
		ifaces[1].(map[string]interface{})["media_type"] != "FIBRE" {
		t.Fatalf("media_type = %v/%v", ifaces[0], ifaces[1])
	}
	// 不过滤时该节点也在分组内
	result = s5OK(t, env.get(t, "/api/v1/gateway/interfaces", cookies), "list all nodes")
	found := false
	for _, nd := range result.Data["nodes"].([]interface{}) {
		if nd.(map[string]interface{})["node_name"] == node {
			found = true
		}
	}
	if !found {
		t.Fatalf("node %s not in unfiltered list", node)
	}

	// ---------- PUT 整体替换排序 + 角色 ----------
	putBody := `{"node_name":"` + node + `","items":[
	  {"ifname":"eth2","sort_order":1,"role":"TRAFFIC"},
	  {"ifname":"eth0","sort_order":2,"role":"MANAGEMENT"},
	  {"ifname":"eth1","sort_order":3,"role":""}
	]}`
	result = s5OK(t, env.do(t, http.MethodPut, "/api/v1/gateway/interfaces/order", putBody, cookies, csrf), "put order")
	nodes, _ = result.Data["nodes"].([]interface{})
	ifaces, _ = nodes[0].(map[string]interface{})["interfaces"].([]interface{})
	for i, want := range []string{"eth2", "eth0", "eth1"} {
		if ifaces[i].(map[string]interface{})["ifname"] != want {
			t.Fatalf("after put interfaces[%d] = %v, want %s", i, ifaces[i], want)
		}
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM gateway_node_interfaces WHERE node_name = $1 AND ifname = 'eth2' AND sort_order = 1 AND role = 'TRAFFIC'`, node); n != 1 {
		t.Fatal("eth2 sort_order/role 未落库")
	}
	// 审计：module=system / action=update_gateway_interface_order / risk_level=LOW
	if n := s8Count(t, env,
		`SELECT count(*) FROM operation_audits WHERE module = 'system' AND action = 'update_gateway_interface_order' AND risk_level = 'LOW' AND object_id = $1`, node); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}

	// ---------- 第二轮快照：eth1 消失保留 present=false、eth3 新口排末尾、用户设定不被覆盖 ----------
	snapshot2 := strings.Join([]string{
		`{"node_name":"` + node + `","ifname":"eth2","mac":"00:11:22:33:44:02","pci_path":"0000:03:00.2","driver":"ixgbe","media_type":"FIBRE","link_speed":10000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"` + node + `","ifname":"eth0","mac":"00:11:22:33:44:00","pci_path":"0000:03:00.0","driver":"igb","media_type":"TP","link_speed":1000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
		`{"node_name":"` + node + `","ifname":"eth3","mac":"00:11:22:33:44:03","pci_path":"0000:03:00.3","driver":"i40e","media_type":"FIBRE","link_speed":25000,"operstate":"up","collected_at":"` + collected.Format(time.RFC3339Nano) + `"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(snapshot2), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("collect round2: %v", err)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM gateway_node_interfaces WHERE node_name = $1 AND ifname = 'eth1' AND NOT present`, node); n != 1 {
		t.Fatal("eth1 消失未标注 present=false")
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM gateway_node_interfaces WHERE node_name = $1 AND ifname = 'eth2' AND sort_order = 1 AND role = 'TRAFFIC'`, node); n != 1 {
		t.Fatal("采集覆盖了用户 sort_order/role")
	}
	// 新口 eth3 排在末尾（sort_order 大于所有已有口）
	if n := s8Count(t, env,
		`SELECT count(*) FROM gateway_node_interfaces n1 WHERE n1.node_name = $1 AND n1.ifname = 'eth3'
		   AND n1.sort_order > (SELECT max(n2.sort_order) FROM gateway_node_interfaces n2
		                        WHERE n2.node_name = $1 AND n2.ifname <> 'eth3')`, node); n != 1 {
		t.Fatal("新口 eth3 未排末尾")
	}

	// ---------- 参数校验 ----------
	for name, body := range map[string]string{
		"missing node_name": `{"items":[{"ifname":"eth0","sort_order":1,"role":""}]}`,
		"empty items":       `{"node_name":"` + node + `","items":[]}`,
		"dup ifname":        `{"node_name":"` + node + `","items":[{"ifname":"eth0","sort_order":1,"role":""},{"ifname":"eth0","sort_order":2,"role":""}]}`,
		"unknown ifname":    `{"node_name":"` + node + `","items":[{"ifname":"eth9","sort_order":1,"role":""}]}`,
		"negative order":    `{"node_name":"` + node + `","items":[{"ifname":"eth0","sort_order":-1,"role":""}]}`,
		"invalid role":      `{"node_name":"` + node + `","items":[{"ifname":"eth0","sort_order":1,"role":"admin"}]}`,
	} {
		resp := env.do(t, http.MethodPut, "/api/v1/gateway/interfaces/order", body, cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "put "+name)
	}

	// ---------- 权限矩阵：SECURITY_ADMIN 读/写均 403 ----------
	secCookies, secCSRF := env.s5Login(t, "s8ifcs", "SECURITY_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/gateway/interfaces?node_name="+node, secCookies),
		http.StatusForbidden, "security_admin list")
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/gateway/interfaces/order", putBody, secCookies, secCSRF),
		http.StatusForbidden, "security_admin put")
	// 未登录 401
	s5Expect(t, env.get(t, "/api/v1/gateway/interfaces", nil),
		http.StatusUnauthorized, "anonymous list")
}
