// WDSP 页面配置网桥与路由牵引（server 侧，docs/NETWORK_MODES_DESIGN.md §七）集成测试。
//
// 覆盖：GET 默认空配置（bridges/routes 空数组、updated_at/status 为 null）、PUT 严格校验
// （MANAGEMENT 口禁入桥、成员口存在且 present、CIDR/IP 合法、仅默认节点可写）、保存落库
// node_network_configs + 原子写边车 network.json（契约字段齐全）、network-status.json
// 只读透传、审计落库（module=system / risk_level=MEDIUM）、权限矩阵
// （SYSTEM_ADMIN 读写放行，SECURITY_ADMIN 读写均 403，匿名 401）。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8NetworkConfig -count=1
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

func TestStage8NetworkConfig(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8ncc", "SYSTEM_ADMIN")
	node := env.cfg.WAF.GatewayNodeName // setupStage8Env 固定为 it-gateway-01
	sidecarDir := env.cfg.WAF.SidecarDir

	// ---------- 网口清单（校验数据源）：eth0 管理口，eth1-eth3 业务口 ----------
	ifaceStore := nodeinterfaces.NewStore(env.db)
	seenAt := time.Now().UTC()
	if err := ifaceStore.ApplySnapshot(context.Background(), node, []nodeinterfaces.SnapshotItem{
		s8IfSnapshot(node, "eth0", "TP", 1000),
		s8IfSnapshot(node, "eth1", "TP", 1000),
		s8IfSnapshot(node, "eth2", "FIBRE", 10000),
		s8IfSnapshot(node, "eth3", "FIBRE", 10000),
	}, seenAt); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}
	if err := ifaceStore.ReplaceOrder(context.Background(), node, []nodeinterfaces.OrderItem{
		{Ifname: "eth0", SortOrder: 1, Role: "MANAGEMENT"},
		{Ifname: "eth1", SortOrder: 2, Role: "TRAFFIC"},
		{Ifname: "eth2", SortOrder: 3, Role: "TRAFFIC"},
		{Ifname: "eth3", SortOrder: 4, Role: "TRAFFIC"},
	}); err != nil {
		t.Fatalf("ReplaceOrder: %v", err)
	}

	// ---------- GET 默认空配置 ----------
	result := s5OK(t, env.get(t, "/api/v1/gateway/network-config", cookies), "get default")
	desired, _ := result.Data["desired"].(map[string]interface{})
	if desired == nil {
		t.Fatalf("desired missing: %v", result.Data)
	}
	if desired["updated_at"] != nil || desired["ip_forward"] != false {
		t.Fatalf("default desired = %v", desired)
	}
	if b, ok := desired["bridges"].([]interface{}); !ok || len(b) != 0 {
		t.Fatalf("default bridges = %v, want 空数组", desired["bridges"])
	}
	if r, ok := desired["routes"].([]interface{}); !ok || len(r) != 0 {
		t.Fatalf("default routes = %v, want 空数组", desired["routes"])
	}
	if result.Data["status"] != nil {
		t.Fatalf("default status = %v, want null", result.Data["status"])
	}

	// ---------- PUT 合法配置：保存 DB + 原子写 network.json + 审计 ----------
	putBody := `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,` +
		`"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}]}`
	result = s5OK(t, env.do(t, http.MethodPut, "/api/v1/gateway/network-config", putBody, cookies, csrf), "put config")
	desired, _ = result.Data["desired"].(map[string]interface{})
	if desired["updated_at"] == nil || desired["ip_forward"] != true {
		t.Fatalf("put desired = %v", desired)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM node_network_configs WHERE node_name = $1
		   AND config->>'ip_forward' = 'true'
		   AND config->'bridges'->0->>'name' = 'br0'
		   AND config->'routes'->0->>'dst' = '10.9.0.0/24'`, node); n != 1 {
		t.Fatalf("config rows = %d, want 1", n)
	}
	// 边车 network.json 契约字段
	raw, err := os.ReadFile(filepath.Join(sidecarDir, "network.json"))
	if err != nil {
		t.Fatalf("network.json 未写出: %v", err)
	}
	var fileCfg struct {
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
	if err := json.Unmarshal(raw, &fileCfg); err != nil {
		t.Fatalf("network.json 解析: %v raw=%s", err, raw)
	}
	if len(fileCfg.Bridges) != 1 || fileCfg.Bridges[0].Name != "br0" ||
		len(fileCfg.Bridges[0].Ports) != 2 || !fileCfg.IPForward ||
		len(fileCfg.Routes) != 1 || fileCfg.Routes[0].Via != "192.168.50.1" || fileCfg.UpdatedAt == "" {
		t.Fatalf("network.json = %+v", fileCfg)
	}
	// 审计：module=system / action=update_gateway_network_config / risk_level=MEDIUM
	if n := s8Count(t, env,
		`SELECT count(*) FROM operation_audits WHERE module = 'system' AND action = 'update_gateway_network_config' AND risk_level = 'MEDIUM' AND object_id = $1`, node); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}

	// ---------- network-status.json 只读透传 ----------
	statusRaw := `{"applied_at":"2026-08-19T10:00:00Z","ok":true,"bridges":[{"name":"br0","state":"ok","message":""}],"ip_forward":"ok","routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1","state":"ok","message":""}],"message":""}`
	if err := os.WriteFile(filepath.Join(sidecarDir, "network-status.json"), []byte(statusRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	result = s5OK(t, env.get(t, "/api/v1/gateway/network-config", cookies), "get with status")
	status, _ := result.Data["status"].(map[string]interface{})
	if status == nil || status["ok"] != true || status["ip_forward"] != "ok" {
		t.Fatalf("status = %v", result.Data["status"])
	}
	// 查询非默认节点：状态属本网关共享卷，status 为 null
	result = s5OK(t, env.get(t, "/api/v1/gateway/network-config?node_name=gw-other", cookies), "get other node")
	if result.Data["status"] != nil {
		t.Fatalf("非默认节点 status = %v, want null", result.Data["status"])
	}
	// 状态文件损坏：status 降级 null，接口不报错
	if err := os.WriteFile(filepath.Join(sidecarDir, "network-status.json"), []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	result = s5OK(t, env.get(t, "/api/v1/gateway/network-config", cookies), "get broken status")
	if result.Data["status"] != nil {
		t.Fatalf("损坏状态文件 status = %v, want null", result.Data["status"])
	}

	// ---------- 参数校验（高危操作严格校验） ----------
	for name, body := range map[string]string{
		"management port":  `{"bridges":[{"name":"br0","ports":["eth0","eth2"]}]}`,
		"unknown port":     `{"bridges":[{"name":"br0","ports":["eth2","eth9"]}]}`,
		"too few ports":    `{"bridges":[{"name":"br0","ports":["eth2"]}]}`,
		"bad bridge name":  `{"bridges":[{"name":"bridge0","ports":["eth2","eth3"]}]}`,
		"dup bridge":       `{"bridges":[{"name":"br0","ports":["eth1","eth2"]},{"name":"br0","ports":["eth3","eth4"]}]}`,
		"port two bridges": `{"bridges":[{"name":"br0","ports":["eth2","eth3"]},{"name":"br1","ports":["eth3","eth1"]}]}`,
		"bad dst":          `{"routes":[{"dst":"10.9.0.0/33","via":"192.168.50.1"}]}`,
		"bad via":          `{"routes":[{"dst":"10.9.0.0/24","via":"not-an-ip"}]}`,
		"dup dst":          `{"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"},{"dst":"10.9.0.0/24","via":"192.168.50.2"}]}`,
		"non-default node": `{"node_name":"gw-other","bridges":[{"name":"br0","ports":["eth2","eth3"]}]}`,
	} {
		resp := env.do(t, http.MethodPut, "/api/v1/gateway/network-config", body, cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "put "+name)
	}

	// ---------- 权限矩阵：SECURITY_ADMIN 读/写均 403，匿名 401 ----------
	secCookies, secCSRF := env.s5Login(t, "s8nccs", "SECURITY_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/gateway/network-config", secCookies),
		http.StatusForbidden, "security_admin get")
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/gateway/network-config", putBody, secCookies, secCSRF),
		http.StatusForbidden, "security_admin put")
	s5Expect(t, env.get(t, "/api/v1/gateway/network-config", nil),
		http.StatusUnauthorized, "anonymous get")
}
