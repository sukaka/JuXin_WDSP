// 端口联动（Link-Pair）服务端测试：校验/缺省归一化、PUT 全链路
// （DB + network.json 契约 + desired 回显）。设计见 docs/HA_ACTIVE_STANDBY_DESIGN.md §6。
package netconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 校验：启用联动的桥成员口必须恰好 2 个；参数越界拒绝；零值落缺省；
// enabled=false 等价未配置（不校验成员数）。
func TestValidateLinkPair(t *testing.T) {
	cases := []struct {
		name    string
		bridge  Bridge
		wantErr string
	}{
		{
			name:    "成员口3个拒绝",
			bridge:  Bridge{Name: "br0", Ports: []string{"eth2", "eth3", "eth4"}, LinkPair: &LinkPair{Enabled: true}},
			wantErr: "恰好 2 个",
		},
		{
			name:    "hold_down_ms 越界",
			bridge:  Bridge{Name: "br0", Ports: []string{"eth2", "eth3"}, LinkPair: &LinkPair{Enabled: true, HoldDownMs: 50}},
			wantErr: "hold_down_ms 越界",
		},
		{
			name:    "hold_up_ms 越界",
			bridge:  Bridge{Name: "br0", Ports: []string{"eth2", "eth3"}, LinkPair: &LinkPair{Enabled: true, HoldUpMs: 99999}},
			wantErr: "hold_up_ms 越界",
		},
		{
			name:    "max_flaps 越界",
			bridge:  Bridge{Name: "br0", Ports: []string{"eth2", "eth3"}, LinkPair: &LinkPair{Enabled: true, MaxFlapsPerHour: 999}},
			wantErr: "max_flaps_per_hour 越界",
		},
		{
			name:   "合法零值落缺省",
			bridge: Bridge{Name: "br0", Ports: []string{"eth2", "eth3"}, LinkPair: &LinkPair{Enabled: true}},
		},
		{
			name:   "enabled=false 不校验成员数",
			bridge: Bridge{Name: "br0", Ports: []string{"eth2", "eth3", "eth4"}, LinkPair: &LinkPair{Enabled: false}},
		},
		{
			name:   "未配置 link_pair 行为不变",
			bridge: Bridge{Name: "br0", Ports: []string{"eth2", "eth3"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Bridges: []Bridge{tc.bridge}}
			err := Validate(&cfg, testIfaces())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("期望错误含 %q，实际: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			lp := cfg.Bridges[0].LinkPair
			if lp != nil && lp.Enabled {
				if lp.HoldDownMs != defaultLinkPairHoldDownMs ||
					lp.HoldUpMs != defaultLinkPairHoldUpMs ||
					lp.MaxFlapsPerHour != defaultLinkPairMaxFlaps {
					t.Fatalf("缺省值未生效: %+v", lp)
				}
			}
		})
	}
}

// PUT 全链路：link_pair 经 API → DB → network.json，缺省值落盘，desired 回显。
func TestUpdateLinkPairEndToEnd(t *testing.T) {
	h, store, dir := newTestHandler(t)
	mux := newTestMux(h, injectPrincipal)

	body := map[string]any{
		"bridges": []map[string]any{{
			"name":  "br0",
			"ports": []string{"eth2", "eth3"},
			"link_pair": map[string]any{
				"enabled":      true,
				"hold_down_ms": 2000,
			},
		}},
		"ip_forward": true,
		"routes":     []any{},
	}
	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	// desired 回显：显式 2000 保留，其余落缺省
	data := decodeData(t, rr)
	desired := data["desired"].(map[string]any)
	lp := desired["bridges"].([]any)[0].(map[string]any)["link_pair"].(map[string]any)
	if lp["enabled"] != true || lp["hold_down_ms"] != float64(2000) ||
		lp["hold_up_ms"] != float64(defaultLinkPairHoldUpMs) ||
		lp["max_flaps_per_hour"] != float64(defaultLinkPairMaxFlaps) {
		t.Fatalf("desired link_pair = %v", lp)
	}

	// DB 已保存
	cfg, _, found, err := store.Get(context.Background(), "gw-1")
	if err != nil || !found {
		t.Fatalf("saved found=%v err=%v", found, err)
	}
	if cfg.Bridges[0].LinkPair == nil || !cfg.Bridges[0].LinkPair.Enabled ||
		cfg.Bridges[0].LinkPair.HoldDownMs != 2000 {
		t.Fatalf("saved link_pair = %+v", cfg.Bridges[0].LinkPair)
	}

	// network.json 契约含 link_pair 段（netmgrd 消费）
	raw, err := os.ReadFile(filepath.Join(dir, "network.json"))
	if err != nil {
		t.Fatalf("network.json 未写出: %v", err)
	}
	var file struct {
		Bridges []struct {
			Name     string `json:"name"`
			LinkPair *struct {
				Enabled         bool `json:"enabled"`
				HoldDownMs      int  `json:"hold_down_ms"`
				HoldUpMs        int  `json:"hold_up_ms"`
				MaxFlapsPerHour int  `json:"max_flaps_per_hour"`
			} `json:"link_pair"`
		} `json:"bridges"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("network.json 解析: %v raw=%s", err, raw)
	}
	flp := file.Bridges[0].LinkPair
	if flp == nil || !flp.Enabled || flp.HoldDownMs != 2000 ||
		flp.HoldUpMs != defaultLinkPairHoldUpMs || flp.MaxFlapsPerHour != defaultLinkPairMaxFlaps {
		t.Fatalf("file link_pair = %+v", flp)
	}
}

// PUT 校验：link_pair 成员口不是 2 个时整份 400（不下发、不入库）。
func TestUpdateLinkPairReject(t *testing.T) {
	h, store, dir := newTestHandler(t)
	mux := newTestMux(h, injectPrincipal)

	body := map[string]any{
		"bridges": []map[string]any{{
			"name":      "br0",
			"ports":     []string{"eth2", "eth3", "eth4"},
			"link_pair": map[string]any{"enabled": true},
		}},
	}
	rr := doJSON(t, mux, http.MethodPut, "/api/v1/gateway/network-config", body)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, _, found, _ := store.Get(context.Background(), "gw-1"); found {
		t.Fatal("非法配置不应入库")
	}
	if _, err := os.Stat(filepath.Join(dir, "network.json")); !os.IsNotExist(err) {
		t.Fatal("非法配置不应写 network.json")
	}
}
