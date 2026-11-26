package settings

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestXDPAccelerationSettingsValidation(t *testing.T) {
	// 确认 xdp_acceleration 组不被标记为敏感设置，且不开放给未经业务门控的通用设置白名单直接写。
	for _, key := range []string{"enabled", "socket_path", "interfaces", "attach_mode", "sync_interval_seconds"} {
		if isSensitiveSetting("xdp_acceleration", key, false) {
			t.Errorf("xdp_acceleration:%s must not be sensitive", key)
		}
	}

	// 1. sync_interval_seconds 范围 1..300
	for _, tc := range []struct {
		name    string
		val     string
		wantErr bool
	}{
		{"min 1", "1", false},
		{"default 5", "5", false},
		{"max 300", "300", false},
		{"zero rejected", "0", true},
		{"negative rejected", "-5", true},
		{"over max 301", "301", true},
	} {
		t.Run("sync_interval/"+tc.name, func(t *testing.T) {
			err := validateValueRange("xdp_acceleration", "sync_interval_seconds", "integer", json.RawMessage(tc.val))
			if (err != nil) != tc.wantErr {
				t.Fatalf("val=%s err=%v wantErr=%v", tc.val, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "value must be") {
				t.Errorf("error must contain 'value must be' for 400 mapping: %v", err)
			}
		})
	}

	// 2. socket_path 受控前缀与路径穿越校验
	for _, tc := range []struct {
		name    string
		val     string
		wantErr bool
	}{
		{"default caddy sidecars", `"/var/run/caddy/sidecars/xdpguard.sock"`, false},
		{"run jiuzhang", `"/run/jiuzhang/xdpguard.sock"`, false},
		{"empty", `""`, true},
		{"tmp rejected", `"/tmp/xdpguard.sock"`, true},
		{"traversal rejected", `"/var/run/caddy/sidecars/../docker.sock"`, true},
		{"double dot rejected", `"/run/jiuzhang/a..b.sock"`, true},
		{"double slash rejected", `"/run/jiuzhang//xdpguard.sock"`, true},
		{"dir trailing slash rejected", `"/var/run/caddy/sidecars/"`, true},
		{"http ssrf rejected", `"http://127.0.0.1:8080/v1/sync"`, true},
		{"unix scheme rejected", `"unix:///var/run/caddy/sidecars/xdpguard.sock"`, true},
		{"control char rejected", `"/run/jiuzhang/xdp\nguard.sock"`, true},
		{"overlong rejected", `"/run/jiuzhang/` + strings.Repeat("a", 256) + `"`, true},
	} {
		t.Run("socket_path/"+tc.name, func(t *testing.T) {
			err := validateValueRange("xdp_acceleration", "socket_path", "string", json.RawMessage(tc.val))
			if (err != nil) != tc.wantErr {
				t.Fatalf("val=%s err=%v wantErr=%v", tc.val, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "value must be") {
				t.Errorf("error must contain 'value must be': %v", err)
			}
		})
	}
	if settingStringMaxLen["xdp_acceleration:socket_path"] != 256 {
		t.Fatalf("xdp_acceleration:socket_path max len = %d, want 256", settingStringMaxLen["xdp_acceleration:socket_path"])
	}

	// 3. attach_mode 仅限 auto|native|generic
	for _, tc := range []struct {
		val     string
		wantErr bool
	}{
		{`"auto"`, false},
		{`"native"`, false},
		{`"generic"`, false},
		{`"offload"`, true},
		{`"AUTO"`, true},
		{`""`, true},
	} {
		t.Run("attach_mode/"+tc.val, func(t *testing.T) {
			err := validateValueRange("xdp_acceleration", "attach_mode", "string", json.RawMessage(tc.val))
			if (err != nil) != tc.wantErr {
				t.Fatalf("val=%s err=%v wantErr=%v", tc.val, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "value must be") {
				t.Errorf("error must contain 'value must be': %v", err)
			}
		})
	}

	// 4. interfaces 物理业务网卡列表校验（拒绝 lo/虚拟网桥/容器口/隧道口/重复/超 16 个/null）
	tooMany := make([]string, 17)
	for i := range tooMany {
		tooMany[i] = "eth" + string(rune('a'+i))
	}
	tooManyJSON, _ := json.Marshal(tooMany)

	for _, tc := range []struct {
		name    string
		val     string
		wantErr bool
	}{
		{"empty array allowed", `[]`, false},
		{"valid physical nics", `["eth0","ens192","enp3s0f0","bond0.100"]`, false},
		{"null rejected", `null`, true},
		{"object rejected", `{"eth0":true}`, true},
		{"loopback lo rejected", `["lo"]`, true},
		{"loopback LO uppercase rejected", `["LO"]`, true},
		{"docker0 rejected", `["docker0"]`, true},
		{"br- bridge rejected", `["br-12345678"]`, true},
		{"veth rejected", `["veth9a8b7c"]`, true},
		{"virbr rejected", `["virbr0"]`, true},
		{"cni rejected", `["cni0"]`, true},
		{"flannel rejected", `["flannel.1"]`, true},
		{"cali rejected", `["cali12345"]`, true},
		{"tun rejected", `["tun0"]`, true},
		{"tap rejected", `["tap0"]`, true},
		{"wg rejected", `["wg0"]`, true},
		{"duplicate rejected", `["eth0","eth0"]`, true},
		{"shell chars rejected", `["eth0;rm"]`, true},
		{"over 15 chars rejected", `["enp0123456789abcdef"]`, true},
		{"over 16 interfaces rejected", string(tooManyJSON), true},
	} {
		t.Run("interfaces/"+tc.name, func(t *testing.T) {
			err := validateValueRange("xdp_acceleration", "interfaces", "json", json.RawMessage(tc.val))
			if (err != nil) != tc.wantErr {
				t.Fatalf("val=%s err=%v wantErr=%v", tc.val, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "value must be") {
				t.Errorf("error must contain 'value must be': %v", err)
			}
		})
	}
}
