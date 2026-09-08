// types_test.go 纯单元测试：状态派生 / 注册校验 / 摘要比对 / 策略 JSON 校验 /
// flows 批量上限 / RAW 二进制帧解析 / 分页钳制。
package agents

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDeriveStatus 状态派生矩阵（契约 §5）。
func TestDeriveStatus(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-10 * time.Second)
	boundary := now.Add(-OfflineAfterSeconds * time.Second) // 恰好 60s：未超窗 → 不判离线
	stale := now.Add(-(OfflineAfterSeconds + 1) * time.Second)

	cases := []struct {
		name         string
		disabled     bool
		lastSeen     *time.Time
		lastReported string
		want         string
	}{
		{"禁用优先一切", true, &recent, StatusOnline, StatusDisabled},
		{"禁用且从未心跳", true, nil, "", StatusDisabled},
		{"从未心跳判离线", false, nil, "", StatusOffline},
		{"超窗判离线", false, &stale, StatusOnline, StatusOffline},
		{"窗口边界不判离线", false, &boundary, StatusDegraded, StatusDegraded},
		{"窗口内取自报 ONLINE", false, &recent, StatusOnline, StatusOnline},
		{"窗口内取自报 DEGRADED", false, &recent, StatusDegraded, StatusDegraded},
		{"窗口内取自报 ERROR", false, &recent, StatusError, StatusError},
		{"窗口内空自报兜底 ONLINE", false, &recent, "", StatusOnline},
		{"窗口内非法自报兜底 ONLINE", false, &recent, "garbage", StatusOnline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveStatus(c.disabled, c.lastSeen, c.lastReported, now); got != c.want {
				t.Errorf("DeriveStatus(%v, %v, %q) = %q, want %q",
					c.disabled, c.lastSeen, c.lastReported, got, c.want)
			}
		})
	}
}

// TestHashSecretKnownVector 摘要算法稳定性（SHA-256 hex 已知向量；
// 与 apm.HashEnrollmentToken 同算法，改动会破坏存量令牌/凭据比对）。
func TestHashSecretKnownVector(t *testing.T) {
	// sha256("") 的公开已知值
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := HashSecret(""); got != want {
		t.Errorf("HashSecret(\"\") = %q, want %q", got, want)
	}
	cred := "wda_" + strings.Repeat("ab", 32)
	sum := HashSecret(cred)
	if len(sum) != 64 || sum == cred {
		t.Errorf("HashSecret 输出异常: %q", sum)
	}
	if HashSecret(cred) != sum {
		t.Error("HashSecret 不稳定")
	}
}

// TestGenerateSecrets 令牌/凭据明文格式（wdt_/wda_ + 64 hex；契约 §2）。
func TestGenerateSecrets(t *testing.T) {
	tok, err := GenerateEnrollmentToken()
	if err != nil {
		t.Fatalf("GenerateEnrollmentToken: %v", err)
	}
	if !enrollmentTokenPattern.MatchString(tok) {
		t.Errorf("token 格式非法: %q", tok)
	}
	cred, err := GenerateCredential()
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if !credentialPattern.MatchString(cred) {
		t.Errorf("credential 格式非法: %q", cred)
	}
	tok2, _ := GenerateEnrollmentToken()
	if tok == tok2 {
		t.Error("令牌随机性不足（两次生成相同）")
	}
}

// TestEnrollRequestValidate 注册入参校验矩阵。
func TestEnrollRequestValidate(t *testing.T) {
	valid := func() *EnrollRequest {
		return &EnrollRequest{
			EnrollmentToken: "wdt_" + strings.Repeat("cd", 32),
			Hostname:        "web-prod-01",
			IP:              "10.0.1.10",
			OS:              "Rocky Linux 9",
			Kernel:          "5.14.0",
			Arch:            "x86_64",
			Version:         "1.0.0",
			Interfaces: []InterfaceInfo{
				{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", IPv4: "10.0.1.10", MTU: 1500, SpeedMbps: 1000},
			},
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("合法入参被拒绝: %v", err)
	}

	t.Run("令牌格式非法", func(t *testing.T) {
		req := valid()
		req.EnrollmentToken = "bad-token"
		if err := req.Validate(); err == nil {
			t.Error("应拒绝非法令牌格式")
		}
	})
	t.Run("hostname 缺失", func(t *testing.T) {
		req := valid()
		req.Hostname = "  "
		if err := req.Validate(); err == nil {
			t.Error("应拒绝空 hostname")
		}
	})
	t.Run("ip 非法", func(t *testing.T) {
		req := valid()
		req.IP = "not-an-ip"
		if err := req.Validate(); err == nil {
			t.Error("应拒绝非法 ip")
		}
	})
	t.Run("ipv6 合法", func(t *testing.T) {
		req := valid()
		req.IP = "fd00::1"
		req.Interfaces[0].IPv4 = ""
		req.Interfaces[0].IPv6 = "fd00::1"
		if err := req.Validate(); err != nil {
			t.Errorf("合法 ipv6 被拒绝: %v", err)
		}
	})
	t.Run("interfaces 超限", func(t *testing.T) {
		req := valid()
		req.Interfaces = make([]InterfaceInfo, 33)
		for i := range req.Interfaces {
			req.Interfaces[i].Name = "eth"
		}
		if err := req.Validate(); err == nil {
			t.Error("应拒绝超过 32 条网卡")
		}
	})
	t.Run("mtu 越界", func(t *testing.T) {
		req := valid()
		req.Interfaces[0].MTU = 70000
		if err := req.Validate(); err == nil {
			t.Error("应拒绝 mtu > 65535")
		}
	})
	t.Run("网卡 ipv4 非法", func(t *testing.T) {
		req := valid()
		req.Interfaces[0].IPv4 = "999.1.1.1"
		if err := req.Validate(); err == nil {
			t.Error("应拒绝非法网卡 ipv4")
		}
	})
}

// validPolicyJSON 契约 §3.3 示例策略。
func validPolicyJSON() json.RawMessage {
	return json.RawMessage(`{
	  "name": "production-web",
	  "capture": {"interfaces": ["eth0"], "direction": "both", "protocols": ["tcp"], "ports": [80, 443, 8080, 8443]},
	  "capture_level": "L0",
	  "output": {"mode": "FLOW"},
	  "limits": {"max_body_size": 262144, "outbound_mbps": 100, "cpu_percent": 20, "memory_mb": 512},
	  "sampling": {"enabled": false, "rate": 1.0},
	  "buffer": {"enabled": true, "max_size_mb": 512, "max_age_minutes": 30}
	}`)
}

// TestValidatePolicyConfigJSON 策略 JSON 校验矩阵。
func TestValidatePolicyConfigJSON(t *testing.T) {
	if err := ValidatePolicyConfigJSON(validPolicyJSON()); err != nil {
		t.Fatalf("契约示例策略被拒绝: %v", err)
	}

	mutate := func(fn func(map[string]interface{})) json.RawMessage {
		var m map[string]interface{}
		if err := json.Unmarshal(validPolicyJSON(), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		raw, _ := json.Marshal(m)
		return raw
	}

	t.Run("L2/L3 合法接收", func(t *testing.T) {
		for _, lvl := range []string{"L1", "L2", "L3"} {
			raw := mutate(func(m map[string]interface{}) { m["capture_level"] = lvl })
			if err := ValidatePolicyConfigJSON(raw); err != nil {
				t.Errorf("capture_level=%s 应合法: %v", lvl, err)
			}
		}
	})
	t.Run("direction 非法", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["capture"].(map[string]interface{})["direction"] = "sideways"
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝非法 direction")
		}
	})
	t.Run("output.mode 非法", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["output"].(map[string]interface{})["mode"] = "PCAP"
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝非法 output.mode")
		}
	})
	t.Run("FLOW_RAW 合法", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["output"].(map[string]interface{})["mode"] = "FLOW_RAW"
		})
		if err := ValidatePolicyConfigJSON(raw); err != nil {
			t.Errorf("FLOW_RAW 应合法: %v", err)
		}
	})
	t.Run("ports 为空", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["capture"].(map[string]interface{})["ports"] = []int{}
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝空 ports")
		}
	})
	t.Run("端口越界", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["capture"].(map[string]interface{})["ports"] = []int{80, 70000}
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝越界端口")
		}
	})
	t.Run("端口重复", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["capture"].(map[string]interface{})["ports"] = []int{80, 80}
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝重复端口")
		}
	})
	t.Run("采样率越界（enabled=true）", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["sampling"].(map[string]interface{})["enabled"] = true
			m["sampling"].(map[string]interface{})["rate"] = 1.5
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝 enabled=true 且 rate > 1")
		}
	})
	t.Run("采样率为零（enabled=true）", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["sampling"].(map[string]interface{})["enabled"] = true
			m["sampling"].(map[string]interface{})["rate"] = 0
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝 enabled=true 且 rate <= 0")
		}
	})
	t.Run("采样率合法边界（enabled=true，rate=1）", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["sampling"].(map[string]interface{})["enabled"] = true
			m["sampling"].(map[string]interface{})["rate"] = 1.0
		})
		if err := ValidatePolicyConfigJSON(raw); err != nil {
			t.Errorf("rate=1 应合法: %v", err)
		}
	})
	t.Run("enabled=false 不校验 rate（Phase 4 契约 §4）", func(t *testing.T) {
		for _, rate := range []float64{0, -0.5, 1.5} {
			raw := mutate(func(m map[string]interface{}) {
				m["sampling"].(map[string]interface{})["enabled"] = false
				m["sampling"].(map[string]interface{})["rate"] = rate
			})
			if err := ValidatePolicyConfigJSON(raw); err != nil {
				t.Errorf("enabled=false 时 rate=%v 不应被校验: %v", rate, err)
			}
		}
	})
	t.Run("未知字段拒绝", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) { m["evil_field"] = true })
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝未知字段")
		}
	})
	t.Run("空 config", func(t *testing.T) {
		if err := ValidatePolicyConfigJSON(nil); err == nil {
			t.Error("应拒绝空 config")
		}
	})
	t.Run("限速为零", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["limits"].(map[string]interface{})["outbound_mbps"] = 0
		})
		if err := ValidatePolicyConfigJSON(raw); err == nil {
			t.Error("应拒绝 outbound_mbps = 0")
		}
	})
}

// validFlowEvent 合法流量事件（契约 §3.4 示例）。
func validFlowEvent() FlowEvent {
	return FlowEvent{
		EventType: "request", FlowID: "a1-10.1.1.10-51234-10.1.2.20-8080-1788256800",
		Timestamp: 1788256800,
		SrcIP:     "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
		Protocol: "tcp", Direction: "ingress",
		TLSVisibility: "PLAINTEXT",
		HTTPMethod:    "POST", HTTPHost: "api.example.com", HTTPURI: "/api/login",
	}
}

// TestFlowsRequestValidate flows 批量校验（上限 500——契约 §3.4）。
func TestFlowsRequestValidate(t *testing.T) {
	t.Run("空批量拒绝", func(t *testing.T) {
		if err := (&FlowsRequest{}).Validate(); err == nil {
			t.Error("应拒绝空 events")
		}
	})
	t.Run("单条合法", func(t *testing.T) {
		if err := (&FlowsRequest{Events: []FlowEvent{validFlowEvent()}}).Validate(); err != nil {
			t.Errorf("合法事件被拒绝: %v", err)
		}
	})
	t.Run("500 条上限内放行", func(t *testing.T) {
		events := make([]FlowEvent, MaxFlowEventsPerBatch)
		for i := range events {
			events[i] = validFlowEvent()
		}
		if err := (&FlowsRequest{Events: events}).Validate(); err != nil {
			t.Errorf("500 条应放行: %v", err)
		}
	})
	t.Run("501 条拒绝", func(t *testing.T) {
		events := make([]FlowEvent, MaxFlowEventsPerBatch+1)
		for i := range events {
			events[i] = validFlowEvent()
		}
		if err := (&FlowsRequest{Events: events}).Validate(); err == nil {
			t.Error("501 条应被拒绝")
		}
	})
	t.Run("event_type 非法", func(t *testing.T) {
		e := validFlowEvent()
		e.EventType = "response"
		if err := (&FlowsRequest{Events: []FlowEvent{e}}).Validate(); err == nil {
			t.Error("应拒绝非法 event_type")
		}
	})
	t.Run("flow_end 合法", func(t *testing.T) {
		e := validFlowEvent()
		e.EventType = "flow_end"
		e.BytesIn, e.BytesOut = 1024, 2048
		if err := (&FlowsRequest{Events: []FlowEvent{e}}).Validate(); err != nil {
			t.Errorf("flow_end 应合法: %v", err)
		}
	})
	t.Run("tls_visibility 非法", func(t *testing.T) {
		e := validFlowEvent()
		e.TLSVisibility = "DECRYPTED"
		if err := (&FlowsRequest{Events: []FlowEvent{e}}).Validate(); err == nil {
			t.Error("应拒绝非法 tls_visibility")
		}
	})
	t.Run("host 含控制字符", func(t *testing.T) {
		e := validFlowEvent()
		e.HTTPHost = "evil\r\nhost"
		if err := (&FlowsRequest{Events: []FlowEvent{e}}).Validate(); err == nil {
			t.Error("应拒绝含控制字符的 host")
		}
	})
	t.Run("端口越界", func(t *testing.T) {
		e := validFlowEvent()
		e.SrcPort = 70000
		if err := (&FlowsRequest{Events: []FlowEvent{e}}).Validate(); err == nil {
			t.Error("应拒绝越界端口")
		}
	})
}

// buildBatch 构造契约 §3.5 WDP1 二进制批量。
func buildBatch(frames ...[]byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(packetBatchMagic)
	_ = binary.Write(buf, binary.BigEndian, uint64(1788256800))
	_ = binary.Write(buf, binary.BigEndian, uint16(len(frames)))
	for _, f := range frames {
		_ = binary.Write(buf, binary.BigEndian, uint64(1788256800))
		_ = binary.Write(buf, binary.BigEndian, uint32(123456))
		_ = binary.Write(buf, binary.BigEndian, uint32(len(f)))
		_ = binary.Write(buf, binary.BigEndian, uint32(len(f)))
		buf.Write(f)
	}
	return buf.Bytes()
}

// TestParsePacketBatch RAW 二进制帧解析（magic/长度/cap_len 上限/尾部校验——契约 §3.5）。
func TestParsePacketBatch(t *testing.T) {
	t.Run("合法批量", func(t *testing.T) {
		body := buildBatch([]byte("frame-one"), []byte("frame-two!!"))
		frames, bytesTotal, err := ParsePacketBatch(body)
		if err != nil {
			t.Fatalf("合法批量被拒绝: %v", err)
		}
		if frames != 2 || bytesTotal != int64(len("frame-one")+len("frame-two!!")) {
			t.Errorf("frames=%d bytes=%d, want 2/%d", frames, bytesTotal, len("frame-one")+len("frame-two!!"))
		}
	})
	t.Run("零帧合法", func(t *testing.T) {
		frames, bytesTotal, err := ParsePacketBatch(buildBatch())
		if err != nil || frames != 0 || bytesTotal != 0 {
			t.Errorf("frames=%d bytes=%d err=%v, want 0/0/nil", frames, bytesTotal, err)
		}
	})
	t.Run("magic 非法", func(t *testing.T) {
		body := buildBatch([]byte("x"))
		copy(body[:4], "XXXX")
		if _, _, err := ParsePacketBatch(body); err == nil {
			t.Error("应拒绝非法 magic")
		}
	})
	t.Run("头部过短", func(t *testing.T) {
		if _, _, err := ParsePacketBatch([]byte("WDP1\000")); err == nil {
			t.Error("应拒绝过短头部")
		}
	})
	t.Run("帧头过短", func(t *testing.T) {
		body := buildBatch([]byte("0123456789"))
		if _, _, err := ParsePacketBatch(body[:packetBatchHeaderLen+10]); err == nil {
			t.Error("应拒绝不完整帧头")
		}
	})
	t.Run("cap_len 超上限", func(t *testing.T) {
		body := buildBatch([]byte("0123456789"))
		// 篡改首帧 cap_len（帧头内偏移：14 + 16）
		binary.BigEndian.PutUint32(body[14+16:14+20], MaxFrameCapLen+1)
		if _, _, err := ParsePacketBatch(body); err == nil {
			t.Error("应拒绝 cap_len > 65535")
		}
	})
	t.Run("cap_len 达上限合法", func(t *testing.T) {
		body := buildBatch(make([]byte, MaxFrameCapLen))
		frames, bytesTotal, err := ParsePacketBatch(body)
		if err != nil || frames != 1 || bytesTotal != MaxFrameCapLen {
			t.Errorf("frames=%d bytes=%d err=%v, want 1/%d/nil", frames, bytesTotal, err, MaxFrameCapLen)
		}
	})
	t.Run("载荷截断", func(t *testing.T) {
		body := buildBatch([]byte("0123456789"))
		if _, _, err := ParsePacketBatch(body[:len(body)-3]); err == nil {
			t.Error("应拒绝截断载荷")
		}
	})
	t.Run("尾部多余数据", func(t *testing.T) {
		body := append(buildBatch(), 0x00)
		if _, _, err := ParsePacketBatch(body); err == nil {
			t.Error("应拒绝尾部多余数据")
		}
	})
	t.Run("超 8MB 拒绝", func(t *testing.T) {
		body := make([]byte, MaxPacketBatchBytes+1)
		copy(body[:4], packetBatchMagic)
		if _, _, err := ParsePacketBatch(body); err == nil {
			t.Error("应拒绝超 8MB 批量")
		}
	})
}

// TestParsePageParams 分页参数钳制（契约 §2：默认 20 最大 100，page 1 起）。
func TestParsePageParams(t *testing.T) {
	q := func(kv map[string]string) func(string) string {
		return func(k string) string { return kv[k] }
	}
	cases := []struct {
		name             string
		query            map[string]string
		wantPage, wantSz int
	}{
		{"缺省默认", map[string]string{}, 1, 20},
		{"正常取值", map[string]string{"page": "3", "page_size": "50"}, 3, 50},
		{"page_size 超上限钳 100", map[string]string{"page_size": "500"}, 1, 100},
		{"page_size 边界 100", map[string]string{"page_size": "100"}, 1, 100},
		{"page 非正回落 1", map[string]string{"page": "-3"}, 1, 20},
		{"page 0 回落 1", map[string]string{"page": "0"}, 1, 20},
		{"page_size 0 回落默认", map[string]string{"page_size": "0"}, 1, 20},
		{"非数字回落默认", map[string]string{"page": "abc", "page_size": "x"}, 1, 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := ParsePageParams(q(c.query))
			if p.Page != c.wantPage || p.PageSize != c.wantSz {
				t.Errorf("ParsePageParams(%v) = %+v, want page=%d size=%d",
					c.query, p, c.wantPage, c.wantSz)
			}
		})
	}
	if got := (PageParams{Page: 3, PageSize: 20}).Offset(); got != 40 {
		t.Errorf("Offset = %d, want 40", got)
	}
}

// TestConfigAckRequestValidate ACK 校验。
func TestConfigAckRequestValidate(t *testing.T) {
	if err := (&ConfigAckRequest{Version: 12, Status: "APPLIED"}).Validate(); err != nil {
		t.Errorf("APPLIED 应合法: %v", err)
	}
	if err := (&ConfigAckRequest{Version: 12, Status: "FAILED", Error: "apply error"}).Validate(); err != nil {
		t.Errorf("FAILED+error 应合法: %v", err)
	}
	if err := (&ConfigAckRequest{Version: 12, Status: "FAILED"}).Validate(); err == nil {
		t.Error("FAILED 缺 error 应拒绝")
	}
	if err := (&ConfigAckRequest{Version: -1, Status: "APPLIED"}).Validate(); err == nil {
		t.Error("负版本应拒绝")
	}
	if err := (&ConfigAckRequest{Version: 1, Status: "UNKNOWN"}).Validate(); err == nil {
		t.Error("非法 status 应拒绝")
	}
}

// TestHeartbeatRequestValidate 心跳校验（status 枚举；metrics 须为 JSON 对象）。
func TestHeartbeatRequestValidate(t *testing.T) {
	if err := (&HeartbeatRequest{Status: "ONLINE"}).Validate(); err != nil {
		t.Errorf("合法心跳被拒绝: %v", err)
	}
	if err := (&HeartbeatRequest{Status: "ONLINE", Metrics: json.RawMessage(`{"cpu_percent":3.2}`)}).Validate(); err != nil {
		t.Errorf("携带 metrics 的合法心跳被拒绝: %v", err)
	}
	if err := (&HeartbeatRequest{Status: "SLEEPING"}).Validate(); err == nil {
		t.Error("非法 status 应拒绝")
	}
	if err := (&HeartbeatRequest{Status: "ONLINE", Metrics: json.RawMessage(`[1,2]`)}).Validate(); err == nil {
		t.Error("非对象 metrics 应拒绝")
	}
}
