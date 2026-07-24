package syslogfw

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSettings 是测试用内存 SettingsReader（键为 group:key）。
type fakeSettings struct{ vals map[string]interface{} }

func (f fakeSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if v, ok := f.vals[group+":"+key].(bool); ok {
		return v
	}
	return def
}

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if v, ok := f.vals[group+":"+key].(int); ok {
		return v
	}
	return def
}

func (f fakeSettings) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f.vals[group+":"+key].(string); ok {
		return v
	}
	return def
}

func enabledSettings(protocol, address string) fakeSettings {
	return fakeSettings{vals: map[string]interface{}{
		"logging:syslog_enabled":                       true,
		"logging:syslog_protocol":                      protocol,
		"logging:syslog_address":                       address,
		"logging:syslog_facility":                      1,
		"logging:syslog_forward_security_events":       true,
		"logging:syslog_forward_access_control_events": true,
		"logging:syslog_forward_access_logs":           true,
	}}
}

func newTestForwarder(s SettingsReader, dir string) *Forwarder {
	fw := NewForwarder(s, dir)
	fw.hostname = "test-host"
	return fw
}

// TestForwarderUDP 用本地 UDP listener 验证真实发送。
func TestForwarderUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	fw := newTestForwarder(enabledSettings("udp", pc.LocalAddr().String()), t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fw.Run(ctx)

	fw.Enqueue(KindSecurityEvent, "HIGH", map[string]interface{}{"attack_type": "XSS", "request_id": "r1"})

	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("未收到 UDP 消息: %v", err)
	}
	msg := string(buf[:n])
	if !strings.HasPrefix(msg, "<11>1 ") { // facility=1, HIGH→3
		t.Errorf("pri 错误: %s", msg)
	}
	if !strings.Contains(msg, " security-event ") || !strings.Contains(msg, `"attack_type":"XSS"`) {
		t.Errorf("消息内容错误: %s", msg)
	}
}

// TestForwarderTCP 用本地 TCP listener 验证 non-transparent framing（\n 分隔）。
func TestForwarderTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	fw := newTestForwarder(enabledSettings("tcp", ln.Addr().String()), t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fw.Run(ctx)

	fw.Enqueue(KindAccessLog, "", map[string]interface{}{"request_id": "r2", "response_status": 200})

	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			acceptCh <- c
		}
	}()
	var conn net.Conn
	select {
	case conn = <-acceptCh:
	case <-time.After(3 * time.Second):
		t.Fatal("TCP 未建立连接")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("未收到 TCP 消息: %v", err)
	}
	if !strings.HasPrefix(line, "<14>1 ") { // facility=1, info→6
		t.Errorf("pri 错误: %s", line)
	}
	if !strings.Contains(line, " access-log ") || !strings.Contains(line, `"request_id":"r2"`) {
		t.Errorf("消息内容错误: %s", line)
	}
}

// TestForwarderDisabled 未启用时消息被丢弃，不发送。
func TestForwarderDisabled(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	st := enabledSettings("udp", pc.LocalAddr().String())
	st.vals["logging:syslog_enabled"] = false
	fw := newTestForwarder(st, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fw.Run(ctx)

	fw.Enqueue(KindSecurityEvent, "HIGH", map[string]interface{}{"attack_type": "XSS"})

	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("未启用时不应收到消息")
	}
}

// TestKindSwitch 类型开关关闭时该类型不外发。
func TestKindSwitch(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	st := enabledSettings("udp", pc.LocalAddr().String())
	st.vals["logging:syslog_forward_access_logs"] = false
	fw := newTestForwarder(st, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fw.Run(ctx)

	fw.Enqueue(KindAccessLog, "", map[string]interface{}{"request_id": "off"})
	fw.Enqueue(KindSecurityEvent, "LOW", map[string]interface{}{"request_id": "on"})

	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("未收到消息: %v", err)
	}
	msg := string(buf[:n])
	if strings.Contains(msg, `"request_id":"off"`) {
		t.Errorf("开关关闭的 access log 不应外发: %s", msg)
	}
	if !strings.Contains(msg, `"request_id":"on"`) {
		t.Errorf("安全事件应外发: %s", msg)
	}
	// LOW → severity 5 → pri=1*8+5=13
	if !strings.HasPrefix(msg, "<13>1 ") {
		t.Errorf("LOW pri 错误: %s", msg)
	}
}

// TestQueueFullDropOldest 队列满时丢弃最旧并计数。
func TestQueueFullDropOldest(t *testing.T) {
	fw := newTestForwarder(fakeSettings{}, t.TempDir())
	fw.queue = make(chan item, 2) // 小队列便于测试（不启动 Run，无人消费）

	for i := 0; i < 5; i++ {
		fw.Enqueue(KindAccessLog, "", map[string]interface{}{"n": i})
	}
	if got := fw.DroppedCount(); got != 3 {
		t.Fatalf("丢弃计数 = %d, want 3", got)
	}
	// 队列里应是最后两条（最旧三条被丢弃）
	first := <-fw.queue
	payload, _ := json.Marshal(first.payload)
	if !strings.Contains(string(payload), `"n":3`) {
		t.Errorf("最旧消息未被丢弃，队首为: %s", payload)
	}
	second := <-fw.queue
	payload, _ = json.Marshal(second.payload)
	if !strings.Contains(string(payload), `"n":4`) {
		t.Errorf("队尾错误: %s", payload)
	}
}

// TestSpoolAndReplay 发送失败写入 spool，恢复后重放成功并删除文件。
func TestSpoolAndReplay(t *testing.T) {
	dir := t.TempDir()
	// 先指向一个不可达 TCP 地址（连接被拒）→ 发送失败进 spool
	st := enabledSettings("tcp", "127.0.0.1:1")
	fw := newTestForwarder(st, dir)

	snd := &sender{}
	fw.sendBatch(context.Background(), snd, []item{
		{kind: KindSecurityEvent, severityHint: "HIGH", payload: map[string]interface{}{"request_id": "sp1"}},
	})

	data, err := os.ReadFile(filepath.Join(dir, spoolFileName))
	if err != nil {
		t.Fatalf("spool 未写入: %v", err)
	}
	if !strings.Contains(string(data), `"request_id\":\"sp1\"`) && !strings.Contains(string(data), "sp1") {
		t.Fatalf("spool 内容错误: %s", data)
	}

	// 起 TCP listener，把地址改到 listener（热读取生效），重放 spool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	st.vals["logging:syslog_address"] = ln.Addr().String()

	// 重放用新 sender（sendBatch 的旧 sender 处于重连退避窗口内）
	go fw.replaySpool(context.Background(), &sender{})

	acceptCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			acceptCh <- c
		}
	}()
	var conn net.Conn
	select {
	case conn = <-acceptCh:
	case <-time.After(3 * time.Second):
		t.Fatal("重放未建立 TCP 连接")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("重放未收到消息: %v", err)
	}
	if !strings.Contains(line, "sp1") {
		t.Errorf("重放消息内容错误: %s", line)
	}

	// 全部重放成功后 spool 文件应被删除
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, spoolFileName)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("重放成功后 spool 文件未删除")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSpoolTruncate 超过上限时截断只留后半部分（对齐行边界）。
func TestSpoolTruncate(t *testing.T) {
	dir := t.TempDir()
	fw := newTestForwarder(fakeSettings{}, dir)

	var lines []string
	for i := 0; i < 100; i++ {
		rec, _ := json.Marshal(spoolRecord{Message: strings.Repeat("x", 100) + string(rune('A'+i%26))})
		lines = append(lines, string(rec))
	}
	if err := os.WriteFile(fw.spoolPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fw.truncateSpool()

	data, err := os.ReadFile(fw.spoolPath)
	if err != nil {
		t.Fatal(err)
	}
	kept := splitLines(data)
	if len(kept) == 0 || len(kept) >= 100 {
		t.Fatalf("截断后行数错误: %d", len(kept))
	}
	// 首行必须是完整 JSON（行边界对齐）
	var rec spoolRecord
	if err := json.Unmarshal(kept[0], &rec); err != nil {
		t.Fatalf("截断后首行不是完整记录: %v", err)
	}
	// 保留的应是后半部分
	if !strings.Contains(string(data), string(rune('A'+99%26))) {
		t.Errorf("截断后未保留尾部内容")
	}
}

// TestSendTestMessage 测试消息：未启用/地址为空/正常发送。
func TestSendTestMessage(t *testing.T) {
	dir := t.TempDir()

	// 未启用
	fw := newTestForwarder(fakeSettings{vals: map[string]interface{}{}}, dir)
	if err := fw.SendTestMessage(context.Background()); err == nil || !strings.Contains(err.Error(), "未启用") {
		t.Errorf("未启用应报错: %v", err)
	}

	// 地址为空
	st := fakeSettings{vals: map[string]interface{}{"logging:syslog_enabled": true}}
	fw = newTestForwarder(st, dir)
	if err := fw.SendTestMessage(context.Background()); err == nil || !strings.Contains(err.Error(), "地址为空") {
		t.Errorf("地址为空应报错: %v", err)
	}

	// 正常发送
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	st.vals["logging:syslog_protocol"] = "udp"
	st.vals["logging:syslog_address"] = pc.LocalAddr().String()
	if err := fw.SendTestMessage(context.Background()); err != nil {
		t.Fatalf("测试消息发送失败: %v", err)
	}
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("未收到测试消息: %v", err)
	}
	msg := string(buf[:n])
	if !strings.Contains(msg, `"test":true`) || !strings.Contains(msg, `"source":"jiuzhang-waf"`) {
		t.Errorf("测试消息内容错误: %s", msg)
	}
	if !strings.HasPrefix(msg, "<14>1 ") { // facility=1, info
		t.Errorf("测试消息 pri 错误: %s", msg)
	}

	// 协议非法
	st.vals["logging:syslog_protocol"] = "tls"
	if err := fw.SendTestMessage(context.Background()); err == nil || !strings.Contains(err.Error(), "协议") {
		t.Errorf("非法协议应报错: %v", err)
	}
}
