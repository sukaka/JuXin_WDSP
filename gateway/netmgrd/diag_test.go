package netmgrd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testJobID = "123e4567-e89b-42d3-a456-426614174000"
const testJobID2 = "223e4567-e89b-42d3-a456-426614174001"

// nopConn 最小 net.Conn 桩（tcp_probe 成功路径 Close 用）。
type nopConn struct{}

func (nopConn) Read(_ []byte) (int, error)         { return 0, nil }
func (nopConn) Write(b []byte) (int, error)        { return len(b), nil }
func (nopConn) Close() error                       { return nil }
func (nopConn) LocalAddr() net.Addr                { return nil }
func (nopConn) RemoteAddr() net.Addr               { return nil }
func (nopConn) SetDeadline(_ time.Time) error      { return nil }
func (nopConn) SetReadDeadline(_ time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(_ time.Time) error { return nil }

// diagHarness 诊断服务测试线束：全依赖桩化，scanOnce 同步驱动（确定性）。
type diagHarness struct {
	d *DiagService

	mu       sync.Mutex
	cmds     []cmdRunOpts
	binaries map[string]bool
	runFn    func(opts cmdRunOpts) cmdOutcome
	dialFn   func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupFn func(ctx context.Context, host string) ([]net.IP, error)
}

func newDiagHarness(t *testing.T, nodeName string) *diagHarness {
	t.Helper()
	h := &diagHarness{binaries: map[string]bool{
		"ping": true, "traceroute": true, "tracepath": true, "tcpdump": true,
	}}
	d := NewDiagService(t.TempDir(), nodeName, time.Hour) // 间隔无关：测试直驱 scanOnce
	d.lookPath = func(name string) bool { return h.binaries[name] }
	d.runCmd = func(_ context.Context, opts cmdRunOpts) cmdOutcome {
		h.mu.Lock()
		h.cmds = append(h.cmds, opts)
		h.mu.Unlock()
		if h.runFn != nil {
			return h.runFn(opts)
		}
		return cmdOutcome{stdout: "ok", exitCode: 0}
	}
	d.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h.dialFn != nil {
			return h.dialFn(ctx, network, addr)
		}
		return nopConn{}, nil
	}
	d.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		if h.lookupFn != nil {
			return h.lookupFn(ctx, host)
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	h.d = d
	return h
}

func (h *diagHarness) calls() []cmdRunOpts {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]cmdRunOpts(nil), h.cmds...)
}

// writeDiagRequest 以 0600 写请求文件（契约权限）。
func writeDiagRequest(t *testing.T, dir, jobID, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "request-"+jobID+".json"), []byte(body), 0o600); err != nil {
		t.Fatalf("写请求文件: %v", err)
	}
}

func pingBody(jobID, node, target string) string {
	return fmt.Sprintf(`{"version":1,"job_id":%q,"node":%q,"action":"ping","target":%q,"params":{"count":4},"timeout_sec":30}`,
		jobID, node, target)
}

// readDiagResult 读结果文件；不存在返回 ok=false；存在必须是完整 JSON（原子写）。
func readDiagResult(t *testing.T, dir, jobID string) (DiagResult, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "result-"+jobID+".json"))
	if err != nil {
		return DiagResult{}, false
	}
	var res DiagResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("结果文件应为完整 JSON（原子写）: %v", err)
	}
	return res, true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestDiagClaimByNode(t *testing.T) {
	h := newDiagHarness(t, "node-a")
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "node-a", "192.0.2.1"))

	h.d.scanOnce()

	res, ok := readDiagResult(t, h.d.Dir, testJobID)
	if !ok || res.Status != DiagSuccess {
		t.Fatalf("本节点请求应被认领并成功: %+v exists=%v", res, ok)
	}
	if res.JobID != testJobID || res.ExitCode != 0 || res.FinishedAt == "" {
		t.Fatalf("结果字段不全: %+v", res)
	}
	if fileExists(filepath.Join(h.d.Dir, "request-"+testJobID+".json")) {
		t.Fatal("处理完应删除请求文件")
	}
	calls := h.calls()
	if len(calls) != 1 {
		t.Fatalf("应执行 1 条外部命令: %v", calls)
	}
	wantArgs := []string{"-c", "4", "-W", "2", "192.0.2.1"}
	if calls[0].name != "ping" || strings.Join(calls[0].args, " ") != strings.Join(wantArgs, " ") {
		t.Fatalf("ping 参数拼装错误: %s %v", calls[0].name, calls[0].args)
	}
	if calls[0].timeout > diagPingHardTimeout {
		t.Fatalf("ping 硬超时应 ≤30s: %v", calls[0].timeout)
	}
}

func TestDiagNodeMismatchSkipped(t *testing.T) {
	h := newDiagHarness(t, "node-a")
	reqPath := filepath.Join(h.d.Dir, "request-"+testJobID+".json")
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "node-b", "192.0.2.1"))

	h.d.scanOnce()

	if _, ok := readDiagResult(t, h.d.Dir, testJobID); ok {
		t.Fatal("非本节点请求不应产生结果")
	}
	if !fileExists(reqPath) {
		t.Fatal("非本节点请求文件应保留（留给对应节点）")
	}
	if len(h.calls()) != 0 {
		t.Fatalf("非本节点请求不应执行: %v", h.calls())
	}
}

func TestDiagEmptyNodeClaimsAll(t *testing.T) {
	h := newDiagHarness(t, "") // 空节点名 = 认领全部
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "node-b", "192.0.2.1"))

	h.d.scanOnce()

	if _, ok := readDiagResult(t, h.d.Dir, testJobID); !ok {
		t.Fatal("空节点名应认领任意节点请求")
	}
}

func TestDiagInvalidJobIDIgnored(t *testing.T) {
	h := newDiagHarness(t, "")
	bad := filepath.Join(h.d.Dir, "request-../../etc-passwd.json")
	if err := os.WriteFile(bad, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	h.d.scanOnce()

	if !fileExists(bad) {
		t.Fatal("非法 job_id 文件应忽略（不删除，防路径穿越误判）")
	}
	if len(h.calls()) != 0 {
		t.Fatalf("非法 job_id 不应执行: %v", h.calls())
	}
	entries, _ := os.ReadDir(h.d.Dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "result-") {
			t.Fatalf("非法 job_id 不应产生结果: %s", e.Name())
		}
	}
}

func TestDiagPoisonRequestConsumed(t *testing.T) {
	// JSON 损坏的毒文件必须消化（写 FAILED + 删请求），否则卡死串行队列
	h := newDiagHarness(t, "")
	writeDiagRequest(t, h.d.Dir, testJobID, `{"version":1,broken`)

	h.d.scanOnce()

	res, ok := readDiagResult(t, h.d.Dir, testJobID)
	if !ok || res.Status != DiagFailed || !strings.Contains(res.Stderr, "解析") {
		t.Fatalf("毒文件应写 FAILED 结果: %+v exists=%v", res, ok)
	}
	if fileExists(filepath.Join(h.d.Dir, "request-"+testJobID+".json")) {
		t.Fatal("毒文件应删除（防卡死串行队列）")
	}
}

func TestDiagJobIDBodyMismatch(t *testing.T) {
	h := newDiagHarness(t, "")
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID2, "", "192.0.2.1"))

	h.d.scanOnce()

	res, ok := readDiagResult(t, h.d.Dir, testJobID)
	if !ok || res.Status != DiagFailed || !strings.Contains(res.Stderr, "不一致") {
		t.Fatalf("文件名与请求体 job_id 不一致应 FAILED: %+v", res)
	}
}

func TestDiagUnknownActionRejected(t *testing.T) {
	h := newDiagHarness(t, "")
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"shell","target":"127.0.0.1","timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	res, ok := readDiagResult(t, h.d.Dir, testJobID)
	if !ok || res.Status != DiagFailed || !strings.Contains(res.Stderr, "未知动作") {
		t.Fatalf("未知动作应 FAILED: %+v", res)
	}
	if len(h.calls()) != 0 {
		t.Fatalf("未知动作不应执行任何命令: %v", h.calls())
	}
}

func TestDiagInvalidTargetFailsWithoutExec(t *testing.T) {
	h := newDiagHarness(t, "")
	for _, target := range []string{"-c evil", "a;rm -rf /", "a b", "$(id)", ""} {
		writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", target))
		h.d.scanOnce()
		res, ok := readDiagResult(t, h.d.Dir, testJobID)
		if !ok || res.Status != DiagFailed || !strings.Contains(res.Stderr, "非法目标") {
			t.Fatalf("非法目标 %q 应写 FAILED: %+v", target, res)
		}
		os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))
	}
	if len(h.calls()) != 0 {
		t.Fatalf("非法目标不得执行任何外部命令: %v", h.calls())
	}
}

func TestDiagPingCountClamp(t *testing.T) {
	h := newDiagHarness(t, "")
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"ping","target":"192.0.2.1","params":{"count":50},"timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	calls := h.calls()
	if len(calls) != 1 || calls[0].args[1] != "20" {
		t.Fatalf("count 应夹紧到 20: %+v", calls)
	}
}

func TestDiagPingMissingBinary(t *testing.T) {
	h := newDiagHarness(t, "")
	h.binaries["ping"] = false
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))

	h.d.scanOnce()

	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "iputils") {
		t.Fatalf("ping 缺失应 FAILED 并注明缺哪个包: %+v", res)
	}
	if len(h.calls()) != 0 {
		t.Fatal("二进制不存在不应调用执行器")
	}
}

func TestDiagTracerouteArgsAndFallback(t *testing.T) {
	h := newDiagHarness(t, "")
	body := fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"traceroute","target":"192.0.2.1","params":{"max_hops":99},"timeout_sec":120}`, testJobID)

	// traceroute 存在：-m 夹紧到 30，超时夹紧到 60s
	writeDiagRequest(t, h.d.Dir, testJobID, body)
	h.d.scanOnce()
	calls := h.calls()
	if len(calls) != 1 || calls[0].name != "traceroute" ||
		strings.Join(calls[0].args, " ") != "-m 30 192.0.2.1" {
		t.Fatalf("traceroute 参数错误: %+v", calls)
	}
	if calls[0].timeout != diagTracerouteHardTimeout {
		t.Fatalf("traceroute 硬超时应为 60s: %v", calls[0].timeout)
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	// traceroute 缺失 → 回退 tracepath
	h.binaries["traceroute"] = false
	h.mu.Lock()
	h.cmds = nil
	h.mu.Unlock()
	writeDiagRequest(t, h.d.Dir, testJobID, body)
	h.d.scanOnce()
	calls = h.calls()
	if len(calls) != 1 || calls[0].name != "tracepath" ||
		strings.Join(calls[0].args, " ") != "192.0.2.1" {
		t.Fatalf("tracepath 回退参数错误: %+v", calls)
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	// 两者均缺失 → FAILED 注明包
	h.binaries["tracepath"] = false
	h.mu.Lock()
	h.cmds = nil
	h.mu.Unlock()
	writeDiagRequest(t, h.d.Dir, testJobID, body)
	h.d.scanOnce()
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "traceroute") {
		t.Fatalf("均缺失应 FAILED: %+v", res)
	}
}

func TestDiagTimeoutAndExitFailure(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		return cmdOutcome{stdout: "partial", timedOut: true, exitCode: -1}
	}
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))
	h.d.scanOnce()
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagTimeout || res.Stdout != "partial" {
		t.Fatalf("超时应映射 TIMEOUT 且保留部分输出: %+v", res)
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		return cmdOutcome{stderr: "100% packet loss", exitCode: 1}
	}
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))
	h.d.scanOnce()
	res, _ = readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || res.ExitCode != 1 || !strings.Contains(res.Stderr, "packet loss") {
		t.Fatalf("非零退出应映射 FAILED: %+v", res)
	}
}

func TestDiagStopFileProducesStoppedAndCleanup(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		// 模拟执行器轮询到 stop 文件后杀进程
		return cmdOutcome{stopped: true, exitCode: -1}
	}
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))
	stopPath := filepath.Join(h.d.Dir, "stop-"+testJobID)
	if err := os.WriteFile(stopPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}

	h.d.scanOnce()

	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagStopped {
		t.Fatalf("stop 文件路径应映射 STOPPED: %+v", res)
	}
	if fileExists(stopPath) {
		t.Fatal("处理完应删除 stop 文件")
	}
	// 执行器收到的 stopFile 路径应正确
	calls := h.calls()
	if len(calls) != 1 || calls[0].stopFile != stopPath {
		t.Fatalf("执行器 stopFile 路径错误: %+v", calls)
	}
}

func TestDiagStdoutTruncated64KB(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		return cmdOutcome{stdout: strings.Repeat("x", 100*1024), exitCode: 0}
	}
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))

	h.d.scanOnce()

	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagSuccess || len(res.Stdout) != diagOutputLimit {
		t.Fatalf("stdout 应截断到 64KB: status=%s len=%d", res.Status, len(res.Stdout))
	}
}

func TestDiagTCPProbe(t *testing.T) {
	h := newDiagHarness(t, "")
	var gotAddr string
	h.dialFn = func(_ context.Context, network, addr string) (net.Conn, error) {
		gotAddr = network + " " + addr
		return nopConn{}, nil
	}
	// port 缺省 80
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"tcp_probe","target":"192.0.2.1","params":{},"timeout_sec":10}`, testJobID))
	h.d.scanOnce()
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagSuccess || !strings.Contains(res.Stdout, "connected") {
		t.Fatalf("tcp_probe 应成功: %+v", res)
	}
	if gotAddr != "tcp 192.0.2.1:80" {
		t.Fatalf("缺省端口应为 80: %s", gotAddr)
	}
	if len(h.calls()) != 0 {
		t.Fatal("tcp_probe 为 Go 原生动作，不应调用外部命令执行器")
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	// 显式端口 + 连接失败 → FAILED
	h.dialFn = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"tcp_probe","target":"192.0.2.1","params":{"port":443},"timeout_sec":10}`, testJobID))
	h.d.scanOnce()
	res, _ = readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "refused") {
		t.Fatalf("连接失败应 FAILED: %+v", res)
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	// 非法端口 → FAILED 且不拨号
	dialed := false
	h.dialFn = func(_ context.Context, _, _ string) (net.Conn, error) {
		dialed = true
		return nopConn{}, nil
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"tcp_probe","target":"192.0.2.1","params":{"port":70000},"timeout_sec":10}`, testJobID))
	h.d.scanOnce()
	res, _ = readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || dialed {
		t.Fatalf("非法端口应 FAILED 且不拨号: %+v dialed=%v", res, dialed)
	}
}

func TestDiagDNSQuery(t *testing.T) {
	h := newDiagHarness(t, "")
	h.lookupFn = func(_ context.Context, host string) ([]net.IP, error) {
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected host %s", host)
		}
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}, nil
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"dns_query","target":"example.com","timeout_sec":10}`, testJobID))
	h.d.scanOnce()
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagSuccess ||
		!strings.Contains(res.Stdout, "93.184.216.34") || !strings.Contains(res.Stdout, "2606:") {
		t.Fatalf("dns_query 应输出 A/AAAA 地址列表: %+v", res)
	}
	os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))

	h.lookupFn = func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"dns_query","target":"nx.example.com","timeout_sec":10}`, testJobID))
	h.d.scanOnce()
	res, _ = readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "NXDOMAIN") {
		t.Fatalf("解析失败应 FAILED: %+v", res)
	}
}

// writePcapFromArgs fake tcpdump：按 -w 参数落产物文件。
func writePcapFromArgs(t *testing.T, args []string, size int64) {
	t.Helper()
	for i, a := range args {
		if a == "-w" && i+1 < len(args) {
			f, err := os.Create(args[i+1])
			if err != nil {
				t.Fatalf("创建 pcap: %v", err)
			}
			if err := f.Truncate(size); err != nil { // 稀疏文件，避免真实写 100MB
				t.Fatalf("设置 pcap 大小: %v", err)
			}
			f.Close()
			return
		}
	}
	t.Fatalf("tcpdump 参数缺少 -w: %v", args)
}

func TestDiagCaptureArgsAndSuccess(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		writePcapFromArgs(t, opts.args, 2048)
		return cmdOutcome{timedOut: true, exitCode: -1, stdout: "10 packets captured"} // 到期 = 抓满时长
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"capture","target":"",
			"params":{"iface":"eth0","duration_sec":10,"count":100,
				"filter_proto":"tcp","filter_host":"192.0.2.1","filter_port":443},"timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	calls := h.calls()
	if len(calls) != 1 || calls[0].name != "tcpdump" {
		t.Fatalf("应调用 tcpdump: %+v", calls)
	}
	wantPcap := filepath.Join(h.d.Dir, "capture-"+testJobID+".pcap")
	wantArgs := "-i eth0 -w " + wantPcap + " -s 128 -c 100 tcp and host 192.0.2.1 and port 443"
	if strings.Join(calls[0].args, " ") != wantArgs {
		t.Fatalf("capture 参数拼装错误:\n got=%s\nwant=%s", strings.Join(calls[0].args, " "), wantArgs)
	}
	if !calls[0].softKill {
		t.Fatal("capture 到期应 SIGTERM（softKill）让 tcpdump 刷盘")
	}
	if calls[0].timeout != 10*time.Second {
		t.Fatalf("capture 超时应为 duration_sec: %v", calls[0].timeout)
	}
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagSuccess || res.CaptureFile != "capture-"+testJobID+".pcap" || res.CaptureSize != 2048 {
		t.Fatalf("capture 到期+产物存在应 SUCCESS 并回报产物: %+v", res)
	}
}

func TestDiagCaptureDurationClamp(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		writePcapFromArgs(t, opts.args, 128)
		return cmdOutcome{timedOut: true, exitCode: -1}
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"capture","target":"",
			"params":{"iface":"eth0","duration_sec":99999},"timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	calls := h.calls()
	if len(calls) != 1 || calls[0].timeout != 300*time.Second {
		t.Fatalf("duration_sec 应夹紧到 300: %+v", calls)
	}
}

func TestDiagCaptureOversizeDeleted(t *testing.T) {
	h := newDiagHarness(t, "")
	h.runFn = func(opts cmdRunOpts) cmdOutcome {
		writePcapFromArgs(t, opts.args, diagCaptureMaxBytes+1)
		return cmdOutcome{timedOut: true, exitCode: -1}
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"capture","target":"",
			"params":{"iface":"eth0","duration_sec":5},"timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "100MB") {
		t.Fatalf("超限产物应 FAILED: %+v", res)
	}
	if fileExists(filepath.Join(h.d.Dir, "capture-"+testJobID+".pcap")) {
		t.Fatal("超限 pcap 应删除")
	}
	if res.CaptureFile != "" {
		t.Fatalf("失败结果不应带 capture_file: %+v", res)
	}
}

func TestDiagCaptureValidation(t *testing.T) {
	h := newDiagHarness(t, "")
	for _, tc := range []struct {
		name   string
		params string
		want   string
	}{
		{"缺网卡", `"duration_sec":5`, "iface"},
		{"非法协议", `"iface":"eth0","duration_sec":5,"filter_proto":"gre"`, "filter_proto"},
		{"非法过滤端口", `"iface":"eth0","duration_sec":5,"filter_port":70000`, "filter_port"},
		{"非法过滤主机", `"iface":"eth0","duration_sec":5,"filter_host":"-evil"`, "filter_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeDiagRequest(t, h.d.Dir, testJobID,
				fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"capture","target":"",
					"params":{%s},"timeout_sec":30}`, testJobID, tc.params))
			h.d.scanOnce()
			res, _ := readDiagResult(t, h.d.Dir, testJobID)
			if res.Status != DiagFailed || !strings.Contains(res.Stderr, tc.want) {
				t.Fatalf("应 FAILED 且 stderr 含 %q: %+v", tc.want, res)
			}
			os.Remove(filepath.Join(h.d.Dir, "result-"+testJobID+".json"))
		})
	}
	if len(h.calls()) != 0 {
		t.Fatalf("校验失败不应执行 tcpdump: %v", h.calls())
	}
}

func TestDiagCaptureMissingTcpdump(t *testing.T) {
	h := newDiagHarness(t, "")
	h.binaries["tcpdump"] = false
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"capture","target":"",
			"params":{"iface":"eth0","duration_sec":5},"timeout_sec":30}`, testJobID))

	h.d.scanOnce()

	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagFailed || !strings.Contains(res.Stderr, "tcpdump") {
		t.Fatalf("tcpdump 缺失应 FAILED 注明包名: %+v", res)
	}
}

func TestDiagSerialOnePerScan(t *testing.T) {
	h := newDiagHarness(t, "")
	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))
	writeDiagRequest(t, h.d.Dir, testJobID2, pingBody(testJobID2, "", "192.0.2.2"))

	h.d.scanOnce()

	if _, ok := readDiagResult(t, h.d.Dir, testJobID); !ok {
		t.Fatal("首个请求应被处理")
	}
	if _, ok := readDiagResult(t, h.d.Dir, testJobID2); ok {
		t.Fatal("一次扫描只处理一个请求（串行）")
	}
	if !fileExists(filepath.Join(h.d.Dir, "request-"+testJobID2+".json")) {
		t.Fatal("未处理请求应保留到下一轮")
	}

	h.d.scanOnce()
	if _, ok := readDiagResult(t, h.d.Dir, testJobID2); !ok {
		t.Fatal("第二轮扫描应处理剩余请求")
	}
}

func TestDiagNativeStopFile(t *testing.T) {
	// Go 原生动作（tcp_probe）执行期间出现 stop 文件 → STOPPED
	h := newDiagHarness(t, "")
	h.dialFn = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done() // 模拟慢连接，直到被取消
		return nil, ctx.Err()
	}
	writeDiagRequest(t, h.d.Dir, testJobID,
		fmt.Sprintf(`{"version":1,"job_id":%q,"node":"","action":"tcp_probe","target":"192.0.2.1","params":{"port":443},"timeout_sec":60}`, testJobID))

	done := make(chan struct{})
	go func() { h.d.scanOnce(); close(done) }()

	time.Sleep(100 * time.Millisecond) // 确保已进入拨号等待
	stopPath := filepath.Join(h.d.Dir, "stop-"+testJobID)
	if err := os.WriteFile(stopPath, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stop 文件应在轮询周期内终止原生动作")
	}
	res, _ := readDiagResult(t, h.d.Dir, testJobID)
	if res.Status != DiagStopped {
		t.Fatalf("原生动作遇 stop 文件应 STOPPED: %+v", res)
	}
}

func TestDiagRunLoopAndClose(t *testing.T) {
	h := newDiagHarness(t, "")
	h.d.Interval = 20 * time.Millisecond

	runDone := make(chan struct{})
	go func() { h.d.Run(); close(runDone) }()

	writeDiagRequest(t, h.d.Dir, testJobID, pingBody(testJobID, "", "192.0.2.1"))
	waitFor(t, "Run 循环消费诊断请求", 2*time.Second, func() bool {
		_, ok := readDiagResult(t, h.d.Dir, testJobID)
		return ok
	})

	h.d.Close()
	h.d.Close() // 幂等
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Run 未及时返回")
	}
}

func TestDefaultRunCmdRealExec(t *testing.T) {
	// 真实执行器冒烟：参数数组执行、退出码提取、输出捕获（不经 shell）
	out := defaultRunCmd(context.Background(), cmdRunOpts{
		name: "echo", args: []string{"hello diag"}, timeout: 5 * time.Second,
	})
	if out.err != nil || out.exitCode != 0 || strings.TrimSpace(out.stdout) != "hello diag" {
		t.Fatalf("echo 应成功: %+v", out)
	}

	out = defaultRunCmd(context.Background(), cmdRunOpts{
		name: "sh", args: []string{"-c", "exit 3"}, timeout: 5 * time.Second,
	})
	if out.err != nil || out.exitCode != 3 {
		t.Fatalf("非零退出应提取退出码 3: %+v", out)
	}

	// 超时路径：进程被杀，timedOut 置位
	out = defaultRunCmd(context.Background(), cmdRunOpts{
		name: "sleep", args: []string{"30"}, timeout: 200 * time.Millisecond,
	})
	if !out.timedOut {
		t.Fatalf("超时应置 timedOut: %+v", out)
	}

	// stop 文件路径：执行期间出现 → stopped 置位
	stopPath := filepath.Join(t.TempDir(), "stop-x")
	time.AfterFunc(100*time.Millisecond, func() { os.WriteFile(stopPath, []byte{}, 0o600) })
	out = defaultRunCmd(context.Background(), cmdRunOpts{
		name: "sleep", args: []string{"30"}, timeout: 30 * time.Second, stopFile: stopPath,
	})
	if !out.stopped {
		t.Fatalf("stop 文件应置 stopped: %+v", out)
	}

	// 二进制不存在 → err（调用方映射 FAILED）
	out = defaultRunCmd(context.Background(), cmdRunOpts{
		name: "jiuzhang-no-such-binary", timeout: time.Second,
	})
	if out.err == nil {
		t.Fatal("不存在的二进制应返回启动错误")
	}
}
