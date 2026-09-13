// 网络诊断（diag）子契约：<sidecarDir>/diag/ 目录下的请求/结果文件协议。
//
// 契约（与服务端冻结，勿单方面变更）：
//   - server 写 request-<uuid>.json（0600）；netmgrd 每 1s（独立于 15s 主 tick）
//     扫描，串行处理（一次一个请求，避免并发抓包打爆网卡）；
//   - 认领：本节点名（NodeName，缺省空）为空或与请求 node 相等才认领，不匹配
//     跳过该文件（留给对应节点）；job_id 必须匹配 ^[0-9a-fA-F-]{36}$ 且文件名
//     必须是 request-<job_id>.json，否则忽略（防路径穿越）；
//   - 动作白名单 ping/tcp_probe/traceroute/dns_query/capture；target 仅允许
//     IPv4/IPv6 字面量或合法主机名（纵深防御，server 侧同样校验）；非法目标
//     直接写 FAILED 结果（原因在 stderr 字段）；
//   - 停止：执行期间出现 stop-<job_id> 文件（每 500ms 轮询）→ 杀进程写
//     STOPPED 结果并删除 stop 文件；
//   - 结果 result-<job_id>.json（原子写 tmp+rename），stdout/stderr 截断 64KB；
//     处理完删除 request 文件，结果文件留给 server 消费（server 删除）；
//   - capture 产物 capture-<job_id>.pcap 留在 diag 目录供 server 提取；
//     执行后检查 >100MB 删除并报 FAILED。
//
// 执行纪律同 netmgrd 主体：外部命令一律参数数组、不经 shell；二进制不存在
// → FAILED（stderr 注明缺哪个包）；进程永不因单个请求失败退出。
package netmgrd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultDiagInterval diag 目录扫描周期（独立于主 tick）。
	DefaultDiagInterval = 1 * time.Second
	// diagStopPollInterval stop 文件轮询间隔。
	diagStopPollInterval = 500 * time.Millisecond
	// diagOutputLimit stdout/stderr 单字段截断上限（64KB）。
	diagOutputLimit = 64 * 1024
	// diagCaptureMaxBytes capture 产物大小上限（100MB，超限删除并报 FAILED）。
	diagCaptureMaxBytes = 100 * 1024 * 1024
	// diagDefaultTimeoutSec 请求未给 timeout_sec 时的缺省值。
	diagDefaultTimeoutSec = 30
	// diagPingHardTimeout ping 硬超时。
	diagPingHardTimeout = 30 * time.Second
	// diagTracerouteHardTimeout traceroute 硬超时。
	diagTracerouteHardTimeout = 60 * time.Second
	// diagSoftKillGrace SIGTERM 后等待优雅退出的宽限（tcpdump 刷盘），超时 SIGKILL。
	diagSoftKillGrace = 3 * time.Second
)

// 诊断结果状态取值（与 server 契约一致）。
const (
	DiagSuccess = "SUCCESS"
	DiagFailed  = "FAILED"
	DiagTimeout = "TIMEOUT"
	DiagStopped = "STOPPED"
)

// jobIDRE 合法 job_id（UUID 形态，防路径穿越）。
var jobIDRE = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)

// DiagParams 诊断动作参数（全部可选，按动作取用）。
type DiagParams struct {
	Count       int    `json:"count"`        // ping/capture 报文数（ping 夹紧 1-20）
	Port        int    `json:"port"`         // tcp_probe 端口（1-65535，缺省 80）
	MaxHops     int    `json:"max_hops"`     // traceroute 最大跳数（夹紧 1-30）
	DurationSec int    `json:"duration_sec"` // capture 时长（夹紧 5-300）
	Iface       string `json:"iface"`        // capture 网卡
	FilterProto string `json:"filter_proto"` // capture 过滤协议（仅 tcp/udp/icmp）
	FilterPort  int    `json:"filter_port"`  // capture 过滤端口（0=不过滤）
	FilterHost  string `json:"filter_host"`  // capture 过滤主机（空=不过滤）
}

// DiagRequest 诊断请求（request-<job_id>.json）。
type DiagRequest struct {
	Version    int        `json:"version"`
	JobID      string     `json:"job_id"`
	Node       string     `json:"node"`
	Action     string     `json:"action"`
	Target     string     `json:"target"`
	Params     DiagParams `json:"params"`
	TimeoutSec int        `json:"timeout_sec"`
}

// DiagResult 诊断结果（result-<job_id>.json）。
type DiagResult struct {
	JobID       string `json:"job_id"`
	Status      string `json:"status"` // SUCCESS/FAILED/TIMEOUT/STOPPED
	ExitCode    int    `json:"exit_code"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	DurationMs  int64  `json:"duration_ms"`
	CaptureFile string `json:"capture_file,omitempty"`
	CaptureSize int64  `json:"capture_size,omitempty"`
	FinishedAt  string `json:"finished_at"`
}

// cmdRunOpts 外部命令执行参数。
type cmdRunOpts struct {
	name     string
	args     []string
	timeout  time.Duration
	softKill bool   // 到期/停止时先 SIGTERM（tcpdump 需要刷盘）再 SIGKILL
	stopFile string // 非空：执行期间轮询该文件，出现即终止（STOPPED）
}

// cmdOutcome 外部命令执行结果。
type cmdOutcome struct {
	stdout   string
	stderr   string
	exitCode int
	timedOut bool
	stopped  bool
	err      error // 启动失败（含二进制不存在）
}

// DiagService 诊断请求扫描执行服务（串行，一次一个请求）。
type DiagService struct {
	// Dir diag 子契约目录（<sidecarDir>/diag）。
	Dir string
	// NodeName 本节点名（认领判定；空 = 认领全部节点）。
	NodeName string
	// Interval 扫描周期（<=0 取 DefaultDiagInterval）。
	Interval time.Duration

	// 依赖注入（生产为真实实现；单测替换桩）。
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	lookupIP    func(ctx context.Context, host string) ([]net.IP, error)
	lookPath    func(name string) bool
	runCmd      func(ctx context.Context, opts cmdRunOpts) cmdOutcome
	now         func() time.Time

	mu     sync.Mutex
	stopCh chan struct{}
	closed bool
}

// NewDiagService 构建诊断服务（生产依赖为真实实现）。
func NewDiagService(dir, nodeName string, interval time.Duration) *DiagService {
	if interval <= 0 {
		interval = DefaultDiagInterval
	}
	resolver := &net.Resolver{}
	dialer := &net.Dialer{}
	return &DiagService{
		Dir: dir, NodeName: nodeName, Interval: interval,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			return resolver.LookupIP(ctx, "ip", host)
		},
		lookPath: func(name string) bool {
			_, err := exec.LookPath(name)
			return err == nil
		},
		runCmd: defaultRunCmd,
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
}

// Run 阻塞运行扫描循环：每 Interval 扫描一次 diag 目录，直到 Close。
func (d *DiagService) Run() {
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.scanOnce()
		}
	}
}

// Close 停止扫描（幂等；进行中的请求随进程退出自然终止）。
func (d *DiagService) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	close(d.stopCh)
}

// scanOnce 扫描一轮：按文件名序取首个可认领请求执行（串行，一次一个）。
func (d *DiagService) scanOnce() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return // 目录不存在/不可读 = 无请求（server 尚未创建）
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasPrefix(name, "request-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		jobID := strings.TrimSuffix(strings.TrimPrefix(name, "request-"), ".json")
		if !jobIDRE.MatchString(jobID) {
			continue // 非法 job_id/文件名：忽略（防路径穿越），不删除（可能属其他写入方）
		}
		req, err := d.loadRequest(name, jobID)
		if err != nil {
			// 毒文件必须消化掉（否则卡死串行队列）：以文件名 job_id 写 FAILED 结果
			d.finish(DiagResult{JobID: jobID, Status: DiagFailed, Stderr: err.Error()},
				name, time.Now())
			return
		}
		if d.NodeName != "" && req.Node != d.NodeName {
			continue // 非本节点请求：跳过，留给对应节点
		}
		d.execute(req, name)
		return
	}
}

// loadRequest 读取并校验请求文件（版本/动作白名单/job_id 一致性）。
func (d *DiagService) loadRequest(fileName, jobID string) (DiagRequest, error) {
	data, err := os.ReadFile(filepath.Join(d.Dir, fileName))
	if err != nil {
		return DiagRequest{}, fmt.Errorf("读取请求文件失败: %v", err)
	}
	var req DiagRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return DiagRequest{}, fmt.Errorf("请求 JSON 解析失败: %v", err)
	}
	if req.Version != 1 {
		return DiagRequest{}, fmt.Errorf("不支持的契约版本: %d（仅支持 1）", req.Version)
	}
	if req.JobID != jobID {
		return DiagRequest{}, fmt.Errorf("请求体 job_id %q 与文件名 %q 不一致", req.JobID, jobID)
	}
	switch req.Action {
	case "ping", "tcp_probe", "traceroute", "dns_query", "capture":
	default:
		return DiagRequest{}, fmt.Errorf("未知动作 %q（白名单 ping/tcp_probe/traceroute/dns_query/capture）", req.Action)
	}
	return req, nil
}

// execute 执行已认领请求：结果写盘 + 删除 request/stop 文件（defer 兜底，
// 任何分支都保证请求文件被消化、结果文件完整原子可见）。
func (d *DiagService) execute(req DiagRequest, fileName string) {
	start := time.Now()
	res := DiagResult{JobID: req.JobID, ExitCode: -1}
	defer func() {
		d.finish(res, fileName, start)
	}()

	// 目标校验（纵深防御）：capture 无 target 语义，其余动作必须有合法目标
	if req.Action != "capture" && !validHostOrIP(req.Target) {
		res.Status = DiagFailed
		res.Stderr = fmt.Sprintf("非法目标 %q（仅允许 IPv4/IPv6 字面量或合法主机名）", req.Target)
		return
	}

	switch req.Action {
	case "tcp_probe":
		d.execTCPProbe(req, &res)
	case "dns_query":
		d.execDNSQuery(req, &res)
	case "ping":
		d.execPing(req, &res)
	case "traceroute":
		d.execTraceroute(req, &res)
	case "capture":
		d.execCapture(req, &res)
	}
}

// finish 收尾：补全结果字段，原子写 result 文件，删除 request/stop 文件。
func (d *DiagService) finish(res DiagResult, fileName string, start time.Time) {
	res.Stdout = truncDiagOutput(res.Stdout)
	res.Stderr = truncDiagOutput(res.Stderr)
	res.DurationMs = time.Since(start).Milliseconds()
	res.FinishedAt = d.now().UTC().Format(time.RFC3339)
	if err := d.writeResult(res); err != nil {
		log.Printf("[netmgrd/diag] 结果回写失败 job=%s: %v", res.JobID, err)
	}
	if err := os.Remove(filepath.Join(d.Dir, fileName)); err != nil && !os.IsNotExist(err) {
		log.Printf("[netmgrd/diag] 请求文件删除失败 %s: %v", fileName, err)
	}
	stopPath := filepath.Join(d.Dir, "stop-"+res.JobID)
	if err := os.Remove(stopPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[netmgrd/diag] stop 文件删除失败 %s: %v", stopPath, err)
	}
}

// writeResult 原子写结果文件（同目录临时文件 + rename，0644 供 server 消费）。
func (d *DiagService) writeResult(res DiagResult) error {
	data, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("序列化结果: %w", err)
	}
	return writeFileAtomic(filepath.Join(d.Dir, "result-"+res.JobID+".json"), data, 0o644)
}

// requestTimeout 请求超时归一化：<=0 取缺省，夹紧到 [1, cap] 秒。
func requestTimeout(sec int, hardCap time.Duration) time.Duration {
	if sec <= 0 {
		sec = diagDefaultTimeoutSec
	}
	t := time.Duration(sec) * time.Second
	if t > hardCap {
		t = hardCap
	}
	if t < time.Second {
		t = time.Second
	}
	return t
}

// stopFilePath 本请求的 stop 文件路径。
func (d *DiagService) stopFilePath(jobID string) string {
	return filepath.Join(d.Dir, "stop-"+jobID)
}

// awaitNative Go 原生动作（tcp_probe/dns_query）的统一等待：结果/超时/stop 文件三选。
// fn 在独立 goroutine 执行；stop 文件出现 → 等待 fn 随 ctx 取消结束后报 STOPPED。
func (d *DiagService) awaitNative(ctx context.Context, jobID string, timeout time.Duration,
	fn func(ctx context.Context) (string, error), res *DiagResult) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type nativeOutcome struct {
		stdout string
		err    error
	}
	done := make(chan nativeOutcome, 1)
	go func() {
		out, err := fn(cctx)
		done <- nativeOutcome{out, err}
	}()
	ticker := time.NewTicker(diagStopPollInterval)
	defer ticker.Stop()
	stopPath := d.stopFilePath(jobID)
	for {
		select {
		case out := <-done:
			if out.err != nil {
				if cctx.Err() == context.DeadlineExceeded {
					res.Status = DiagTimeout
				} else {
					res.Status = DiagFailed
				}
				res.Stderr = out.err.Error()
			} else {
				res.Status = DiagSuccess
				res.ExitCode = 0
				res.Stdout = out.stdout
			}
			return
		case <-ticker.C:
			if _, err := os.Stat(stopPath); err == nil {
				cancel()
				out := <-done // 等 fn 感知取消退出，丢弃其结果
				_ = out
				res.Status = DiagStopped
				return
			}
		}
	}
}

// execTCPProbe Go 原生 TCP 探测：net.DialTimeout 语义，端口缺省 80。
func (d *DiagService) execTCPProbe(req DiagRequest, res *DiagResult) {
	port := req.Params.Port
	if port == 0 {
		port = 80
	}
	if port < 1 || port > 65535 {
		res.Status = DiagFailed
		res.Stderr = fmt.Sprintf("非法端口 %d（需 1-65535）", port)
		return
	}
	addr := net.JoinHostPort(req.Target, strconv.Itoa(port))
	timeout := requestTimeout(req.TimeoutSec, 300*time.Second)
	d.awaitNative(context.Background(), req.JobID, timeout,
		func(ctx context.Context) (string, error) {
			start := time.Now()
			conn, err := d.dialContext(ctx, "tcp", addr)
			if err != nil {
				return "", fmt.Errorf("tcp 连接 %s 失败: %w", addr, err)
			}
			conn.Close()
			return fmt.Sprintf("connected to %s in %dms", addr, time.Since(start).Milliseconds()), nil
		}, res)
}

// execDNSQuery Go 原生 DNS 查询：A/AAAA（net.Resolver，context 超时）。
func (d *DiagService) execDNSQuery(req DiagRequest, res *DiagResult) {
	timeout := requestTimeout(req.TimeoutSec, 300*time.Second)
	d.awaitNative(context.Background(), req.JobID, timeout,
		func(ctx context.Context) (string, error) {
			ips, err := d.lookupIP(ctx, req.Target)
			if err != nil {
				return "", fmt.Errorf("dns 解析 %s 失败: %w", req.Target, err)
			}
			if len(ips) == 0 {
				return "", fmt.Errorf("dns 解析 %s 无 A/AAAA 记录", req.Target)
			}
			lines := make([]string, 0, len(ips))
			for _, ip := range ips {
				lines = append(lines, ip.String())
			}
			return strings.Join(lines, "\n"), nil
		}, res)
}

// execPing ping -c <count夹紧1-20> -W 2 <target>，硬超时 30s。
func (d *DiagService) execPing(req DiagRequest, res *DiagResult) {
	if !d.lookPath("ping") {
		res.Status = DiagFailed
		res.Stderr = "ping 二进制不存在（需安装 iputils 包）"
		return
	}
	count := req.Params.Count
	if count <= 0 {
		count = 4
	}
	count = clampInt(count, 1, 20)
	mapCmdOutcome(res, d.runCmd(context.Background(), cmdRunOpts{
		name:     "ping",
		args:     []string{"-c", strconv.Itoa(count), "-W", "2", req.Target},
		timeout:  requestTimeout(req.TimeoutSec, diagPingHardTimeout),
		stopFile: d.stopFilePath(req.JobID),
	}))
}

// execTraceroute traceroute -m <max_hops夹紧1-30> <target>；二进制不存在时回退
// tracepath；硬超时 60s。
func (d *DiagService) execTraceroute(req DiagRequest, res *DiagResult) {
	maxHops := req.Params.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}
	maxHops = clampInt(maxHops, 1, 30)
	bin := "traceroute"
	args := []string{"-m", strconv.Itoa(maxHops), req.Target}
	if !d.lookPath("traceroute") {
		if !d.lookPath("tracepath") {
			res.Status = DiagFailed
			res.Stderr = "traceroute/tracepath 均不存在（需安装 traceroute 或 iputils 包）"
			return
		}
		bin = "tracepath"
		args = []string{req.Target} // tracepath 无通用 -m 支持，仅传目标
	}
	mapCmdOutcome(res, d.runCmd(context.Background(), cmdRunOpts{
		name: bin, args: args,
		timeout:  requestTimeout(req.TimeoutSec, diagTracerouteHardTimeout),
		stopFile: d.stopFilePath(req.JobID),
	}))
}

// execCapture tcpdump 抓包：-i <iface> -w capture-<job_id>.pcap -s 128，
// 可选 -c <count>，过滤器固定模板 [proto] [host X] [port N]（and 连接，全部可选）。
// duration_sec 夹紧 5-300，到期 SIGTERM（属正常结束路径）；产物 >100MB 删除并报 FAILED。
func (d *DiagService) execCapture(req DiagRequest, res *DiagResult) {
	if !d.lookPath("tcpdump") {
		res.Status = DiagFailed
		res.Stderr = "tcpdump 二进制不存在（需安装 tcpdump 包）"
		return
	}
	iface := strings.TrimSpace(req.Params.Iface)
	if !ifNameRE.MatchString(iface) {
		res.Status = DiagFailed
		res.Stderr = fmt.Sprintf("capture 需要合法网卡名 params.iface: %q", iface)
		return
	}
	filter, err := buildCaptureFilter(req.Params)
	if err != nil {
		res.Status = DiagFailed
		res.Stderr = err.Error()
		return
	}
	duration := req.Params.DurationSec
	if duration <= 0 {
		duration = 10
	}
	duration = clampInt(duration, 5, 300)
	pcapName := "capture-" + req.JobID + ".pcap"
	pcapPath := filepath.Join(d.Dir, pcapName)
	args := []string{"-i", iface, "-w", pcapPath, "-s", "128"}
	if req.Params.Count > 0 {
		args = append(args, "-c", strconv.Itoa(req.Params.Count))
	}
	if filter != "" {
		args = append(args, filter)
	}
	out := d.runCmd(context.Background(), cmdRunOpts{
		name: "tcpdump", args: args,
		timeout:  time.Duration(duration) * time.Second,
		softKill: true, // 到期 SIGTERM 让 tcpdump 刷盘，宽限后 SIGKILL
		stopFile: d.stopFilePath(req.JobID),
	})

	// capture 特有意义映射：到期（抓满 duration）= 正常结束，按产物判定成败
	switch {
	case out.err != nil:
		res.Status = DiagFailed
		res.Stderr = "tcpdump 启动失败: " + out.err.Error()
		return
	case out.stopped:
		res.Status = DiagStopped
		res.Stdout, res.Stderr, res.ExitCode = out.stdout, out.stderr, out.exitCode
		return
	case !out.timedOut && out.exitCode != 0:
		res.Status = DiagFailed
		res.Stdout, res.Stderr, res.ExitCode = out.stdout, out.stderr, out.exitCode
		return
	}

	// 到期或 tcpdump 自行退出（-c 达标）：检查产物
	fi, statErr := os.Stat(pcapPath)
	if statErr != nil {
		res.Status = DiagFailed
		res.Stdout, res.Stderr = out.stdout, out.stderr
		res.Stderr = strings.TrimSpace(res.Stderr + "\n抓包结束但产物缺失: " + statErr.Error())
		return
	}
	if fi.Size() > diagCaptureMaxBytes {
		os.Remove(pcapPath)
		res.Status = DiagFailed
		res.Stdout = out.stdout
		res.Stderr = fmt.Sprintf("pcap 大小 %d 字节超过 100MB 上限，已删除", fi.Size())
		return
	}
	res.Status = DiagSuccess
	res.ExitCode = 0
	res.Stdout, res.Stderr = out.stdout, out.stderr
	res.CaptureFile = pcapName
	res.CaptureSize = fi.Size()
}

// buildCaptureFilter 固定模板拼装过滤器：[proto] [host X] [port N]，and 连接，
// 全部可选；proto 仅 tcp/udp/icmp，host 复用目标校验，port 需 1-65535。
func buildCaptureFilter(p DiagParams) (string, error) {
	var parts []string
	if proto := strings.TrimSpace(p.FilterProto); proto != "" {
		switch proto {
		case "tcp", "udp", "icmp":
			parts = append(parts, proto)
		default:
			return "", fmt.Errorf("非法 filter_proto %q（仅 tcp/udp/icmp）", proto)
		}
	}
	if host := strings.TrimSpace(p.FilterHost); host != "" {
		if !validHostOrIP(host) {
			return "", fmt.Errorf("非法 filter_host %q", host)
		}
		parts = append(parts, "host "+host)
	}
	if p.FilterPort != 0 {
		if p.FilterPort < 1 || p.FilterPort > 65535 {
			return "", fmt.Errorf("非法 filter_port %d（需 1-65535）", p.FilterPort)
		}
		parts = append(parts, "port "+strconv.Itoa(p.FilterPort))
	}
	return strings.Join(parts, " and "), nil
}

// mapCmdOutcome 通用外部命令结果 → 诊断结果映射（ping/traceroute）。
func mapCmdOutcome(res *DiagResult, out cmdOutcome) {
	res.Stdout, res.Stderr, res.ExitCode = out.stdout, out.stderr, out.exitCode
	switch {
	case out.err != nil:
		res.Status = DiagFailed
		res.Stderr = strings.TrimSpace(out.stderr + "\n" + out.err.Error())
	case out.stopped:
		res.Status = DiagStopped
	case out.timedOut:
		res.Status = DiagTimeout
	case out.exitCode != 0:
		res.Status = DiagFailed
	default:
		res.Status = DiagSuccess
	}
}

// defaultRunCmd 生产命令执行器：参数数组不经 shell；超时/停止按 softKill
// 决定先 SIGTERM（宽限 diagSoftKillGrace 后 SIGKILL）还是直接 SIGKILL。
func defaultRunCmd(ctx context.Context, opts cmdRunOpts) cmdOutcome {
	cmd := exec.Command(opts.name, opts.args...) //nolint:gosec // 动作白名单 + 参数数组 + 目标校验
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	if err := cmd.Start(); err != nil {
		return cmdOutcome{err: fmt.Errorf("启动 %s: %w", opts.name, err), exitCode: -1}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(opts.timeout)
	defer timer.Stop()
	var stopTick <-chan time.Time
	var ticker *time.Ticker
	if opts.stopFile != "" {
		ticker = time.NewTicker(diagStopPollInterval)
		defer ticker.Stop()
		stopTick = ticker.C
	}
	killAndWait := func() {
		terminateCmd(cmd, opts.softKill)
		<-done
	}
	for {
		select {
		case err := <-done:
			return cmdOutcome{
				stdout: so.String(), stderr: se.String(),
				exitCode: exitCodeOf(err),
			}
		case <-timer.C:
			killAndWait()
			return cmdOutcome{stdout: so.String(), stderr: se.String(), exitCode: -1, timedOut: true}
		case <-stopTick:
			if _, err := os.Stat(opts.stopFile); err == nil {
				killAndWait()
				return cmdOutcome{stdout: so.String(), stderr: se.String(), exitCode: -1, stopped: true}
			}
		case <-ctx.Done():
			killAndWait()
			return cmdOutcome{stdout: so.String(), stderr: se.String(), exitCode: -1, stopped: true}
		}
	}
}

// terminateCmd 终止进程：soft=true 先 SIGTERM（tcpdump 等需要刷盘），
// 宽限 diagSoftKillGrace 后仍未退出则 SIGKILL。
func terminateCmd(cmd *exec.Cmd, soft bool) {
	if cmd.Process == nil {
		return
	}
	if soft {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(diagSoftKillGrace, func() { _ = cmd.Process.Kill() })
		return
	}
	_ = cmd.Process.Kill()
}

// exitCodeOf 从 Wait 错误提取退出码（nil=0；信号终止=-1）。
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// truncDiagOutput 输出截断到 64KB（保留头部）。
func truncDiagOutput(s string) string {
	if len(s) <= diagOutputLimit {
		return s
	}
	return s[:diagOutputLimit]
}

// clampInt 整数夹紧到 [lo, hi]。
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
