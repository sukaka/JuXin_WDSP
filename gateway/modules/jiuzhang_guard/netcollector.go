package jiuzhang_guard

// 网口清单采集器装配（WDSP 阶段A 网口管理，docs/NETWORK_MODES_DESIGN.md §2.3）。
//
// 进程级单例，跟随共享引擎同一生命周期（常驻，配置重载同签名复用、异签名替换）：
// 启动时同步采集一次（写入快照后再起 60s 定时器），采集/写盘失败仅告警，
// 绝不阻断网关主流程。输出为全量快照原子替换（临时文件 + rename），
// 与事件日志同目录，经网关日志只读卷由服务端采集入库。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/netif"
	"go.uber.org/zap"
)

const (
	// netifCollectInterval 采集周期（设计文档 §2.3：启动 + 每 60s）
	netifCollectInterval = 60 * time.Second
	// netifSnapshotName 清单快照文件名（与事件日志同目录；服务端经只读卷采集）
	netifSnapshotName = "node-interfaces.jsonl"
)

// netifSysfsDir sysfs 网口目录（包级变量供测试替换）。
var netifSysfsDir = "/sys/class/net"

var (
	netifCollMu sync.Mutex
	netifColl   *netifCollectorHandle
)

type netifCollectorHandle struct {
	sig    string
	ctx    context.Context
	cancel context.CancelFunc
	// unavailable sysfs 缺失（已 Warn 一次）：同签名下不再重复尝试与告警
	unavailable bool
}

// ensureNetifCollector 启动/复用进程级网口清单采集器（Provision 时调用）。
func ensureNetifCollector(g *Guard) {
	dir := filepath.Dir(g.EventsLog)
	node := os.Getenv("GATEWAY_NODE_NAME")
	if node == "" {
		node = g.GatewayNode
	}
	sig := dir + "|" + node

	netifCollMu.Lock()
	h := netifColl
	if h != nil && h.sig == sig {
		netifCollMu.Unlock()
		return // 复用（含 unavailable 状态，不重复告警）
	}
	if h != nil && h.cancel != nil {
		h.cancel() // 签名变化：替换旧采集器
	}
	// ctx/cancel 随 handle 一次性发布：替换窗口内并发 Provision 读到的 cancel 必非 nil，
	// 旧 runner 不会因读到 nil 而跳过取消泄漏
	ctx, cancel := context.WithCancel(context.Background())
	h = &netifCollectorHandle{sig: sig, ctx: ctx, cancel: cancel}
	netifColl = h
	netifCollMu.Unlock()

	if _, err := os.Stat(netifSysfsDir); err != nil {
		// 非 Linux 宿主（开发机）或容器未挂载 /sys：Warn 一次后跳过，不影响主流程。
		// 未起 runner：立即回收 ctx 并清空 ctx/cancel，保持「unavailable 无可取消执行体」语义
		cancel()
		netifCollMu.Lock()
		h.ctx, h.cancel = nil, nil
		h.unavailable = true
		netifCollMu.Unlock()
		g.logger.Warn("netif collector: sysfs 不可用，跳过网口清单采集",
			zap.String("sysfs_dir", netifSysfsDir), zap.Error(err))
		return
	}
	// 注意保持接口语义：ethtool 缺失时必须把 nil 接口（而非 nil 指针）传给 runner
	var prober netif.Prober
	if ep := netif.NewEthtoolProber(); ep != nil {
		prober = ep
	} else {
		// 容器内通常无 ethtool：介质识别降级 UNKNOWN（设计文档 §2.3 降级路径）
		g.logger.Warn("netif collector: ethtool 不可用，media_type 降级 UNKNOWN（可在宿主机运行 ops 脚本补全介质识别）")
	}

	r := &netifRunner{
		sysfsDir: netifSysfsDir,
		outPath:  filepath.Join(dir, netifSnapshotName),
		node:     node,
		prober:   prober,
		logger:   g.logger,
	}
	r.collectOnce() // 启动时同步首采（失败仅告警）
	go r.loop(ctx)
}

// resetNetifCollectorForTest 测试辅助：停止并清空进程级采集器。
func resetNetifCollectorForTest() {
	netifCollMu.Lock()
	defer netifCollMu.Unlock()
	if netifColl != nil && netifColl.cancel != nil {
		netifColl.cancel()
	}
	netifColl = nil
}

// netifRunner 周期采集执行体。
type netifRunner struct {
	sysfsDir string
	outPath  string
	node     string
	prober   netif.Prober
	logger   *zap.Logger
	// lastErr / lastProbeErr 连续同类错误去重（仅告警一次，恢复时 Info）
	lastErr      string
	lastProbeErr string
}

func (r *netifRunner) loop(ctx context.Context) {
	t := time.NewTicker(netifCollectInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.collectOnce()
		}
	}
}

// collectOnce 采集一次并原子重写快照；任何失败仅告警（错误去重），不影响网关主流程。
func (r *netifRunner) collectOnce() {
	inv, err := netif.Collect(r.sysfsDir, r.prober)
	if err != nil {
		r.reportErr(err)
		return
	}
	if err := netif.WriteSnapshot(r.outPath, r.node, inv.Interfaces, time.Now().UTC()); err != nil {
		r.reportErr(err)
		return
	}
	if r.lastErr != "" {
		r.logger.Info("netif collector: 采集已恢复")
		r.lastErr = ""
	}
	if len(inv.ProbeErrors) > 0 {
		r.reportProbeErrs(inv.ProbeErrors)
	}
}

func (r *netifRunner) reportErr(err error) {
	msg := err.Error()
	if msg == r.lastErr {
		return
	}
	r.lastErr = msg
	r.logger.Warn("netif collector: 采集/写入失败（不影响网关主流程）", zap.Error(err))
}

func (r *netifRunner) reportProbeErrs(errs []error) {
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	msg := strings.Join(msgs, "; ")
	if msg == r.lastProbeErr {
		return
	}
	r.lastProbeErr = msg
	r.logger.Warn("netif collector: ethtool 探测失败（相关字段降级兜底值）",
		zap.Int("count", len(errs)), zap.String("errors", msg))
}
