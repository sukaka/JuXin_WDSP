// coverage_out.go 覆盖观测进程级输出单例（NG-COV-01 guard 侧装配挂点）。
//
// 语义与纪律：
//   - 默认关闭：COVERAGE_OBSERVATIONS_ENABLED 未显式为真值（1/true/on）时
//     coverageEmitter() 返回 nil → pipeline.Config.Coverage=nil，零行为变化；
//   - 开启时懒初始化（sync.Once）：NewFileSink + NewEmitter + Start，并启动
//     节点计数快照 janitor（周期把 DefaultCovCounters 快照写为同一 JSONL 的
//     counter_snapshot 行——record_type 路由字段，server 采集器据此分流入库）；
//   - 进程级单例：与应用 Cleanup 解耦、随进程生命周期（多应用共享同一发射器与
//     计数器；emitter 不在应用 Cleanup 中停止，避免互相踩踏，与共享引擎同策略）。
//   - 热路径零新增依赖：仅环境变量读取（GATEWAY_NODE_NAME /
//     GATEWAY_COVERAGE_OBS_LOG 默认 /var/log/caddy/coverage-observations.jsonl）。
package jiuzhang_guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

// 环境变量名（装配常量；enable 语义：未显式真值 = 关闭）。
const (
	covEnabledEnv = "COVERAGE_OBSERVATIONS_ENABLED"
	covLogEnv     = "GATEWAY_COVERAGE_OBS_LOG"
	covNodeEnv    = "GATEWAY_NODE_NAME"

	defaultCovLogPath = "/var/log/caddy/coverage-observations.jsonl"
	covCounterTick    = 60 * time.Second
)

var (
	covOnce   sync.Once
	covHandle *covOutHandle
)

// covOutHandle 输出句柄（仅在开启时构建）。
type covOutHandle struct {
	emitter  *coverage.Emitter
	sink     *coverage.FileSink
	nodeName string
	stopJan  chan struct{}
	janDone  chan struct{}
}

// coverageEnabled 开关判定（真值集与既有 GUARD 类开关同口径）。
func coverageEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(covEnabledEnv))) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// coverageLogPath 输出文件路径（环境变量缺省回退默认路径；dir 取其目录）。
func coverageLogPath() string {
	if v := strings.TrimSpace(os.Getenv(covLogEnv)); v != "" {
		return v
	}
	return defaultCovLogPath
}

// coverageEmitter 返回进程级覆盖发射器；未启用返回 nil（调用方按 nil=关闭处理）。
func coverageEmitter() *coverage.Emitter {
	if !coverageEnabled() {
		return nil
	}
	covOnce.Do(initCovOut)
	if covHandle == nil {
		return nil
	}
	return covHandle.emitter
}

// coverageNodeName 节点名（观测/计数快照 node_id；与 netcollector 同口径）。
func coverageNodeName() string {
	return strings.TrimSpace(os.Getenv(covNodeEnv))
}

// initCovOut 懒初始化输出句柄与计数快照 janitor（仅调用方已判定开启后进入）。
func initCovOut() {
	sink := coverage.NewFileSink(filepath.Dir(coverageLogPath()))
	em := coverage.NewEmitter(1024, 128, sink)
	em.Start()
	h := &covOutHandle{
		emitter:  em,
		sink:     sink,
		nodeName: coverageNodeName(),
		stopJan:  make(chan struct{}),
		janDone:  make(chan struct{}),
	}
	go h.counterJanitor(covCounterTick)
	covHandle = h
}

// resetCovOutForTest 重置输出单例（仅测试使用：停止 janitor 与发射器、重建 Once，
// 使开启/关闭用例可在同进程内顺序执行；生产路径只经 coverageEmitter 懒初始化）。
func resetCovOutForTest() {
	if covHandle != nil {
		close(covHandle.stopJan)
		<-covHandle.janDone
		covHandle.emitter.Stop()
		_ = covHandle.sink.Close()
		covHandle = nil
	}
	covOnce = sync.Once{}
}

// counterSnapshotLine 计数快照行（record_type=counter_snapshot，server 采集器路由键）。
type counterSnapshotLine struct {
	RecordType string          `json:"record_type"`
	NodeID     string          `json:"node_id"`
	CapturedAt string          `json:"captured_at"`
	Counts     []CovStageCount `json:"counts"`
}

// writeCounterSnapshot 立刻写一份计数快照（janitor 周期调用；测试可直接调用）。
func (h *covOutHandle) writeCounterSnapshot() {
	line := counterSnapshotLine{
		RecordType: "counter_snapshot",
		NodeID:     h.nodeName,
		CapturedAt: time.Now().UTC().Format(time.RFC3339),
		Counts:     DefaultCovCounters.Snapshot(),
	}
	b, err := json.Marshal(line)
	if err != nil { // 结构全字段可序列化，理论不可达；失败仅放弃本次
		return
	}
	h.sink.WriteRaw(b)
}

// counterJanitor 周期计数快照（60s tick；stopJan 关闭时收尾退出）。
func (h *covOutHandle) counterJanitor(tick time.Duration) {
	defer close(h.janDone)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			h.writeCounterSnapshot()
		case <-h.stopJan:
			return
		}
	}
}
