package jiuzhang_guard

// 网关节点心跳（W17-HB，任务书 §201 活性+版本上报升级）。
//
// 背景：多节点版本校验 v1（W12-NODE）以 api_runtime_events 业务流量事件为节点活性与
// 策略版本数据源——无流量时段节点状态失真（SILENT 误判）、版本停留在最后一次发布。
// 架构约束为网关→管理面单向日志采集（不可新增反向 HTTP 推送），故心跳复用现有
// API 事件日志通道：周期向 api-runtime-events.log 写入合成心跳记录（heartbeat=true），
// 采集端识别后不产任何业务数据，仅透传给节点活性聚合（server apiruntime/apinodes）。
//
// 生命周期：Provision 装配时启动（api_dynamic_protection 开启且
// api_node_heartbeat_seconds>0），Cleanup/配置重载时停止并等待 goroutine 退出，
// 不泄漏。发射失败仅告警（同类错误去重，恢复时 Info 一条），绝不影响网关主流程。

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

const (
	// heartbeatEndpointKey 心跳记录端点键占位（无业务端点语义；采集端不落端点资产，
	// 与 server 侧 apiruntime/apinodes 的心跳识别口径一致，不得随业务端点命名改动）。
	heartbeatEndpointKey = "__heartbeat__"
	// 心跳间隔合法范围（秒）：0 = 关闭；开启时为 30~300。过密徒增日志量，
	// 过疏活性判定滞后——节点状态窗口为 5min/1h，300s 周期仍保留心跳冗余。
	minHeartbeatSeconds = 30
	maxHeartbeatSeconds = 300
)

// heartbeatRunner 周期心跳发射体（每 Guard 实例一个，随 Cleanup 停止）。
type heartbeatRunner struct {
	log        *apievents.Logger
	logger     *zap.Logger
	interval   time.Duration
	policyVer  string // 装配时快照（配置重载 = 新 Guard 实例新 runner，无需动态读取）
	modelCount int
	startTime  time.Time
	seq        atomic.Int64
	cancel     context.CancelFunc
	done       chan struct{}
	lastErr    string // 同类发射错误去重（防日志洪泛；恢复时 Info 一条）
	// authzState NG-AZ-02 D6 授权 ACK 状态提供者（注册表合并态；nil/返回 false = 未启用
	// 授权快照，心跳不携带 authz 字段——v1 零变化）
	authzState func() (authzACKState, bool)
}

func newHeartbeatRunner(log *apievents.Logger, logger *zap.Logger, interval time.Duration, policyVer string, modelCount int) *heartbeatRunner {
	return &heartbeatRunner{
		log: log, logger: logger, interval: interval,
		policyVer: policyVer, modelCount: modelCount,
		startTime: time.Now().UTC(),
	}
}

// SetAuthzStateProvider 注入授权 ACK 状态提供者（NG-AZ-02 D6；启动前调用，nil 忽略）。
func (r *heartbeatRunner) SetAuthzStateProvider(fn func() (authzACKState, bool)) {
	if fn != nil {
		r.authzState = fn
	}
}

// emit 输出一条心跳记录。RequestID 由启动时间戳+序号生成（单 runner 内序号单调，
// 跨装配由启动时间区分，全局唯一）：采集端按 request_id 幂等口径消费，
// 日志重放/重复采集不产生重复活性数据。
func (r *heartbeatRunner) emit() error {
	now := time.Now().UTC()
	rec := apievents.Record{
		RequestID: "hb-" + strconv.FormatInt(r.startTime.Unix(), 36) +
			"-" + strconv.FormatInt(r.seq.Add(1), 36),
		OccurredAt:          now,
		EndpointKey:         heartbeatEndpointKey,
		FinalAction:         "ALLOW",
		RiskLevel:           "NONE",
		Heartbeat:           true,
		PolicyVersion:       r.policyVer,
		FormalModelVersions: r.modelCount,
		UptimeSeconds:       int64(now.Sub(r.startTime).Seconds()),
		GuardStartTime:      &r.startTime,
	}
	// NG-AZ-02 D6：授权 ACK 字段（注册表合并态；未启用授权快照时不携带——v1 零变化）
	if r.authzState != nil {
		if st, ok := r.authzState(); ok {
			rec.AuthzPolicyVersion = st.PolicyVersion
			rec.AuthzWatermark = authzWatermarkToEvents(st.Watermark)
			rec.AuthzSnapshotExpiresAt = st.SnapshotExpiresAt
			if st.LeaseSeconds > 0 {
				rec.AuthzLeaseSeconds = st.LeaseSeconds
			}
			if !st.AppliedAt.IsZero() {
				t := st.AppliedAt
				rec.AuthzAppliedAt = &t
			}
		}
	}
	return r.log.Emit(rec)
}

// authzWatermarkToEvents 注册表水位 → apievents 水位（跨包类型转换，键值逐项拷贝不共享）。
func authzWatermarkToEvents(w *authzWatermarkJSON) *apievents.AuthzWatermark {
	if w == nil {
		return nil
	}
	out := &apievents.AuthzWatermark{ManualSeq: w.ManualSeq}
	if len(w.Sources) > 0 {
		out.Sources = map[string]int64{}
		for k, v := range w.Sources {
			out.Sources[k] = v
		}
	}
	return out
}

// tick 发射一拍；失败仅告警（同类错误去重），不影响网关主流程。
func (r *heartbeatRunner) tick() {
	if err := r.emit(); err != nil {
		if msg := err.Error(); msg != r.lastErr {
			r.lastErr = msg
			r.logger.Warn("api node heartbeat emit failed（不影响网关主流程）", zap.Error(err))
		}
		return
	}
	if r.lastErr != "" {
		r.lastErr = ""
		r.logger.Info("api node heartbeat emit recovered")
	}
}

// run 启动后立即首跳（活性即时建立，不等首个周期），随后按周期发射；ctx 取消时退出。
func (r *heartbeatRunner) run(ctx context.Context) {
	defer close(r.done)
	r.tick()
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick()
		}
	}
}

// start 启动后台 goroutine。
func (r *heartbeatRunner) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go r.run(ctx)
}

// stop 取消并等待 goroutine 退出（幂等；Cleanup/配置重载路径调用，不泄漏 goroutine）。
func (r *heartbeatRunner) stop() {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	if r.done != nil {
		<-r.done
	}
}

// startAPINodeHeartbeat 装配节点心跳（Provision 在 apiEvents 就绪后调用）：
// 0=关闭（缺省）零行为变化；开启时周期向 API 事件日志写合成心跳记录。
func (g *Guard) startAPINodeHeartbeat() {
	if g.APINodeHeartbeatSeconds <= 0 || g.apiEvents == nil {
		return
	}
	r := newHeartbeatRunner(g.apiEvents, g.logger,
		time.Duration(g.APINodeHeartbeatSeconds)*time.Second,
		g.APIPolicyVersion, len(g.APIFormalModelVersions))
	// NG-AZ-02 D6：授权 ACK 状态提供者（注册表合并态；无授权内容时返回 false，字段省略）
	r.SetAuthzStateProvider(defaultAuthzRegistry.merged)
	r.start()
	g.heartbeat = r
	g.logger.Info("api node heartbeat enabled",
		zap.Int("interval_seconds", g.APINodeHeartbeatSeconds),
		zap.String("policy_version", g.APIPolicyVersion),
		zap.Int("formal_model_versions", len(g.APIFormalModelVersions)))
}
