// Package hastatus 主备高可用与网络执行状态告警清扫器（M4）：
// 周期读取边车卷状态文件（network-status.json / ha-vip-status.json，网关侧
// netmgrd/havipd 回写），异常经系统告警引擎 Raise（合并/冷却/抖动抑制复用引擎
// 机制），恢复 AutoRecover——与 apinodes.Sweeper 同一模式。
//
// 覆盖范围（如实边界）：仅 api 容器挂载的本节点边车卷（与 netconfig/hagroups
// 状态透传同一口径）；其他节点的 HA 状态告警待节点级遥测通道。
//
// 判定语义：
//   - 状态文件不存在 = 能力未启用/已收回：不告警，并对既有告警 AutoRecover；
//   - 解析失败 = 契约破坏/写盘损坏：告警；
//   - network-status ok=false（含 link_pairs PROPAGATED_DOWN/SUPPRESSED）：告警；
//   - ha-vip FAULT、ENABLED 但 keepalived 不存活、配置存在但状态文件过期
//     （havipd 疑似停止）：告警；DISABLED/STOPPED 为运维意图，不告警。
package hastatus

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// 告警类型（须在 systemalerts/rules.go severityRules 注册）。
const (
	TypeHAVIPFault         = "HA_VIP_FAULT"
	TypeNetworkApplyFailed = "NETWORK_APPLY_FAILED"
	TypeLinkPairDown       = "LINK_PAIR_DOWN"
	TypeLinkPairSuppressed = "LINK_PAIR_SUPPRESSED"
)

// 告警 component（固定常量，变动信息只放 message——引擎按指纹合并）。
const (
	ComponentHAVIP    = "HA_VIP"
	ComponentNetwork  = "NETWORK"
	ComponentLinkPair = "LINK_PAIR"
)

// 状态文件名（与网关侧契约一致，勿单方面变更）。
const (
	networkStatusFile = "network-status.json"
	haVipStatusFile   = "ha-vip-status.json"
	haVipConfigFile   = "ha-vip.json"
)

// havipStaleThreshold havipd 状态文件过期阈值（havipd 每秒刷新 status；
// 超过该时长未刷新 = havipd 疑似停止）。
const havipStaleThreshold = 30 * time.Second

// Alerter 系统告警接口（*systemalerts.Engine 天然实现，装配时直接注入）。
type Alerter interface {
	NotifyFailure(ctx context.Context, alertType, component, title, message string) (*systemalerts.Alert, error)
	AutoRecover(ctx context.Context, component string, alertTypes ...string) (int, error)
}

// ---------- 网关侧状态契约镜像（勿单方面变更） ----------

// networkStatus network-status.json 镜像（netmgrd 回写）。
type networkStatus struct {
	OK        bool   `json:"ok"`
	Message   string `json:"message"`
	LinkPairs []struct {
		Bridge         string `json:"bridge"`
		State          string `json:"state"` // BOTH_UP/PROPAGATED_DOWN/SUPPRESSED
		DownPort       string `json:"down_port"`
		PropagatedPort string `json:"propagated_port"`
		Message        string `json:"message"`
	} `json:"link_pairs"`
}

// haVipStatus ha-vip-status.json 镜像（havipd 回写）。
type haVipStatus struct {
	Group             string `json:"group"`
	Node              string `json:"node"`
	State             string `json:"state"` // MASTER/BACKUP/FAULT/DISABLED/STOPPED
	KeepalivedRunning bool   `json:"keepalived_running"`
	Message           string `json:"message"`
}

// Sweeper HA/网络状态告警清扫器。
type Sweeper struct {
	dir      string
	interval time.Duration
	alerter  Alerter
	now      func() time.Time
}

// NewSweeper 创建清扫器（dir = sidecar 卷目录；默认 30s 周期）。
func NewSweeper(dir string) *Sweeper {
	return &Sweeper{dir: dir, interval: 30 * time.Second, now: time.Now}
}

// SetAlerter 注入告警引擎。
func (s *Sweeper) SetAlerter(a Alerter) *Sweeper { s.alerter = a; return s }

// SetInterval 覆盖周期（测试用）。
func (s *Sweeper) SetInterval(d time.Duration) *Sweeper { s.interval = d; return s }

// Run 周期驱动（直到 ctx 取消）。
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.SweepOnce(ctx); err != nil {
				slog.Error("ha status sweep failed", "error", err)
			}
		}
	}
}

// SweepOnce 执行一轮清扫（可由调度与测试直接调用）。
func (s *Sweeper) SweepOnce(ctx context.Context) error {
	if s.alerter == nil {
		return nil
	}
	s.sweepNetwork(ctx)
	s.sweepHAVIP(ctx)
	return nil
}

// sweepNetwork 网络执行状态（network-status.json + link_pairs）。
func (s *Sweeper) sweepNetwork(ctx context.Context) {
	path := filepath.Join(s.dir, networkStatusFile)
	st, err := readJSON[networkStatus](path)
	switch {
	case os.IsNotExist(err):
		// 未启用/已收回：恢复既有告警
		s.recover(ctx, ComponentNetwork, TypeNetworkApplyFailed)
		s.recover(ctx, ComponentLinkPair, TypeLinkPairDown, TypeLinkPairSuppressed)
		return
	case err != nil:
		s.raise(ctx, TypeNetworkApplyFailed, ComponentNetwork,
			"网络执行状态文件解析失败", fmt.Sprintf("%s 无法解析（契约破坏/写盘损坏）: %v", path, err))
		return
	}

	if !st.OK {
		s.raise(ctx, TypeNetworkApplyFailed, ComponentNetwork,
			"网络配置执行存在失败项", st.Message)
	} else {
		s.recover(ctx, ComponentNetwork, TypeNetworkApplyFailed)
	}

	// 端口联动：PROPAGATED_DOWN = 链路故障已联动（设计行为但属故障信号）；
	// SUPPRESSED = 频率超限抑制（需人工关注）；全部 BOTH_UP 恢复。
	down, suppressed := []string{}, []string{}
	for _, lp := range st.LinkPairs {
		switch lp.State {
		case "PROPAGATED_DOWN":
			down = append(down, fmt.Sprintf("桥 %s（故障口 %s）", lp.Bridge, lp.DownPort))
		case "SUPPRESSED":
			suppressed = append(suppressed, fmt.Sprintf("桥 %s", lp.Bridge))
		}
	}
	if len(down) > 0 {
		s.raise(ctx, TypeLinkPairDown, ComponentLinkPair,
			"端口联动已触发（链路故障）",
			fmt.Sprintf("以下网桥存在链路故障并已联动 down 配对口: %s；请检查物理链路", joinComma(down)))
	} else {
		s.recover(ctx, ComponentLinkPair, TypeLinkPairDown)
	}
	if len(suppressed) > 0 {
		s.raise(ctx, TypeLinkPairSuppressed, ComponentLinkPair,
			"端口联动频率超限进入抑制态",
			fmt.Sprintf("以下网桥联动频率超限已冻结动作: %s；请检查物理链路后重新保存一次网络配置复位", joinComma(suppressed)))
	} else {
		s.recover(ctx, ComponentLinkPair, TypeLinkPairSuppressed)
	}
}

// sweepHAVIP 主备 VIP 状态（ha-vip-status.json）。
func (s *Sweeper) sweepHAVIP(ctx context.Context) {
	cfgPath := filepath.Join(s.dir, haVipConfigFile)
	stPath := filepath.Join(s.dir, haVipStatusFile)
	_, cfgErr := os.Stat(cfgPath)
	configExists := cfgErr == nil

	st, err := readJSON[haVipStatus](stPath)
	switch {
	case os.IsNotExist(err):
		if configExists {
			s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
				"主备配置已下发但 havipd 未上报状态",
				"ha-vip.json 存在而 ha-vip-status.json 不存在：havipd 未运行或未产出状态，VIP 可能未生效")
			return
		}
		s.recover(ctx, ComponentHAVIP, TypeHAVIPFault)
		return
	case err != nil:
		s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
			"主备状态文件解析失败", fmt.Sprintf("%s 无法解析: %v", stPath, err))
		return
	}

	// 状态文件过期（havipd 每秒刷新；过期 = 疑似停止）
	if configExists {
		if fi, statErr := os.Stat(stPath); statErr == nil && s.now().Sub(fi.ModTime()) > havipStaleThreshold {
			s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
				"havipd 疑似停止（状态文件过期）",
				fmt.Sprintf("ha-vip-status.json 已超过 %s 未刷新（最近 %s），主备组 %s 的 VIP 状态不可信",
					havipStaleThreshold, fi.ModTime().Format("01-02 15:04:05"), st.Group))
			return
		}
	}

	switch {
	case st.State == "FAULT":
		s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
			fmt.Sprintf("主备组 %s keepalived 实例异常", st.Group),
			orDefault(st.Message, "keepalived 进程不存活（配置启用中）"))
	case st.State != "DISABLED" && st.State != "STOPPED" && !st.KeepalivedRunning && configExists:
		s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
			fmt.Sprintf("主备组 %s keepalived 未运行", st.Group),
			fmt.Sprintf("配置启用但 keepalived 未运行（当前状态 %s），VIP 可能未生效", st.State))
	default:
		// MASTER/BACKUP 正常；DISABLED/STOPPED 为运维意图
		s.recover(ctx, ComponentHAVIP, TypeHAVIPFault)
	}
}

// raise 产告警（引擎 FindOpen→Merge 去重，sweeper 侧不做指纹）。
func (s *Sweeper) raise(ctx context.Context, alertType, component, title, message string) {
	if _, err := s.alerter.NotifyFailure(ctx, alertType, component, title, message); err != nil {
		slog.Error("raise ha status alert failed", "type", alertType, "component", component, "error", err)
	}
}

// recover 恢复告警（RECOVERED；抖动中的由引擎保持 OPEN）。
func (s *Sweeper) recover(ctx context.Context, component string, alertTypes ...string) {
	if _, err := s.alerter.AutoRecover(ctx, component, alertTypes...); err != nil {
		slog.Error("auto recover ha status alert failed", "component", component, "error", err)
	}
}

// readJSON 读并解析 JSON 文件（os.ErrNotExist 原样透传供 switch 判定）。
func readJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("解析 %s: %w", path, err)
	}
	return &v, nil
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "、"
		}
		out += s
	}
	return out
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
