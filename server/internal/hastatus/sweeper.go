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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// 告警类型（须在 systemalerts/rules.go severityRules 注册）。
const (
	TypeHAVIPFault         = "HA_VIP_FAULT"
	TypeHASplitBrain       = "HA_SPLIT_BRAIN"
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
	Group             string   `json:"group"`
	Node              string   `json:"node"`
	State             string   `json:"state"` // MASTER/BACKUP/FAULT/DISABLED/STOPPED
	KeepalivedRunning bool     `json:"keepalived_running"`
	VIPsPresent       []string `json:"vips_present"`
	Message           string   `json:"message"`
}

// HAGroupSnapshot 描述一个主备组及其成员节点名（跨节点脑裂与故障巡检用）。
type HAGroupSnapshot struct {
	ID          string
	Name        string
	State       string // ENABLED / DISABLED
	MemberNodes []string
}

// NodeStatusSnapshot 描述单节点汇聚后的 HA VIP 与网络执行状态快照（来自 api_gateway_nodes）。
type NodeStatusSnapshot struct {
	NodeName        string
	HaVipStatus     json.RawMessage
	HaVipStatusAt   *time.Time
	NetworkStatus   json.RawMessage
	NetworkStatusAt *time.Time
}

// MultiNodeProvider 多节点 HA/网络状态数据源（Phase 3 由 app.go 适配 haStore + apiNodeStore 装配；
// nil 时保持原有单节点本机边车文件检查行为不变）。
type MultiNodeProvider interface {
	ListHAGroups(ctx context.Context) ([]HAGroupSnapshot, error)
	ListNodeStatuses(ctx context.Context) ([]NodeStatusSnapshot, error)
}

// SplitBrainEventRecorder 脑裂新触发时的持久化事件回调（写入 ha_events SPLIT_BRAIN，按组状态转换去重）。
type SplitBrainEventRecorder func(ctx context.Context, groupID, groupName string, masters []string, overlappingVIPs []string) error

// Sweeper HA/网络状态告警清扫器。
type Sweeper struct {
	dir           string
	localNodeName string
	interval      time.Duration
	alerter       Alerter
	multiNode     MultiNodeProvider
	onSplitBrain  SplitBrainEventRecorder
	now           func() time.Time

	mu               sync.Mutex
	splitBrainActive map[string]bool // groupID (or name) -> currently in split-brain
}

// NewSweeper 创建清扫器（dir = sidecar 卷目录；默认 30s 周期）。
func NewSweeper(dir string) *Sweeper {
	return &Sweeper{
		dir:              dir,
		interval:         30 * time.Second,
		now:              time.Now,
		splitBrainActive: make(map[string]bool),
	}
}

// SetAlerter 注入告警引擎。
func (s *Sweeper) SetAlerter(a Alerter) *Sweeper { s.alerter = a; return s }

// SetInterval 覆盖周期（测试用）。
func (s *Sweeper) SetInterval(d time.Duration) *Sweeper { s.interval = d; return s }

// SetClock 覆盖时钟（测试用）。
func (s *Sweeper) SetClock(fn func() time.Time) *Sweeper {
	if fn != nil {
		s.now = fn
	}
	return s
}

// SetLocalNodeName 设置本机网关节点名（多节点汇聚时优先合并本机更新鲜的边车文件）。
func (s *Sweeper) SetLocalNodeName(name string) *Sweeper {
	s.localNodeName = strings.TrimSpace(name)
	return s
}

// SetMultiNodeProvider 注入多节点 HA/网络汇聚数据源（Phase 3 启用全集群巡检与脑裂告警）。
func (s *Sweeper) SetMultiNodeProvider(p MultiNodeProvider) *Sweeper {
	s.multiNode = p
	return s
}

// SetSplitBrainEventRecorder 注入脑裂事件持久化回调（ha_events SPLIT_BRAIN）。
func (s *Sweeper) SetSplitBrainEventRecorder(fn SplitBrainEventRecorder) *Sweeper {
	s.onSplitBrain = fn
	return s
}

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
	if s.multiNode == nil {
		s.sweepNetwork(ctx)
		s.sweepHAVIP(ctx)
		return nil
	}
	groups, gErr := s.multiNode.ListHAGroups(ctx)
	nodes, nErr := s.multiNode.ListNodeStatuses(ctx)
	if gErr != nil || nErr != nil {
		slog.Warn("multi-node ha status query failed, falling back to local sidecar sweep",
			"groups_err", gErr, "nodes_err", nErr)
		s.sweepNetwork(ctx)
		s.sweepHAVIP(ctx)
		return nil
	}
	s.sweepMultiNodeNetwork(ctx, nodes)
	s.sweepMultiNodeHAVIP(ctx, groups, nodes)
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

// sweepMultiNodeNetwork 评估本机及所有远端节点汇聚的 network-status（含 link_pairs）。
func (s *Sweeper) sweepMultiNodeNetwork(ctx context.Context, nodes []NodeStatusSnapshot) {
	netByNode := make(map[string]json.RawMessage, len(nodes)+1)
	for _, n := range nodes {
		if n.NodeName != "" && len(n.NetworkStatus) > 0 {
			netByNode[n.NodeName] = n.NetworkStatus
		}
	}

	var netFailures, down, suppressed []string

	// 本机边车文件优先覆盖 localNodeName（若存在且损坏则直接报解析失败）
	localLabel := s.localNodeName
	if localLabel == "" {
		localLabel = "local"
	}
	localPath := filepath.Join(s.dir, networkStatusFile)
	if raw, err := os.ReadFile(localPath); err == nil {
		if json.Valid(raw) {
			netByNode[localLabel] = json.RawMessage(raw)
		} else {
			netFailures = append(netFailures, fmt.Sprintf("节点 %s 状态文件解析失败", localLabel))
			delete(netByNode, localLabel)
		}
	} else if !os.IsNotExist(err) {
		netFailures = append(netFailures, fmt.Sprintf("节点 %s 状态文件读取失败: %v", localLabel, err))
	}

	nodeNames := make([]string, 0, len(netByNode))
	for name := range netByNode {
		nodeNames = append(nodeNames, name)
	}
	sort.Strings(nodeNames)

	for _, name := range nodeNames {
		var st networkStatus
		if err := json.Unmarshal(netByNode[name], &st); err != nil {
			netFailures = append(netFailures, fmt.Sprintf("节点 %s 网络状态解析失败: %v", name, err))
			continue
		}
		if !st.OK {
			netFailures = append(netFailures, fmt.Sprintf("节点 %s: %s", name, orDefault(st.Message, "网络配置应用失败")))
		}
		for _, lp := range st.LinkPairs {
			switch lp.State {
			case "PROPAGATED_DOWN":
				down = append(down, fmt.Sprintf("节点 %s 桥 %s（故障口 %s）", name, lp.Bridge, lp.DownPort))
			case "SUPPRESSED":
				suppressed = append(suppressed, fmt.Sprintf("节点 %s 桥 %s", name, lp.Bridge))
			}
		}
	}

	if len(netFailures) > 0 {
		s.raise(ctx, TypeNetworkApplyFailed, ComponentNetwork,
			"网络配置执行存在失败项", joinComma(netFailures))
	} else {
		s.recover(ctx, ComponentNetwork, TypeNetworkApplyFailed)
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

type nodeHaStatusEntry struct {
	raw       json.RawMessage
	updatedAt *time.Time
	parseErr  error
}

// sweepMultiNodeHAVIP 评估全部 ENABLED 主备组成员节点的汇聚 HA 状态与双主脑裂。
func (s *Sweeper) sweepMultiNodeHAVIP(ctx context.Context, groups []HAGroupSnapshot, nodes []NodeStatusSnapshot) {
	now := s.now().UTC()
	byNode := make(map[string]nodeHaStatusEntry, len(nodes)+1)
	for _, n := range nodes {
		if n.NodeName == "" || len(n.HaVipStatus) == 0 {
			continue
		}
		byNode[n.NodeName] = nodeHaStatusEntry{
			raw:       n.HaVipStatus,
			updatedAt: n.HaVipStatusAt,
		}
	}

	// 合并本机 ha-vip-status.json（仅在缺失或更新时间更新鲜时覆盖本机节点条目）
	localPath := filepath.Join(s.dir, haVipStatusFile)
	if fi, statErr := os.Stat(localPath); statErr == nil {
		mt := fi.ModTime().UTC()
		data, readErr := os.ReadFile(localPath)
		if readErr == nil {
			var parsed haVipStatus
			pErr := json.Unmarshal(data, &parsed)
			nodeName := strings.TrimSpace(parsed.Node)
			if nodeName == "" {
				nodeName = s.localNodeName
			}
			if nodeName != "" {
				existing, exists := byNode[nodeName]
				if !exists || existing.updatedAt == nil || mt.After(*existing.updatedAt) {
					byNode[nodeName] = nodeHaStatusEntry{
						raw:       json.RawMessage(data),
						updatedAt: &mt,
						parseErr:  pErr,
					}
				}
			}
		}
	}

	enabledGroups := make([]HAGroupSnapshot, 0, len(groups))
	for _, g := range groups {
		if strings.EqualFold(g.State, "ENABLED") {
			enabledGroups = append(enabledGroups, g)
		}
	}

	// 无启用主备组时回退本机单文件检查并恢复任何既有脑裂告警
	if len(enabledGroups) == 0 {
		s.mu.Lock()
		clear(s.splitBrainActive)
		s.mu.Unlock()
		s.recover(ctx, ComponentHAVIP, TypeHASplitBrain)
		s.sweepHAVIP(ctx)
		return
	}

	var faults []string
	var splitBrains []string
	seenGroups := make(map[string]bool, len(enabledGroups))

	for _, g := range enabledGroups {
		gKey := g.ID
		if gKey == "" {
			gKey = g.Name
		}
		seenGroups[gKey] = true

		masters := []string{}
		vipHolders := map[string][]string{}
		members := append([]string(nil), g.MemberNodes...)
		sort.Strings(members)

		for _, member := range members {
			entry, ok := byNode[member]
			if !ok || len(entry.raw) == 0 {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s 未上报 HA 状态", g.Name, member))
				continue
			}
			if entry.parseErr != nil {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s HA 状态解析失败: %v", g.Name, member, entry.parseErr))
				continue
			}
			var st haVipStatus
			if err := json.Unmarshal(entry.raw, &st); err != nil {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s HA 状态解析失败: %v", g.Name, member, err))
				continue
			}
			if entry.updatedAt == nil || now.Sub(entry.updatedAt.UTC()) > havipStaleThreshold {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s havipd 状态过期（疑似停止）", g.Name, member))
				continue
			}
			upperState := strings.ToUpper(strings.TrimSpace(st.State))
			if upperState == "FAULT" {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s keepalived 实例 FAULT（%s）",
					g.Name, member, orDefault(st.Message, "进程异常")))
				continue
			}
			if upperState != "DISABLED" && upperState != "STOPPED" && !st.KeepalivedRunning {
				faults = append(faults, fmt.Sprintf("主备组 %s 节点 %s keepalived 未运行（状态 %s）",
					g.Name, member, upperState))
				continue
			}
			// 仅统计归属该组的活跃节点参与脑裂判定
			if st.Group != "" && st.Group != g.Name {
				continue
			}
			if upperState == "MASTER" {
				masters = append(masters, member)
			}
			for _, vip := range st.VIPsPresent {
				v := strings.TrimSpace(vip)
				if v != "" {
					vipHolders[v] = append(vipHolders[v], member)
				}
			}
		}

		overlappingVIPs := []string{}
		for vip, holders := range vipHolders {
			if len(holders) >= 2 {
				overlappingVIPs = append(overlappingVIPs, vip)
			}
		}
		sort.Strings(overlappingVIPs)

		isSplit := len(masters) >= 2 || len(overlappingVIPs) > 0
		if isSplit {
			detail := fmt.Sprintf("主备组 %s", g.Name)
			if len(masters) >= 2 {
				detail += fmt.Sprintf(" 多节点同时处于 MASTER（%s）", joinComma(masters))
			}
			if len(overlappingVIPs) > 0 {
				detail += fmt.Sprintf(" 重复持有 VIP（%s）", joinComma(overlappingVIPs))
			}
			splitBrains = append(splitBrains, detail)

			s.mu.Lock()
			wasActive := s.splitBrainActive[gKey]
			s.splitBrainActive[gKey] = true
			s.mu.Unlock()
			if !wasActive && s.onSplitBrain != nil {
				if err := s.onSplitBrain(ctx, g.ID, g.Name, masters, overlappingVIPs); err != nil {
					slog.Warn("record HA split-brain event failed", "group", g.Name, "error", err)
				}
			}
		} else {
			s.mu.Lock()
			s.splitBrainActive[gKey] = false
			s.mu.Unlock()
		}
	}

	// 清理已删除或停用组的内存状态
	s.mu.Lock()
	for k := range s.splitBrainActive {
		if !seenGroups[k] {
			delete(s.splitBrainActive, k)
		}
	}
	s.mu.Unlock()

	if len(splitBrains) > 0 {
		s.raise(ctx, TypeHASplitBrain, ComponentHAVIP,
			"主备集群检测到双主脑裂",
			fmt.Sprintf("检测到双主脑裂：%s；请立即检查 VRRP 心跳链路、防火墙协议号 112 放行及单播对端配置", joinComma(splitBrains)))
	} else {
		s.recover(ctx, ComponentHAVIP, TypeHASplitBrain)
	}

	if len(faults) > 0 {
		s.raise(ctx, TypeHAVIPFault, ComponentHAVIP,
			"主备节点 VIP 运行异常", joinComma(faults))
	} else {
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
