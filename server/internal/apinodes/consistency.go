// consistency.go 节点状态判定与版本一致性评估（纯函数，单测直接覆盖；
// sweeper 周期判定与 handler 读接口共用同一套口径，避免读写路径漂移）。
package apinodes

import (
	"sort"
	"time"
)

// StatusFor 状态判定：以 lastSeen 距 now 的时长划分，边界含端点
// （恰好 5min 仍 ACTIVE、恰好 1h 仍 STALE）。lastSeen 为零值（从未有事件，
// 防御路径——正常行由事件聚合产生必有事件时间）按 SILENT 处理。
func StatusFor(now, lastSeen time.Time) string {
	if lastSeen.IsZero() {
		return StatusSilent
	}
	if !lastSeen.Before(now.Add(-ActiveWindow)) {
		return StatusActive
	}
	if !lastSeen.Before(now.Add(-StaleWindow)) {
		return StatusStale
	}
	return StatusSilent
}

// EvaluateConsistency 版本一致性判定（纯函数）：
//   - 状态以 now 对 last_seen_at 现算（不信任库存 status——读路径距上一轮
//     聚合可能已跨过窗口边界，现算保证响应口径当下真实）；
//   - 参与判定：状态非 SILENT 且 last_policy_version 非空（已上报）的节点；
//   - Consistent = 参与节点版本去重 ≤ 1；参与节点为 0 时无版本数据可比，
//     Consistent 如实为 true（不谎报不一致），EvaluatedNodes=0 呈现；
//   - SILENT 节点离线不参与判定（其留存的旧版本不应在升级后长期误报），
//     单独列入 SilentNodes；
//   - 未上报版本（空串）的活跃节点单列一组如实呈现，但不参与版本一致性判定
//     （「不知道版本」不等于「版本不一致」）。
func EvaluateConsistency(nodes []Node, now time.Time) ConsistencyReport {
	report := ConsistencyReport{
		Consistent:  true,
		Groups:      []VersionGroup{},
		SilentNodes: []string{},
		GeneratedAt: now,
	}
	byVersion := map[string][]string{}
	for i := range nodes {
		n := &nodes[i]
		if StatusFor(now, n.LastSeenAt) == StatusSilent {
			report.SilentNodes = append(report.SilentNodes, n.NodeName)
			continue
		}
		byVersion[n.LastPolicyVersion] = append(byVersion[n.LastPolicyVersion], n.NodeName)
	}
	for version, names := range byVersion {
		sort.Strings(names)
		report.Groups = append(report.Groups, VersionGroup{
			PolicyVersion: version,
			NodeCount:     len(names),
			Nodes:         names,
		})
	}
	// 组排序：节点数降序，并列取版本字典序（确定性输出；未上报空串组自然排前）
	sort.Slice(report.Groups, func(i, j int) bool {
		if report.Groups[i].NodeCount != report.Groups[j].NodeCount {
			return report.Groups[i].NodeCount > report.Groups[j].NodeCount
		}
		return report.Groups[i].PolicyVersion < report.Groups[j].PolicyVersion
	})
	sort.Strings(report.SilentNodes)

	// 多数派版本：仅统计已上报（非空）版本组；并列时取字典序小者（确定性，
	// 与组排序并列规则一致——空串组不参与故需单独求）
	dominant, dominantCount := "", 0
	evaluated := 0
	for _, g := range report.Groups {
		if g.PolicyVersion == "" {
			continue
		}
		evaluated += g.NodeCount
		if g.NodeCount > dominantCount || (g.NodeCount == dominantCount && (dominant == "" || g.PolicyVersion < dominant)) {
			dominant, dominantCount = g.PolicyVersion, g.NodeCount
		}
	}
	report.EvaluatedNodes = evaluated
	report.DominantVersion = dominant

	distinct := 0
	for _, g := range report.Groups {
		if g.PolicyVersion != "" {
			distinct++
		}
	}
	report.Consistent = distinct <= 1
	return report
}

// versionConsistentFlag 单节点一致性标记（读接口逐项计算）：
// 未参与判定（SILENT 离线/未上报版本/无多数派）返回 nil；
// 参与判定节点返回其版本是否等于多数派版本。
func versionConsistentFlag(n Node, dominant string, now time.Time) *bool {
	if dominant == "" || n.LastPolicyVersion == "" ||
		StatusFor(now, n.LastSeenAt) == StatusSilent {
		return nil
	}
	v := n.LastPolicyVersion == dominant
	return &v
}
