// Package upgrades 提供系统升级能力：升级包登记/校验、升级前检查、升级执行与回滚。
//
// 安全约束（AGENTS.md）：
//   - 升级前必须备份（BACKUP 步骤创建 FULL 加密备份并等待验证成功）；
//   - 数据库迁移必须具备回滚能力（任一 APPLYING/MIGRATING/VERIFYING 失败自动回滚）；
//   - 失败必须可查询原因（failure_code/failure_message）并产生系统告警；
//   - 不静默吞错。
package upgrades

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 升级任务状态机
const (
	StatusScheduled   = "SCHEDULED"
	StatusPending     = "PENDING"
	StatusPrecheck    = "PRECHECK"
	StatusBackup      = "BACKUP"
	StatusApplying    = "APPLYING"
	StatusMigrating   = "MIGRATING"
	StatusVerifying   = "VERIFYING"
	StatusSuccess     = "SUCCESS"
	StatusFailed      = "FAILED"
	StatusRollingBack = "ROLLING_BACK"
	StatusRolledBack  = "ROLLED_BACK"
	StatusCancelled   = "CANCELLED"
)

// 升级包状态
const (
	PackageRegistered = "REGISTERED"
	PackageVerified   = "VERIFIED"
	PackageRejected   = "REJECTED"
)

// 失败码
const (
	FailPrecheck = "PRECHECK_FAILED"
	FailBackup   = "BACKUP_FAILED"
	FailApply    = "APPLY_FAILED"
	FailMigrate  = "MIGRATE_FAILED"
	FailVerify   = "VERIFY_FAILED"
	FailRollback = "ROLLBACK_FAILED"
	// FailExecutorTimeout 宿主机执行器超期未返回终态结果（含 API 重启前等待时长），
	// 滞留 APPLYING 任务由兜底清扫按中断终结（不自动重跑、不假装成功）。
	FailExecutorTimeout = "EXECUTOR_TIMEOUT"
	// FailStandbyUpgrade HA 集群滚动升级中备节点升级失败，已立即中止且未触碰主节点。
	FailStandbyUpgrade = "STANDBY_UPGRADE_FAILED"
	// FailClusterSplitBrain 检测到未处置的主备脑裂告警（HA_SPLIT_BRAIN），拒绝启动滚动升级。
	FailClusterSplitBrain = "CLUSTER_SPLIT_BRAIN"
)

// 集群升级模式（与迁移 000237 upgrade_jobs.cluster_mode 列一致）。
const (
	ClusterModeLocal     = "LOCAL"
	ClusterModeHARolling = "HA_ROLLING"
)

// 逐节点执行角色与状态（与迁移 000237 upgrade_node_executions 列一致）。
const (
	NodeRoleStandby = "STANDBY"
	NodeRolePrimary = "PRIMARY"

	NodeStatusPending      = "PENDING"
	NodeStatusTransferring = "TRANSFERRING"
	NodeStatusApplying     = "APPLYING"
	NodeStatusVerifying    = "VERIFYING"
	NodeStatusSuccess      = "SUCCESS"
	NodeStatusFailed       = "FAILED"
	NodeStatusSkipped      = "SKIPPED"
)

// CurrentVersion 当前系统版本（未在 system_settings 配置 system:current_version 时的兜底值）。
const CurrentVersion = "1.14.0"

// 错误
var (
	ErrNotFound                 = errors.New("upgrade resource not found")
	ErrInvalidInput             = errors.New("invalid upgrade input")
	ErrInvalidStatus            = errors.New("invalid upgrade status for this operation")
	ErrActiveUpgrade            = errors.New("another upgrade job is active")
	ErrPackageNotVerified       = errors.New("upgrade package is not verified")
	ErrNoBackup                 = errors.New("upgrade job has no backup to roll back to")
	ErrClusterSplitBrain        = errors.New("cluster split-brain detected")
	ErrClusterSyncNotConfigured = errors.New("cluster sync client is not configured")
)

// NormalizeClusterMode 规范化集群升级模式；空串默认 LOCAL，非法值返回 ErrInvalidInput。
func NormalizeClusterMode(mode string) (string, error) {
	m := strings.ToUpper(strings.TrimSpace(mode))
	if m == "" {
		return ClusterModeLocal, nil
	}
	if m == ClusterModeLocal || m == ClusterModeHARolling {
		return m, nil
	}
	return "", fmt.Errorf("%w: 无效的集群升级模式 %q（仅支持 LOCAL 或 HA_ROLLING）", ErrInvalidInput, mode)
}

// transitions 合法状态迁移（状态机白名单）。
var transitions = map[string][]string{
	StatusScheduled:   {StatusPending, StatusCancelled},
	StatusPending:     {StatusPrecheck},
	StatusPrecheck:    {StatusBackup, StatusFailed},
	StatusBackup:      {StatusApplying, StatusFailed},
	StatusApplying:    {StatusMigrating, StatusRollingBack},
	StatusMigrating:   {StatusVerifying, StatusRollingBack},
	StatusVerifying:   {StatusSuccess, StatusRollingBack},
	StatusRollingBack: {StatusRolledBack, StatusFailed},
	StatusSuccess:     {StatusRollingBack},
	StatusFailed:      {StatusRollingBack},
}

// ValidStatus 校验任务状态合法。
func ValidStatus(s string) bool {
	_, ok := transitions[s]
	return ok || s == StatusRolledBack || s == StatusCancelled
}

// CanTransition 判断 from → to 是否为合法状态迁移。
func CanTransition(from, to string) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// TerminalStatus 判断是否为终态（不再流转）。
func TerminalStatus(s string) bool {
	return s == StatusSuccess || s == StatusFailed || s == StatusRolledBack || s == StatusCancelled
}

// 定时执行时间窗边界：太近无法保证调度及时性，太远不利于变更管控。
const (
	MinScheduleLead    = 2 * time.Minute
	MaxScheduleHorizon = 90 * 24 * time.Hour
)

// ParseScheduledAt 解析并校验定时执行时间：RFC3339 且必须带时区偏移；
// 早于 now+MinScheduleLead（太近）或晚于 now+MaxScheduleHorizon（太远）一律拒绝。
// 边界值（恰好 now+2 分钟 / 恰好 now+90 天）视为合法。
func ParseScheduledAt(text string, now time.Time) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(text))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: 定时时间格式无效（须为 RFC3339 且带时区，如 2026-09-14T20:00:00+08:00）", ErrInvalidInput)
	}
	if t.Before(now.Add(MinScheduleLead)) {
		return time.Time{}, fmt.Errorf("%w: 定时时间距离现在不足 2 分钟，请设置更晚的时间", ErrInvalidInput)
	}
	if t.After(now.Add(MaxScheduleHorizon)) {
		return time.Time{}, fmt.Errorf("%w: 定时时间超过 90 天上限，请设置更近的时间", ErrInvalidInput)
	}
	return t.UTC(), nil
}

// versionRe 简版语义化版本号：v?MAJOR.MINOR.PATCH（可带 -prerelease 后缀，比较时忽略）。
var versionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$`)

// Version 简版语义化版本号。
type Version struct {
	Major int
	Minor int
	Patch int
}

// ParseVersion 解析版本号（接受 "2.0.0" 或 "v2.0.0"）。
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("%w: 无效版本号 %q（须为 MAJOR.MINOR.PATCH）", ErrInvalidInput, s)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return Version{Major: major, Minor: minor, Patch: patch}, nil
}

// Compare 比较版本：-1 小于 / 0 等于 / 1 大于。
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		return cmpInt(v.Major, o.Major)
	case v.Minor != o.Minor:
		return cmpInt(v.Minor, o.Minor)
	default:
		return cmpInt(v.Patch, o.Patch)
	}
}

// String 返回规范化版本字符串。
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// hashRe 升级包哈希：64 位小写十六进制（sha256）。
var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidHash 校验 sha256 哈希格式。
func ValidHash(h string) bool {
	return hashRe.MatchString(h)
}

// ValidPackageStatus 校验升级包状态。
func ValidPackageStatus(s string) bool {
	return s == PackageRegistered || s == PackageVerified || s == PackageRejected
}

// truncate 截断错误信息，适配 failure_message VARCHAR(500)。
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// failMsg 规范化失败信息。
func failMsg(err error) string {
	return truncate(fmt.Sprintf("%v", err), 500)
}
