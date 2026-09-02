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
)

// 升级任务状态机
const (
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
)

// CurrentVersion 当前系统版本（未在 system_settings 配置 system:current_version 时的兜底值）。
const CurrentVersion = "2.5.3"

// 错误
var (
	ErrNotFound           = errors.New("upgrade resource not found")
	ErrInvalidInput       = errors.New("invalid upgrade input")
	ErrInvalidStatus      = errors.New("invalid upgrade status for this operation")
	ErrActiveUpgrade      = errors.New("another upgrade job is active")
	ErrPackageNotVerified = errors.New("upgrade package is not verified")
	ErrNoBackup           = errors.New("upgrade job has no backup to roll back to")
)

// transitions 合法状态迁移（状态机白名单）。
var transitions = map[string][]string{
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
	return ok || s == StatusRolledBack
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
	return s == StatusSuccess || s == StatusFailed || s == StatusRolledBack
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
