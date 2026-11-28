// Package restores 提供备份恢复：校验 → 隔离恢复 → 预览 → 管理员确认 → 正式恢复。
//
// 安全约束（AGENTS.md）：
//   - 绝不未确认就覆盖生产（Create 仅写入隔离 schema，Confirm 才触碰正式表）；
//   - 正式恢复前进入维护模式（Valkey 标志），失败必须可查询原因并告警；
//   - 审计归档段（operation_audits）永不恢复写回；
//   - 不静默吞错。
package restores

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/backups"
)

// 恢复范围
const (
	ScopeFull        = "FULL"
	ScopeConfig      = "CONFIG"
	ScopeDatabase    = "DATABASE"
	ScopeCertificate = "CERTIFICATE"
)

// 任务状态
const (
	StatusPending         = "PENDING"
	StatusValidating      = "VALIDATING"
	StatusIsolatedRestore = "ISOLATED_RESTORE"
	StatusVerifying       = "VERIFYING"
	StatusAwaitingConfirm = "AWAITING_CONFIRM"
	StatusRestoring       = "RESTORING"
	StatusSuccess         = "SUCCESS"
	StatusFailed          = "FAILED"
	StatusCancelled       = "CANCELLED"
)

// 失败码
const (
	FailBackupNotReady  = "BACKUP_NOT_READY"
	FailValidate        = "VALIDATE_FAILED"
	FailIsolatedRestore = "ISOLATED_RESTORE_FAILED"
	FailVerify          = "VERIFY_FAILED"
	FailMaintenance     = "MAINTENANCE_FAILED"
	FailPrivilege       = "PRIVILEGE_REQUIRED"
	FailRestore         = "RESTORE_FAILED"
	FailEmptyScope      = "EMPTY_SCOPE"
	FailActiveRestore   = "ACTIVE_RESTORE_EXISTS"
	FailRulePack        = "RULEPACK_RESTORE_FAILED"
)

// 维护模式标志（Valkey key；本阶段实现标志设置，中间件读取在后续阶段接入）
const (
	MaintenanceKey = "jiuzhang:maintenance"
	// MaintenanceTTL 维护标志兜底过期（防进程崩溃后无法退出维护）
	MaintenanceTTL = 30 * time.Minute
	// IsolatedTimeout 隔离恢复超时
	IsolatedTimeout = 60 * time.Minute
	// ConfirmTimeout 正式恢复超时
	ConfirmTimeout = 30 * time.Minute
	// RestoreTmpDirName 解包临时目录名（位于 GATEWAY_DATA_DIR 下）
	RestoreTmpDirName = "restore-tmp"
	// insertBatchSize 批量插入行数
	insertBatchSize = 200
)

// 错误
var (
	ErrNotFound           = errors.New("restore job not found")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidScope       = errors.New("invalid restore scope")
	ErrInvalidStatus      = errors.New("invalid restore status for this operation")
	ErrBackupNotReady     = errors.New("backup not verified successful")
	ErrActiveRestore      = errors.New("another restore is active")
	ErrMaintenanceUnavail = errors.New("maintenance flag store unavailable")
	ErrEmptyScope         = errors.New("no tables in scope for this backup")
	ErrStagingSchema      = errors.New("invalid staging schema name")
)

// ValidScope 校验恢复范围。
func ValidScope(s string) bool {
	switch s {
	case ScopeFull, ScopeConfig, ScopeDatabase, ScopeCertificate:
		return true
	}
	return false
}

// ScopeGroups 范围对应的表分组。
func ScopeGroups(scope string) []string {
	switch scope {
	case ScopeFull:
		return []string{backups.GroupDatabase, backups.GroupCertificate, backups.GroupConfig, backups.GroupLearning, backups.GroupFact}
	case ScopeConfig:
		return []string{backups.GroupConfig}
	case ScopeDatabase:
		return []string{backups.GroupDatabase}
	case ScopeCertificate:
		return []string{backups.GroupCertificate}
	}
	return nil
}

// ScopeTables 范围内可恢复表（拓扑序，parent → child）。
// available 为备份中实际存在的表（如 CONFIG_ONLY 备份无审计段）。
func ScopeTables(scope string, available map[string]bool) ([]string, error) {
	groups := ScopeGroups(scope)
	if groups == nil {
		return nil, ErrInvalidScope
	}
	var names []string
	for _, n := range backups.TablesForGroups(groups...) {
		td, _ := backups.TableByName(n)
		if td.Group == backups.GroupAudit {
			continue // 审计归档只导出，永不恢复
		}
		if available[n] {
			names = append(names, n)
		}
	}
	return backups.RestoreOrder(names)
}

// ScopeTablesForRestore 返回当前版本中该范围的完整表集合（拓扑序）。
// 它与 ScopeTables 的备份可用表过滤分开：旧格式备份可以缺少后来新增的
// 表，但正式恢复仍需清理这些当前表，避免新旧数据在同一数据库中混用。
func ScopeTablesForRestore(scope string) ([]string, error) {
	groups := ScopeGroups(scope)
	if groups == nil {
		return nil, ErrInvalidScope
	}
	var names []string
	for _, n := range backups.TablesForGroups(groups...) {
		td, _ := backups.TableByName(n)
		if td.Group != backups.GroupAudit {
			names = append(names, n)
		}
	}
	return backups.RestoreOrder(names)
}

// stagingSchemaRe 隔离 schema 名白名单。
var stagingSchemaRe = regexp.MustCompile(`^jzrestore_[0-9a-f]{8}$`)

// StagingSchema 由任务 ID 派生隔离 schema 名（jzrestore_{id短码}）。
func StagingSchema(id uuid.UUID) string {
	hex := id.String()
	compact := make([]byte, 0, 8)
	for i := 0; i < len(hex) && len(compact) < 8; i++ {
		if hex[i] != '-' {
			compact = append(compact, hex[i])
		}
	}
	return "jzrestore_" + string(compact)
}

// ValidStagingSchema 校验隔离 schema 名合法性。
func ValidStagingSchema(name string) bool {
	return stagingSchemaRe.MatchString(name)
}

// TablePreview 单表预览。
type TablePreview struct {
	Name         string `json:"name"`
	Group        string `json:"group"`
	BackupRows   int64  `json:"backup_rows"`
	RestoredRows int64  `json:"restored_rows,omitempty"`
	Match        bool   `json:"match"`
	InScope      bool   `json:"in_scope"`
}

// Preview 恢复预览（存入 restore_jobs.preview）。
type Preview struct {
	BackupID             uuid.UUID      `json:"backup_id"`
	BackupType           string         `json:"backup_type"`
	Scope                string         `json:"scope,omitempty"`
	BackupTime           time.Time      `json:"backup_time"`
	SchemaVersion        int            `json:"schema_version"`
	CurrentSchemaVersion int            `json:"current_schema_version"`
	Compatible           bool           `json:"compatible"`
	Tables                []TablePreview `json:"tables"`
	TotalRows             int64          `json:"total_rows"`
	ActiveRulePackVersion string         `json:"active_rulepack_version,omitempty"`
	Note                  string         `json:"note,omitempty"`
}

// failMsg 规范化失败信息。
func failMsg(err error) string {
	s := fmt.Sprintf("%v", err)
	if len(s) > 500 {
		return s[:500]
	}
	return s
}
