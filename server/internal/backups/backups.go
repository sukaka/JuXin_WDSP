// Package backups 提供配置与数据的逻辑备份：导出 → 加密 → 清单 → 验证。
//
// 安全约束（AGENTS.md）：
//   - 备份文件必须加密（AES-256-GCM，主密钥仅在进程内，不落备份目录）；
//   - 必须先验证再显示成功（Worker 导出后自动验证，SUCCESS 仅当 verified=true）；
//   - 失败必须可查询原因（failure_code/failure_message）并产生系统告警；
//   - 不静默吞错。
package backups

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// 备份类型
const (
	TypeFull       = "FULL"        // 配置表 + 审计归档（最近100万行）
	TypeConfigOnly = "CONFIG_ONLY" // 仅配置表
)

// 任务状态
const (
	StatusPending   = "PENDING"
	StatusRunning   = "RUNNING"
	StatusVerifying = "VERIFYING"
	StatusSuccess   = "SUCCESS"
	StatusFailed    = "FAILED"
	StatusCancelled = "CANCELLED"
)

// 失败码
const (
	FailExportFailed   = "EXPORT_FAILED"
	FailSizeLimit      = "SIZE_LIMIT"
	FailVerifyFailed   = "VERIFY_FAILED"
	FailHashMismatch   = "HASH_MISMATCH"
	FailSchemaMismatch = "SCHEMA_MISMATCH"
	FailFileMissing    = "FILE_MISSING"
	FailEncryption     = "ENCRYPTION_UNAVAILABLE"
)

// 目录与文件名
const (
	// DirName 备份目录名（位于 GATEWAY_DATA_DIR 下）
	DirName = "backups"
	// FileExt 备份文件扩展名
	FileExt = ".jzbk"
)

// 错误
var (
	ErrNotFound        = errors.New("backup job not found")
	ErrInvalidType     = errors.New("invalid backup type")
	ErrInvalidStatus   = errors.New("invalid backup status for this operation")
	ErrUnsafePath      = errors.New("unsafe file path")
	ErrReferenced      = errors.New("backup referenced by restore jobs")
	ErrFileMissing     = errors.New("backup file missing")
	ErrNoEncryption    = errors.New("encryption service unavailable")
	ErrIncompatible    = errors.New("backup schema version newer than current")
	ErrManifestInvalid = errors.New("backup manifest invalid")
	ErrHashMismatch    = errors.New("backup hash mismatch")
)

// AlertFunc 系统告警回调（备份/恢复失败时调用），允许为 nil。
type AlertFunc func(alertType, component, title, message string)

// ValidType 校验备份类型。
func ValidType(t string) bool {
	return t == TypeFull || t == TypeConfigOnly
}

// BackupFileName 生成固定模式的备份文件名（防路径穿越：仅由 UUID 派生）。
func BackupFileName(id uuid.UUID) string {
	return "backup-" + id.String() + FileExt
}

// SafeJoin 将文件名安全拼入目录，拒绝任何穿越/绝对路径/嵌套路径。
func SafeJoin(dir, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", ErrUnsafePath
	}
	if filepath.Base(name) != name {
		return "", ErrUnsafePath
	}
	cleanDir := filepath.Clean(dir)
	p := filepath.Join(cleanDir, name)
	if p != cleanDir+string(filepath.Separator)+name {
		return "", ErrUnsafePath
	}
	return p, nil
}

// BackupPath 返回备份任务文件的完整安全路径。
func BackupPath(dataDir string, id uuid.UUID) (string, error) {
	return SafeJoin(filepath.Join(dataDir, DirName), BackupFileName(id))
}

// TempFileName 生成导出过程中的临时文件名（同目录，完成后原子改名）。
func TempFileName(id uuid.UUID) string {
	return ".backup-" + id.String() + ".tmp"
}

// NotifyAlert 安全调用告警回调（nil 容忍）。
func NotifyAlert(fn AlertFunc, alertType, component, title, message string) {
	if fn != nil {
		fn(alertType, component, title, message)
	}
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
