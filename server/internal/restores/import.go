// import.go 备份文件导入（全新环境恢复入口）：
// 外部 .jzbk 文件经完整性验证后登记为可恢复备份。
package restores

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/backups"
)

// ImportBackup 导入外部备份文件：
// 安全边界（路径限制）→ 复制进备份目录 → 全量完整性验证（哈希/解密/清单/行数）
// → 登记 backup_jobs（SUCCESS+verified）→ 返回任务。
// 任何一步失败即拒绝，未验证的文件绝不可恢复。
func (s *Service) ImportBackup(ctx context.Context, srcPath string, importedBy *uuid.UUID) (*backups.Job, error) {
	if srcPath == "" {
		return nil, fmt.Errorf("%w: empty source path", ErrInvalidInput)
	}
	// 防路径穿越与任意文件读取：源文件必须位于数据目录内
	dataDirAbs, err := filepath.Abs(s.dataDir)
	if err != nil {
		return nil, err
	}
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid source path", ErrInvalidInput)
	}
	if srcAbs != dataDirAbs && !strings.HasPrefix(srcAbs, dataDirAbs+string(os.PathSeparator)) {
		return nil, fmt.Errorf("%w: source file must be inside data directory", ErrInvalidInput)
	}
	st, err := os.Stat(srcAbs)
	if err != nil || st.IsDir() {
		return nil, fmt.Errorf("%w: source file missing", backups.ErrFileMissing)
	}

	// 复制到备份目录（新 ID 命名，不覆盖既有文件）
	newID := uuid.New()
	dst, err := backups.BackupPath(s.dataDir, newID)
	if err != nil {
		return nil, err
	}
	if err := copyFile(srcAbs, dst); err != nil {
		return nil, fmt.Errorf("copy backup file: %w", err)
	}

	// 全量完整性验证（文件哈希自算 + 解密 + 清单 + 逐表行数/哈希）
	res, err := s.exporter.Verify(ctx, dst, "")
	if err != nil {
		_ = os.Remove(dst)
		return nil, fmt.Errorf("import verify failed: %w", err)
	}
	manifestJSON, err := json.Marshal(res.Manifest)
	if err != nil {
		_ = os.Remove(dst)
		return nil, err
	}
	backupType := res.Manifest.BackupType
	if backupType == "" {
		backupType = backups.TypeFull
	}
	fileHash, err := backups.FileSHA256(dst)
	if err != nil {
		_ = os.Remove(dst)
		return nil, err
	}
	job, err := s.backups.InsertImported(ctx, newID, backupType, dst, st.Size(), fileHash, manifestJSON, importedBy)
	if err != nil {
		_ = os.Remove(dst)
		return nil, err
	}
	return job, nil
}

// copyFile 流式复制（内存有界，目标 0600）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	return closeErr
}
