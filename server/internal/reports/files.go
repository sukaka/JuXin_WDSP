package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/google/uuid"
)

// reportFileNameRe 合法报告文件名（report-{uuid}.{html|pdf}）。
var reportFileNameRe = regexp.MustCompile(`^report-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.(html|pdf)$`)

// ReportFileName 生成报告文件名（仅由任务ID与格式组成，防路径穿越）。
func ReportFileName(id uuid.UUID, format string) string {
	return "report-" + id.String() + "." + format
}

// ValidateReportFileName 校验文件名形态合法，且确属指定任务与格式（防任意下载）。
func ValidateReportFileName(name string, id uuid.UUID, format string) bool {
	return reportFileNameRe.MatchString(name) && name == ReportFileName(id, format)
}

// ReportsDir 报告文件目录（GATEWAY_DATA_DIR/reports/）。
func ReportsDir(dataDir string) string {
	return filepath.Join(dataDir, "reports")
}

// reportPath 拼接受控文件路径（二次防御：文件名必须不含路径分隔符）。
func reportPath(dataDir, name string) (string, error) {
	if !reportFileNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid report file name")
	}
	dir := ReportsDir(dataDir)
	p := filepath.Join(dir, name)
	if filepath.Base(p) != name || filepath.Dir(p) != filepath.Clean(dir) {
		return "", fmt.Errorf("invalid report file path")
	}
	return p, nil
}

// writeReportFile 写入报告文件（0600 权限），返回 sha256 与大小；超限报错并清理。
func writeReportFile(dataDir, name string, content []byte) (hash string, size int64, err error) {
	if len(content) > MaxReportFileSize {
		return "", 0, fmt.Errorf("report file exceeds %d bytes limit", MaxReportFileSize)
	}
	p, err := reportPath(dataDir, name)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), int64(len(content)), nil
}

// readReportFile 读取报告文件并校验大小上限。
func readReportFile(dataDir, name string) ([]byte, error) {
	p, err := reportPath(dataDir, name)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxReportFileSize {
		return nil, fmt.Errorf("report file exceeds %d bytes limit", MaxReportFileSize)
	}
	return os.ReadFile(p)
}

// removeReportFile 删除报告文件（不存在视为成功）。
func removeReportFile(dataDir, name string) error {
	p, err := reportPath(dataDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// sha256Bytes 计算内容哈希（下载完整性校验用）。
func sha256Bytes(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
