package gatewayconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteCertificateFiles 将证书与私钥写入数据目录（权限0600，仅所有者）。
// 返回证书文件名（不含目录）。
func WriteCertificateFiles(dataDir, certID, certPEM, keyPEM string) (string, error) {
	if dataDir == "" {
		dataDir = "runtime/certificates"
	}
	certDir := filepath.Join(dataDir, "certificates")
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return "", fmt.Errorf("创建证书目录失败: %w", err)
	}
	// 清理 certID，防路径穿越
	cleanID := sanitizeFilename(certID)
	if cleanID == "" {
		return "", fmt.Errorf("无效的证书标识")
	}
	certFile := filepath.Join(certDir, cleanID+".pem")
	keyFile := filepath.Join(certDir, cleanID+".key")
	// 证书（含链）
	if err := os.WriteFile(certFile, []byte(certPEM), 0o600); err != nil {
		return "", fmt.Errorf("写入证书文件失败: %w", err)
	}
	// 私钥
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0o600); err != nil {
		return "", fmt.Errorf("写入私钥文件失败: %w", err)
	}
	return cleanID + ".pem", nil
}

// WriteCandidate 保存候选配置。
func WriteCandidate(dataDir, versionNum, configJSON string) (string, error) {
	dir := filepath.Join(dataDir, "configs", "candidates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	file := filepath.Join(dir, sanitizeFilename(versionNum)+".json")
	if err := os.WriteFile(file, []byte(configJSON), 0o600); err != nil {
		return "", err
	}
	return file, nil
}

// WriteActiveConfig 保存生效配置。
func WriteActiveConfig(dataDir, versionNum, configJSON string) (string, error) {
	dir := filepath.Join(dataDir, "configs", "active")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	file := filepath.Join(dir, sanitizeFilename(versionNum)+".json")
	if err := os.WriteFile(file, []byte(configJSON), 0o600); err != nil {
		return "", err
	}
	return file, nil
}

// WriteVersionConfig 保存历史版本配置。
func WriteVersionConfig(dataDir, versionNum, configJSON string) (string, error) {
	dir := filepath.Join(dataDir, "configs", "versions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	file := filepath.Join(dir, sanitizeFilename(versionNum)+".json")
	if err := os.WriteFile(file, []byte(configJSON), 0o600); err != nil {
		return "", err
	}
	return file, nil
}

// WriteFailedCandidate 保存失败候选配置。
func WriteFailedCandidate(dataDir, configJSON, reason string) error {
	dir := filepath.Join(dataDir, "configs", "failed")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("failed-%d.json", time.Now().Unix())
	file := filepath.Join(dir, name)
	content := fmt.Sprintf("{\"failure_reason\": %q, \"config\": %s}", reason, configJSON)
	return os.WriteFile(file, []byte(content), 0o600)
}

// sanitizeFilename 清理文件名（防路径穿越）。
func sanitizeFilename(name string) string {
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		}
	}
	s := b.String()
	s = strings.TrimPrefix(s, "..")
	s = strings.TrimPrefix(s, ".")
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
