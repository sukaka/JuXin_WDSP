//go:build !windows

// Package fsperm 跨平台私有目录与凭据文件权限保护。
// Unix 平台使用标准 POSIX 0700/0600 权限（显式 chmod 防御异常 umask）。
package fsperm

import (
	"fmt"
	"os"
)

// MkdirPrivate 创建私有目录（0700）并显式修正权限。
func MkdirPrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建私有目录 %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("修正目录权限 %s: %w", dir, err)
	}
	return nil
}

// SecureFile 设置文件权限（如私钥/配置 0600、证书 0644）。
func SecureFile(path string, perm os.FileMode) error {
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("修正文件权限 %s: %w", path, err)
	}
	return nil
}
