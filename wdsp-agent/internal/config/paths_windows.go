//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func windowsBaseDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "JiuZhang", "WDSPAgent")
}

// Windows 默认路径（跨平台契约 §2：%ProgramData%\JiuZhang\WDSPAgent）。
var (
	DefaultConfigPath    = filepath.Join(windowsBaseDir(), "agent.json")
	DefaultStateDir      = filepath.Join(windowsBaseDir(), "state")
	DefaultBufferDir     = filepath.Join(windowsBaseDir(), "state", "buffer")
	DefaultLogDir        = filepath.Join(windowsBaseDir(), "logs")
	DefaultAPISocketPath = filepath.Join(windowsBaseDir(), "run", "api.sock")
)
