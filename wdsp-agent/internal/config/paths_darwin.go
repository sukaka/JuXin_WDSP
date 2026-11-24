//go:build darwin

package config

// macOS 系统级守护进程默认路径（跨平台契约 §2）。
var (
	DefaultConfigPath    = "/Library/Application Support/WDSPAgent/agent.json"
	DefaultStateDir      = "/Library/Application Support/WDSPAgent/state"
	DefaultBufferDir     = "/Library/Application Support/WDSPAgent/state/buffer"
	DefaultLogDir        = "/Library/Logs/WDSPAgent"
	DefaultAPISocketPath = "/Library/Application Support/WDSPAgent/run/api.sock"
)
