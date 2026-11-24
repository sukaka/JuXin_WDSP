//go:build !linux && !darwin && !windows

package config

// 其他类 Unix 平台回退默认路径。
var (
	DefaultConfigPath    = "/etc/wdsp-agent/agent.json"
	DefaultStateDir      = "/var/lib/wdsp-agent"
	DefaultBufferDir     = "/var/lib/wdsp-agent/buffer"
	DefaultLogDir        = "/var/log/wdsp-agent"
	DefaultAPISocketPath = "/run/wdsp-agent/api.sock"
)
