//go:build linux

package config

// Linux 默认目录（沿用既有契约 §6，不破坏既有部署）。
var (
	DefaultConfigPath    = "/etc/wdsp-agent/agent.json"
	DefaultStateDir      = "/var/lib/wdsp-agent"
	DefaultBufferDir     = "/var/lib/wdsp-agent/buffer"
	DefaultLogDir        = "/var/log/wdsp-agent"
	DefaultAPISocketPath = "/run/wdsp-agent/api.sock"
)
