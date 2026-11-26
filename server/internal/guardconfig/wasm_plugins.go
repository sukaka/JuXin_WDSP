// wasm_plugins.go Wasm 自定义检测插件下发（Phase 9D-1）：
//   - wasm_plugins（全局 + 应用级）→ GuardConfig.WasmPlugins（key=应用编码）；
//   - 读取失败中止发布（fail-hard，与 jwt_trust / bot_policy / ai_crawl / client_side / api_a2a / semantic_guard 同口径）；
//   - api_policy_version 版本戳仅纳入插件元数据与 sha256，绝不将原始 wasm_base64 二进制块送入哈希。
package guardconfig

import (
	"context"
	"fmt"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// WasmPluginLister Wasm 检测插件读取接口（由 wasmplugins.Store 实现）。
type WasmPluginLister interface {
	ListForGuard(ctx context.Context) (map[string]*gatewayconfig.GuardWasmPluginsConfig, error)
}

// SetWasmPluginLister 注入 Wasm 检测插件读取（nil 时不下发 wasm_plugins 段）。
func (p *Provider) SetWasmPluginLister(l WasmPluginLister) { p.wasmPlugins = l }

// loadWasmPlugins 读取全局与应用级 Wasm 检测插件并填充 wasm_plugins 段（仅 WDSP 开启时调用）。
// 读取失败中止发布（fail-hard）；无配置记录/未注入 lister 时不下发该段，网关零行为变化。
func (p *Provider) loadWasmPlugins(ctx context.Context, cfg *gatewayconfig.GuardConfig) error {
	if p.wasmPlugins == nil {
		return nil
	}
	compiled, err := p.wasmPlugins.ListForGuard(ctx)
	if err != nil {
		return fmt.Errorf("list wasm plugins: %w", err)
	}
	if len(compiled) == 0 {
		return nil
	}
	cfg.WasmPlugins = compiled
	return nil
}

// wasmPluginHashEntry 参与 api_policy_version 版本戳的插件元数据（仅含元数据与 sha256，绝不含 raw wasm_base64）。
type wasmPluginHashEntry struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      int      `json:"version"`
	ABIVersion   string   `json:"abi_version"`
	Mode         string   `json:"mode"`
	SHA256       string   `json:"sha256"`
	Priority     int      `json:"priority"`
	TimeoutMs    int      `json:"timeout_ms"`
	MaxMemoryKB  int      `json:"max_memory_kb"`
	MaxBodyBytes int      `json:"max_body_bytes"`
	FailPolicy   string   `json:"fail_policy"`
	PathPrefixes []string `json:"path_prefixes"`
}

// wasmPluginsHashConfig 参与 api_policy_version 版本戳的单应用插件段视图（不含原始 wasm_base64）。
type wasmPluginsHashConfig struct {
	SchemaVersion int                   `json:"schema_version"`
	ApplicationID string                `json:"application_id"`
	Plugins       []wasmPluginHashEntry `json:"plugins"`
}

// wasmPluginsForVersionHash 返回仅包含插件元数据与 sha256（剥离 raw wasm_base64 二进制块）的版本戳视图。
func wasmPluginsForVersionHash(in map[string]*gatewayconfig.GuardWasmPluginsConfig) map[string]*wasmPluginsHashConfig {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*wasmPluginsHashConfig, len(in))
	for code, cfg := range in {
		if cfg == nil {
			continue
		}
		entries := make([]wasmPluginHashEntry, 0, len(cfg.Plugins))
		for _, pl := range cfg.Plugins {
			entries = append(entries, wasmPluginHashEntry{
				ID:           pl.ID,
				Name:         pl.Name,
				Version:      pl.Version,
				ABIVersion:   pl.ABIVersion,
				Mode:         pl.Mode,
				SHA256:       pl.SHA256,
				Priority:     pl.Priority,
				TimeoutMs:    pl.TimeoutMs,
				MaxMemoryKB:  pl.MaxMemoryKB,
				MaxBodyBytes: pl.MaxBodyBytes,
				FailPolicy:   pl.FailPolicy,
				PathPrefixes: pl.PathPrefixes,
			})
		}
		out[code] = &wasmPluginsHashConfig{
			SchemaVersion: cfg.SchemaVersion,
			ApplicationID: cfg.ApplicationID,
			Plugins:       entries,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
