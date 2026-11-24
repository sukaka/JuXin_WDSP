// discovery_filter.go API 资产发现静态资源与非 API 过滤规则配置（系统设置 api_discovery 组）。
//
// 职责：
//   - 提供默认静态资源排除规则（复用 classifier 统一口径）；
//   - 校验与持久化管理员自定义的排除扩展名、排除路径前缀与强制保留白名单前缀；
//   - 通过短 TTL 内存缓存为 4 条发现入口（apiruntime / agents / apidataflow / 存量清理）
//     提供热路径零 DB 往返的统一过滤判定；写操作后立即失效缓存。
package apiassets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
)

const (
	// DiscoveryFilterSettingGroup 系统设置分组名。
	DiscoveryFilterSettingGroup = "api_discovery"
	// DiscoveryFilterSettingKey 过滤规则 JSON 键名。
	DiscoveryFilterSettingKey = "filter_rules"

	maxFilterExtensions   = 200
	maxFilterPathPrefixes = 100
	defaultFilterCacheTTL = 5 * time.Second
)

// DiscoveryFilterConfig API 资产发现过滤配置（管理面可编辑，4 条发现入口共用）。
type DiscoveryFilterConfig struct {
	// ExcludeStaticAssets 是否自动排除静态资源路径（图片/脚本/样式/字体/音视频/压缩包等），默认 true。
	ExcludeStaticAssets bool `json:"exclude_static_assets"`
	// FilterNonAPI 是否仅允许 is_api=true 的流量进入 API 资产表，默认 true。
	FilterNonAPI bool `json:"filter_non_api"`
	// ExcludeExtensions 静态资源排除扩展名列表（小写带前导 '.'，支持复合后缀如 .tar.gz）。
	ExcludeExtensions []string `json:"exclude_extensions"`
	// ExcludePathPrefixes 自定义排除路径前缀（段前缀匹配，如 /astro、/_next/static、/assets）。
	ExcludePathPrefixes []string `json:"exclude_path_prefixes"`
	// IncludePathPrefixes 强制保留（不按静态规则排除）的白名单路径前缀，优先级最高。
	IncludePathPrefixes []string `json:"include_path_prefixes"`
}

// DefaultDiscoveryFilterConfig 返回内置默认过滤配置。
func DefaultDiscoveryFilterConfig() DiscoveryFilterConfig {
	return DiscoveryFilterConfig{
		ExcludeStaticAssets: true,
		FilterNonAPI:        true,
		ExcludeExtensions:   classifier.DefaultStaticAssetExtensions(),
		ExcludePathPrefixes: []string{},
		IncludePathPrefixes: []string{},
	}
}

// NormalizeAndValidateDiscoveryFilter 校验并规范化发现过滤配置（去重、统一格式、长度与数量护栏）。
func NormalizeAndValidateDiscoveryFilter(in DiscoveryFilterConfig) (DiscoveryFilterConfig, error) {
	if len(in.ExcludeExtensions) > maxFilterExtensions {
		return DiscoveryFilterConfig{}, fmt.Errorf("静态排除扩展名数量不能超过 %d 个", maxFilterExtensions)
	}
	if len(in.ExcludePathPrefixes) > maxFilterPathPrefixes {
		return DiscoveryFilterConfig{}, fmt.Errorf("自定义排除路径前缀不能超过 %d 条", maxFilterPathPrefixes)
	}
	if len(in.IncludePathPrefixes) > maxFilterPathPrefixes {
		return DiscoveryFilterConfig{}, fmt.Errorf("白名单保留路径前缀不能超过 %d 条", maxFilterPathPrefixes)
	}

	exts := make([]string, 0, len(in.ExcludeExtensions))
	seenExt := make(map[string]struct{}, len(in.ExcludeExtensions))
	for _, raw := range in.ExcludeExtensions {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		norm := classifier.NormalizeExtension(raw)
		if norm == "" {
			return DiscoveryFilterConfig{}, fmt.Errorf("非法扩展名：%q（仅允许字母、数字、点、短横线与下划线，如 .png / .tar.gz）", raw)
		}
		if _, dup := seenExt[norm]; dup {
			continue
		}
		seenExt[norm] = struct{}{}
		exts = append(exts, norm)
	}

	normPrefixes := func(list []string, label string) ([]string, error) {
		out := make([]string, 0, len(list))
		seen := make(map[string]struct{}, len(list))
		for _, raw := range list {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			norm := classifier.NormalizePathPrefix(raw)
			if norm == "" || norm == "/" {
				return nil, fmt.Errorf("非法%s：%q（须为具体路径前缀，不能为根路径 / 或包含空白）", label, raw)
			}
			key := strings.ToLower(norm)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, norm)
		}
		return out, nil
	}

	exclPrefs, err := normPrefixes(in.ExcludePathPrefixes, "排除路径前缀")
	if err != nil {
		return DiscoveryFilterConfig{}, err
	}
	inclPrefs, err := normPrefixes(in.IncludePathPrefixes, "白名单路径前缀")
	if err != nil {
		return DiscoveryFilterConfig{}, err
	}

	return DiscoveryFilterConfig{
		ExcludeStaticAssets: in.ExcludeStaticAssets,
		FilterNonAPI:        in.FilterNonAPI,
		ExcludeExtensions:   exts,
		ExcludePathPrefixes: exclPrefs,
		IncludePathPrefixes: inclPrefs,
	}, nil
}

// StaticFilter 转换为 classifier.StaticFilterConfig。
func (c DiscoveryFilterConfig) StaticFilter() classifier.StaticFilterConfig {
	return classifier.StaticFilterConfig{
		ExcludeExtensions:   c.ExcludeExtensions,
		UseCustomExtensions: true,
		ExcludePathPrefixes: c.ExcludePathPrefixes,
		IncludePathPrefixes: c.IncludePathPrefixes,
	}
}

// ShouldFilterDiscovery 判定一条新发现记录是否应被拦截而不写入 api_endpoints。
// 返回 (true, reason) 表示过滤拦截，(false, "") 表示允许入库。
func (c DiscoveryFilterConfig) ShouldFilterDiscovery(method, pathTemplate string, isAPI bool) (bool, string) {
	sf := c.StaticFilter()
	inWhitelist := sf.MatchesIncludePrefix(pathTemplate)
	if !inWhitelist && c.ExcludeStaticAssets {
		if matched, reason := sf.MatchStaticPath(method, pathTemplate); matched {
			return true, reason
		}
	}
	if c.FilterNonAPI && !isAPI && !inWhitelist {
		return true, "non_api"
	}
	return false, ""
}

// MatchNoiseEndpoint 判定存量端点是否属于可清理的非 API / 静态资源噪声。
func (c DiscoveryFilterConfig) MatchNoiseEndpoint(method, pathTemplate string, isAPI bool) (bool, string) {
	sf := c.StaticFilter()
	if sf.MatchesIncludePrefix(pathTemplate) {
		return false, ""
	}
	if c.ExcludeStaticAssets {
		if matched, reason := sf.MatchStaticPath(method, pathTemplate); matched {
			return true, reason
		}
	}
	if !isAPI {
		return true, "non_api"
	}
	return false, ""
}

// DiscoveryFilterSettingsStore 过滤规则持久化最小接口（*settings.Service 满足）。
type DiscoveryFilterSettingsStore interface {
	GetStringWithSource(ctx context.Context, group, key string) (value string, found bool, err error)
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
}

// DiscoveryFilterProvider 运行期过滤配置提供者（带短 TTL 内存缓存，支持热失效）。
type DiscoveryFilterProvider struct {
	settings DiscoveryFilterSettingsStore
	ttl      time.Duration

	mu       sync.RWMutex
	cached   DiscoveryFilterConfig
	loadedAt time.Time
	hasCache bool
}

// NewDiscoveryFilterProvider 创建带缓存的发现过滤配置加载器（settings 为 nil 时恒返回内置默认配置）。
func NewDiscoveryFilterProvider(settings DiscoveryFilterSettingsStore) *DiscoveryFilterProvider {
	return &DiscoveryFilterProvider{
		settings: settings,
		ttl:      defaultFilterCacheTTL,
	}
}

// Get 读取当前生效配置（命中缓存直接返回；数据库故障时回落默认或上次缓存，不中断采集）。
func (p *DiscoveryFilterProvider) Get(ctx context.Context) DiscoveryFilterConfig {
	if p == nil || p.settings == nil {
		return DefaultDiscoveryFilterConfig()
	}
	now := time.Now()
	p.mu.RLock()
	if p.hasCache && now.Sub(p.loadedAt) < p.ttl {
		cfg := cloneDiscoveryFilterConfig(p.cached)
		p.mu.RUnlock()
		return cfg
	}
	p.mu.RUnlock()

	cfg, err := p.LoadStrict(ctx)
	if err != nil {
		p.mu.RLock()
		if p.hasCache {
			fallback := cloneDiscoveryFilterConfig(p.cached)
			p.mu.RUnlock()
			return fallback
		}
		p.mu.RUnlock()
		return DefaultDiscoveryFilterConfig()
	}
	return cfg
}

// LoadStrict 强一致从数据库加载配置（管理面 GET/保存校验使用，出错如实返回）。
func (p *DiscoveryFilterProvider) LoadStrict(ctx context.Context) (DiscoveryFilterConfig, error) {
	if p == nil || p.settings == nil {
		return DefaultDiscoveryFilterConfig(), nil
	}
	raw, found, err := p.settings.GetStringWithSource(ctx, DiscoveryFilterSettingGroup, DiscoveryFilterSettingKey)
	if err != nil {
		return DiscoveryFilterConfig{}, err
	}
	cfg := DefaultDiscoveryFilterConfig()
	if found && strings.TrimSpace(raw) != "" {
		var stored DiscoveryFilterConfig
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return DiscoveryFilterConfig{}, fmt.Errorf("解析 api_discovery.filter_rules 失败：%w", err)
		}
		norm, err := NormalizeAndValidateDiscoveryFilter(stored)
		if err != nil {
			return DiscoveryFilterConfig{}, err
		}
		cfg = norm
	}
	p.mu.Lock()
	p.cached = cloneDiscoveryFilterConfig(cfg)
	p.loadedAt = time.Now()
	p.hasCache = true
	p.mu.Unlock()
	return cfg, nil
}

// Save 校验、持久化配置并立即刷新缓存。
func (p *DiscoveryFilterProvider) Save(ctx context.Context, in DiscoveryFilterConfig, operatorID uuid.UUID) (DiscoveryFilterConfig, error) {
	norm, err := NormalizeAndValidateDiscoveryFilter(in)
	if err != nil {
		return DiscoveryFilterConfig{}, err
	}
	if p == nil || p.settings == nil {
		return norm, nil
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return DiscoveryFilterConfig{}, err
	}
	if err := p.settings.UpsertString(ctx, DiscoveryFilterSettingGroup, DiscoveryFilterSettingKey,
		string(raw), "API 资产发现静态资源与非 API 过滤规则", operatorID); err != nil {
		return DiscoveryFilterConfig{}, err
	}
	p.mu.Lock()
	p.cached = cloneDiscoveryFilterConfig(norm)
	p.loadedAt = time.Now()
	p.hasCache = true
	p.mu.Unlock()
	return norm, nil
}

// Invalidate 清空内存缓存。
func (p *DiscoveryFilterProvider) Invalidate() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.hasCache = false
	p.mu.Unlock()
}

func cloneDiscoveryFilterConfig(in DiscoveryFilterConfig) DiscoveryFilterConfig {
	out := in
	out.ExcludeExtensions = append([]string{}, in.ExcludeExtensions...)
	out.ExcludePathPrefixes = append([]string{}, in.ExcludePathPrefixes...)
	out.IncludePathPrefixes = append([]string{}, in.IncludePathPrefixes...)
	return out
}
