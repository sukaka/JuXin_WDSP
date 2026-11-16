// recorder.go 采集侧来源聚合记录器（实现 apiruntime.SourceRecorder，装配层注入采集器）。
//
// 每条 API 事件在端点发现 upsert 成功后调用一次：client_ip 按 apigeo 口径分类
// 内网/公网，命中合作方出口 CIDR（system_settings exposure_engine.partner_egress_cidrs，
// 60s 缓存）时升级 PARTNER；非法 IP 不聚合（脏数据不产生错误）。settings 读取与
// partner 判定全部收敛在本侧，apiruntime 不感知 settings。
//
// 事务批量化：WithDB(apiruntime.DBTX) 支持采集器 W22 批次事务切换（浅拷贝共享
// partner 缓存）；聚合写随批次整批 COMMIT/回滚，断点重放不重复计数。
package apiexposure

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// SourceStore 来源聚合写入窄接口（*Store 与 *MemStore 实现）。
type SourceStore interface {
	RecordSource(ctx context.Context, endpointID uuid.UUID, scope, fingerprint string, ts time.Time) error
}

// SourceRecorder 来源聚合记录器（apiruntime.SourceRecorder 实现）。
type SourceRecorder struct {
	store   SourceStore
	partner *partnerCIDRCache
}

// 确保实现采集器接口（装配层经 SetSourceRecorder 注入；nil 时采集器跳过）。
var _ apiruntime.SourceRecorder = (*SourceRecorder)(nil)

// NewSourceRecorder 创建记录器（settings 为 nil 时无合作方 CIDR，PARTNER 永不命中）。
func NewSourceRecorder(store SourceStore, settings SettingsReader) *SourceRecorder {
	return &SourceRecorder{store: store, partner: &partnerCIDRCache{settings: settings}}
}

// RecordSource 单事件来源聚合：分类 scope → bucket 计数 + seen 指纹去重明细。
// clientIP 非法时返回 nil（不聚合、不报错——采集链路脏数据容忍，与流量桶同一纪律）。
func (r *SourceRecorder) RecordSource(ctx context.Context, endpointID uuid.UUID, clientIP, fingerprint string, ts time.Time) error {
	scope := apigeo.ClassifyIPScope(clientIP)
	if scope == apigeo.IPScopeInvalid {
		return nil
	}
	// 合作方出口网段优先于公/内网二分：管理员显式登记的网段语义更具体
	// （含合作方 VPN 内网段场景）。
	if r.partner.match(ctx, clientIP) {
		scope = ScopePartner
	}
	return r.store.RecordSource(ctx, endpointID, scope, fingerprint, ts)
}

// WithDB 切换批次事务作用域（apiruntime W22 事务批量化接线；浅拷贝共享 partner 缓存）。
// 内存实现等无事务句柄可切时原样保留（autocommit，幂等键兜底——同 scopedXxx 纪律）。
func (r *SourceRecorder) WithDB(db apiruntime.DBTX) apiruntime.SourceRecorder {
	if s, ok := r.store.(*Store); ok {
		return &SourceRecorder{store: s.WithDB(db), partner: r.partner}
	}
	return r
}

// partnerCIDRCache 合作方出口网段缓存（TTL 60s；settings 变更最多 60s 后生效）。
type partnerCIDRCache struct {
	mu       sync.Mutex
	settings SettingsReader
	prefixes []netip.Prefix
	loadedAt time.Time
}

// partnerCacheTTL 缓存有效期（采集热路径不逐事件读库；变更生效滞后上界 60s）。
const partnerCacheTTL = time.Minute

// match clientIP 是否命中合作方出口网段（settings 未配置/地址非法时 false）。
func (c *partnerCIDRCache) match(ctx context.Context, clientIP string) bool {
	if c == nil || c.settings == nil {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return false
	}
	for _, p := range c.load(ctx) {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// load 读缓存（过期重读 settings 重建；非法项已由 ParseCIDRList 过滤）。
func (c *partnerCIDRCache) load(ctx context.Context) []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.loadedAt) < partnerCacheTTL {
		return c.prefixes
	}
	raw := c.settings.GetString(ctx, SettingsGroup, KeyPartnerEgressCIDRs, "")
	prefixes := []netip.Prefix{}
	for _, cidr := range ParseCIDRList(raw) {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	c.prefixes = prefixes
	c.loadedAt = time.Now()
	return c.prefixes
}
