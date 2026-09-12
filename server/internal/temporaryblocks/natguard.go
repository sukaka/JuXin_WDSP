// natguard.go 阶段5 §十五：CC 自动封禁前的共享出口（NAT/代理）风险检查。
//
// 落点：UpsertFromEvent（采集器消费网关 CC_TEMP_BLOCK_CREATED 事件的自动封禁入库）。
// 网关已先行在 Valkey 写入全时长封禁，故命中风险时除 DB 缩短外必须回写 Valkey
// 缩短后的到期时间，网关下一轮轮询（秒级）生效——这是不改网关前提下的降档通路。
//
// 风险信号（按现实存在性选择）：近 24h 同 IP 关联的不同身份数
// （identity_ip_history，迁移 000097，与 accessrules 预填接口 sharedEgressHint
// 同口径）。保护地址/白名单已在网关请求链短路，不在此重复判定；
// 身份数据缺失（identity_behavior 未开启等）自然零产出，不误判。
//
// 降档策略（三选一选定「缩短封禁时长」）：命中风险时把封禁到期时间夹紧到
// now+nat_block_minutes（原时长更短则不延长），全程写 CC_TEMP_BLOCK_DOWNGRADED
// 审计事件可溯源。默认行为保守：开关默认开、阈值默认 2（宁可不封长）。
package temporaryblocks

import (
	"context"
	"log/slog"
	"time"
)

// 配置键（system_settings cc_auto_block 组，种子见迁移 000153；非法值回落默认）。
const (
	NATSettingsGroup        = "cc_auto_block"
	natGuardEnabledKey      = "nat_guard_enabled"
	natIdentityThresholdKey = "nat_identity_threshold"
	natBlockMinutesKey      = "nat_block_minutes"

	DefaultNATGuardEnabled      = true
	DefaultNATIdentityThreshold = 2
	DefaultNATBlockMinutes      = 15

	natDowngradeReason = "shared_egress_suspected"
)

// SettingsReader 是 NAT 风险检查读取系统设置的最小接口（*settings.Service 实现）。
type SettingsReader interface {
	GetBool(ctx context.Context, group, key string, def bool) bool
	GetInt(ctx context.Context, group, key string, def int) int
}

// NATDowngrade 是一次降档决策的明细（审计事件 details 载荷）。
type NATDowngrade struct {
	Reason              string    `json:"reason"`
	IdentityCount       int64     `json:"identity_count"`
	IdentityThreshold   int       `json:"identity_threshold"`
	BlockMinutes        int       `json:"block_minutes"`
	OriginalExpiresAt   time.Time `json:"original_expires_at"`
	DowngradedExpiresAt time.Time `json:"downgraded_expires_at"`
	ValkeySynced        bool      `json:"valkey_synced"` // 缩短后的到期时间是否已回写 Valkey（false 时网关侧维持原时长至到期）
}

// NATDowngradeEmitter 降档审计事件回调（由装配层注入写 access_control_events，
// 避免与 accesscontrolevents 包循环依赖——与 Handler.ReleaseEventEmitter 同一先例）。
type NATDowngradeEmitter func(ctx context.Context, b *Block, d NATDowngrade)

// SetNATGuardSettings 注入设置读取器（nil 时关闭检查，行为与历史版本一致）。
func (s *Store) SetNATGuardSettings(r SettingsReader) { s.natSettings = r }

// SetNATDowngradeEmitter 注入降档审计事件回调（nil 时仅记日志）。
func (s *Store) SetNATDowngradeEmitter(fn NATDowngradeEmitter) { s.natEmitter = fn }

// natIdentityCounter 近 24h 同 IP 关联身份数查询（默认 identity_ip_history SQL，
// 测试可注入内存实现）。
type natIdentityCounter func(ctx context.Context, ip string, since time.Time) (int64, error)

// identityCount24h 默认实现：identity_ip_history 近 24h 去重身份数
// （与 accessrules sharedEgressHint 同口径）。
func (s *Store) identityCount24h(ctx context.Context, ip string, since time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT identity_id) FROM identity_ip_history
WHERE ip = $1 AND last_seen_at >= $2`, ip, since).Scan(&n)
	return n, err
}

// applyNATGuard 共享出口风险评估：命中疑似共享出口时把 b.BlockExpiresAt 夹紧到
// now+nat_block_minutes 并返回降档明细；未命中/关闭/查询失败返回 nil（失败按原样
// 封禁并如实记错误日志——身份信号缺失不构成放行理由，也不扩大封禁）。
func (s *Store) applyNATGuard(ctx context.Context, b *Block, now time.Time) *NATDowngrade {
	if s.natSettings == nil {
		return nil
	}
	if !s.natSettings.GetBool(ctx, NATSettingsGroup, natGuardEnabledKey, DefaultNATGuardEnabled) {
		return nil
	}
	threshold := s.natSettings.GetInt(ctx, NATSettingsGroup, natIdentityThresholdKey, DefaultNATIdentityThreshold)
	if threshold < 2 || threshold > 1000 {
		threshold = DefaultNATIdentityThreshold
	}
	minutes := s.natSettings.GetInt(ctx, NATSettingsGroup, natBlockMinutesKey, DefaultNATBlockMinutes)
	if minutes < 1 || minutes > 1440 {
		minutes = DefaultNATBlockMinutes
	}
	counter := s.natCounter
	if counter == nil {
		counter = s.identityCount24h
	}
	n, err := counter(ctx, b.ClientIP, now.Add(-24*time.Hour))
	if err != nil {
		slog.Error("nat guard identity count query failed, keep original block",
			"client_ip", b.ClientIP, "error", err)
		return nil
	}
	if n < int64(threshold) {
		return nil
	}
	capAt := now.Add(time.Duration(minutes) * time.Minute)
	if !b.BlockExpiresAt.After(capAt) {
		return nil // 原时长已不长于降档上限，不延长
	}
	d := &NATDowngrade{
		Reason:              natDowngradeReason,
		IdentityCount:       n,
		IdentityThreshold:   threshold,
		BlockMinutes:        minutes,
		OriginalExpiresAt:   b.BlockExpiresAt,
		DowngradedExpiresAt: capAt,
	}
	b.BlockExpiresAt = capAt
	return d
}

// afterNATDowngrade 降档后置：回写 Valkey 缩短封禁 + 审计事件。
// Valkey 回写失败不静默：记错误日志并随审计明细带出（DB 已缩短，
// 网关侧维持原时长到期前仍有效，下轮事件会再次降档兜底）。
func (s *Store) afterNATDowngrade(ctx context.Context, b *Block, d *NATDowngrade) {
	if err := s.cachePut(ctx, b, ""); err != nil {
		slog.Error("nat guard downgrade valkey sync failed",
			"client_ip", b.ClientIP, "block_id", b.ID, "error", err)
	} else {
		d.ValkeySynced = s.cache != nil
	}
	slog.Warn("auto temp block downgraded for suspected shared egress",
		"client_ip", b.ClientIP, "block_id", b.ID,
		"identity_count", d.IdentityCount, "expires_at", d.DowngradedExpiresAt)
	if s.natEmitter != nil {
		s.natEmitter(ctx, b, *d)
	}
}
