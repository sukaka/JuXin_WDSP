// Package riskengine 身份级风险累加与处置评估（WDSP AI 自动化渗透防护增强 阶段3，网关侧）。
//
// 设计纪律（与 guard 既有组件一致）：
//   - 配置缺省 = 零行为变化：risk_policy 段不下发或 enabled=false 时引擎不装配，
//     请求链路无评估、无事件、无存储；
//   - 任何配置缺失/非法 fail-open 按 OBSERVE：Compile 逐项消毒（默认值兜底 + zap Warn），
//     mode 非法按 OBSERVE——风险策略配置问题永不阻断整体配置加载，也绝不据非法配置实断；
//   - OBSERVE 永不实断（只记录"假设会处置"事件）；PROTECT 按阈值实断 403/429，
//     事件 reason 固定 identity_risk_policy，不伪装成规则阻断（设计 #15.2 红线）；
//   - 请求路径禁止 DB/复杂计算：累加器为内存滑窗 + 可选 Valkey（单 Lua 原子往返），
//     Valkey 故障 fail-open 回退进程内存（节流 Warn），评估/记账失败仅告警——请求永不因本包失败而失败；
//   - 跨请求聚合：信号在身份解析后进入累加器，后续请求在身份解析后评估处置——
//     不在单请求内同步聚合（信号产出晚于统一决策点，见任务书架构裁定）。
package riskengine

import (
	"time"

	"go.uber.org/zap"
)

// 模式（与发布契约一致；非法值 fail-open 按 OBSERVE）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 执行动作（冻结契约：仅这四类，不做 CHALLENGE/TEMP_BLOCK 新类别）。
const (
	ActionPass      = "PASS"
	ActionRateLimit = "RATE_LIMIT"
	ActionBlock     = "BLOCK"
)

// 引擎默认值（发布通道未显式下发或值非法时兜底；与冻结契约示例一致）。
const (
	DefaultBlockThreshold      = 80
	DefaultRateLimitThreshold  = 40
	DefaultRateLimitRPS        = 10
	DefaultSignalWindowSeconds = 86400 // 24h

	defaultLevelMedium   = 20
	defaultLevelHigh     = 40
	defaultLevelCritical = 70

	// maxSignalWindowSeconds 滑窗上限（7 天；防内存/Valkey 误配无限留存）。
	maxSignalWindowSeconds = 7 * 24 * 3600
	// maxScore 风险分截断上界（契约：截断 [0,100]）。
	maxScore = 100
	// MaxEntriesPerIdentity 单 identity 滑窗内信号明细上限（防扫描洪泛撑爆内存/事件；
	// 超限淘汰最旧——此时分数早已截断达阈，处置语义不受影响）。
	MaxEntriesPerIdentity = 256
	// maxReasonLen 单条信号 reason 长度上限（事件/存储体量纪律）。
	maxReasonLen = 128
)

// Params 发布通道下发原文（risk_policy 段，与 identity_behavior 同级；json tag 为
// 跨分片冻结契约，不得改动）。nil 或 enabled=false = 零行为变化。
type Params struct {
	Enabled             bool   `json:"enabled"`
	Mode                string `json:"mode,omitempty"`                 // OBSERVE（默认）| PROTECT
	Version             int    `json:"version,omitempty"`              // 策略版本，原样写入事件 policy_version
	BlockThreshold      int    `json:"block_threshold,omitempty"`      // 默认 80
	RateLimitThreshold  int    `json:"rate_limit_threshold,omitempty"` // 默认 40
	RateLimitRPS        int    `json:"rate_limit_rps,omitempty"`       // 默认 10
	SignalWindowSeconds int    `json:"signal_window_seconds,omitempty"`
	// Scores 信号分覆盖表（键 = signal_type；缺省用信号自带分；0 = 该信号不计分）。
	Scores     map[string]int `json:"scores,omitempty"`
	RiskLevels *RiskLevels    `json:"risk_levels,omitempty"`
}

// RiskLevels 风险等级边界（score >= 边界即入级；缺省 20/40/70，设计 #14.2）。
type RiskLevels struct {
	Medium   int `json:"medium,omitempty"`
	High     int `json:"high,omitempty"`
	Critical int `json:"critical,omitempty"`
}

// Config 编译后的风险策略（Provision 产物，请求路径只读）。
type Config struct {
	Enabled             bool
	Mode                string // OBSERVE | PROTECT（非法值已按 OBSERVE 消毒）
	Version             int
	BlockThreshold      int
	RateLimitThreshold  int
	RateLimitRPS        int
	SignalWindowSeconds int
	Scores              map[string]int // 覆盖表原样（键 = signal_type）
	LevelMedium         int
	LevelHigh           int
	LevelCritical       int
}

// Compile 编译发布参数为运行时配置：p 为 nil 或 enabled=false 返回 (nil, nil)（零行为变化）。
// 契约约定任何配置缺失/非法 fail-open 按 OBSERVE：逐项消毒 + Warn，永不返回错误——
// 风险策略配置问题不得阻断整体配置加载，也绝不据非法配置实断。
func Compile(p *Params, logger *zap.Logger) (*Config, error) {
	if p == nil || !p.Enabled {
		return nil, nil
	}
	warn := func(msg string, fields ...zap.Field) {
		if logger != nil {
			logger.Warn("risk_policy: "+msg+"（fail-open 按默认值/OBSERVE 处理）", fields...)
		}
	}
	c := &Config{
		Enabled:             true,
		Mode:                ModeObserve,
		Version:             p.Version,
		BlockThreshold:      DefaultBlockThreshold,
		RateLimitThreshold:  DefaultRateLimitThreshold,
		RateLimitRPS:        DefaultRateLimitRPS,
		SignalWindowSeconds: DefaultSignalWindowSeconds,
		Scores:              map[string]int{},
		LevelMedium:         defaultLevelMedium,
		LevelHigh:           defaultLevelHigh,
		LevelCritical:       defaultLevelCritical,
	}
	switch p.Mode {
	case "", ModeObserve:
	case ModeProtect:
		c.Mode = ModeProtect
	default:
		warn("mode 非法", zap.String("mode", p.Mode))
	}
	if p.Version < 0 {
		warn("version 非法", zap.Int("version", p.Version))
		c.Version = 0
	}
	if p.BlockThreshold > 0 && p.BlockThreshold <= maxScore {
		c.BlockThreshold = p.BlockThreshold
	} else if p.BlockThreshold != 0 {
		warn("block_threshold 非法", zap.Int("block_threshold", p.BlockThreshold))
	}
	if p.RateLimitThreshold > 0 && p.RateLimitThreshold <= maxScore {
		c.RateLimitThreshold = p.RateLimitThreshold
	} else if p.RateLimitThreshold != 0 {
		warn("rate_limit_threshold 非法", zap.Int("rate_limit_threshold", p.RateLimitThreshold))
	}
	if c.RateLimitThreshold >= c.BlockThreshold {
		warn("rate_limit_threshold >= block_threshold，RATE_LIMIT 档为空（BLOCK 优先评估）",
			zap.Int("rate_limit_threshold", c.RateLimitThreshold), zap.Int("block_threshold", c.BlockThreshold))
	}
	if p.RateLimitRPS > 0 {
		c.RateLimitRPS = p.RateLimitRPS
	} else if p.RateLimitRPS != 0 {
		warn("rate_limit_rps 非法", zap.Int("rate_limit_rps", p.RateLimitRPS))
	}
	switch {
	case p.SignalWindowSeconds > 0 && p.SignalWindowSeconds <= maxSignalWindowSeconds:
		c.SignalWindowSeconds = p.SignalWindowSeconds
	case p.SignalWindowSeconds > maxSignalWindowSeconds:
		warn("signal_window_seconds 超上限，截断", zap.Int("signal_window_seconds", p.SignalWindowSeconds))
		c.SignalWindowSeconds = maxSignalWindowSeconds
	case p.SignalWindowSeconds < 0:
		warn("signal_window_seconds 非法", zap.Int("signal_window_seconds", p.SignalWindowSeconds))
	}
	for k, v := range p.Scores {
		if v < 0 {
			warn("scores 分值非法，该项忽略", zap.String("signal_type", k), zap.Int("score", v))
			continue
		}
		c.Scores[k] = v
	}
	if rl := p.RiskLevels; rl != nil {
		if rl.Medium > 0 && rl.Medium <= maxScore {
			c.LevelMedium = rl.Medium
		}
		if rl.High > 0 && rl.High <= maxScore {
			c.LevelHigh = rl.High
		}
		if rl.Critical > 0 && rl.Critical <= maxScore {
			c.LevelCritical = rl.Critical
		}
		if !(c.LevelMedium < c.LevelHigh && c.LevelHigh < c.LevelCritical) {
			warn("risk_levels 非递增，回退默认等级边界",
				zap.Int("medium", c.LevelMedium), zap.Int("high", c.LevelHigh), zap.Int("critical", c.LevelCritical))
			c.LevelMedium, c.LevelHigh, c.LevelCritical = defaultLevelMedium, defaultLevelHigh, defaultLevelCritical
		}
	}
	return c, nil
}

// Level 风险等级（score 已截断 [0,100]；边界配置化，设计 #14.2）。
func (c *Config) Level(score int) string {
	switch {
	case score >= c.LevelCritical:
		return "CRITICAL"
	case score >= c.LevelHigh:
		return "HIGH"
	case score >= c.LevelMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Window 滑窗时长。
func (c *Config) Window() time.Duration {
	return time.Duration(c.SignalWindowSeconds) * time.Second
}
