// types.go 数据出境观察记录实体、看板聚合类型与查询过滤（handler 与 store 共用）。
package apigeo

import (
	"time"

	"github.com/google/uuid"
)

// 方向（api_cross_border_events.direction CHECK 对齐）：
// OUT = 响应侧涉敏数据流向境外客户端（数据出境）；IN = 境外客户端提交涉敏数据（数据入境）。
const (
	DirectionOut = "OUT"
	DirectionIn  = "IN"
)

// 风险等级（api_cross_border_events.risk_level CHECK 对齐）。
// 由 data_types 经 api_sensitive_data_types.level 推导：CORE/IMPORTANT→HIGH，
// SENSITIVE 或字典外类型（保守口径）→MEDIUM，其余/无类型→LOW。
const (
	RiskLow    = "LOW"
	RiskMedium = "MEDIUM"
	RiskHigh   = "HIGH"
)

// 看板窗口约束（与 apidata 态势同口径）。
const (
	DashboardDefaultDays = 7
	DashboardMaxDays     = 30
)

// by_endpoint 聚合上限（国家/类型天然有界，端点无界需防爆）。
const dashboardEndpointLimit = 50

// CrossBorderEvent 跨境观察记录（api_cross_border_events）。
type CrossBorderEvent struct {
	ID                  uuid.UUID `json:"id"`
	OccurredAt          time.Time `json:"occurred_at"`
	ClientIP            string    `json:"client_ip"` // netip 归一化（maskIP 纪律）
	Country             string    `json:"country"`   // ISO 3166-1 alpha-2
	Asn                 *int64    `json:"asn"`       // 预留：当前数据源无 ASN，恒 NULL
	EndpointKey         string    `json:"endpoint_key"`
	IdentityFingerprint string    `json:"identity_fingerprint"` // 匿名流量为空串
	DataTypes           []string  `json:"data_types"`
	Direction           string    `json:"direction"`
	RiskLevel           string    `json:"risk_level"`
	SourceEventID       uuid.UUID `json:"source_event_id"`
	CreatedAt           time.Time `json:"created_at"`
}

// EventFilter 明细分页过滤（枚举值已在 handler 层归一校验）。
type EventFilter struct {
	Days        int // 窗口天数（聚合与明细同窗口）
	Country     string
	Direction   string
	RiskLevel   string
	EndpointKey string
	Page        int
	PageSize    int
}

// DashboardSummary 窗口内汇总。
type DashboardSummary struct {
	TotalEvents   int64 `json:"total_events"`
	CountryCount  int64 `json:"country_count"`  // 涉及境外国家/地区数
	EndpointCount int64 `json:"endpoint_count"` // 涉及端点数
	HighRiskCount int64 `json:"high_risk_count"`
}

// CountryStat 国家/地区聚合项（DataTypes 由 country×type 明细归并）。
type CountryStat struct {
	Country       string   `json:"country"`
	EventCount    int64    `json:"event_count"`
	EndpointCount int64    `json:"endpoint_count"`
	DataTypes     []string `json:"data_types"`
}

// CountryTypeStat 国家/地区×敏感类型聚合项（一事件多类型时每类型各计一次）。
type CountryTypeStat struct {
	Country    string `json:"country"`
	DataType   string `json:"data_type"`
	EventCount int64  `json:"event_count"`
}

// EndpointStat 端点聚合项。
type EndpointStat struct {
	EndpointKey  string `json:"endpoint_key"`
	EventCount   int64  `json:"event_count"`
	CountryCount int64  `json:"country_count"` // 该端点涉及的境外国家/地区数
}

// TrendPoint 单日趋势点。
type TrendPoint struct {
	Date       string `json:"date"` // YYYY-MM-DD（库会话时区 CURRENT_DATE 口径）
	EventCount int64  `json:"event_count"`
}

// DashboardData 看板聚合（geo_enabled/home_regions 元信息由 handler 补充）。
type DashboardData struct {
	Days          int               `json:"days"`
	Summary       DashboardSummary  `json:"summary"`
	ByCountry     []CountryStat     `json:"by_country"`
	ByCountryType []CountryTypeStat `json:"by_country_type"`
	ByEndpoint    []EndpointStat    `json:"by_endpoint"`
	Trend         []TrendPoint      `json:"trend"`
}

// clampDays 归一看板窗口（1..DashboardMaxDays，默认 DashboardDefaultDays）。
func clampDays(days int) int {
	if days <= 0 {
		return DashboardDefaultDays
	}
	if days > DashboardMaxDays {
		return DashboardMaxDays
	}
	return days
}

// validDirection / validRiskLevel 枚举校验（handler 查询参数白名单）。
func validDirection(s string) bool { return s == DirectionOut || s == DirectionIn }

func validRiskLevel(s string) bool { return s == RiskLow || s == RiskMedium || s == RiskHigh }
