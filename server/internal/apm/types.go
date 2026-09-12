// Package apm APM 业务性能监控查询（无 Agent 模式；决策 docs/APM_STAGE0_ADR.md D8/D9/D11/D12）。
//
// 数据源（全部为既有聚合体系读模型，不新增基础设施）：
//   - 应用级 RED：管道 B 聚合指标 http_requests_total{app,status_class}、
//     http_request_duration_ms{app}（extra.buckets 直方图，分位数估算用
//     metrics.PercentileFromBuckets）、waf_blocks_total{app}、waf_observes_total{app}；
//   - 端点级 RED：管道 A 端点聚合指标 http_endpoint_requests_total /
//     http_endpoint_duration_ms（labels app/endpoint/status_class/action，action 小写
//     allow/observe/block），仅 logging.access_log_enabled 开启时由聚合任务产出；
//   - trace 检索：access_logs.trace_id（迁移 000088）→ request_id 关联 security_events。
//
// 聚合表分层：查询窗口 ≤6h 查 metric_minute_aggregates（分钟桶），否则查
// metric_hour_aggregates（小时桶；直方图桶由小时 rollup 合并保留，分位数可跨天估算）。
// trend 粒度与所选表桶一致（分钟桶/小时桶）。所有查询强制时间窗上限与分页上限，
// SQL 全部参数化；纯查询接口不写操作审计（沿用现有惯例，ADR D12）。
package apm

import (
	"time"

	"github.com/google/uuid"
)

// Latency 分位数（毫秒，直方图桶线性插值估算；无样本时各项为 0）。
type Latency struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// TrendBucket 趋势桶（errors 为 5xx 计数，与 error_rate=5xx/requests 口径一致；
// p95 为该桶内合并直方图估算，无样本为 0）。
type TrendBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Requests    float64   `json:"requests"`
	Errors      float64   `json:"errors"`
	Blocked     float64   `json:"blocked"`
	P95         float64   `json:"p95"`
}

// AppRankItem 应用排行项（application_id 在应用已删除或聚合标签无法匹配时为 null）。
type AppRankItem struct {
	ApplicationID *uuid.UUID `json:"application_id"`
	App           string     `json:"app"`
	Name          string     `json:"name"`
	Requests      float64    `json:"requests"`
	ErrorRate     float64    `json:"error_rate"`
	P95           float64    `json:"p95"`
}

// EndpointStat 端点排行项（overview 时填充 app；服务详情 top_endpoints 省略 app）。
type EndpointStat struct {
	App       string  `json:"app,omitempty"`
	Endpoint  string  `json:"endpoint"`
	Requests  float64 `json:"requests"`
	ErrorRate float64 `json:"error_rate"`
	P95       float64 `json:"p95"`
}

// OverviewData GET /api/v1/apm/overview 响应数据。
type OverviewData struct {
	DataSource           string         `json:"data_source"` // 恒 "agentless"（无 Agent 网关侧观测）
	AccessLogEnabled     bool           `json:"access_log_enabled"`
	StartTime            time.Time      `json:"start_time"`
	EndTime              time.Time      `json:"end_time"`
	RequestsTotal        float64        `json:"requests_total"`
	Error5xxTotal        float64        `json:"error_5xx_total"`
	Error4xxTotal        float64        `json:"error_4xx_total"`
	BlockedTotal         float64        `json:"blocked_total"`
	ErrorRate            float64        `json:"error_rate"` // 5xx / requests_total
	Latency              Latency        `json:"latency"`
	Trend                []TrendBucket  `json:"trend"`
	TopSlowApplications  []AppRankItem  `json:"top_slow_applications"`
	TopErrorApplications []AppRankItem  `json:"top_error_applications"`
	TopSlowEndpoints     []EndpointStat `json:"top_slow_endpoints"` // access_log 关闭时为空数组
	UnclassifiedRequests int64          `json:"unclassified_requests"`
	// P1-01 A2 增量（旧字段全部保留）：
	Availability *Availability `json:"availability"` // 数据质量自述（§4.3）
}

// ServiceRow APM 服务（应用）列表行。
type ServiceRow struct {
	ApplicationID   uuid.UUID  `json:"application_id"`
	App             string     `json:"app"`
	Name            string     `json:"name"`
	ObservationMode string     `json:"observation_mode"` // "agent"（有在线 Agent 映射到该应用）/ "agentless"
	AgentsOnline    int        `json:"agents_online"`    // 在线 Agent 数（心跳未超离线阈值且非 REVOKED）
	AgentsTotal     int        `json:"agents_total"`     // 登记 Agent 总数（不含 REVOKED）
	Requests        float64    `json:"requests"`
	ErrorRate       float64    `json:"error_rate"`
	Blocked         float64    `json:"blocked"`
	P50             float64    `json:"p50"`
	P95             float64    `json:"p95"`
	P99             float64    `json:"p99"`
	LastSeenAt      *time.Time `json:"last_seen_at"` // 窗口内无流量为 null
}

// StatusClassCount 状态码类别计数。
type StatusClassCount struct {
	StatusClass string  `json:"status_class"`
	Count       float64 `json:"count"`
}

// ActionCount 动作分布计数（action ∈ allow/observe/block；app 级由
// requests/blocks/observes 派生：allow=requests−block−observe，与端点级 action 标签口径一致）。
type ActionCount struct {
	Action string  `json:"action"`
	Count  float64 `json:"count"`
}

// ServiceDetailData GET /api/v1/apm/services/{id} 响应数据。
type ServiceDetailData struct {
	ApplicationID   uuid.UUID          `json:"application_id"`
	App             string             `json:"app"`
	Name            string             `json:"name"`
	ObservationMode string             `json:"observation_mode"` // 恒 "agentless"
	RequestsTotal   float64            `json:"requests_total"`
	ErrorRate       float64            `json:"error_rate"`
	Latency         Latency            `json:"latency"`
	Trend           []TrendBucket      `json:"trend"`
	StatusClasses   []StatusClassCount `json:"status_classes"`
	Actions         []ActionCount      `json:"actions"`
	TopEndpoints    []EndpointStat     `json:"top_endpoints"` // access_log 关闭时为空数组
	// P1-01 A2 增量（旧字段全部保留）：
	Availability *Availability `json:"availability"`
}

// EndpointRow APM 端点列表行（__OTHER__/__UNCLASSIFIED__ 保留桶原样返回，前端负责标注）。
type EndpointRow struct {
	App           string     `json:"app"`
	ApplicationID *uuid.UUID `json:"application_id"`
	Endpoint      string     `json:"endpoint"`
	Method        string     `json:"method"`        // 从 endpoint 键拆出；保留桶为空串
	PathTemplate  string     `json:"path_template"` // 从 endpoint 键拆出；保留桶为空串
	Requests      float64    `json:"requests"`
	ErrorRate     float64    `json:"error_rate"`
	Blocked       float64    `json:"blocked"`
	P50           float64    `json:"p50"`
	P95           float64    `json:"p95"`
	P99           float64    `json:"p99"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
}

// TraceAccessLog trace 关联的访问记录（安全子集：不含请求/响应头体留痕；
// waf_action 历史空串按 ALLOW 归一，与 ADR D9 口径一致）。
type TraceAccessLog struct {
	ID             uuid.UUID  `json:"id"`
	OccurredAt     time.Time  `json:"occurred_at"`
	RequestID      string     `json:"request_id"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	Domain         string     `json:"domain"`
	ClientIP       string     `json:"client_ip"`
	RequestMethod  string     `json:"request_method"`
	RequestURI     string     `json:"request_uri"`
	RequestPath    string     `json:"request_path"`
	ResponseStatus int        `json:"response_status"`
	DurationMS     int        `json:"duration_ms"`
	TTFBMS         *int       `json:"ttfb_ms"` // 旧网关无此字段为 null
	WAFAction      string     `json:"waf_action"`
	SpanID         *string    `json:"span_id"`
	EndpointKey    *string    `json:"endpoint_key"`
	PathTemplate   *string    `json:"path_template"`
}

// TraceSecurityEvent trace 关联的安全事件（必要安全字段子集，不含头体留痕，
// 遵循 securityevents 既有脱敏口径——脱敏在写入侧完成，本子集不引入新的暴露面）。
type TraceSecurityEvent struct {
	ID                uuid.UUID  `json:"id"`
	OccurredAt        time.Time  `json:"occurred_at"`
	RequestID         string     `json:"request_id"`
	ApplicationID     *uuid.UUID `json:"application_id"`
	AttackType        string     `json:"attack_type"`
	Severity          string     `json:"severity"`
	Action            string     `json:"action"`
	ResponseStatus    int        `json:"response_status"`
	RequestMethod     string     `json:"request_method"`
	RequestURI        string     `json:"request_uri"`
	RuleMatchCount    int        `json:"rule_match_count"`
	DispositionStatus string     `json:"disposition_status"`
}

// TraceViewData GET /api/v1/apm/traces/{trace_id} 响应数据。
// 无 Agent 模式只有网关侧单跳记录；接入 OTel 数据面后 otel_spans 携带瀑布数据。
// 均无命中时 access_logs/security_events/otel_spans 为空数组而非 404。
type TraceViewData struct {
	TraceID        string               `json:"trace_id"`
	AccessLogs     []TraceAccessLog     `json:"access_logs"`
	SecurityEvents []TraceSecurityEvent `json:"security_events"`
	OTelSpans      []OTelSpan           `json:"otel_spans"`  // OTel 瀑布（属性仅白名单键；无数据面/未命中为空数组）
	SpanCount      int                  `json:"span_count"`  // 返回的 span 数（截断时为上限值）
	Truncated      bool                 `json:"truncated"`   // span 超上限被截断时为 true
	DataSource     string               `json:"data_source"` // agentless / otel / mixed（见 dataSource* 常量）
	Partial        bool                 `json:"partial"`     // 可能不完整：无 OTel span、缺根 span 或被截断
	Note           string               `json:"note"`        // 数据来源说明（与 data_source 同值）
	// P1-01 A2 增量（旧字段全部保留）：
	Availability *Availability `json:"availability"` // 数据质量自述（§4.3）
	Correlation  *Correlation  `json:"correlation"`  // trace_id 直达关联判定（恒携带）
}

// ---------- 阶段2 下半：ClickHouse 数据面（OTel trace 检索与瀑布） ----------

// data_source 词表：agentless=仅无 Agent 网关侧数据；otel=仅 OTel 数据面；mixed=两侧均有。
const (
	dataSourceAgentless = "agentless"
	dataSourceOTel      = "otel"
	dataSourceMixed     = "mixed"
)

// OTelSpan trace 瀑布单个 span（attributes 只含白名单键，见 chstore.go spanAttrWhitelist）。
type OTelSpan struct {
	SpanID        string            `json:"span_id"`
	ParentSpanID  string            `json:"parent_span_id"` // 根 span 为空串
	ServiceName   string            `json:"service_name"`
	OperationName string            `json:"operation_name"`
	SpanKind      string            `json:"span_kind"` // Server / Client / Internal / Producer / Consumer
	StartTime     time.Time         `json:"start_time"`
	DurationMS    float64           `json:"duration_ms"` // 毫秒（微秒精度，3 位小数）
	StatusCode    string            `json:"status_code"` // Unset / Ok / Error
	Attributes    map[string]string `json:"attributes"`  // 白名单键子集，无命中为 {}
}

// TraceSearchFilter trace-search 查询条件（handler 已完成校验与夹紧：
// Start/End 强制限窗 ≤24h；TraceIDs 均为合法 32hex；Page/PageSize 已夹紧）。
type TraceSearchFilter struct {
	Start         time.Time
	End           time.Time
	Service       string   // ServiceName 精确匹配（空 = 不限）
	TraceIDs      []string // trace_id 直达集（handler 校验后小写化）；空且 RequestID 非空时由 store 解析
	RequestID     string   // 先查 access_logs 解析 trace_id 集合再查 CH（空 = 不用）
	MinDurationMS float64
	ErrorOnly     bool
	Page          int
	PageSize      int
	// P1-01 A2 增量：
	ApplicationID *uuid.UUID // 按应用约束检索（handler 已校验存在性；store 反解 apm_services 服务名集合并下推 access_logs 约束）
	// ServiceNames 应用映射的 OTel 服务名集合（store 由 ApplicationID 反解；
	// 非 nil 时 CH 查询强制 ServiceName IN 约束；空集合 = 约束不可满足，如实空页）
	ServiceNames []string
	// AccessLogEnabled 访问日志总开关（ACCESS_LOG_DISABLED 原因码证据；handler 读取设置填入）
	AccessLogEnabled bool
	// IngestLagThreshold 采集滞后判定阈值（INGESTION_DELAY_CONFIRMED/PENDING 证据；
	// handler 读 apm_alert.ingest_lag_seconds，非法值已回退默认）
	IngestLagThreshold time.Duration
}

// TraceSearchItem trace-search 列表行（trace 粒度聚合）。
type TraceSearchItem struct {
	TraceID       string    `json:"trace_id"`
	RootService   string    `json:"root_service"`   // 根 span 服务名（缺根 span 时为空串，如实返回）
	RootOperation string    `json:"root_operation"` // 根 span 操作名（同上）
	StartTime     time.Time `json:"start_time"`     // trace 最早 span 开始时间
	DurationMS    float64   `json:"duration_ms"`    // 墙钟耗时：max(span 结束) − min(span 开始)，毫秒
	SpanCount     int64     `json:"span_count"`
	ErrorCount    int64     `json:"error_count"`
	Services      []string  `json:"services"` // 参与服务名（去重，上限 32）
}

// TraceSearchData GET /api/v1/apm/trace-search 响应数据。
// CH 未配置/不可用时 List 为空、DataSource=agentless 且 Message 给出原因（不 500）。
type TraceSearchData struct {
	List       []TraceSearchItem `json:"list"`
	Total      int64             `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
	DataSource string            `json:"data_source"` // otel / agentless
	Message    string            `json:"message"`     // 降级原因提示/过滤约束不可满足说明（正常时为空串）
	// P1-01 A2 增量（旧字段全部保留）：
	Availability *Availability `json:"availability"`          // 数据质量自述（§4.3）
	Correlation  *Correlation  `json:"correlation,omitempty"` // 仅 request_id 检索时携带（trace_id 直达优先时不经解析链，不携带）
}

// ---------- 阶段3 第一批：SQL 指纹聚合 / 异常指纹 / 服务依赖（CH 数据面） ----------

// SQLFilter SQL 指纹聚合查询条件（handler 已完成校验与夹紧：
// Start/End 强制限窗 ≤24h；Sort 已白名单校验；Page/PageSize 已夹紧）。
type SQLFilter struct {
	Start    time.Time
	End      time.Time
	Service  string // ServiceName 精确匹配（空 = 不限）
	DBSystem string // db.system 精确匹配（空 = 不限）
	Sort     string // calls / avg_ms / p95_ms（默认 p95_ms 倒序）
	Page     int
	PageSize int
	// P1-01 A2 增量：
	TraceID string // trace 级定位（空 = 窗口聚合模式）；非空时仅从该 trace 的 DB span 派生指纹
	// IngestLagThreshold 采集滞后判定阈值（同 TraceSearchFilter）
	IngestLagThreshold time.Duration
}

// SQLRow SQL 指纹聚合行。口径：只出指纹不出原始 statement（设计 §11.1：首期只存指纹）；
// calls/error_count/avg_ms 来自 002 SQL 指纹分钟聚合表（apm.apm_sql_minutes），
// p95_ms/namespace/operation/sample_trace_ids 由 apm.otel_traces 同窗派生
// （分钟聚合表无分位数与命名空间列，见 chstore_aggregates.go 注释）。
type SQLRow struct {
	SQLFingerprint string   `json:"sql_fingerprint"` // hex(MD5(normalized db.statement))
	DBSystem       string   `json:"db_system"`       // OTel db.system（如 postgresql/mysql）
	Namespace      string   `json:"namespace"`       // db.namespace（库/Schema；缺失为空串）
	Operation      string   `json:"operation"`       // db.operation.name（如 SELECT；缺失为空串）
	Calls          int64    `json:"calls"`
	ErrorCount     int64    `json:"error_count"`
	AvgMS          float64  `json:"avg_ms"`           // 平均耗时（毫秒，3 位小数）
	P95MS          float64  `json:"p95_ms"`           // p95 耗时（毫秒，3 位小数；原始表同窗估算）
	SampleTraceIDs []string `json:"sample_trace_ids"` // 示例 trace（去重，上限 3）
}

// SQLData GET /api/v1/apm/sql 响应数据。
// CH 未配置/不可用时 List 为空、DataSource=agentless 且 Message 给出原因（不 500）。
type SQLData struct {
	List       []SQLRow `json:"list"`
	Total      int64    `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	DataSource string   `json:"data_source"` // otel / agentless
	Message    string   `json:"message"`     // 降级原因提示（正常时为空串）
	// P1-01 A2 增量（旧字段全部保留）：
	TraceID      string        `json:"trace_id"`   // 请求侧 trace_id 回显（未提供为空串）
	MatchMode    string        `json:"match_mode"` // trace_exact / window_aggregate（见 matchMode* 常量）
	MatchNote    string        `json:"match_note"` // 匹配语义说明（window_aggregate 时如实标注"非特定请求定位"）
	Availability *Availability `json:"availability"`
}

// ExceptionsFilter 异常指纹聚合查询条件（handler 已校验/夹紧，口径同 SQLFilter）。
type ExceptionsFilter struct {
	Start    time.Time
	End      time.Time
	Service  string // ServiceName 精确匹配（空 = 不限）
	Page     int
	PageSize int
	// P1-01 A2 增量：
	TraceID string // trace 级定位（空 = 窗口聚合模式）；非空时直读该 trace 的 exception 事件
	// IngestLagThreshold 采集滞后判定阈值（同 TraceSearchFilter）
	IngestLagThreshold time.Duration
}

// ExceptionRow 异常指纹聚合行。数据源为 002 异常指纹表（apm.apm_exception_fingerprints，
// AggregatingMergeTree）：count 为 exception 事件数（一个 span 可携带多个 exception 事件）；
// first_seen_at/last_seen_at 为分钟聚合桶粒度（±1 分钟）；不存/不出堆栈原文。
type ExceptionRow struct {
	ExceptionType    string    `json:"exception_type"` // exception.type（缺失为空串）
	Fingerprint      string    `json:"fingerprint"`    // hex(MD5(归一化 exception.stacktrace))
	Count            int64     `json:"count"`
	FirstSeenAt      time.Time `json:"first_seen_at"`     // 窗口内首个分钟桶
	LastSeenAt       time.Time `json:"last_seen_at"`      // 窗口内最后分钟桶
	AffectedServices []string  `json:"affected_services"` // 受影响服务（去重，上限 16）
	SampleTraceIDs   []string  `json:"sample_trace_ids"`  // 示例 trace（去重，上限 3）
}

// ExceptionTraceItem trace 级异常定位行（P1-01 A2：trace_id 参数模式，
// 从 otel_traces 的 exception 事件直接派生——精确语义，非窗口聚合候选）。
// exception_message/stacktrace 为应用上报原文经凭据形态掩码 + rune 长度上限截断
// 后的纯文本（截断时对应 *_truncated=true）；fingerprint 与聚合表同式
// （hex(MD5(stacktrace 原文))），可与窗口聚合行指纹对照。
type ExceptionTraceItem struct {
	TraceID             string    `json:"trace_id"`
	SpanID              string    `json:"span_id"`
	ServiceName         string    `json:"service_name"`
	OccurredAt          time.Time `json:"occurred_at"`       // exception 事件时间（Events.Timestamp）
	ExceptionType       string    `json:"exception_type"`    // exception.type（缺失为空串）
	ExceptionMessage    string    `json:"exception_message"` // 掩码+截断后纯文本
	Stacktrace          string    `json:"stacktrace"`        // 掩码+截断后纯文本
	Fingerprint         string    `json:"fingerprint"`       // hex(MD5(exception.stacktrace 原文))
	MessageTruncated    bool      `json:"message_truncated"`
	StacktraceTruncated bool      `json:"stacktrace_truncated"`
}

// ExceptionsData GET /api/v1/apm/exceptions 响应数据（降级口径同 SQLData）。
// trace_id 提供时结果在 trace_exceptions（trace 级精确定位），list 为空数组。
type ExceptionsData struct {
	List       []ExceptionRow `json:"list"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	DataSource string         `json:"data_source"` // otel / agentless
	Message    string         `json:"message"`     // 降级原因提示（正常时为空串）
	// P1-01 A2 增量（旧字段全部保留）：
	TraceID         string               `json:"trace_id"`         // 请求侧 trace_id 回显（未提供为空串）
	MatchMode       string               `json:"match_mode"`       // trace_exact / window_aggregate
	MatchNote       string               `json:"match_note"`       // 匹配语义说明
	TraceExceptions []ExceptionTraceItem `json:"trace_exceptions"` // trace 级定位结果（仅 trace_exact 模式；窗口模式为空数组）
	Availability    *Availability        `json:"availability"`
}

// DependenciesFilter 服务依赖查询条件（handler 已校验/夹紧：窗口 ≤24h）。
type DependenciesFilter struct {
	Start   time.Time
	End     time.Time
	Service string // 源端 ServiceName 精确匹配（空 = 不限）
}

// DependencyEdge 服务依赖边（客户端 span 单视角派生：CLIENT/PRODUCER span 的
// ServiceName → peer；无对端 SERVER span 配对，见 chstore_aggregates.go 口径注释）。
type DependencyEdge struct {
	Source     string  `json:"source"`      // 调用方服务名
	Target     string  `json:"target"`      // 对端标识（peer.service / db.system[/namespace] / messaging.system[/destination] / server.address）
	TargetType string  `json:"target_type"` // service / db / messaging / external
	Calls      int64   `json:"calls"`
	ErrorRate  float64 `json:"error_rate"` // Error span 占比（0~1，3 位小数）
	AvgMS      float64 `json:"avg_ms"`     // 平均耗时（毫秒，3 位小数）
}

// DependenciesData GET /api/v1/apm/dependencies 响应数据。
// CH 未配置/不可用时 Edges 为空、DataSource=agentless 且 Note 给出原因（不 500）；
// 正常时 Note 如实标注派生口径（客户端 span 单视角）。
type DependenciesData struct {
	Edges      []DependencyEdge `json:"edges"`
	DataSource string           `json:"data_source"` // otel / agentless
	Note       string           `json:"note"`        // 派生口径/降级原因说明
}

// ---------- 阶段3 第二批：运行时指标（metrics 信号，CH 数据面 otel_metrics_* 表） ----------

// RuntimeFilter 运行时指标查询条件（handler 已完成校验与夹紧：
// Start/End 强制限窗 ≤24h；Service/InstanceID 长度已限制）。
type RuntimeFilter struct {
	Start      time.Time
	End        time.Time
	Service    string // ServiceName 精确匹配（空 = 不限）
	InstanceID string // ResourceAttributes['service.instance.id'] 精确匹配（空 = 不限）
}

// RuntimePoint 降采样后的单个指标点（ts 为桶起点；value 为桶内均值，
// 同名多序列按桶求和合并——口径见 chstore_metrics.go 与 RuntimeData.Note）。
type RuntimePoint struct {
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// RuntimeMetric 单实例单个指标（name/unit/description 来自上报原值；
// description 尾部附来源 scope 与折算口径说明——不同语言 Agent 指标集不强行统一，
// 设计 §10.3"统一类别 + 原生指标明细，并展示数据来源与兼容性"）。
type RuntimeMetric struct {
	Name        string         `json:"name"`
	Unit        string         `json:"unit"`        // UCUM 单位（如 By / {goroutine} / s；上报缺失为空串）
	Description string         `json:"description"` // 上报描述 + 来源/折算口径说明
	LatestValue float64        `json:"latest_value"`
	Points      []RuntimePoint `json:"points"` // 按窗口降采样（≤200 点，桶起点升序）
}

// RuntimeInstance 服务实例运行时指标（instance_id 为 OTel resource
// service.instance.id；Agent 未上报该属性时为空串，如实返回）。
type RuntimeInstance struct {
	InstanceID  string          `json:"instance_id"`
	ServiceName string          `json:"service_name"`
	Metrics     []RuntimeMetric `json:"metrics"` // ≤20 个（按指标名升序截取）
}

// RuntimeData GET /api/v1/apm/runtime 响应数据。
// CH 未配置/不可用时 Instances 为空、DataSource=agentless 且 Note 给出原因（不 500）。
type RuntimeData struct {
	DataSource string            `json:"data_source"` // otel / agentless
	Instances  []RuntimeInstance `json:"instances"`   // ≤20 个实例（超限截断并在 note 标注）
	Note       string            `json:"note"`        // 口径/截断/降级说明
}

// ---------- P1-01 A2：数据质量自述（availability）与关联（correlation） ----------
// 契约见 docs/tasks/wdsp-p1/P1-01_SECURITY_APM_DEMO.md §4.2/§4.3；
// 词表在此冻结，新增取值须先改任务书契约。

// query_state 词表：READY 有实际可用数据；EMPTY 成功查询的零结果（存储异常不得改成
// EMPTY）；PARTIAL 部分结果（丢 Span/单腿降级/截断/授权裁剪）；UNAVAILABLE 存储
// 未配置/不可用。
const (
	queryStateReady       = "READY"
	queryStateEmpty       = "EMPTY"
	queryStatePartial     = "PARTIAL"
	queryStateUnavailable = "UNAVAILABLE"
)

// reason_codes 冻结枚举（只填有依据的原因，允许多个数据源问题并存）。
// NO_INSTRUMENTATION_CONFIRMED / NOT_SAMPLED_CONFIRMED 在 A2 暂无证据来源
// （无探针注册/采样决策数据），词表冻结保留但本阶段不产出——单凭"查不到 Span"
// 只能返回 NO_MATCH 或 UNKNOWN。
const (
	reasonStorageNotConfigured       = "STORAGE_NOT_CONFIGURED"
	reasonStorageUnavailable         = "STORAGE_UNAVAILABLE"
	reasonAccessLogDisabled          = "ACCESS_LOG_DISABLED"
	reasonNoInstrumentationConfirmed = "NO_INSTRUMENTATION_CONFIRMED"
	reasonNotSampledConfirmed        = "NOT_SAMPLED_CONFIRMED"
	reasonIngestionDelayConfirmed    = "INGESTION_DELAY_CONFIRMED"
	reasonOutsideRetention           = "OUTSIDE_RETENTION"
	reasonNoMatch                    = "NO_MATCH"
	reasonUnknown                    = "UNKNOWN"
)

// observed_sources 词表（从本次真实查询结果判定；Agent 心跳不构成观测证据）。
const (
	sourceGateway = "GATEWAY"
	sourceOTel    = "OTEL"
)

// correlation state 词表（独立于数据源健康）。
const (
	correlationMatched     = "MATCHED"      // 唯一候选且已命中
	correlationAmbiguous   = "AMBIGUOUS"    // 一对多：返回全部候选，不任取第一条
	correlationPending     = "PENDING"      // 目标可能尚在采集/入库途中（有界等待由前端做，后端不轮询）
	correlationNotFound    = "NOT_FOUND"    // 目标在证据范围内不存在
	correlationNotExpected = "NOT_EXPECTED" // 已证实网关终止且未调用源站，无 Span 为预期
	correlationUnknown     = "UNKNOWN"      // 证据不足，不编造结论
)

// match_basis 匹配依据词表（机器可读稳定值；人类可读解释在 reason）。
const (
	matchBasisRequestIDChain = "request_id_to_trace_id" // request_id 经 access_logs 解析 trace_id
	matchBasisTraceIDDirect  = "trace_id_direct"        // trace_id 直接精确匹配
	// 候选级依据：候选证据来自哪一侧
	candidateBasisOTel       = "otel_traces.trace_id" // 数据面 Span 命中
	candidateBasisAccessLogs = "access_logs.trace_id" // 网关访问记录解析（数据面未确认）
)

// match_mode 词表（SQL/异常接口的定位语义）。
const (
	matchModeTraceExact      = "trace_exact"      // trace 级精确定位（仅该 trace 的 Span/事件派生）
	matchModeWindowAggregate = "window_aggregate" // 窗口级聚合（与特定请求无精确关系，仅为候选）
)

// Availability 数据质量自述（§4.3）：替代"data_source=agentless 承载所有健康状态"。
// reason_codes/observed_sources 恒为数组（无内容为空数组而非 null）；
// last_collected_at/last_ingested_at 未知为 null（严禁用 now 填充）；
// estimated_lag_ms 仅在取得可比较水位时非 null（估计值，非请求级精确延迟）。
type Availability struct {
	QueryState      string     `json:"query_state"`
	ReasonCodes     []string   `json:"reason_codes"`
	ObservedSources []string   `json:"observed_sources"`
	LastCollectedAt *time.Time `json:"last_collected_at"` // 最近实际观测到的数据时间（本次结果集内）
	LastIngestedAt  *time.Time `json:"last_ingested_at"`  // CH 数据面最近确认入库水位（max(Timestamp)）
	EstimatedLagMS  *int64     `json:"estimated_lag_ms"`  // now − last_ingested_at（非负）
	Partial         bool       `json:"partial"`           // 丢 Span/降级/截断/关闭的腿导致部分结果
}

// CorrelationCandidate 关联候选（一对多时逐候选返回时间/服务/匹配依据）。
type CorrelationCandidate struct {
	TraceID    string     `json:"trace_id"`
	OccurredAt *time.Time `json:"occurred_at"` // 候选时间（数据面 trace 起始或访问记录发生时间；未知为 null）
	Services   []string   `json:"services"`    // 候选涉及服务（未知为空数组）
	MatchBasis string     `json:"match_basis"` // 候选级依据（candidateBasis*）
}

// Correlation 关联判定（独立于数据源健康；§4.3）。
type Correlation struct {
	State          string                 `json:"state"`
	MatchBasis     string                 `json:"match_basis"`
	CandidateCount int                    `json:"candidate_count"`
	Reason         string                 `json:"reason"` // 人类可读判定解释（无附带说明为空串）
	Candidates     []CorrelationCandidate `json:"candidates"`
}
