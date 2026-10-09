// collector.go API 动态防护运行时事件采集器（阶段8 / WDSP）。
// 读取网关 jiuzhang_guard 输出的 api-runtime-events JSONL，断点续传入库：
//   - 全部记录按 endpoint 发现信息 upsert 端点资产（持续发现数据源）；
//   - 含检测明细或动作非 ALLOW 的记录写入 api_runtime_events（按 request_id 幂等）；
//   - 心跳记录（heartbeat=true，W17-HB）不产任何业务数据，仅透传给节点活性聚合
//     （HeartbeatRecorder；不落 api_runtime_events，评估结论见 CollectOnce 分支注释）。
//
// 与 accesscontrolevents 采集器同一套断点纪律：offset+inode+前缀指纹、轮转检测、
// 原子保存断点、解析失败行写错误文件（不静默丢弃）。
//
// flush 节奏（W20 批量化修复，docs/evidence/api-security-performance-baseline.md §11.8）：
// 不再等读到 EOF 才唯一一次 flush——每处理 flushBatch 行或距上次 flush 超
// flushInterval 即落一次主事件批次 + 断点（断点与批次同节奏），深 backlog 下入库
// 滞后与容器重建/崩溃后的重扫量有界；重放安全由 request_id 幂等（SavePrimary
// WHERE NOT EXISTS）兜底。EOF 时维持原有末次 flush。
//
// 事务批量化（W22，batchtx.go）：SetBatchTxFactory 接线后，每个 flush 批次的
// 副作用与主事件写入并入一个 DB 事务，整批一次 COMMIT（消除逐语句 commit 开销，
// §11.8 入库瓶颈）；提交成功才前移断点，失败整体回滚、断点不前移、重放幂等。
// 未接线时保持逐语句 autocommit，行为与 W20 完全一致。
package apiruntime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apillm"
	"github.com/jiuzhang-waf/server/internal/strongflow"
)

// PrimaryEvent 待入库主事件：网关统一主事件 + 身份维度字段 + 响应状态码 + 审计维度字段。
// 网关 events.PrimaryEvent（dynamic_security 模块）不含这些字段，由采集端
// 从上报记录透传落库：identity_fingerprint 仅由凭据派生（匿名空串），
// auth_type 为凭据形态（bearer_or_basic/api_key/cookie_session/空），
// response_status 为响应状态码（0 = 网关未采集到，见迁移 000030），
// client_ip/method/raw_path/latency_ms/model_version/policy_version 为审计维度
// （列定义见迁移 000035；旧版网关事件缺字段时为零值，入库落 NULL）。
type PrimaryEvent struct {
	events.PrimaryEvent
	IdentityFingerprint string
	AuthType            string
	ResponseStatus      int
	ClientIP            string
	Method              string
	RawPath             string
	LatencyMs           int64
	ModelVersion        string
	PolicyVersion       string
	// GatewayNode 网关节点标识（多节点版本校验的数据源，迁移 000069；
	// 旧版网关事件缺 gateway_node_id 键时为空串，入库落 NULL）。
	GatewayNode string
	// JWTVerification JWT 信任链验证摘要（WDSP P0-03；nil = 网关未上报/请求未
	// 经 jwt_trust 范围评估，入库落 NULL——列定义见迁移 000127，历史事件不回填）。
	JWTVerification *events.JWTVerification
	// FinalDecision 请求最终处置上下文（WDSP P0-04；nil = 网关未上报/处置事实
	// 未确定，入库落 NULL——列定义见迁移 000131，历史事件不回填）。
	FinalDecision json.RawMessage
	// APILevel §8.2 四级识别标签（CONFIRMED_API/PROBABLE_API/POSSIBLE_API/NON_API；
	// 空串 = 旧版网关事件未上报或管线未写 api.classification，入库落 NULL——
	// 列定义见迁移 000149，历史事件不回填）。
	APILevel string
}

// PrimarySaver 主事件入库接口（*Store 实现，测试可注入内存实现）。
type PrimarySaver interface {
	SavePrimary(ctx context.Context, ev *PrimaryEvent) error
}

// DiscoveryUpserter 端点发现入库接口（*apiassets.Store 实现，可为 nil）。
type DiscoveryUpserter interface {
	UpsertDiscovery(ctx context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error)
}

// Record 网关 apievents.Record 的采集端镜像（字段名与 JSON 输出一一对应）。
type Record struct {
	ID                  string                `json:"id"`
	RequestID           string                `json:"request_id"`
	OccurredAt          time.Time             `json:"occurred_at"`
	ApplicationID       string                `json:"application_id"`
	AppCode             string                `json:"app_code"`
	Domain              string                `json:"domain"`
	EndpointKey         string                `json:"endpoint_key"`
	Method              string                `json:"method"`
	PathTemplate        string                `json:"path_template"`
	IsAPI               bool                  `json:"is_api"`
	APIConfidence       float64               `json:"api_confidence"`
	RiskScore           int                   `json:"risk_score"`
	RiskLevel           string                `json:"risk_level"`
	FinalAction         string                `json:"final_action"`
	Details             []dsctx.DetectorMatch `json:"details"`
	ResponseStatus      int                   `json:"response_status"` // 网关响应后输出的真实回包状态码；0 = 未采集到（旧版网关或异常场景）
	SourceFingerprint   string                `json:"source_fingerprint"`
	IdentityFingerprint string                `json:"identity_fingerprint"`
	AuthType            string                `json:"auth_type"` // bearer_or_basic / api_key / cookie_session / 空（匿名）
	// 以下两个 §7 字段为后补（迁移 000150）：旧版网关事件不含这些键，
	// json 缺省解析为零值，采集与落库全程容忍（缺失即 NULL）。
	// DeviceFingerprint 被动客户端指纹（UA/Accept 族 HMAC 哈希，
	// 低熵群体特征非设备唯一标识）。
	DeviceFingerprint string `json:"device_fingerprint"`
	// ObjectIdentifiers 对象标识哈希集合（dsctx.ObjectIdentifier 同一 JSON 契约，
	// 只记哈希不落明文；入库前经 validateObjectIdentifiers 校验形态）。
	ObjectIdentifiers []dsctx.ObjectIdentifier `json:"object_identifiers"`
	// 以下审计维度字段为后补（迁移 000035）：旧版网关事件不含这些键，
	// json 缺省解析为零值，采集与落库全程容忍（缺失即 NULL）。
	ClientIP          string             `json:"client_ip"`
	RawPath           string             `json:"raw_path"`
	LatencyMs         int64              `json:"latency_ms"`
	ModelVersion      string             `json:"model_version"`
	PolicyVersion     string             `json:"policy_version"`
	GatewayNode       string             `json:"gateway_node_id"`
	ParamObservations []ParamObservation `json:"param_observations"`
	// ResponseObservations 响应结构观测（P0-06；dsctx.ResponseObservation 同一 JSON 契约，
	// 旧版网关事件缺该键时为零值，采集全程容忍缺失）。
	ResponseObservations []dsctx.ResponseObservation `json:"response_observations"`
	// FileObservations 文件传输观测（P1-04；FileObservation 镜像网关 dsctx.FileObservation
	// JSON 契约，旧版网关事件缺该键时为零值，采集全程容忍缺失）。
	FileObservations []FileObservation `json:"file_observations"`
	// LLMObservation LLM 调用观测（P2-04；apillm.LLMObservation 同一 JSON 契约，
	// 旧版网关事件缺该键时为 nil，采集全程容忍缺失）。
	LLMObservation *apillm.LLMObservation `json:"llm_observation"`
	// Proto HTTP 协议版本（HTTP/1.1/2/3，W14 起网关上报；缺失为空串，容忍）。
	Proto string `json:"proto"`
	// Protocol 协议类型标注（§9 词表：REST_JSON/GRAPHQL/JSON_RPC/SSE/FILE_UPLOAD 等，
	// 另含历史值 GRPC；缺失为空串回落 REST 语义，容忍）。
	Protocol string `json:"protocol"`
	// Heartbeat 合成心跳标记（W17-HB：网关节点活性/版本周期上报；缺失为 false，
	// 旧版网关事件零变化，容忍）。
	Heartbeat bool `json:"heartbeat"`
	// JWTVerification JWT 信任链验证摘要（WDSP P0-03；events.JWTVerification
	// 同一 JSON 契约，旧版网关事件缺该键时为 nil，采集全程容忍缺失；
	// 不落原始 Token/payload/明文 sub/tenant）。
	JWTVerification *events.JWTVerification `json:"jwt_verification"`
	// AuthzDecision 是 BOLA/BFLA OBSERVE 判定组。即使最终动作为 ALLOW，也必须
	// 落授权决策表，以便覆盖率和误报复核不丢失允许样本。
	AuthzDecision *events.AuthorizationDecisionGroup `json:"authz_decision"`
	// APILevel §8.2 四级识别标签（CONFIRMED_API/PROBABLE_API/POSSIBLE_API/NON_API；
	// 来自统一上下文扩展 api.classification，omitempty：缺键/空串为零值，采集与
	// 落库全程容忍，缺失即 NULL——列定义见迁移 000149）。
	APILevel string `json:"api_level"`
	// FinalDecision 请求最终处置上下文（WDSP P0-04，final_decision JSON
	// schema_version=1；旧版网关事件缺该键时为 nil，采集全程容忍缺失）。
	// 仅网关处置事实已确定（终止/源站完成/错误）的事件携带；
	// 入库落 api_runtime_events.final_decision（迁移 000131）。
	FinalDecision json.RawMessage `json:"final_decision"`
	// StrongFlow 强流程动作数组（NG-FLOW-02；`strong_flow` JSON 数组逐键冻结——
	// 一请求可携带多动作（首步 INSTANCE_NEW+RESERVE 同拍）；网关 flowguard 执行侧
	// 发射，server 落 api_strong_flow_instances/step_events（迁移 000177）；
	// 旧版网关事件缺该键时为 nil，采集全程容忍缺失。
	// 实例标识线契约：元素 InstanceID 字段承载实例键（sfref: 前缀域隔离 HMAC）；
	// 归属字段（application_id/tenant_ref/principal_ref/request_id）由采集侧从
	// 宿主主事件注入（宿主行已有归属与请求 ID，事件数组元素不重复携带）。
	StrongFlow []*strongflow.StrongFlowEvent `json:"strong_flow"`
	// 以下授权 ACK 字段为 NG-AZ-02 §1.3 心跳扩展（仅 heartbeat=true 的合成记录携带；
	// JSON 名与网关 apievents.Record 冻结一致，不得改名）。空载/未启用授权快照的
	// 节点与旧版网关不携带这些键——json 缺省解析为零值，采集透传全程容忍，
	// 零值即「未携带」（v1 节点 ack_state=NEVER_ACKED 如实呈现，不伪造 ACK 行）。
	// AuthzPolicyVersion 授权快照策略版本戳（区别于全局 policy_version）。
	AuthzPolicyVersion string `json:"authz_policy_version"`
	// AuthzWatermark 节点当前应用授权快照的向量撤销水位（§1.1 对象形状）。
	AuthzWatermark *VectorWatermark `json:"authz_watermark"`
	// AuthzSnapshotExpiresAt 授权快照过期时刻。
	AuthzSnapshotExpiresAt *time.Time `json:"authz_snapshot_expires_at"`
	// AuthzLeaseSeconds 授权租约秒数（per-app 取最小者合并上报）。
	AuthzLeaseSeconds *int `json:"authz_lease_seconds"`
	// AuthzAppliedAt 节点应用该授权快照的时刻（陈旧窗口与漂移对账基准）。
	AuthzAppliedAt *time.Time `json:"authz_applied_at"`
}

// notable 是否需要写入主事件表（有检测明细或动作非 ALLOW；纯通行的 API 请求只喂发现）。
func (r *Record) notable() bool {
	return r.AuthzDecision != nil || len(r.Details) > 0 || (r.FinalAction != "" && r.FinalAction != "ALLOW")
}

// VectorWatermark 向量撤销水位（NG-AZ-02 §1.1 冻结契约）：
// 管理面撤销水位是向量而非标量——各权威来源 sequence 编号空间互相独立，
// 手工撤销通道（manual_seq）与权威来源（sources 逐来源 revocation_watermark）
// 分量比较，混用即伪造单调性。JSON 形状 {"manual_seq":N,"sources":{"<uuid>":M}}。
type VectorWatermark struct {
	ManualSeq int64            `json:"manual_seq"`
	Sources   map[string]int64 `json:"sources"`
}

// AtLeast 分量比较（§1.1）：w ≥ other ⇔ manual_seq 不小于 且 sources 对 other
// 的每个键都有不小于的值（缺失键视为 0）。任何分量更小即「低于」。
func (w VectorWatermark) AtLeast(other VectorWatermark) bool {
	if w.ManualSeq < other.ManualSeq {
		return false
	}
	for k, v := range other.Sources {
		if w.Sources[k] < v {
			return false
		}
	}
	return true
}

// StrongFlowRecorder 强流程事件消费接口（NG-FLOW-02；事件形状唯一事实源为
// strongflow.StrongFlowEvent（字段冻结，改名即破线契约）；StrongFlowEventStore
// 实现。nil 时强流程事件仅计数不消费——采集链路不因此报错）。
type StrongFlowRecorder interface {
	RecordStrongFlow(ctx context.Context, ev *strongflow.StrongFlowEvent) error
}

// Heartbeat 网关节点心跳（W17-HB，任务书 §201 活性+版本上报升级）：
// 网关周期写入 API 事件日志的合成记录（heartbeat=true），仅携带节点活性与版本维度。
// NG-AZ-02 §1.3 起追加授权 ACK 扩展字段（可选；空载/未启用授权快照的节点不携带）。
type Heartbeat struct {
	RequestID     string    // 心跳记录请求 ID（网关按启动时间+序号生成，全局唯一）
	NodeName      string    // 网关节点标识（事件 gateway_node_id）
	OccurredAt    time.Time // 心跳产生时间（节点活性判定基准；漂移对账中即节点时钟读数）
	PolicyVersion string    // 节点当前策略版本戳（空串 = 未下发）
	// 授权 ACK 扩展（NG-AZ-02；指针/空串零值 = 未携带，语义无猜测补全）：
	AuthzPolicyVersion     string           // 授权快照策略版本戳
	AuthzWatermark         *VectorWatermark // 节点当前应用快照的向量水位
	AuthzSnapshotExpiresAt *time.Time       // 授权快照过期时刻
	AuthzLeaseSeconds      *int             // 授权租约秒数
	AuthzAppliedAt         *time.Time       // 节点应用该快照的时刻
}

// HasAuthzAck 心跳是否携带授权 ACK 字段（任一非零即视为携带——网关约定启用
// 授权快照后整组发射；单字段到达也如实落库）。false 时 RecordHeartbeat 不写
// api_node_authz_acks（纯 v1 节点在 ACK 视图中如实 NEVER_ACKED）。
func (hb Heartbeat) HasAuthzAck() bool {
	return hb.AuthzPolicyVersion != "" || hb.AuthzWatermark != nil ||
		hb.AuthzSnapshotExpiresAt != nil || hb.AuthzLeaseSeconds != nil ||
		hb.AuthzAppliedAt != nil
}

// HeartbeatRecorder 心跳消费接口（server/internal/apinodes.Store 实现；
// nil 时心跳仅计数不消费——采集链路不因此报错，节点视图停留在业务事件口径）。
type HeartbeatRecorder interface {
	RecordHeartbeat(ctx context.Context, hb Heartbeat) error
}

// Collector 是 API 运行时事件采集器。
type Collector struct {
	saver          PrimarySaver
	discovery      DiscoveryUpserter  // nil 时跳过端点发现
	resolver       Resolver           // nil 时归属留空（未归属）
	samples        SampleRecorder     // nil 时跳过学习样本落库
	violations     ViolationSaver     // nil 时跳过 schema 违例落库
	findings       FindingSaver       // nil 时跳过风险发现物化
	paramObs       ParamObsRecorder   // nil 时跳过参数值观测聚合
	respSchemas    RespSchemaRecorder // nil 时跳过响应 Schema 学习落库
	fileObs        FileObsRecorder    // nil 时跳过文件资产观测落库
	llmObs         apillm.ObsRecorder // nil 时跳过 LLM 观测落库
	traffic        TrafficRecorder    // nil 时跳过流量趋势桶计数
	heartbeats     HeartbeatRecorder  // nil 时心跳仅计数不消费
	strongFlows    StrongFlowRecorder // nil 时强流程事件仅计数不消费
	collectorID    string
	logPath        string
	checkpointPath string
	errorPath      string
	nodeName       string
	flushBatch     int            // 批量 flush 阈值（处理行数，W20）
	flushInterval  time.Duration  // 周期 flush 阈值（距上次 flush 时长，W20）
	batchTxFactory BatchTxFactory // nil 时逐语句 autocommit（W20 行为）；接线后每个 flush 批次一个 DB 事务（W22）
	// quotaAlert 授权端点配额超限告警回调（nil 时仅记日志）
	quotaAlert func(ctx context.Context, endpointKey string)
	// 指标
	processedCount int64
	savedCount     int64
	failedCount    int64
	heartbeatCount int64
	lastProcessed  time.Time
}

// 默认 flush 阈值（W20 批量化修复；SetFlushPolicy 或 WAF_COLLECTOR_FLUSH_BATCH /
// WAF_COLLECTOR_FLUSH_INTERVAL 可覆盖）。依据 §11.8 现场：11.5 万条 backlog 追平约
// 6.5 分钟（≈300 行/s），2000 行 ≈ 7s 扫描量、2s 与采集轮询周期同量级——崩溃重放
// 上界（≤2000 行 + ≤2s）与断点写频率均可接受，取值保守。
const (
	defaultFlushBatch    = 2000
	defaultFlushInterval = 2 * time.Second
)

// NewCollector 创建采集器。checkpointPath 为空时使用 logPath+".checkpoint"。
func NewCollector(saver PrimarySaver, collectorID, logPath, checkpointPath, nodeName string) *Collector {
	if checkpointPath == "" {
		checkpointPath = logPath + ".checkpoint"
	}
	return &Collector{
		saver:          saver,
		collectorID:    collectorID,
		logPath:        logPath,
		checkpointPath: checkpointPath,
		errorPath:      logPath + ".errors",
		nodeName:       nodeName,
		flushBatch:     defaultFlushBatch,
		flushInterval:  defaultFlushInterval,
	}
}

// SetDiscoveryUpserter 设置端点发现入库接口（应用装配时使用）。
func (c *Collector) SetDiscoveryUpserter(u DiscoveryUpserter) { c.discovery = u }

// SetQuotaAlertFunc 设置授权端点配额超限告警回调（装配层接 systemalerts；
// nil 时仅记日志）。回调逐拒绝事件触发一次，合并/冷却由告警引擎同指纹机制承担。
func (c *Collector) SetQuotaAlertFunc(fn func(ctx context.Context, endpointKey string)) {
	c.quotaAlert = fn
}

// SetResolver 设置归属解析器（应用装配时使用；未设置时端点按未归属处理）。
func (c *Collector) SetResolver(r Resolver) { c.resolver = r }

// SetSampleRecorder 设置学习样本落库接口（应用装配时使用；未设置时跳过样本采集）。
func (c *Collector) SetSampleRecorder(r SampleRecorder) { c.samples = r }

// SetViolationSaver 设置 schema 违例落库接口（应用装配时使用；未设置时跳过违例落库）。
func (c *Collector) SetViolationSaver(s ViolationSaver) { c.violations = s }

// SetFindingSaver 设置风险发现物化写入接口（应用装配时使用；未设置时跳过物化）。
func (c *Collector) SetFindingSaver(s FindingSaver) { c.findings = s }

// SetParamObsRecorder 设置参数值观测聚合写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetParamObsRecorder(r ParamObsRecorder) { c.paramObs = r }

// SetRespSchemaRecorder 设置响应 Schema 学习写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetRespSchemaRecorder(r RespSchemaRecorder) { c.respSchemas = r }

// SetFileObsRecorder 设置文件资产观测写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetFileObsRecorder(r FileObsRecorder) { c.fileObs = r }

// SetLLMObsRecorder 设置 LLM 观测写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetLLMObsRecorder(r apillm.ObsRecorder) { c.llmObs = r }

// SetTrafficRecorder 设置流量趋势桶计数写入（应用装配时使用；未设置时跳过）。
func (c *Collector) SetTrafficRecorder(r TrafficRecorder) { c.traffic = r }

// SetHeartbeatRecorder 设置网关心跳消费写入（应用装配时使用；未设置时心跳仅计数不消费）。
func (c *Collector) SetHeartbeatRecorder(r HeartbeatRecorder) { c.heartbeats = r }

// SetStrongFlowRecorder 设置强流程事件消费（应用装配时使用；未设置时仅计数不消费）。
func (c *Collector) SetStrongFlowRecorder(r StrongFlowRecorder) { c.strongFlows = r }

// SetFlushPolicy 设置批量/周期 flush 阈值（W20 批量化修复；非正值保持默认）。
// batchSize：每处理 batchSize 行触发一次 flush（主事件批次 + 断点同节奏落盘）；
// interval：距上次 flush 超过该时长且有新数据时触发一次 flush。
func (c *Collector) SetFlushPolicy(batchSize int, interval time.Duration) {
	if batchSize > 0 {
		c.flushBatch = batchSize
	}
	if interval > 0 {
		c.flushInterval = interval
	}
}

// Metrics 返回采集指标。
func (c *Collector) Metrics() map[string]interface{} {
	return map[string]interface{}{
		"collector_id":    c.collectorID,
		"processed_count": c.processedCount,
		"saved_count":     c.savedCount,
		"failed_count":    c.failedCount,
		"heartbeat_count": c.heartbeatCount,
		"last_processed":  c.lastProcessed,
		"log_path":        c.logPath,
	}
}

// checkpoint 是采集断点（JSON 文件持久化）。
type checkpoint struct {
	Offset       int64  `json:"offset"`
	Inode        uint64 `json:"inode"`
	PrefixSize   int64  `json:"prefix_size,omitempty"`
	PrefixSHA256 string `json:"prefix_sha256,omitempty"`
}

const checkpointPrefixLimit int64 = 4096

func (cp checkpoint) valid() bool {
	return cp.Offset >= 0 &&
		cp.PrefixSize >= 0 &&
		cp.PrefixSize <= checkpointPrefixLimit &&
		cp.PrefixSize <= cp.Offset
}

// loadCheckpoint 从 checkpoint 文件加载断点；文件不存在时从头开始，
// 文件损坏时告警并从头开始（不静默吞错：slog.Warn 记录）。
func (c *Collector) loadCheckpoint() checkpoint {
	data, err := os.ReadFile(c.checkpointPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("checkpoint file unreadable, restarting from offset 0",
				"collector", c.collectorID, "path", c.checkpointPath, "error", err)
		}
		return checkpoint{}
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		slog.Warn("checkpoint file corrupted, restarting from offset 0",
			"collector", c.collectorID, "path", c.checkpointPath, "error", err)
		return checkpoint{}
	}
	if !cp.valid() {
		slog.Warn("checkpoint values invalid, restarting from offset 0",
			"collector", c.collectorID, "path", c.checkpointPath)
		return checkpoint{}
	}
	return cp
}

// saveCheckpoint 原子保存断点（临时文件 + rename）。
func (c *Collector) saveCheckpoint(cp checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	tmp := c.checkpointPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.checkpointPath)
}

// persistCheckpoint 计算已提交前缀指纹并原子保存断点（autocommit 与批次事务
// 两条 flush 路径共用；调用方保证对应数据已持久化——autocommit 逐语句已提交，
// 批次事务路径已 COMMIT）。
func (c *Collector) persistCheckpoint(f *os.File, offset int64, inode uint64) error {
	prefixSize, prefixSHA256, err := checkpointFingerprint(f, offset)
	if err != nil {
		return fmt.Errorf("fingerprint checkpoint: %w", err)
	}
	if err := c.saveCheckpoint(checkpoint{
		Offset:       offset,
		Inode:        inode,
		PrefixSize:   prefixSize,
		PrefixSHA256: prefixSHA256,
	}); err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	return nil
}

// fileInode 获取文件 inode（用于轮转检测，Unix 系统）。
func fileInode(f *os.File) uint64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat != nil {
		return stat.Ino
	}
	return 0
}

// prefixFingerprint 返回文件开头指定长度内容的 SHA-256。
// ReadAt 不改变采集器当前读取位置。
func prefixFingerprint(f *os.File, size int64) (string, error) {
	if size <= 0 {
		return "", nil
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return "", err
	}
	if int64(n) != size {
		return "", io.ErrUnexpectedEOF
	}
	return fmt.Sprintf("%x", sha256.Sum256(buf)), nil
}

func checkpointFingerprint(f *os.File, offset int64) (int64, string, error) {
	prefixSize := min(offset, checkpointPrefixLimit)
	hash, err := prefixFingerprint(f, prefixSize)
	return prefixSize, hash, err
}

// CollectOnce 执行一次采集（读取新增内容并入库）。返回处理行数。
func (c *Collector) CollectOnce(ctx context.Context) (int, error) {
	cp := c.loadCheckpoint()

	f, err := os.Open(c.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // 日志文件尚未生成（无事件时正常）
		}
		return 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	currentInode := fileInode(f)

	// 轮转检测：inode 变化、文件变小或已提交前缀变化 → 从头读取。
	offset := cp.Offset
	rotated := (cp.Inode != 0 && currentInode != cp.Inode) || info.Size() < offset
	if !rotated && cp.PrefixSize > 0 && cp.PrefixSHA256 != "" {
		currentPrefix, err := prefixFingerprint(f, cp.PrefixSize)
		if err != nil {
			return 0, fmt.Errorf("fingerprint api event log: %w", err)
		}
		rotated = currentPrefix != cp.PrefixSHA256
	}
	if rotated {
		slog.Info("api runtime event log rotated, resetting offset",
			"collector", c.collectorID, "old_offset", offset, "new_size", info.Size())
		offset = 0
		// 立即落断点（空前缀指纹）：文件截断为空期间若无新内容，断点不前进会导致每轮采集重复判定轮转刷日志
		if err := c.persistCheckpoint(f, 0, currentInode); err != nil {
			slog.Warn("save checkpoint after rotation failed", "collector", c.collectorID, "error", err)
		}
	}
	if info.Size() == offset {
		return 0, nil // 无新内容
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(f)
	processed := 0
	committedOffset := offset
	var pending []PrimaryEvent

	// W22 事务批量化：factory 接线后，批次窗口（上次 flush 之后）的副作用与
	// 主事件写入并入一个 DB 事务，flush 整体 COMMIT，提交成功才前移断点。
	var batchTx pgx.Tx
	var snap *recorderSnapshot
	// beginBatch 批次窗口首条业务记录前懒开启事务（无数据不开空事务），
	// recorders 切换为 tx 作用域浅拷贝（原引用快照在 snap）。
	beginBatch := func() error {
		if c.batchTxFactory == nil || batchTx != nil {
			return nil
		}
		tx, err := c.batchTxFactory(ctx)
		if err != nil {
			return fmt.Errorf("begin batch tx: %w", err)
		}
		batchTx = tx
		snap = c.enterBatchTx(tx)
		return nil
	}
	// endBatch 恢复 recorder 引用（事务句柄的终结由 flush/abortBatch 负责）。
	endBatch := func() {
		if snap != nil {
			c.exitBatchTx(snap)
			snap = nil
		}
	}
	// abortBatch 回滚未提交的批次并恢复 recorder（失败路径；回滚错误仅告警，
	// 不覆盖正在返回的主错误——连接已坏时 pgx 会自行销毁连接）。
	abortBatch := func() {
		if batchTx != nil {
			if err := batchTx.Rollback(ctx); err != nil {
				slog.Warn("rollback batch tx failed", "collector", c.collectorID, "error", err)
			}
			batchTx = nil
		}
		endBatch()
	}
	// 任意返回路径兜底（读取失败等绕过 flush 的路径）：正常 flush 后 batchTx 已置 nil，此处 no-op。
	defer abortBatch()

	// flush 主事件入库 + 保存断点；失败时断点不前移，下轮重读（SavePrimary 按 request_id 幂等）。
	// batchTx 非空时走批次事务路径：主事件在事务内落库（c.saver 已为 tx 作用域浅拷贝），
	// 整批（副作用 + 主事件）一次 COMMIT；任一失败整体回滚，断点不前移，重放由幂等键兜底。
	flush := func() error {
		if batchTx != nil {
			for i := range pending {
				if err := c.saver.SavePrimary(ctx, &pending[i]); err != nil {
					abortBatch()
					return fmt.Errorf("save primary event: %w", err)
				}
			}
			if err := batchTx.Commit(ctx); err != nil {
				abortBatch()
				return fmt.Errorf("commit batch tx: %w", err)
			}
			batchTx = nil
			c.savedCount += int64(len(pending)) // 提交成功后整批计入（回滚批次不计）
			endBatch()
			pending = pending[:0]
			return c.persistCheckpoint(f, committedOffset, currentInode)
		}
		for i := range pending {
			if err := c.saver.SavePrimary(ctx, &pending[i]); err != nil {
				return fmt.Errorf("save primary event: %w", err)
			}
			c.savedCount++
		}
		pending = pending[:0]
		return c.persistCheckpoint(f, committedOffset, currentInode)
	}

	// W20 批量/周期 flush：深 backlog 下不再等 EOF 才落批+断点，入库滞后与
	// 崩溃/重建重扫量有界（≤flushBatch 行 + ≤flushInterval 的重放上界）。
	lastFlush := time.Now()
	processedAtFlush := 0

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			processed++
			committedOffset += int64(len(line))
			rec, perr := parseRecordLine(line)
			if perr != nil {
				c.failedCount++
				c.appendError(line, perr)
			} else if rec.Heartbeat {
				// 心跳记录（W17-HB）：跳过端点发现/学习样本/schema 违例/findings/参数·
				// 响应·文件·LLM 观测与流量桶等全部业务物化，且【不落 api_runtime_events】。
				// 落表方案评估后否决：该表消费方众多，apisecurity 运行时统计（count(*)/
				// GROUP BY final_action/risk_level、Top10 端点）与事件列表、ainoise
				// 降噪输入、行为画像扫描等按全量/弱过滤读取，合成心跳行（每日每节点
				// 数千行）会污染业务视图并令 __heartbeat__ 冲上 Top 端点；心跳仅透传
				// 给节点活性聚合（apinodes 经 api_gateway_nodes 表，与事件表解耦）。
				c.recordHeartbeat(ctx, rec)
				c.processedCount++
				c.lastProcessed = time.Now()
			} else {
				if berr := beginBatch(); berr != nil {
					return processed, berr
				}
				if batchTx != nil {
					c.handleRecordInTx(ctx, batchTx, rec)
				} else {
					c.handleRecord(ctx, rec)
				}
				if rec.notable() {
					pending = append(pending, PrimaryEvent{
						PrimaryEvent: events.PrimaryEvent{
							ID:            rec.ID,
							RequestID:     rec.RequestID,
							OccurredAt:    rec.OccurredAt,
							ApplicationID: rec.ApplicationID,
							EndpointKey:   rec.EndpointKey,
							RiskScore:     rec.RiskScore,
							RiskLevel:     rec.RiskLevel,
							FinalAction:   rec.FinalAction,
							Details:       rec.Details,
							AuthzDecision: rec.AuthzDecision,
							// 任务书 §7：设备指纹与对象标识哈希透传（落库见 SavePrimary）
							DeviceFingerprint: rec.DeviceFingerprint,
							ObjectIdentifiers: rec.ObjectIdentifiers,
						},
						IdentityFingerprint: rec.IdentityFingerprint,
						AuthType:            rec.AuthType,
						ResponseStatus:      rec.ResponseStatus,
						ClientIP:            rec.ClientIP,
						Method:              rec.Method,
						RawPath:             rec.RawPath,
						LatencyMs:           rec.LatencyMs,
						ModelVersion:        rec.ModelVersion,
						PolicyVersion:       rec.PolicyVersion,
						GatewayNode:         rec.GatewayNode,
						JWTVerification:     rec.JWTVerification,
						FinalDecision:       rec.FinalDecision,
						APILevel:            rec.APILevel,
					})
				}
				c.processedCount++
				c.lastProcessed = time.Now()
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return processed, err
		}
		if processed > processedAtFlush &&
			(processed-processedAtFlush >= c.flushBatch || time.Since(lastFlush) >= c.flushInterval) {
			if ferr := flush(); ferr != nil {
				return processed, ferr
			}
			lastFlush = time.Now()
			processedAtFlush = processed
		}
	}
	if err := flush(); err != nil {
		return processed, err
	}
	return processed, nil
}

// handleRecord 记录副作用：归属解析 + 端点发现 upsert + 流量桶计数 + 学习样本落样
// + schema 违例落库 + 风险发现物化 + 参数观测 + 响应 Schema 学习 + 文件资产观测
// （错误仅记录日志，不影响主流程）。
func (c *Collector) handleRecord(ctx context.Context, rec *Record) {
	if c.discovery != nil && rec.Method != "" && rec.PathTemplate != "" {
		c.recordTrafficBucket(ctx, rec, c.upsertDiscovery(ctx, rec))
	}
	c.recordSample(ctx, rec)
	c.recordViolations(ctx, rec)
	c.recordFindings(ctx, rec)
	if c.paramObs != nil && rec.EndpointKey != "" && len(rec.ParamObservations) > 0 {
		if err := c.paramObs.RecordParamObservations(ctx, rec.EndpointKey, rec.ParamObservations); err != nil {
			slog.Error("record param observations failed",
				"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
		}
	}
	if c.respSchemas != nil && rec.EndpointKey != "" && len(rec.ResponseObservations) > 0 {
		if err := c.respSchemas.RecordResponseObservations(ctx, rec.EndpointKey, rec.ResponseObservations); err != nil {
			slog.Error("record response observations failed",
				"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
		}
	}
	if c.fileObs != nil && rec.EndpointKey != "" && len(rec.FileObservations) > 0 {
		if err := c.fileObs.RecordFileObservations(ctx, rec); err != nil {
			slog.Error("record file observations failed",
				"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
		}
	}
	// NG-FLOW-02：强流程动作数组逐条透传消费（实例推进+步骤事件幂等落库）。
	// 归属注入（冻结契约）：事件元素只带操作事实；request_id/application_id 取宿主
	// 主事件，可信租户/主体引用取宿主 JWT 验证指纹（脱敏形态，不落明文）。
	// 与其他副作用同一纪律：错误仅记录日志+计数，不阻断采集主流程、断点照常前移。
	for _, sf := range rec.StrongFlow {
		if sf == nil {
			continue
		}
		sf.RequestID = rec.RequestID
		sf.ApplicationID = rec.ApplicationID
		if rec.JWTVerification != nil {
			if sf.TenantRef == "" {
				sf.TenantRef = rec.JWTVerification.VerifiedTenantID
			}
			if sf.PrincipalRef == "" {
				sf.PrincipalRef = rec.JWTVerification.VerifiedPrincipalID
			}
		}
		if c.strongFlows == nil {
			continue
		}
		if err := c.strongFlows.RecordStrongFlow(ctx, sf); err != nil {
			c.failedCount++
			slog.Error("record strong flow event failed",
				"collector", c.collectorID, "instance_id", sf.InstanceID, "error", err)
		}
	}
	if c.llmObs != nil && rec.EndpointKey != "" && rec.LLMObservation != nil {
		if err := c.llmObs.RecordLLMObservation(ctx, apillm.ObservationInput{
			RequestID:           rec.RequestID,
			OccurredAt:          rec.OccurredAt,
			EndpointKey:         rec.EndpointKey,
			IdentityFingerprint: rec.IdentityFingerprint,
			Observation:         *rec.LLMObservation,
			Details:             rec.Details,
		}); err != nil {
			slog.Error("record llm observation failed",
				"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
		}
	}
}

// recordHeartbeat 心跳透传：交由节点活性聚合消费（apinodes）。与其他副作用同一
// 纪律——错误仅记录日志，断点照常前移（下一周期心跳自愈，不因单拍失败阻断采集）；
// recorder 未接线时仅计数（节点视图退化为业务事件口径，与 W16 及之前行为一致）。
func (c *Collector) recordHeartbeat(ctx context.Context, rec *Record) {
	c.heartbeatCount++
	if c.heartbeats == nil {
		return
	}
	if rec.GatewayNode == "" {
		slog.Warn("api node heartbeat without gateway_node, skipped",
			"collector", c.collectorID, "request_id", rec.RequestID)
		return
	}
	if err := c.heartbeats.RecordHeartbeat(ctx, Heartbeat{
		RequestID:              rec.RequestID,
		NodeName:               rec.GatewayNode,
		OccurredAt:             rec.OccurredAt,
		PolicyVersion:          rec.PolicyVersion,
		AuthzPolicyVersion:     rec.AuthzPolicyVersion,
		AuthzWatermark:         rec.AuthzWatermark,
		AuthzSnapshotExpiresAt: rec.AuthzSnapshotExpiresAt,
		AuthzLeaseSeconds:      rec.AuthzLeaseSeconds,
		AuthzAppliedAt:         rec.AuthzAppliedAt,
	}); err != nil {
		slog.Error("record api node heartbeat failed",
			"collector", c.collectorID, "gateway_node", rec.GatewayNode, "error", err)
	}
}

// upsertDiscovery 归属解析 + 端点发现 upsert；成功返回端点（供流量桶计数取 endpoint_id），
// 失败返回 nil（错误已记日志，不中断采集）。
func (c *Collector) upsertDiscovery(ctx context.Context, rec *Record) *apiassets.Endpoint {
	var appID, domID *uuid.UUID
	if rec.ApplicationID != "" {
		if id, err := uuid.Parse(rec.ApplicationID); err == nil {
			appID = &id
		}
	}
	if c.resolver != nil && rec.AppCode != "" {
		id, err := c.resolver.ResolveApplication(ctx, rec.AppCode)
		if err != nil {
			slog.Error("resolve application failed",
				"collector", c.collectorID, "app_code", rec.AppCode, "error", err)
		} else if id != nil {
			appID = id
		}
		if appID != nil && rec.Domain != "" {
			did, err := c.resolver.ResolveDomain(ctx, appID, rec.Domain)
			if err != nil {
				slog.Error("resolve domain failed",
					"collector", c.collectorID, "domain", rec.Domain, "error", err)
			} else {
				domID = did
			}
		}
	}
	ep, err := c.discovery.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method:        rec.Method,
		PathTemplate:  rec.PathTemplate,
		Confidence:    rec.APIConfidence,
		IsAPI:         rec.IsAPI,
		ApplicationID: appID,
		DomainID:      domID,
		Host:          rec.Domain,
		ProtocolType:  rec.Protocol,
	})
	if err != nil {
		// 授权端点配额超限：新端点不落库（store 已回滚/删回本行），既有端点命中不受影响。
		// 逐事件仅 Warn + 告警回调一次（告警引擎按同指纹合并冷却，不产生风暴）；
		// 不重试——下一事件自然重放同一判定；主事件落库与其他副作用不受影响。
		if errors.Is(err, apiassets.ErrLicenseQuotaExceeded) {
			slog.Warn("api endpoint discovery rejected by license quota",
				"collector", c.collectorID, "endpoint_key", rec.EndpointKey)
			if c.quotaAlert != nil {
				c.quotaAlert(ctx, rec.EndpointKey)
			}
			return nil
		}
		slog.Error("upsert api endpoint discovery failed",
			"collector", c.collectorID, "endpoint_key", rec.EndpointKey, "error", err)
		return nil
	}
	if ep != nil && ep.EndpointKey != "" {
		// All downstream runtime stores key observations by endpoint_key. The
		// discovery result is authoritative because it includes resolved scope.
		rec.EndpointKey = ep.EndpointKey
	}
	return ep
}

// parseRecordLine 解析一行 JSONL 为记录；空 request_id 且空 endpoint_key 视为坏行。
func parseRecordLine(line []byte) (*Record, error) {
	var rec Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return nil, fmt.Errorf("bad json: %w", err)
	}
	if rec.RequestID == "" && rec.EndpointKey == "" {
		return nil, fmt.Errorf("missing request_id and endpoint_key")
	}
	return &rec, nil
}

// errorRecord 是错误文件中的一行。
type errorRecord struct {
	Time        time.Time `json:"time"`
	CollectorID string    `json:"collector_id"`
	Reason      string    `json:"reason"`
	RawLine     string    `json:"raw_line"`
}

// maxErrorFileBytes 错误文件大小上限（10MiB）：超限先单份轮转再写新档，
// 防网关持续产出坏行时错误文件无限增长撑爆磁盘。
const maxErrorFileBytes = 10 << 20

// appendError 把解析失败的行追加到错误文件（不静默丢弃）。
func (c *Collector) appendError(line []byte, cause error) {
	raw := string(line)
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	rec, err := json.Marshal(errorRecord{
		Time:        time.Now().UTC(),
		CollectorID: c.collectorID,
		Reason:      cause.Error(),
		RawLine:     raw,
	})
	if err != nil {
		slog.Error("marshal error record failed", "collector", c.collectorID, "error", err)
		return
	}
	c.rotateErrorFileIfNeeded(len(rec) + 1)
	f, err := os.OpenFile(c.errorPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("open error file failed", "collector", c.collectorID, "path", c.errorPath, "error", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(rec, '\n')); err != nil {
		slog.Error("write error file failed", "collector", c.collectorID, "error", err)
	}
}

// rotateErrorFileIfNeeded 错误文件写入 incoming 字节将超上限时单份轮转：
// .errors → .errors.1（覆盖旧档，仅保留最近一份）。轮转失败仅记日志后继续追加
// ——宁可文件超限也不静默丢错误行（与 appendError 不静默丢弃同一纪律）。
func (c *Collector) rotateErrorFileIfNeeded(incoming int) {
	fi, err := os.Stat(c.errorPath)
	if err != nil {
		return // 文件不存在（新档必然不超）或状态读取失败：交给打开/写入时报错
	}
	if fi.Size()+int64(incoming) <= maxErrorFileBytes {
		return
	}
	if err := os.Rename(c.errorPath, c.errorPath+".1"); err != nil {
		slog.Error("rotate error file failed", "collector", c.collectorID, "path", c.errorPath, "error", err)
	}
}

// Run 持续采集（轮询间隔）。
func (c *Collector) Run(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	slog.Info("api runtime event collector started",
		"collector", c.collectorID, "log", c.logPath, "interval", pollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Info("api runtime event collector stopped", "collector", c.collectorID)
			return
		case <-ticker.C:
			n, err := c.CollectOnce(ctx)
			if err != nil {
				slog.Error("collect error", "collector", c.collectorID, "error", err)
			} else if n > 0 {
				slog.Debug("collected api runtime events", "collector", c.collectorID, "count", n)
			}
		}
	}
}
