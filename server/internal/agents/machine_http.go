// machine_http.go HTTP 事件机器端点（Phase 3，契约 §3 上报 / §6 API 资产联动；
// v2 增量：docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md）：
//
//	POST /api/v1/agents/{agent_id}/http  HTTP 事件批量上报（≤100 条/批、序列化 ≤8MB，202）
//
// 认证复用 machine_handler.authenticate（先读 body 再认证——PoP 签名覆盖正文摘要）；
// disabled Agent 403（与 flows 一致，仅心跳放行）。
//
// 批次版本判别（v2 契约 §1）：包络 schema_version 缺省/1 → v1 路径原样（旧 Agent 兼容，
// 202 {"accepted": n}，入库失败整体 500，无去重）；schema_version=2 → v2 路径（契约 §4：
// 全量校验收集非法记录索引+原因、单事务写入、(agent_id, event_id) 幂等去重、
// 202 {"accepted_count","duplicate_count"}）；未协商 v2 的 Agent 发送 v2 批次 → 400 永久失败。
//
// API 资产联动（契约 §6 / v2 契约 §5）：入库成功后按（host, method, uri 模板化）去重
// 复用 apiassets 既有入口 UpsertDiscovery；来源关系持久化到 agent_http_asset_sources
// （endpoint、Agent、来源实例、绑定版本、首/末次观测、关联状态——配额拒绝/未绑定/
// 关联失败均可查询，不只 Warn）。联动失败不阻断入库与 202 响应。
//
// v2 联动语义：gRPC 端点协议类型由记录 grpc 子对象（可信协议元数据）决定为 GRPC，
// 不统一写死 REST；未声明来源绑定的 v2 记录落 UNASSIGNED 待确认、不执行端点 upsert
// （不随意归入同名路径资产）；重复事件不触发联动、不扩大资产计数。v1 记录维持既有
// 联动行为（REST、无绑定概念）——兼容性冻结。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// machineHTTPMaxBody http 批量请求体上限（契约 §3/§1：每批序列化后 ≤ 8MB，含转义与包络）。
const machineHTTPMaxBody = 8 << 20

// agentDiscoveryConfidence Agent 旁路镜像流量建资产的置信度常量（命中时 apiassets
// 取 GREATEST 不降级既有端点；低于人工确认口径 1.0，与网关观测同量级）。
const agentDiscoveryConfidence = 0.8

// DiscoveryUpserter API 资产发现 upsert 入口（*apiassets.Store 实现——复用 apiassets
// 既有从流量事件建资产入口；nil 时跳过联动，仅测试或装配缺失场景）。
type DiscoveryUpserter interface {
	UpsertDiscovery(ctx context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error)
}

// SetDiscoveryUpserter 注入 API 资产联动入口（生产由 app 装配 *apiassets.Store）。
func (h *MachineHandler) SetDiscoveryUpserter(u DiscoveryUpserter) *MachineHandler {
	h.discovery = u
	return h
}

// HTTPEvents POST /api/v1/agents/{agent_id}/http（Phase 3 契约 §3 + v2 契约 §1/§4）。
func (h *MachineHandler) HTTPEvents(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineHTTPMaxBody)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求体过大或读取失败")
		return
	}
	agent, method, ok := h.authenticate(w, r, body)
	if !ok {
		return
	}
	if method == authMethodBearer && !h.matchPathAgent(w, r, agent) {
		return
	}
	if !requireEnabled(w, agent) {
		return
	}
	var peek struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	switch peek.SchemaVersion {
	case 0, 1:
		h.httpEventsV1(w, r, agent, body)
	case HTTPEventSchemaV2:
		h.httpEventsV2(w, r, agent, body)
	default:
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "不支持的 schema_version（永久失败，请降级采集模式）")
	}
}

// httpEventsV1 v1 批次（Phase 3 契约 §3 原样：整批入库失败整体 500——Agent 转本地缓存补传）。
func (h *MachineHandler) httpEventsV1(w http.ResponseWriter, r *http.Request, agent *Agent, body []byte) {
	var req HTTPRecordsRequest
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if err := req.Validate(); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	if err := h.store.InsertHTTPEvents(r.Context(), agent.AgentID, req.Records); err != nil {
		machineInternal(w, r, err)
		return
	}
	// API 资产联动（契约 §6）：best-effort，失败仅 Warn + 来源关系落状态，不阻断 202。
	items := make([]httpAssetLinkItem, 0, len(req.Records))
	for i := range req.Records {
		rec := &req.Records[i]
		items = append(items, httpAssetLinkItem{
			Host: rec.Request.Host, Method: rec.Request.Method, URI: rec.Request.URI,
			ProtocolType: "REST", SourceType: SourceTypePassiveHTTP1,
		})
	}
	h.linkHTTPAssets(r.Context(), agent.AgentID, items)
	machineJSON(w, http.StatusAccepted, map[string]interface{}{"accepted": len(req.Records)})
}

// httpEventsV2 v2 批次（v2 契约 §4：能力协商准入 → 全量校验 → 单事务幂等写入 →
// 仅对新入库记录联动资产 → 202 accepted_count/duplicate_count）。
func (h *MachineHandler) httpEventsV2(w http.ResponseWriter, r *http.Request, agent *Agent, body []byte) {
	if !agent.SupportsHTTPEventV2() {
		machineError(w, http.StatusBadRequest, mcInvalidArgument,
			"该 Agent 未协商 HTTP 事件 schema v2（请在注册/心跳 capabilities 声明后重试，或降级 v1 采集模式）")
		return
	}
	var req HTTPRecordsRequestV2
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if invalids := req.Validate(); len(invalids) > 0 {
		machineJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": map[string]string{
				"code":    mcInvalidArgument,
				"message": "批次含非法记录（整批未入库；隔离后重建剩余批次重发）",
			},
			"invalid_records": invalids,
		})
		return
	}
	acceptedIdx, duplicates, err := h.store.InsertHTTPEventsV2(r.Context(), agent.AgentID, req.Records, h.now().UTC())
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	// 资产联动仅覆盖新入库记录——重复事件不扩大资产计数（v2 契约 §4.2/§5.5）。
	items := make([]httpAssetLinkItem, 0, len(acceptedIdx))
	for _, i := range acceptedIdx {
		rec := &req.Records[i]
		item := httpAssetLinkItem{
			Host: rec.Request.Host, Method: rec.Request.Method, URI: rec.Request.URI,
			ProtocolType:   "REST",
			SourceType:     rec.SourceType,
			SourceInstance: rec.SourceInstance,
			SourceEpoch:    rec.SourceEpoch,
			RequireBinding: true,
		}
		if rec.GRPC != nil {
			item.ProtocolType = "GRPC" // 可信协议元数据（grpc 子对象），不写死 REST
		}
		if rec.ApplicationBindingID != nil {
			if id, err := uuid.Parse(*rec.ApplicationBindingID); err == nil { // validate 已保证合法
				item.BindingID = &id
			}
			item.BindingVersion = rec.BindingVersion
		}
		items = append(items, item)
	}
	h.linkHTTPAssets(r.Context(), agent.AgentID, items)
	machineJSON(w, http.StatusAccepted, map[string]interface{}{
		"accepted_count":  len(acceptedIdx),
		"duplicate_count": duplicates,
	})
}

// httpAssetLinkItem 资产联动归一输入（v1/v2 共用；去重键含 Host——v2 契约 §5.1，
// 不同 Host/应用不因 method+path 相同而合并）。
type httpAssetLinkItem struct {
	Host           string
	Method         string
	URI            string
	ProtocolType   string // REST/GRPC（v2 按 grpc 子对象；v1 恒 REST）
	SourceType     string
	SourceInstance string
	SourceEpoch    int64
	BindingID      *uuid.UUID
	BindingVersion *int64
	// RequireBinding v2 语义：未声明来源绑定 → UNASSIGNED 待确认、不执行端点 upsert
	// （不随意归入同名路径资产）；v1 记录无绑定概念，维持既有联动行为。
	RequireBinding bool
}

// linkHTTPAssets 资产联动（best-effort：逐来源键失败仅 Warn + 来源关系落状态，
// 不得阻断 http 事件入库——契约 §6 / v2 契约 §5）。
func (h *MachineHandler) linkHTTPAssets(ctx context.Context, agentID uuid.UUID, items []httpAssetLinkItem) {
	if h.discovery == nil {
		return
	}
	now := h.now().UTC()
	seenEndpoint := map[string]uuid.UUID{} // host+method+tpl → 已 upsert 的端点（批内去重）
	seenProvenance := map[string]bool{}    // 完整来源键（含来源三元组）→ 批内去重
	for i := range items {
		item := &items[i]
		tpl := normalizer.NormalizePath(item.URI)
		endpointKey := item.Host + "\x00" + item.Method + "\x00" + tpl
		provenanceKey := endpointKey + "\x00" + item.SourceType + "\x00" + item.SourceInstance
		if seenProvenance[provenanceKey] {
			continue
		}
		seenProvenance[provenanceKey] = true

		source := HTTPAssetSourceInput{
			AgentID: agentID, Host: item.Host, Method: item.Method, PathTemplate: tpl,
			SourceType: item.SourceType, SourceInstance: item.SourceInstance, SourceEpoch: item.SourceEpoch,
			ApplicationBindingID: item.BindingID, BindingVersion: item.BindingVersion,
			Now: now,
		}
		switch {
		case item.RequireBinding && item.BindingID == nil:
			// v2 未声明绑定：UNASSIGNED 待确认，不执行端点 upsert（v2 契约 §5.3）。
			source.State = AssetLinkUnassigned
		default:
			endpointID, linked := seenEndpoint[endpointKey]
			if !linked {
				ep, err := h.discovery.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
					Method:       item.Method,
					PathTemplate: tpl,
					Confidence:   agentDiscoveryConfidence,
					IsAPI:        true,
					ProtocolType: item.ProtocolType,
				})
				switch {
				case err == nil:
					endpointID = ep.ID
					seenEndpoint[endpointKey] = endpointID
				case errors.Is(err, apiassets.ErrLicenseQuotaExceeded):
					// 授权端点配额超限：新端点不落库，既有端点命中不受影响；不重试——
					// 下一批记录自然重放同一判定（与 apiruntime 采集器同口径）；状态可查询。
					slog.Warn("agent http asset link rejected by license quota",
						"agent_id", agentID, "endpoint_key", endpointKey)
					source.State = AssetLinkQuotaRejected
					source.LastError = "license quota exceeded"
				default:
					slog.Warn("agent http asset link failed",
						"agent_id", agentID, "endpoint_key", endpointKey, "error", err)
					source.State = AssetLinkFailed
					source.LastError = truncateErr(err)
				}
			}
			if source.State == "" {
				source.State = AssetLinkLinked
				source.EndpointID = &endpointID
			}
		}
		if err := h.store.UpsertHTTPAssetSource(ctx, source); err != nil {
			slog.Warn("agent http asset source persist failed",
				"agent_id", agentID, "endpoint_key", endpointKey, "error", err)
		}
	}
}

// truncateErr 关联失败原因截断入库（≤255 字符；不泄露内部细节以外的内容——err 文本
// 仅为存储/校验错误类别）。
func truncateErr(err error) string {
	msg := err.Error()
	if len(msg) > 255 {
		return msg[:255]
	}
	return msg
}
