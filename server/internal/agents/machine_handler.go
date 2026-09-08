// machine_handler.go 机器端点（Agent → WDSP；契约 §3，共 8 个）：
//
//	POST /api/v1/agents/enroll                    注册（一次性 Enrollment Token，无需 credential；可选 csr_pem 签发证书——Phase 2-B §7）
//	POST /api/v1/agents/{agent_id}/heartbeat      心跳（含 metrics 快照；disabled 也放行——须能收到 desired_state）
//	POST /api/v1/agents/{agent_id}/metrics        指标快照（与心跳同处理逻辑，返回 204）
//	GET  /api/v1/agents/{agent_id}/config         配置拉取（无绑定 policy=null）
//	POST /api/v1/agents/{agent_id}/config/ack     配置 ACK（APPLIED 回填 applied_config_version）
//	POST /api/v1/agents/{agent_id}/flows          FLOW 事件批量上报（≤500 条/批，202）
//	POST /api/v1/agents/{agent_id}/http           HTTP 事件批量上报（≤100 条/批 ≤8MB，202——Phase 3 契约 §3）
//	POST /api/v1/agents/{agent_id}/packets        RAW 二进制批量（WDP1；校验/计数/丢弃，202）
//	POST /api/v1/agents/{agent_id}/rotate-cert    证书轮换（仅 PoP 认证；旧指纹 24h 宽限——Phase 2-B §9）
//
// 认证（Phase 2-B §8）：PoP 三头（X-WDSP-Agent-Cert/Timestamp/Signature）齐全 → 严格
// 证书 PoP 校验（链/有效期/指纹/CN/时间窗/签名，任一失败 401 绝不降级）；三头全缺 →
// 回退既有 Bearer wda_<64hex>（SHA-256 摘要反查；路径 agent_id 必须与凭据所属 Agent
// 一致）；头不全 → 401。错误响应为契约 §2 信封 {"error":{"code","message"}}。
package agents

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 机器端点错误码（契约 §2 <MACHINE_CODE>）。
const (
	mcInvalidArgument = "INVALID_ARGUMENT"
	mcUnauthenticated = "UNAUTHENTICATED"
	mcForbidden       = "FORBIDDEN"
	mcNotFound        = "NOT_FOUND"
	mcConflict        = "CONFLICT"
	mcInternalError   = "INTERNAL_ERROR"
)

// 机器端点请求体上限。
const (
	machineEnrollMaxBody    = 32768
	machineHeartbeatMaxBody = 16384
	machineFlowsMaxBody     = 4 << 20 // 500 事件 × 单事件 URI/Host 上限，留足余量
)

// packetBatchContentType RAW 批量 Content-Type（契约 §3.5）。
const packetBatchContentType = "application/x-wdsp-packet-batch"

// MachineHandler 机器端点处理器。
type MachineHandler struct {
	store MachineRepository
	ca    *AgentCA // traffic-agent CA（Phase 2-B；nil 时 PoP/证书签发不可用——仅测试或装配缺失场景）
	// discovery API 资产联动入口（Phase 3 契约 §6；*apiassets.Store 实现，nil 时跳过联动）。
	discovery DiscoveryUpserter
	now       func() time.Time
}

// NewMachineHandler 创建机器端点处理器。
func NewMachineHandler(store MachineRepository) *MachineHandler {
	return &MachineHandler{store: store, now: time.Now}
}

// SetCA 注入 traffic-agent CA（生产由 app 装配 LoadOrCreateAgentCA 产物）。
func (h *MachineHandler) SetCA(ca *AgentCA) *MachineHandler { h.ca = ca; return h }

// machineError 契约 §2 错误信封。
func machineError(w http.ResponseWriter, status int, code, msg string) {
	machineJSON(w, status, map[string]interface{}{
		"error": map[string]string{"code": code, "message": msg},
	})
}

// machineJSON 裸 JSON 输出（契约线格式，不经全局响应包装）。
func machineJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readMachineBody 限长读取请求正文。
func readMachineBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
}

// decodeMachineJSON 解析机器端点 JSON（拒绝未知字段与多余内容，fail-closed）。
func decodeMachineJSON(body []byte, dst interface{}) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing content")
	}
	return nil
}

// machineInternal 内部错误（不泄露细节，如实记日志）。
func machineInternal(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("traffic agents machine endpoint internal error",
		"request_id", response.RequestIDFrom(r),
		"method", r.Method, "path", r.URL.Path, "error", err)
	machineError(w, http.StatusInternalServerError, mcInternalError, "服务器内部错误")
}

// machineAuthMethod 机器端点实际使用的认证方式（rotate-cert 仅放行 PoP——契约 §9）。
type machineAuthMethod int

const (
	authMethodBearer machineAuthMethod = iota
	authMethodPoP
)

// authenticate 机器端点统一认证入口（契约 §8）：
//   - PoP 三头全缺 → 回退 Bearer 校验（过渡期兼容）；
//   - 三头齐全 → 严格 PoP 校验（任一失败 401，绝不降级）；
//   - 头不全 → 401（防降级攻击）。
//
// body 为请求原文（PoP 签名覆盖正文摘要，调用方须先读原文再认证；GET 等无正文传 nil）。
func (h *MachineHandler) authenticate(w http.ResponseWriter, r *http.Request, body []byte) (*Agent, machineAuthMethod, bool) {
	certH := strings.TrimSpace(r.Header.Get(popCertHeader))
	ts := strings.TrimSpace(r.Header.Get(popTimestampHeader))
	sig := strings.TrimSpace(r.Header.Get(popSignatureHeader))
	if certH == "" && ts == "" && sig == "" {
		agent, ok := h.authenticateBearer(w, r)
		return agent, authMethodBearer, ok
	}
	if certH == "" || ts == "" || sig == "" {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "PoP 认证头不完整（证书/时间戳/签名须同时携带）")
		return nil, authMethodPoP, false
	}
	agent, ok := h.authenticatePoP(w, r, body, certH, ts, sig)
	return agent, authMethodPoP, ok
}

// authenticateBearer Bearer 认证：格式先验（挡垃圾流量），再按摘要反查登记身份。
func (h *MachineHandler) authenticateBearer(w http.ResponseWriter, r *http.Request) (*Agent, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	cred, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || !credentialPattern.MatchString(strings.TrimSpace(cred)) {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "缺少或非法的 Bearer credential")
		return nil, false
	}
	agent, err := h.store.AgentByCredentialHash(r.Context(), HashSecret(strings.TrimSpace(cred)))
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			machineError(w, http.StatusUnauthorized, mcUnauthenticated, "credential 未登记或已吊销")
			return nil, false
		}
		machineInternal(w, r, err)
		return nil, false
	}
	// 契约 §8：Bearer 回退成功记日志（低基数字段），供后续收紧为仅证书模式时评估存量。
	slog.Debug("traffic agent authenticated via bearer credential (PoP fallback)",
		"agent_id", agent.AgentID, "path", r.URL.Path)
	return agent, true
}

// authenticatePoP 证书 PoP 认证（契约 §8，与 APM 同构）：先做纯密码学校验
// （不触库，挡垃圾流量）——证书解析 → 链到 CA 且有效 → 时间窗 ±300s → 签名；
// 再做身份校验——CN == 路径 agent_id、指纹为当前或宽限中。任一失败 401。
func (h *MachineHandler) authenticatePoP(w http.ResponseWriter, r *http.Request, body []byte, certH, ts, sig string) (*Agent, bool) {
	if h.ca == nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "PoP 认证不可用（CA 未装配）")
		return nil, false
	}
	cert, err := ParseAgentCertHeader(certH)
	if err != nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "客户端证书解析失败")
		return nil, false
	}
	if err := h.ca.VerifyClientCert(cert, h.now()); err != nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "客户端证书未通过 CA 链校验或已过期")
		return nil, false
	}
	if err := CheckPoPTimestamp(ts, h.now()); err != nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "时间戳无效或超出允许时钟偏差")
		return nil, false
	}
	if err := VerifyPoPSignature(cert, r.Method, r.URL.Path, ts, body, sig); err != nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "持有证明签名校验失败")
		return nil, false
	}
	agentID, err := uuid.Parse(r.PathValue("agent_id"))
	if err != nil {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "agent_id 非法")
		return nil, false
	}
	if cert.Subject.CommonName != agentID.String() {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "证书 CN 与路径 agent_id 不匹配")
		return nil, false
	}
	usable, err := h.store.CertFingerprintUsable(r.Context(), agentID, CertFingerprint(cert), h.now().UTC())
	if err != nil {
		machineInternal(w, r, err)
		return nil, false
	}
	if !usable {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "证书指纹未登记或已撤销")
		return nil, false
	}
	agent, err := h.store.AgentByID(r.Context(), agentID)
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			machineError(w, http.StatusUnauthorized, mcUnauthenticated, "Agent 未登记")
			return nil, false
		}
		machineInternal(w, r, err)
		return nil, false
	}
	return agent, true
}

// matchPathAgent 路径 agent_id 解析与归属校验（凭据与路径不一致 → 403 防越权）。
func (h *MachineHandler) matchPathAgent(w http.ResponseWriter, r *http.Request, agent *Agent) bool {
	id, err := uuid.Parse(r.PathValue("agent_id"))
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "agent_id 非法")
		return false
	}
	if id != agent.AgentID {
		machineError(w, http.StatusForbidden, mcForbidden, "credential 与路径 agent_id 不匹配")
		return false
	}
	return true
}

// requireEnabled 禁用 Agent 除心跳外全部 403（Agent 收到心跳 desired_state=DISABLED 后停止抓包）。
func requireEnabled(w http.ResponseWriter, agent *Agent) bool {
	if agent.Disabled {
		machineError(w, http.StatusForbidden, mcForbidden, "Agent 已被禁用，仅允许心跳")
		return false
	}
	return true
}

// ---------- 注册 ----------

// Enroll POST /api/v1/agents/enroll（契约 §3.1 + Phase 2-B §7 增量）。
// 令牌校验与 Agent 创建在同一事务（失败不烧令牌）；credential 明文仅此一次下发。
// 请求携带可选 csr_pem 时由内置 CA 签发客户端证书（CN=agent_id，TTL 90 天），
// 响应返回 agent_cert_pem/ca_cert_pem/cert_expires_at；无 csr_pem 三字段为 null（行为同 Phase 1）。
func (h *MachineHandler) Enroll(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineEnrollMaxBody)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求体过大或读取失败")
		return
	}
	var req EnrollRequest
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if err := req.Validate(); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	// CSR 先于令牌消费校验（格式问题不烧毁令牌）
	var csr *x509.CertificateRequest
	if req.CSRPem != "" {
		if h.ca == nil {
			machineError(w, http.StatusBadRequest, mcInvalidArgument, "证书签发未启用（CA 未装配）")
			return
		}
		csr, err = ParseAgentCSR(req.CSRPem)
		if err != nil {
			machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
			return
		}
	}
	credential, err := GenerateCredential()
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	// v2 契约 §3 能力协商：声明 ∩ 服务端支持集（未声明 → {1}），生效集随注册落库。
	schemas := NegotiateHTTPEventSchemas(req.Capabilities)
	agentID := uuid.New()
	now := h.now().UTC()
	in := EnrollInput{
		AgentID:        agentID,
		TokenHash:      HashSecret(req.EnrollmentToken),
		CredentialHash: HashSecret(credential),
		Hostname:       req.Hostname,
		IP:             req.IP,
		OS:             req.OS,
		Kernel:         req.Kernel,
		Arch:           req.Arch,
		Version:        req.Version,
		Interfaces:     req.Interfaces,
		Now:            now,
	}
	in.HTTPEventSchemas = schemasToInt16(schemas)
	var certPEM string
	if csr != nil {
		pem, fingerprint, notAfter, err := h.ca.IssueCertificate(csr, agentID.String(), now)
		if err != nil {
			machineInternal(w, r, err)
			return
		}
		certPEM = pem
		in.CertFingerprint = &fingerprint
		in.CertNotAfter = &notAfter
	}
	agent, err := h.store.Enroll(r.Context(), in)
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) {
			machineError(w, http.StatusUnauthorized, mcUnauthenticated, "enrollment_token 无效/过期/已使用/已撤销")
			return
		}
		machineInternal(w, r, err)
		return
	}
	resp := map[string]interface{}{
		"agent_id":                   agent.AgentID.String(),
		"credential":                 credential,
		"heartbeat_interval_seconds": HeartbeatIntervalSeconds,
		"config_version":             agent.ConfigVersion,
		"agent_cert_pem":             nil,
		"ca_cert_pem":                nil,
		"cert_expires_at":            nil,
		// v2 契约 §3：回执生效能力集（旧 Agent 忽略未知响应字段不受影响）。
		"capabilities": map[string]interface{}{"http_event_schema_versions": schemas},
	}
	if certPEM != "" {
		resp["agent_cert_pem"] = certPEM
		resp["ca_cert_pem"] = h.ca.CertPEM()
		resp["cert_expires_at"] = in.CertNotAfter.UTC().Format(time.RFC3339)
	}
	machineJSON(w, http.StatusCreated, resp)
}

// ---------- 心跳 / 指标 ----------

// Heartbeat POST /api/v1/agents/{agent_id}/heartbeat（契约 §3.2）。
// disabled Agent 同样放行——心跳是其接收 desired_state 恢复启用的唯一通道。
func (h *MachineHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineHeartbeatMaxBody)
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
	var req HeartbeatRequest
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if err := req.Validate(); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	now := h.now().UTC()
	// 时钟偏移（设计 §23）：服务端收包时间 − Agent 上报 timestamp（毫秒，signed；
	// 正值表示 Agent 时钟偏慢）。timestamp 非法（≤0）时不覆盖既有记录。
	var clockOffsetMS *int64
	if req.Timestamp > 0 {
		offset := now.UnixMilli() - req.Timestamp*1000
		clockOffsetMS = &offset
	}
	// v2 契约 §3 能力协商：携带 capabilities 时更新生效集并回执；未携带保持库中原值，
	// 回执当前生效集（旧 Agent 忽略未知响应字段）。
	effective := agent.HTTPEventSchemas
	var schemas16 []int16
	if req.Capabilities != nil {
		effective = NegotiateHTTPEventSchemas(req.Capabilities)
		schemas16 = schemasToInt16(effective)
	}
	if len(effective) == 0 {
		effective = []int{1}
	}
	cfgVersion, err := h.store.RecordHeartbeat(r.Context(), agent.AgentID, req.Status, req.Metrics, clockOffsetMS, schemas16, now)
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	desired := DesiredEnabled
	if agent.Disabled {
		desired = DesiredDisabled
	}
	machineJSON(w, http.StatusOK, map[string]interface{}{
		"server_time":                now.Unix(),
		"config_version":             cfgVersion,
		"desired_state":              desired,
		"heartbeat_interval_seconds": HeartbeatIntervalSeconds,
		"capabilities":               map[string]interface{}{"http_event_schema_versions": effective},
	})
}

// Metrics POST /api/v1/agents/{agent_id}/metrics（契约 §3.2；body 仅为 metrics 对象，返回 204）。
func (h *MachineHandler) Metrics(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineHeartbeatMaxBody)
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
	var probe map[string]interface{}
	if err := json.Unmarshal(body, &probe); err != nil || probe == nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "metrics 须为 JSON 对象")
		return
	}
	if err := h.store.RecordMetrics(r.Context(), agent.AgentID, body, h.now().UTC()); err != nil {
		machineInternal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- 配置拉取与 ACK ----------

// GetConfig GET /api/v1/agents/{agent_id}/config（契约 §3.3；无绑定策略时 policy=null，
// version 为当前 agents.config_version，Agent 用内置默认并照常 ACK）。
// Phase 4 契约 §2.4：响应新增顶层 overrides（未过期定向采集规则全量；无规则为空数组，
// 字段恒在；无绑定策略时 overrides 照常返回；旧 Agent 忽略该字段不受影响——§5 兼容）。
func (h *MachineHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	agent, method, ok := h.authenticate(w, r, nil)
	if !ok {
		return
	}
	if method == authMethodBearer && !h.matchPathAgent(w, r, agent) {
		return
	}
	if !requireEnabled(w, agent) {
		return
	}
	cfgVersion, policy, err := h.store.AgentConfig(r.Context(), agent.AgentID)
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	overrides, err := h.store.ActiveCaptureOverrides(r.Context(), agent.AgentID, h.now().UTC())
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	overrideItems := make([]captureOverrideConfig, 0, len(overrides))
	for i := range overrides {
		overrideItems = append(overrideItems, captureOverrideConfig{
			ID:           overrides[i].ID,
			Match:        overrides[i].Match,
			CaptureLevel: overrides[i].CaptureLevel,
			ExpiresAt:    overrides[i].ExpiresAt.UTC(),
		})
	}
	var policyJSON json.RawMessage
	if policy != nil {
		policyJSON = policy.Config
	}
	machineJSON(w, http.StatusOK, map[string]interface{}{
		"version":   cfgVersion,
		"policy":    policyJSON, // nil → null
		"overrides": overrideItems,
	})
}

// ConfigAck POST /api/v1/agents/{agent_id}/config/ack（契约 §3.3；APPLIED 推进
// applied_config_version，FAILED 不回填——如实反映 Agent 侧应用结果）。
func (h *MachineHandler) ConfigAck(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineHeartbeatMaxBody)
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
	var req ConfigAckRequest
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if err := req.Validate(); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	if err := h.store.AckConfig(r.Context(), agent.AgentID, req.Version, req.Status == "APPLIED"); err != nil {
		machineInternal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- 流量事件 / RAW 包 ----------

// Flows POST /api/v1/agents/{agent_id}/flows（契约 §3.4；≤500 条/批；
// 入库失败整体 500——Agent 转本地缓存补传）。
func (h *MachineHandler) Flows(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineFlowsMaxBody)
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
	var req FlowsRequest
	if err := decodeMachineJSON(body, &req); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if err := req.Validate(); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	if err := h.store.InsertFlowEvents(r.Context(), agent.AgentID, req.Events); err != nil {
		machineInternal(w, r, err)
		return
	}
	machineJSON(w, http.StatusAccepted, map[string]interface{}{"accepted": len(req.Events)})
}

// Packets POST /api/v1/agents/{agent_id}/packets（契约 §3.5；WDP1 二进制批量，
// 校验 magic/长度后计数并丢弃，不入库）。
func (h *MachineHandler) Packets(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, MaxPacketBatchBytes+1)
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
	if ct := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]); ct != packetBatchContentType {
		machineError(w, http.StatusBadRequest, mcInvalidArgument,
			"Content-Type 须为 "+packetBatchContentType)
		return
	}
	frames, payloadBytes, err := ParsePacketBatch(body)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "批量帧校验失败："+err.Error())
		return
	}
	if err := h.store.AddRawCounters(r.Context(), agent.AgentID, int64(frames), payloadBytes); err != nil {
		machineInternal(w, r, err)
		return
	}
	machineJSON(w, http.StatusAccepted, map[string]interface{}{"accepted_frames": frames})
}

// ---------- 证书轮换（Phase 2-B §9） ----------

// rotateCertRequest 轮换入参（新 CSR；不依赖长期注册令牌——Bearer 不可轮换证书）。
type rotateCertRequest struct {
	CSRPem string `json:"csr_pem"`
}

// RotateCert POST /api/v1/agents/{agent_id}/rotate-cert（契约 §9）。
// 仅接受 PoP 认证（Bearer 401）；签发新证书（新指纹，CN=agent_id，TTL 90 天）→
// 旧指纹写 revocations（grace_until=+24h，宽限期内新旧均可认证）→ 更新当前指纹/到期。
// 出示证书非当前生效证书 → 409（与 APM 轮换先例同构）。
func (h *MachineHandler) RotateCert(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineEnrollMaxBody)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求体过大或读取失败")
		return
	}
	agent, method, ok := h.authenticate(w, r, body)
	if !ok {
		return
	}
	if method != authMethodPoP {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "证书轮换仅接受证书 PoP 认证")
		return
	}
	if !requireEnabled(w, agent) {
		return
	}
	var req rotateCertRequest
	if err := decodeMachineJSON(body, &req); err != nil || strings.TrimSpace(req.CSRPem) == "" {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误（须携带 csr_pem）")
		return
	}
	csr, err := ParseAgentCSR(req.CSRPem)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, err.Error())
		return
	}
	now := h.now().UTC()
	certPEM, fingerprint, notAfter, err := h.ca.IssueCertificate(csr, agent.AgentID.String(), now)
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	// 出示证书（PoP 已验）即旧证书：取其指纹与 NotBefore 落撤销行
	oldCert, err := ParseAgentCertHeader(r.Header.Get(popCertHeader))
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	err = h.store.RotateAgentCert(r.Context(), RotateCertInput{
		AgentID:        agent.AgentID,
		OldFingerprint: CertFingerprint(oldCert),
		OldNotBefore:   oldCert.NotBefore,
		NewFingerprint: fingerprint,
		NewNotAfter:    notAfter,
		GraceUntil:     now.Add(rotateGracePeriod),
		Now:            now,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrCertFingerprintMismatch):
			machineError(w, http.StatusConflict, mcConflict, "出示证书非当前生效证书，请先同步状态")
		case errors.Is(err, ErrAgentNotFound):
			machineError(w, http.StatusNotFound, mcNotFound, "Agent 不存在")
		default:
			machineInternal(w, r, err)
		}
		return
	}
	machineJSON(w, http.StatusOK, map[string]interface{}{
		"agent_cert_pem":  certPEM,
		"ca_cert_pem":     h.ca.CertPEM(),
		"cert_expires_at": notAfter.UTC().Format(time.RFC3339),
	})
}
