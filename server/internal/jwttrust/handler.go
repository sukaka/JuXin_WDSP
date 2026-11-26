// handler.go JWT 信任策略管理面接口（WDSP P0-03；路由在 app.go 注册）：
//
//	GET  /api/v1/applications/{id}/jwt-trust-policy           读取草稿+已发布版本+状态摘要（jwt_trust.read）
//	PUT  /api/v1/applications/{id}/jwt-trust-policy           校验并保存草稿（jwt_trust.manage；
//	      expected_version 乐观锁冲突 409；不自动发布——草稿保存不等于线上生效）
//	POST /api/v1/applications/{id}/jwt-trust-policy/preflight 结构/公钥/SSRF/受限连通性/
//	      目标节点与 API 管线门禁检查（jwt_trust.manage；不自动发布）
//
// 发布复用既有 gateway-config 发布通道（BuildGuardConfig 组装 jwt_trust 段）；
// PROTECT 策略的发布前置校验（API 管线已启用且为 PROTECT、目标节点无已知同步失败）
// 在发布链路与预检中同口径执行，防止外层 OBSERVE 把 JWT 强制静默降级。
package jwttrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apinodes"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AppGetter 应用查询接口（applications.Store 实现；不存在 → 404）。
type AppGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*applications.Application, error)
}

// PipelineStateFunc 读取 API 动态管线状态（装配层注入：产品开关 + settings 覆盖解析后的
// 有效模式；enabled=false 或 mode!=PROTECT 时拒绝发布 PROTECT 策略——防静默降级）。
type PipelineStateFunc func(ctx context.Context) (enabled bool, mode string, err error)

// NodeLister 网关节点查询接口（apinodes.Store 实现；预检/发布门禁用——
// 已知同步失败的节点不接收含 JWT PROTECT 的新配置）。
type NodeLister interface {
	ListNodes(ctx context.Context) ([]apinodes.Node, error)
}

// AllowlistFunc 读取 REMOTE_JWKS 企业内网 IdP 允许清单
// （system_settings jwt_trust:remote_jwks_allowlist；空=仅公网 HTTPS）。
type AllowlistFunc func(ctx context.Context) string

// Handler 是 JWT 信任策略处理器。
type Handler struct {
	store     *Store
	apps      AppGetter
	audits    *audits.Service
	pipeline  PipelineStateFunc
	nodes     NodeLister
	allowlist AllowlistFunc
	resolver  outboundhttp.Resolver // nil → net.DefaultResolver（测试注入假解析器）
	// remoteFetch 受限连通性探测（预检用；nil → 默认实现 remoteProbe）。
	// 返回 nil=可达且 JWKS 合法；错误信息为可回显的失败原因（不含凭据）。
	remoteFetch func(ctx context.Context, rawURL string, policy *outboundhttp.Policy) error
}

// NewHandler 创建处理器。
func NewHandler(store *Store, apps AppGetter, au *audits.Service) *Handler {
	return &Handler{store: store, apps: apps, audits: au}
}

// SetPipelineState 注入 API 动态管线状态读取（预检与发布门禁用）。
func (h *Handler) SetPipelineState(fn PipelineStateFunc) { h.pipeline = fn }

// SetNodeLister 注入网关节点查询（预检节点能力/状态检查用）。
func (h *Handler) SetNodeLister(l NodeLister) { h.nodes = l }

// SetAllowlist 注入 REMOTE_JWKS 允许清单读取。
func (h *Handler) SetAllowlist(fn AllowlistFunc) { h.allowlist = fn }

// SetResolver 注入 DNS 解析器（测试用；nil 用系统默认）。
func (h *Handler) SetResolver(r outboundhttp.Resolver) { h.resolver = r }

// SetRemoteFetch 注入受限连通性探测（测试用；nil 用默认实现）。
func (h *Handler) SetRemoteFetch(fn func(ctx context.Context, rawURL string, policy *outboundhttp.Policy) error) {
	h.remoteFetch = fn
}

// outboundPolicy 构造 REMOTE_JWKS 出站防护策略（2 秒超时、不跟随重定向、允许清单注入）。
func (h *Handler) outboundPolicy() (*outboundhttp.Policy, error) {
	allow := ""
	if h.allowlist != nil {
		allow = h.allowlist(context.Background())
	}
	return outboundhttp.NewPolicy(outboundhttp.Options{
		Timeout:   time.Duration(remoteJWKSTimeoutSec) * time.Second,
		Resolver:  h.resolver,
		Allowlist: allow,
	})
}

// ---------- 请求/响应 DTO ----------

// selectorRequest 选择器请求项（与 Policy.Selectors 元素同形，显式承接防未知字段）。
type selectorRequest struct {
	Methods       []string `json:"methods"`
	PathExact     string   `json:"path_exact"`
	PathPrefix    string   `json:"path_prefix"`
	TokenRequired bool     `json:"token_required"`
}

// tokenBindingRequest 令牌持有证明绑定请求项（指针字段区分「未提供=默认值」与显式 0）。
type tokenBindingRequest struct {
	Mode               string   `json:"mode"`
	RequireNonce       bool     `json:"require_nonce"`
	MaxProofAgeSeconds *int     `json:"max_proof_age_seconds"`
	NonceTTLSeconds    *int     `json:"nonce_ttl_seconds"`
	AllowedDPoPAlgs    []string `json:"allowed_dpop_algs"`
}

// issuerRequest issuer 请求项（clock_skew_seconds 用指针区分「未提供=默认 30」与显式 0）。
type issuerRequest struct {
	Issuer           string               `json:"issuer"`
	Audiences        []string             `json:"audiences"`
	Algorithms       []string             `json:"algorithms"`
	KeySource        KeySource            `json:"key_source"`
	ClockSkewSeconds *int                 `json:"clock_skew_seconds"`
	TenantClaim      string               `json:"tenant_claim"`
	RoleClaims       []string             `json:"role_claims"`
	TokenBinding     *tokenBindingRequest `json:"token_binding,omitempty"`
}

// putRequest PUT 请求体（全量草稿 + 乐观锁 + 变更理由）。
type putRequest struct {
	Mode            string            `json:"mode"`
	ExpectedVersion int               `json:"expected_version"`
	Selectors       []selectorRequest `json:"selectors"`
	Issuers         []issuerRequest   `json:"issuers"`
	Reason          string            `json:"reason"`
}

// toPolicy 转换为领域策略（应用默认 clock_skew；未归一化——Normalize 由调用方执行）。
func (r *putRequest) toPolicy(appID uuid.UUID) *Policy {
	p := &Policy{
		ApplicationID: appID,
		Mode:          strings.ToUpper(strings.TrimSpace(r.Mode)),
		Selectors:     make([]Selector, 0, len(r.Selectors)),
		Issuers:       make([]Issuer, 0, len(r.Issuers)),
	}
	for _, s := range r.Selectors {
		p.Selectors = append(p.Selectors, Selector{
			Methods:       s.Methods,
			PathExact:     s.PathExact,
			PathPrefix:    s.PathPrefix,
			TokenRequired: s.TokenRequired,
		})
	}
	for _, is := range r.Issuers {
		skew := DefaultClockSkew
		if is.ClockSkewSeconds != nil {
			skew = *is.ClockSkewSeconds
		}
		var tb *TokenBindingConfig
		if is.TokenBinding != nil {
			mode := strings.ToUpper(strings.TrimSpace(is.TokenBinding.Mode))
			if mode != "" && mode != TokenBindingNone {
				maxAge := DefaultDPoPMaxProofAgeSeconds
				if is.TokenBinding.MaxProofAgeSeconds != nil {
					maxAge = *is.TokenBinding.MaxProofAgeSeconds
				}
				nonceTTL := DefaultDPoPNonceTTLSeconds
				if is.TokenBinding.NonceTTLSeconds != nil {
					nonceTTL = *is.TokenBinding.NonceTTLSeconds
				}
				tb = &TokenBindingConfig{
					Mode:               mode,
					RequireNonce:       is.TokenBinding.RequireNonce,
					MaxProofAgeSeconds: maxAge,
					NonceTTLSeconds:    nonceTTL,
					AllowedDPoPAlgs:    append([]string(nil), is.TokenBinding.AllowedDPoPAlgs...),
				}
			}
		}
		p.Issuers = append(p.Issuers, Issuer{
			Issuer:           is.Issuer,
			Audiences:        is.Audiences,
			Algorithms:       is.Algorithms,
			KeySource:        is.KeySource,
			ClockSkewSeconds: skew,
			TenantClaim:      is.TenantClaim,
			RoleClaims:       append([]string(nil), is.RoleClaims...),
			TokenBinding:     tb,
		})
	}
	return p
}

// ---------- GET ----------

// Get 读取应用 JWT 信任策略（草稿 + 最近成功发布的生效版本 + 状态摘要；无记录返回默认 OFF 空策略）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	p, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			p = DefaultPolicy(app.ID)
		} else {
			response.InternalError(w, r, err)
			return
		}
	}
	published, err := h.store.PublishedVersion(r.Context(), app.Code)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	summary := StatusSummary{
		State:            StateNotConfigured,
		DraftVersion:     p.Version,
		PublishedVersion: published,
	}
	if p.Version > 0 {
		if p.Version == published {
			summary.State = StatePublished
		} else {
			summary.State = StateDraftPending
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"policy":  p,
		"summary": summary,
	})
}

// ---------- PUT ----------

// Put 校验并保存草稿（expected_version 乐观锁冲突 409；保存/失败均写操作审计；
// 不触发发布——发布走既有 gateway-config 发布通道）。
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	var req putRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: "变更理由不能为空"}})
		return
	}
	if len(req.Reason) > MaxReasonLen {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "reason", Message: fmt.Sprintf("变更理由不能超过 %d 字符", MaxReasonLen)}})
		return
	}
	if req.ExpectedVersion < 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
			[]FieldError{{Field: "expected_version", Message: "expected_version 不能为负数"}})
		return
	}
	// 已有草稿时不允许再以 expected_version=0 创建；无草稿时必须以 0 创建
	if before != nil && req.ExpectedVersion == 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	if before == nil && req.ExpectedVersion != 0 {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}

	p := req.toPolicy(app.ID)
	Normalize(p)
	if errs := ValidateStructure(p); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
		return
	}
	// REMOTE_JWKS 地址 SSRF 校验（保存时；允许清单来自系统设置）
	if hasRemoteJWKS(p) {
		outbound, err := h.outboundPolicy()
		if err != nil {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过",
				[]FieldError{{Field: "issuers.key_source.url", Message: "允许清单配置非法: " + err.Error()}})
			return
		}
		if errs := ValidateRemoteURLs(r.Context(), p, outbound); len(errs) > 0 {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
			return
		}
	}

	if err := h.store.SaveDraft(r.Context(), p, req.ExpectedVersion, req.Reason, principal.Username); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
			return
		}
		var ve *ValidationError
		if errors.As(err, &ve) {
			response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", ve.Errors)
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, principal, "update", app, before, p, req.Reason, audits.ResultSuccess, "")

	final, err := h.store.GetByApp(r.Context(), app.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"policy": final})
}

// ---------- Preflight ----------

// PreflightCheck 单项预检结果（PASS/FAIL/WARN/SKIP）。
type PreflightCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// 预检状态词表。
const (
	CheckPass = "PASS"
	CheckFail = "FAIL"
	CheckWarn = "WARN"
	CheckSkip = "SKIP"
)

// preflightRequest 预检请求体（policy 为空时检查当前草稿；均不保存、不发布）。
type preflightRequest struct {
	Mode      string            `json:"mode"`
	Selectors []selectorRequest `json:"selectors"`
	Issuers   []issuerRequest   `json:"issuers"`
}

// Preflight 发布前检查：结构/公钥、REMOTE_JWKS SSRF 与受限连通性、API 管线门禁、
// 目标节点状态。publishable=false 时发布链路将以同口径拒绝（PROTECT 门禁）。
func (h *Handler) Preflight(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	app, ok := h.resolveApp(w, r)
	if !ok {
		return
	}
	var req preflightRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}

	// 评估对象：请求体提供的候选策略，否则当前草稿（无草稿=默认 OFF）
	var p *Policy
	if req.Mode != "" || len(req.Selectors) > 0 || len(req.Issuers) > 0 {
		put := putRequest{Mode: req.Mode, Selectors: req.Selectors, Issuers: req.Issuers}
		p = put.toPolicy(app.ID)
		Normalize(p)
	} else {
		var err error
		p, err = h.store.GetByApp(r.Context(), app.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				p = DefaultPolicy(app.ID)
			} else {
				response.InternalError(w, r, err)
				return
			}
		}
	}

	checks := []PreflightCheck{}
	publishable := true
	fail := func(name, msg string) {
		checks = append(checks, PreflightCheck{Name: name, Status: CheckFail, Message: msg})
		publishable = false
	}

	// 1. 结构与静态公钥
	if errs := ValidateStructure(p); len(errs) > 0 {
		msg, _ := json.Marshal(errs)
		fail("structure", "结构/公钥校验未通过: "+string(msg))
	} else {
		checks = append(checks, PreflightCheck{Name: "structure", Status: CheckPass, Message: "结构与静态公钥校验通过"})
	}

	// 2. REMOTE_JWKS SSRF + 受限连通性
	if hasRemoteJWKS(p) {
		outbound, err := h.outboundPolicy()
		if err != nil {
			fail("remote_url_ssrf", "允许清单配置非法: "+err.Error())
		} else {
			if errs := ValidateRemoteURLs(r.Context(), p, outbound); len(errs) > 0 {
				msg, _ := json.Marshal(errs)
				fail("remote_url_ssrf", "REMOTE_JWKS 地址 SSRF 校验未通过: "+string(msg))
			} else {
				checks = append(checks, PreflightCheck{Name: "remote_url_ssrf", Status: CheckPass, Message: "地址 SSRF 校验通过"})
				// 受限连通性（管理端视角；不代表各网关节点可达——页面须区分展示）
				fetch := h.remoteFetch
				if fetch == nil {
					fetch = remoteProbe
				}
				for i, is := range p.Issuers {
					if is.KeySource.Type != KeySourceRemoteJWKS {
						continue
					}
					if err := fetch(r.Context(), is.KeySource.URL, outbound); err != nil {
						fail("remote_connectivity",
							fmt.Sprintf("issuers[%d] 受限连通性检查失败（管理端视角，不代表网关节点可达）: %v", i, err))
					}
				}
				checks = append(checks, PreflightCheck{Name: "remote_connectivity", Status: CheckPass,
					Message: "REMOTE_JWKS 受限连通性检查通过（管理端视角）"})
			}
		}
	} else {
		checks = append(checks, PreflightCheck{Name: "remote_url_ssrf", Status: CheckSkip, Message: "无 REMOTE_JWKS 密钥来源"})
		checks = append(checks, PreflightCheck{Name: "remote_connectivity", Status: CheckSkip, Message: "无 REMOTE_JWKS 密钥来源"})
	}

	// 3. API 管线门禁（PROTECT 要求管线已启用且为 PROTECT，防静默降级）
	if p.Mode == ModeProtect {
		enabled, mode, err := h.pipelineState(r.Context())
		switch {
		case err != nil:
			fail("pipeline_gate", "读取 API 动态管线状态失败: "+err.Error())
		case !enabled:
			fail("pipeline_gate", "应用 API 动态管线未启用，拒绝发布 PROTECT 策略")
		case mode != ModeProtect:
			fail("pipeline_gate", fmt.Sprintf("API 动态管线模式为 %s，PROTECT 策略会被静默降级，拒绝发布", mode))
		default:
			checks = append(checks, PreflightCheck{Name: "pipeline_gate", Status: CheckPass,
				Message: "API 动态管线已启用且为 PROTECT"})
		}
	} else {
		enabled, mode, err := h.pipelineState(r.Context())
		if err != nil {
			checks = append(checks, PreflightCheck{Name: "pipeline_gate", Status: CheckWarn,
				Message: "读取 API 动态管线状态失败: " + err.Error()})
		} else if !enabled {
			checks = append(checks, PreflightCheck{Name: "pipeline_gate", Status: CheckWarn,
				Message: "API 动态管线未启用：jwt_trust 段随 WDSP 发布通道下发，当前形态不会下发"})
		} else {
			checks = append(checks, PreflightCheck{Name: "pipeline_gate", Status: CheckPass,
				Message: fmt.Sprintf("API 动态管线模式 %s（%s 策略不受影响）", mode, p.Mode)})
		}
	}

	// 4. 目标节点状态（已知同步失败/离线的节点不接收含 PROTECT 的新配置；
	// 节点能力（网关构建对 jwt_trust schema_version 的支持）由节点同步回执与
	// 集成步骤的能力上报兜底，本检查如实呈现节点注册与同步状态）
	checks = append(checks, h.nodeChecks(p.Mode == ModeProtect, &publishable)...)

	h.recordAudit(r, principal, "preflight", app, nil, p, "", audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"policy":      p,
		"checks":      checks,
		"publishable": publishable,
	})
}

// pipelineState 读取管线状态（未注入视为未启用，fail-safe）。
func (h *Handler) pipelineState(ctx context.Context) (bool, string, error) {
	if h.pipeline == nil {
		return false, "", nil
	}
	return h.pipeline(ctx)
}

// nodeChecks 目标节点检查（无注册节点=单网关部署，SKIP；sync_enabled 节点
// 存在已知同步失败时，PROTECT 策略判 FAIL 阻断发布，OBSERVE/OFF 判 WARN）。
func (h *Handler) nodeChecks(protect bool, publishable *bool) []PreflightCheck {
	if h.nodes == nil {
		return []PreflightCheck{{Name: "node_capability", Status: CheckSkip, Message: "节点查询未装配"}}
	}
	nodes, err := h.nodes.ListNodes(context.Background())
	if err != nil {
		*publishable = false
		return []PreflightCheck{{Name: "node_capability", Status: CheckFail, Message: "读取网关节点状态失败: " + err.Error()}}
	}
	targets := []apinodes.Node{}
	for _, n := range nodes {
		if n.SyncEnabled {
			targets = append(targets, n)
		}
	}
	if len(targets) == 0 {
		return []PreflightCheck{{Name: "node_capability", Status: CheckSkip,
			Message: "无登记参与发布扇出的次要节点（单网关部署）"}}
	}
	out := []PreflightCheck{}
	for _, n := range targets {
		switch {
		case n.LastSyncResult == gatewayconfig.NodeSyncFailed || n.LastSyncResult == gatewayconfig.NodeSyncHashMismatch:
			msg := fmt.Sprintf("节点 %s 上次配置同步结果为 %s（%s），存在已知不可用目标", n.NodeName, n.LastSyncResult, n.LastSyncError)
			if protect {
				*publishable = false
				out = append(out, PreflightCheck{Name: "node_capability", Status: CheckFail, Message: msg})
			} else {
				out = append(out, PreflightCheck{Name: "node_capability", Status: CheckWarn, Message: msg})
			}
		case n.Status == apinodes.StatusSilent:
			out = append(out, PreflightCheck{Name: "node_capability", Status: CheckWarn,
				Message: fmt.Sprintf("节点 %s 超过 1 小时无事件（SILENT），请确认节点在线后再发布", n.NodeName)})
		default:
			out = append(out, PreflightCheck{Name: "node_capability", Status: CheckPass,
				Message: fmt.Sprintf("节点 %s 状态 %s，最近同步 %s", n.NodeName, n.Status, emptyAs(n.LastSyncResult, "未同步"))})
		}
	}
	return out
}

func emptyAs(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// remoteProbe 默认受限连通性探测：防护客户端 GET（2s 超时、禁跳转、拨号复检），
// 响应体 ≤ 256 KiB 且须为合法公钥 JWKS（与保存时校验同口径）。
func remoteProbe(ctx context.Context, rawURL string, policy *outboundhttp.Policy) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := policy.Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return err
	}
	if len(body) > MaxJWKSBytes {
		return fmt.Errorf("响应超过 %d 字节上限", MaxJWKSBytes)
	}
	if _, err := ValidateJWKS(string(body), nil); err != nil {
		return fmt.Errorf("响应不是合法公钥 JWKS: %v", err)
	}
	return nil
}

// hasRemoteJWKS 是否含 REMOTE_JWKS 密钥来源。
func hasRemoteJWKS(p *Policy) bool {
	for _, is := range p.Issuers {
		if is.KeySource.Type == KeySourceRemoteJWKS {
			return true
		}
	}
	return false
}

// resolveApp 解析路径应用 ID 并校验存在（不存在 404；非法 ID 400）。
func (h *Handler) resolveApp(w http.ResponseWriter, r *http.Request) (*applications.Application, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的应用 ID")
		return nil, false
	}
	app, err := h.apps.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return nil, false
		}
		response.InternalError(w, r, err)
		return nil, false
	}
	return app, true
}

// auditSummary 审计差异摘要（含变更理由与版本；不含完整 JWKS 文本——以
// keyset_version 指纹代替；不含任何业务 Token；静态公钥为公开材料但审计只留指纹保持紧凑）。
type auditSummary struct {
	Mode      string              `json:"mode"`
	Version   int                 `json:"version"`
	Reason    string              `json:"reason,omitempty"`
	Selectors []Selector          `json:"selectors"`
	Issuers   []auditIssuerDigest `json:"issuers"`
}

type auditIssuerDigest struct {
	Issuer           string   `json:"issuer"`
	Audiences        []string `json:"audiences"`
	Algorithms       []string `json:"algorithms"`
	KeySourceType    string   `json:"key_source_type"`
	KeysetVersion    string   `json:"keyset_version,omitempty"`
	RemoteURL        string   `json:"remote_url,omitempty"`
	ClockSkewSeconds int      `json:"clock_skew_seconds"`
	TenantClaim      string              `json:"tenant_claim,omitempty"`
	RoleClaims       []string            `json:"role_claims,omitempty"`
	TokenBinding     *TokenBindingConfig `json:"token_binding,omitempty"`
}

func summarizePolicy(p *Policy, reason string) auditSummary {
	s := auditSummary{
		Mode:      p.Mode,
		Version:   p.Version,
		Reason:    reason,
		Selectors: p.Selectors,
		Issuers:   make([]auditIssuerDigest, 0, len(p.Issuers)),
	}
	for _, is := range p.Issuers {
		var tbCopy *TokenBindingConfig
		if is.TokenBinding.Active() {
			cp := *is.TokenBinding
			cp.AllowedDPoPAlgs = append([]string(nil), is.TokenBinding.AllowedDPoPAlgs...)
			tbCopy = &cp
		}
		d := auditIssuerDigest{
			Issuer:           is.Issuer,
			Audiences:        is.Audiences,
			Algorithms:       is.Algorithms,
			KeySourceType:    is.KeySource.Type,
			RemoteURL:        is.KeySource.URL,
			ClockSkewSeconds: is.ClockSkewSeconds,
			TenantClaim:      is.TenantClaim,
			RoleClaims:       append([]string(nil), is.RoleClaims...),
			TokenBinding:     tbCopy,
		}
		if is.KeySource.Type == KeySourceStaticJWKS && is.KeySource.JWKS != "" {
			if v, err := KeysetVersion(is.KeySource.JWKS); err == nil {
				d.KeysetVersion = v
			}
		}
		s.Issuers = append(s.Issuers, d)
	}
	return s
}

// recordAudit 操作审计（保存/预检：含操作人、reason、版本与字段差异摘要；
// mode 升级为 PROTECT（观测转强制）提升为高风险审计，其余中风险；预检低风险）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string,
	app *applications.Application, before, after *Policy, reason, result, failureReason string) {
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizePolicy(before, ""))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizePolicy(after, reason))
	}
	risk := audits.RiskMedium
	switch {
	case action == "preflight":
		risk = audits.RiskLow
	case before != nil && before.Mode != ModeProtect && after != nil && after.Mode == ModeProtect:
		risk = audits.RiskHigh
	}
	objID := app.ID.String()
	if after != nil && after.ID != uuid.Nil {
		objID = after.ID.String()
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        action,
		ObjectType:    "jwt_trust_policy",
		ObjectID:      objID,
		ObjectName:    app.Code,
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// NodePublishGuard 构造发布门禁函数（装配层注入 guardconfig.Provider）：
// 存在 PROTECT 策略时，拒绝向已知同步失败的扇出节点发布新配置
// （防止故障节点继续运行旧配置而管理面显示已生效）；节点读取失败如实返回
// （中止发布，不静默跳过——与发布链路 fail-hard 纪律一致）。
// 节点二进制对 jwt_trust schema_version 的能力判定由节点 /load 拒绝未知配置 +
// 同步回执兜底（集成步骤补能力上报后此处升级为显式能力检查）。
func NodePublishGuard(nodes NodeLister) func(ctx context.Context, protectApps []string) error {
	return func(ctx context.Context, protectApps []string) error {
		if len(protectApps) == 0 || nodes == nil {
			return nil
		}
		list, err := nodes.ListNodes(ctx)
		if err != nil {
			return fmt.Errorf("读取网关节点状态失败: %w", err)
		}
		bad := []string{}
		for _, n := range list {
			if !n.SyncEnabled {
				continue
			}
			if n.LastSyncResult == gatewayconfig.NodeSyncFailed || n.LastSyncResult == gatewayconfig.NodeSyncHashMismatch {
				bad = append(bad, fmt.Sprintf("%s(%s)", n.NodeName, n.LastSyncResult))
			}
		}
		if len(bad) > 0 {
			return fmt.Errorf("应用 %v 的 JWT 信任策略为 PROTECT，但目标节点 %v 存在已知同步失败，拒绝发布以防静默降级",
				protectApps, bad)
		}
		return nil
	}
}
