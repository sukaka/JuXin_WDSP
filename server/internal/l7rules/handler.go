package l7rules

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是 L7 访问控制规则处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 规则列表（含近 24h 命中数）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f, ok := listFilterFrom(w, r)
	if !ok {
		return
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []Rule{}
	}
	if err := h.fillHitCounts(r, list); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 规则详情（含近 24h 命中数）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	rules := []Rule{*rule}
	if err := h.fillHitCounts(r, rules); err != nil {
		response.InternalError(w, r, err)
		return
	}
	rule.HitCount24h = rules[0].HitCount24h
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// ruleRequest 是新建/编辑请求体。编辑（PATCH）为全量更新语义：字段缺失按默认值处理。
type ruleRequest struct {
	Name         string        `json:"name"`
	Priority     *int          `json:"priority"`
	Enabled      *bool         `json:"enabled"`
	Conditions   []Condition   `json:"conditions"`
	Action       string        `json:"action"`
	ActionConfig *ActionConfig `json:"action_config"`
}

// toInput 转换为输入（填默认值：priority 0→100 由校验层处理；enabled 缺省 true）。
func (req *ruleRequest) toInput() RuleInput {
	in := RuleInput{
		Name:       req.Name,
		Conditions: req.Conditions,
		Action:     strings.ToLower(strings.TrimSpace(req.Action)),
		Enabled:    true,
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.Enabled != nil {
		in.Enabled = *req.Enabled
	}
	if req.ActionConfig != nil {
		in.ActionConfig = *req.ActionConfig
	}
	return in
}

// Create 新建规则（发布前不下发网关，即草稿语义）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 256*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	in := req.toInput()
	rule, err := h.store.Create(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", rule.ID.String(), rule.Name, "", ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// Update 编辑规则（全量更新：名称/优先级/启停/条件/动作）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	cur, ok := h.getRule(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 256*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	in := req.toInput()
	rule, err := h.store.Update(r.Context(), cur.ID, in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", rule.ID.String(), rule.Name, ruleSummary(cur), ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// Delete 删除规则（二次确认由前端做）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if err := h.store.Delete(r.Context(), rule.ID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", rule.ID.String(), rule.Name, ruleSummary(rule), "deleted=true",
		audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已删除"})
}

// testRequest 是规则测试器输入。
type testRequest struct {
	URI      string            `json:"uri"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	Cookies  map[string]string `json:"cookies"`
	Query    map[string]string `json:"query"`
	ClientIP string            `json:"client_ip"`
}

// Test 规则测试器：以当前规则集（含停用，评估时跳过）纯函数评估输入，
// 不产生真实流量、不写事件。返回 {matched, rule_id, rule_name, action, reason}。
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if err := response.DecodeJSON(w, r, &req, 128*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	if err := validateTestInput(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	rules, err := h.store.ListAllOrdered(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	ev, err := NewEvaluator(rules)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	result := ev.Eval(Input{
		URI:      req.URI,
		Method:   req.Method,
		Headers:  req.Headers,
		Cookies:  req.Cookies,
		Query:    req.Query,
		ClientIP: req.ClientIP,
	})
	out := map[string]interface{}{
		"matched":   result.Matched,
		"rule_id":   "",
		"rule_name": "",
		"action":    "",
		"reason":    result.Reason,
	}
	if result.Rule != nil {
		out["rule_id"] = result.Rule.ID.String()
		out["rule_name"] = result.Rule.Name
		out["action"] = result.Rule.Action
	}
	response.JSON(w, r, http.StatusOK, out)
}

// validateTestInput 校验测试器输入（URI 以 / 开头、方法白名单、IP 合法、键值不含控制字符）。
func validateTestInput(req *testRequest) error {
	req.URI = strings.TrimSpace(req.URI)
	if req.URI == "" || req.URI[0] != '/' {
		return fmt.Errorf("URI必须以 / 开头")
	}
	if len(req.URI) > 2048 {
		return fmt.Errorf("URI长度不能超过2048字符")
	}
	if hasControlChar(req.URI) {
		return fmt.Errorf("URI含控制字符")
	}
	if req.Method != "" && !validMethods[strings.ToUpper(strings.TrimSpace(req.Method))] {
		return fmt.Errorf("无效的请求方法: %s", req.Method)
	}
	if ip := strings.TrimSpace(req.ClientIP); ip != "" {
		if err := validateTestIP(ip); err != nil {
			return err
		}
	}
	for label, m := range map[string]map[string]string{"请求头": req.Headers, "Cookie": req.Cookies, "Query参数": req.Query} {
		if len(m) > MaxValues {
			return fmt.Errorf("%s条目数不能超过%d个", label, MaxValues)
		}
		for k, v := range m {
			if k == "" || len(k) > MaxCondNameLen || hasControlChar(k) {
				return fmt.Errorf("%s名称非法: %s", label, k)
			}
			if len(v) > 8192 || hasControlChar(v) {
				return fmt.Errorf("%s %s 的值非法（长度超限或含控制字符）", label, k)
			}
		}
	}
	return nil
}

// validateTestIP 校验测试器来源 IP（单 IP，不支持 CIDR；复用黑白名单的严格解析口径）。
func validateTestIP(ip string) error {
	if strings.Contains(ip, "/") {
		return fmt.Errorf("来源IP必须是单个IP地址，不支持CIDR: %s", ip)
	}
	if _, _, err := accessrules.NormalizeAddress(ip); err != nil {
		return fmt.Errorf("无效的来源IP: %s", ip)
	}
	return nil
}

// ---------- 辅助 ----------

// getRule 解析路径 ID 并查询规则，失败时已写出响应，返回 ok=false。
func (h *Handler) getRule(w http.ResponseWriter, r *http.Request) (*Rule, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return nil, false
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return nil, false
	}
	return rule, true
}

// fillHitCounts 填充规则近 24h 命中数。
func (h *Handler) fillHitCounts(r *http.Request, rules []Rule) error {
	ids := make([]uuid.UUID, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, rule.ID)
	}
	counts, err := h.store.HitCounts24h(r.Context(), ids, time.Now().Add(-24*time.Hour))
	if err != nil {
		return err
	}
	for i := range rules {
		rules[i].HitCount24h = counts[rules[i].ID]
	}
	return nil
}

// writeStoreError 将仓储错误映射为 HTTP 响应。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
	case errors.Is(err, ErrTooManyRules):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	case errors.Is(err, ErrInvalidInput):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName,
	before, after, result, failureReason, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "access_control",
		Action:        action,
		ObjectType:    "l7_access_rule",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// listFilterFrom 解析列表查询参数；enabled 非法值返回 400（不静默忽略）。
func listFilterFrom(w http.ResponseWriter, r *http.Request) (ListFilter, bool) {
	f := ListFilter{
		Keyword:  r.URL.Query().Get("keyword"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("enabled"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "enabled 参数必须为 true 或 false")
			return f, false
		}
		f.Enabled = &b
	}
	return f, true
}

// ruleSummary 生成审计摘要（不含自定义页面正文，避免审计膨胀）。
func ruleSummary(r *Rule) string {
	return fmt.Sprintf(`{"name":%q,"priority":%d,"enabled":%t,"conditions":%d,"action":%q}`,
		r.Name, r.Priority, r.Enabled, len(r.Conditions), r.Action)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
