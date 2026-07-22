// analyze_handler.go 一次性 AI 分析端点：构造模板消息调编排器（非流式），
// 使用一次性会话（用完即删，不污染会话列表）；事件/规则/IP 经消息文本由 ExtractIDs 提取。
package aihandlers

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aicost"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// analyzeRequest 分析请求（各端点按需取用字段）。
type analyzeRequest struct {
	EventID  string `json:"event_id"`
	RuleID   int    `json:"rule_id"`
	IP       string `json:"ip"`
	Question string `json:"question"`
	Period   string `json:"period"`
}

func decodeAnalyze(w http.ResponseWriter, r *http.Request) (*analyzeRequest, bool) {
	var req analyzeRequest
	if err := decodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return nil, false
	}
	req.EventID = trunc(strings.TrimSpace(req.EventID), 64)
	req.Question = trunc(strings.TrimSpace(req.Question), 1000)
	req.IP = strings.TrimSpace(req.IP)
	req.Period = trunc(strings.TrimSpace(req.Period), 50)
	return &req, true
}

// validEventID 事件 ID 基础校验（UUID 形态，防注入异常文本进入模板）。
func validEventID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// AnalyzeEvent 安全事件 AI 分析。
func (d *Deps) AnalyzeEvent(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	msg := ""
	switch {
	case req.EventID != "":
		if !validEventID(req.EventID) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
			return
		}
		msg = "请分析安全事件 " + req.EventID + "，给出攻击类型、命中规则、风险等级、是否阻断与处置建议"
	case req.Question != "":
		msg = "请分析安全事件：" + req.Question
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供事件ID或分析问题")
		return
	}
	d.runAnalyze(w, r, msg, "安全事件分析")
}

// AnalyzeFalsePositive 误报 AI 研判。
func (d *Deps) AnalyzeFalsePositive(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	var parts []string
	if req.EventID != "" {
		if !validEventID(req.EventID) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
			return
		}
		parts = append(parts, "事件 "+req.EventID)
	}
	if req.RuleID > 0 {
		parts = append(parts, "规则 "+itoa(req.RuleID))
	}
	if len(parts) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供事件ID或规则ID")
		return
	}
	msg := "请对以下对象做误报研判：" + strings.Join(parts, "，") + "，给出误报可能性、推荐例外范围与验证方法"
	d.runAnalyze(w, r, msg, "误报研判")
}

// AnalyzeAttackProfile 攻击画像（IP/URI/应用）。
func (d *Deps) AnalyzeAttackProfile(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	msg := ""
	switch {
	case req.IP != "":
		if net.ParseIP(req.IP) == nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的IP地址")
			return
		}
		msg = "请对 IP " + req.IP + " 做攻击画像分析，给出首次/最近出现、攻击类型、目标、阻断与封禁情况及处置建议"
	case req.Question != "":
		msg = "请做攻击画像分析：" + req.Question
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供IP或画像问题")
		return
	}
	d.runAnalyze(w, r, msg, "攻击画像")
}

// AnalyzeAttackChain 攻击链关联分析。
func (d *Deps) AnalyzeAttackChain(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	msg := ""
	switch {
	case req.IP != "":
		if net.ParseIP(req.IP) == nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的IP地址")
			return
		}
		msg = "请对 IP " + req.IP + " 做攻击链关联分析，输出攻击时间线、阶段、置信度与排查建议"
	case req.EventID != "":
		if !validEventID(req.EventID) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
			return
		}
		msg = "请对事件 " + req.EventID + " 做攻击链关联分析（提取同源IP的连续攻击行为）"
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供IP或事件ID")
		return
	}
	d.runAnalyze(w, r, msg, "攻击链分析")
}

// AnalyzePolicyRecommendation 策略优化建议。
func (d *Deps) AnalyzePolicyRecommendation(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	msg := "请基于最近事件与误报统计，给出 WAF 策略优化建议（阈值、例外收敛、规则启停），不得建议直接关闭高风险规则"
	if req.Question != "" {
		msg += "；关注点：" + req.Question
	}
	d.runAnalyze(w, r, msg, "策略优化建议")
}

// AnalyzeWhatIf What-If 策略模拟（基于历史数据估算）。
func (d *Deps) AnalyzeWhatIf(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	if req.RuleID <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供要模拟的规则ID")
		return
	}
	msg := "如果关闭规则 " + itoa(req.RuleID) + " 会有什么影响？请做 What-If 模拟，估算受影响请求、误报减少与漏拦风险"
	d.runAnalyze(w, r, msg, "What-If 模拟")
}

// AnalyzeRootCause 运行异常根因分析。
func (d *Deps) AnalyzeRootCause(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	q := req.Question
	if q == "" {
		q = "当前系统运行状态"
	}
	msg := "请做根因分析：" + q + "，结合组件健康、系统告警与最近发布记录，区分已确认/高概率/待验证原因"
	d.runAnalyze(w, r, msg, "根因分析")
}

// AnalyzeReportSummary AI 报告总结（日报/周报/月报摘要）。
func (d *Deps) AnalyzeReportSummary(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	period := req.Period
	if period == "" {
		period = "近7天"
	}
	msg := "请总结" + period + "安全运营情况，生成安全报告总结（事件、阻断、主要攻击类型、攻击源、误报与建议）"
	d.runAnalyze(w, r, msg, "报告总结")
}

// runAnalyze 一次性分析执行（非流式；一次性会话用完即删）。
func (d *Deps) runAnalyze(w http.ResponseWriter, r *http.Request, message, label string) {
	p := authz.PrincipalFrom(r.Context())
	ctx := r.Context()
	// 编排最长 120s + LLM 推理可能超过服务器 WriteTimeout（默认 30s），放宽本请求写期限
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	}
	// 配额检查
	est := aiorchestrator.EstimateTokens(message) + 512
	if err := d.Cost.CheckQuota(ctx, p.UserID, firstRole(p), est); err != nil {
		if errors.Is(err, aicost.ErrQuotaExceeded) {
			response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, "AI 用量配额超限，请明日再试或联系管理员")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	// 一次性会话（分析结果随响应返回，会话用完即删；审计保留 session_id 文本）
	sess, err := d.Sessions.Create(ctx, p.UserID, "[一次性分析] "+label)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dcancel()
		if err := d.Sessions.Delete(dctx, sess.ID); err != nil {
			slog.Warn("delete ephemeral ai session failed", "session_id", sess.ID, "error", err)
		}
	}()
	// 收集执行步骤（上限 100 条）
	steps := make([]sseEvent, 0, 16)
	onStep := func(s aiorchestrator.Step) error {
		if len(steps) < 100 {
			steps = append(steps, sseEvent{Type: s.Kind, Text: s.Text, Payload: s.Payload})
		}
		return nil
	}
	start := time.Now()
	result, err := d.Orch.Run(ctx, aiorchestrator.RunInput{
		SessionID: sess.ID, UserID: p.UserID, Username: p.Username,
		RoleCodes: p.Roles, Permissions: p.PermsSet, Message: message,
	}, onStep)
	durMs := int(time.Since(start).Milliseconds())
	if err != nil {
		d.recordAIAudit(p, aiaudit.Record{
			SessionID: &sess.ID, Action: "analyze", RequestSummary: trunc(message, 400),
			ResultSummary: "执行失败", DurationMs: durMs,
		})
		slog.Error("ai analyze failed", "label", label, "error", err)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "分析执行失败，请稍后重试")
		return
	}
	outTok := aiorchestrator.EstimateTokens(result.Answer)
	pctx, pcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pcancel()
	if uErr := d.Cost.RecordUsage(pctx, p.UserID, &sess.ID, &result.TaskID, nil, est, outTok, 0, 0); uErr != nil {
		slog.Error("record ai usage failed", "error", uErr)
	}
	d.recordAIAudit(p, aiaudit.Record{
		SessionID: &sess.ID, TaskID: &result.TaskID, Action: "analyze",
		TaskType: string(result.Plan.TaskType), InputTokens: est, OutputTokens: outTok,
		DurationMs: durMs, RequestSummary: trunc(message, 400), ResultSummary: trunc(result.Answer, 800),
	})
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"task_id": result.TaskID,
		"answer":  result.Answer,
		"plan":    result.Plan,
		"steps":   steps,
		"evidence": result.Evidence,
	})
}

// itoa 小整数转字符串（避免引入 strconv 仅为一处使用）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
