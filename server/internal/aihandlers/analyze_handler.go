// analyze_handler.go 一次性 AI 分析端点：构造模板消息调编排器（非流式），
// 使用一次性会话（用完即删，不污染会话列表）；事件/规则/IP 经消息文本由 ExtractIDs 提取。
// 结构化维度入参（时间范围/应用/IP/URI/规则/Request ID、画像对象、What-If 场景）的校验、
// 真实数据聚合与离线估算在 analyze_context.go。
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
	// 阶段7 §12.1/§15/§19 结构化扩展（全部可选，逐一校验见 validateAnalyzeStructured）
	TimeRange            string `json:"time_range"`             // 统计区间预设 1h/6h/24h/7d/30d
	ApplicationID        string `json:"application_id"`         // 应用维度过滤 / 应用画像
	URI                  string `json:"uri"`                    // URI 维度过滤 / URI 画像
	RequestID            string `json:"request_id"`             // 网关 Request ID 维度过滤
	Scenario             string `json:"scenario"`               // What-If 场景（§19.1 八种，见 analyze_context.go 白名单）
	CCThreshold          int64  `json:"cc_threshold"`           // What-If：模拟 CC 阈值（次/窗口）
	BlockDurationSeconds int64  `json:"block_duration_seconds"` // What-If：模拟封禁时长（秒）
	AnomalyThreshold     int64  `json:"anomaly_threshold"`      // What-If：模拟入站异常阈值
	ParanoiaLevel        int    `json:"paranoia_level"`         // What-If：模拟 CRS 执行等级（1-4）
	ExceptionID          string `json:"exception_id"`           // What-If remove_exception：模拟删除的例外 ID
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
	req.TimeRange = trunc(strings.TrimSpace(req.TimeRange), 10)
	req.ApplicationID = trunc(strings.TrimSpace(req.ApplicationID), 64)
	req.URI = trunc(strings.TrimSpace(req.URI), 200)
	if i := strings.IndexByte(req.URI, '?'); i >= 0 {
		req.URI = req.URI[:i]
	}
	req.RequestID = trunc(strings.TrimSpace(req.RequestID), 64)
	req.Scenario = trunc(strings.TrimSpace(req.Scenario), 32)
	req.ExceptionID = trunc(strings.TrimSpace(req.ExceptionID), 64)
	return &req, true
}

// validEventID 事件 ID 基础校验（UUID 形态，防注入异常文本进入模板）。
func validEventID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// AnalyzeEvent 安全事件 AI 分析（§12.1：支持时间范围/应用/IP/URI/规则/Request ID 维度入参）。
func (d *Deps) AnalyzeEvent(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	if verr := validateAnalyzeStructured(req); verr != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, verr)
		return
	}
	var runIn aiorchestrator.RunInput
	switch {
	case hasEventFilter(req):
		// 结构化维度过滤：按维度查询真实数据组装分析上下文；缺数据如实返回"数据不足"口径
		now := time.Now()
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "24h", now)
		summary, err := d.queryEventFilterSummary(r.Context(), req, start, end)
		if err != nil {
			slog.Error("ai analyze event filter query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		runIn = buildEventFilterRunInput(req, label, summary, now)
	case req.EventID != "":
		runIn = buildEventIDRunInput(req)
	case req.Question != "":
		runIn = buildEventQuestionRunInput(req)
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供事件ID、过滤维度（时间范围/应用/IP/URI/规则/Request ID）或分析问题")
		return
	}
	d.runAnalyze(w, r, "安全事件分析", runIn)
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
	d.runAnalyze(w, r, "误报研判", buildFalsePositiveRunInput(req, parts))
}

// AnalyzeAttackProfile 攻击画像（IP/URI/应用；§15.2/§15.3 URI 画像与应用画像为一等结构化入参）。
func (d *Deps) AnalyzeAttackProfile(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	if verr := validateAnalyzeStructured(req); verr != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, verr)
		return
	}
	var runIn aiorchestrator.RunInput
	switch {
	case req.IP != "":
		runIn = buildIPProfileRunInput(req, time.Now())
	case req.URI != "":
		// URI 画像：真实 SQL 聚合（事件分布/攻击类型/来源 IP/命中规则 Top）
		now := time.Now()
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "7d", now)
		profile, err := d.queryURIProfile(r.Context(), req.URI, start, end)
		if err != nil {
			slog.Error("ai uri profile query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		runIn = buildURIProfileRunInput(req, label, profile, now)
	case req.ApplicationID != "":
		// 应用画像：真实 SQL 聚合（应用维度同理）
		now := time.Now()
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "7d", now)
		profile, err := d.queryAppProfile(r.Context(), req.ApplicationID, start, end)
		if err != nil {
			slog.Error("ai application profile query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		runIn = buildAppProfileRunInput(req, label, profile, now)
	case req.Question != "":
		runIn = buildProfileQuestionRunInput(req)
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供IP、URI、应用ID或画像问题")
		return
	}
	d.runAnalyze(w, r, "攻击画像", runIn)
}

// AnalyzeAttackChain 攻击链关联分析。
func (d *Deps) AnalyzeAttackChain(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	switch {
	case req.IP != "":
		if net.ParseIP(req.IP) == nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的IP地址")
			return
		}
	case req.EventID != "":
		if !validEventID(req.EventID) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
			return
		}
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供IP或事件ID")
		return
	}
	d.runAnalyze(w, r, "攻击链分析", buildAttackChainRunInput(req))
}

// AnalyzePolicyRecommendation 策略优化建议。
func (d *Deps) AnalyzePolicyRecommendation(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	d.runAnalyze(w, r, "策略优化建议", buildPolicyRecommendationRunInput(req))
}

// AnalyzeWhatIf What-If 策略模拟（§19 八种场景：停用/启用规则、异常阈值、PL 切换、
// 新增/删除例外、CC 阈值、封禁时长；均基于历史事件数据离线统计估算，非逐请求回放引擎）。
func (d *Deps) AnalyzeWhatIf(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	if verr := validateAnalyzeStructured(req); verr != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, verr)
		return
	}
	scenario := req.Scenario
	if scenario == "" {
		scenario = whatIfScenarioDisableRule
	}
	msg := ""
	defPreset := "30d"
	switch scenario {
	case whatIfScenarioDisableRule:
		if req.RuleID <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供要模拟的规则ID")
			return
		}
		msg = "如果关闭规则 " + itoa(req.RuleID) + " 会有什么影响？请做 What-If 模拟，估算受影响请求、误报减少与漏拦风险"
	case whatIfScenarioEnableRule:
		if req.RuleID <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供要模拟启用的规则ID")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "30d", time.Now())
		s, err := d.queryRuleEnableSummary(r.Context(), req.RuleID, start, end)
		if err != nil {
			slog.Error("ai what-if enable rule query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildEnableRuleContext(label, s)
	case whatIfScenarioAnomalyThreshold:
		defPreset = "7d"
		if req.AnomalyThreshold <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供模拟的异常阈值（anomaly_threshold，1-10000）")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "7d", time.Now())
		data, err := d.queryAnomalyThresholdData(r.Context(), start, end)
		if err != nil {
			slog.Error("ai what-if anomaly samples query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildAnomalyThresholdContext(label, req.AnomalyThreshold, data.RefMin, data.RefMax,
			estimateAnomalyThreshold(data.Samples, req.AnomalyThreshold))
	case whatIfScenarioPLSwitch:
		if req.ParanoiaLevel < 1 || req.ParanoiaLevel > 4 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供模拟的执行等级（paranoia_level，1-4）")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "30d", time.Now())
		s, err := d.queryPLSwitchSummary(r.Context(), start, end)
		if err != nil {
			slog.Error("ai what-if pl summary query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildPLSwitchContext(label, req.ParanoiaLevel, s)
	case whatIfScenarioAddException:
		if req.RuleID <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供例外目标规则ID（rule_id，可选 application_id/uri 收敛范围）")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "30d", time.Now())
		where, args := eventFilterWhere(req, start, end)
		s, err := d.queryExceptionImpact(r.Context(), where, args, req.URI == "", req.ApplicationID == "")
		if err != nil {
			slog.Error("ai what-if add exception query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildAddExceptionContext(label, describeEventFilterDims(req), s)
	case whatIfScenarioRemoveException:
		if req.ExceptionID == "" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供要模拟删除的例外ID（exception_id）")
			return
		}
		exc, err := d.queryExceptionScope(r.Context(), req.ExceptionID)
		if err != nil {
			slog.Error("ai what-if exception scope query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		if !exc.Found {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "例外不存在或已删除")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "30d", time.Now())
		where, args := exceptionScopeWhere(exc, start, end)
		s, err := d.queryExceptionImpact(r.Context(), where, args, exc.URIExact == "" && exc.URIPrefix == "", exc.AppID == "")
		if err != nil {
			slog.Error("ai what-if remove exception query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildRemoveExceptionContext(label, exc, s)
	case whatIfScenarioCCThreshold:
		defPreset = "7d"
		if req.CCThreshold <= 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供模拟的 CC 阈值（cc_threshold，次/窗口）")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "7d", time.Now())
		samples, err := d.queryCCThresholdSamples(r.Context(), start, end)
		if err != nil {
			slog.Error("ai what-if cc samples query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildCCThresholdContext(label, req.CCThreshold, estimateCCThreshold(samples, req.CCThreshold))
	case whatIfScenarioBlockDuration:
		defPreset = "7d"
		if req.BlockDurationSeconds < 60 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供模拟的封禁时长（block_duration_seconds，60-2592000 秒）")
			return
		}
		start, end, label, _ := parseAnalyzeTimeRange(req.TimeRange, "7d", time.Now())
		samples, err := d.queryBlockSamples(r.Context(), start, end)
		if err != nil {
			slog.Error("ai what-if block samples query failed", "error", err)
			response.InternalError(w, r, err)
			return
		}
		msg = buildBlockDurationContext(label, time.Duration(req.BlockDurationSeconds)*time.Second,
			estimateBlockDuration(samples, time.Duration(req.BlockDurationSeconds)*time.Second))
	}
	d.runAnalyze(w, r, "What-If 模拟", buildWhatIfRunInput(req, msg, defPreset, time.Now()))
}

// AnalyzeRootCause 运行异常根因分析。
func (d *Deps) AnalyzeRootCause(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	d.runAnalyze(w, r, "根因分析", buildRootCauseRunInput(req))
}

func sliceIfNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func intSliceIfPos(n int) []int {
	if n <= 0 {
		return nil
	}
	return []int{n}
}

func explicitAnalyzeTimeRange(preset, defPreset string, now time.Time) aiorchestrator.QueryTimeRange {
	start, end, label, err := parseAnalyzeTimeRange(preset, defPreset, now)
	if err != nil {
		return aiorchestrator.QueryTimeRange{}
	}
	return aiorchestrator.QueryTimeRange{
		Start:    start,
		End:      end,
		Label:    label,
		Explicit: true,
	}
}

func buildEventFilterRunInput(req *analyzeRequest, label string, summary *eventFilterSummary, now time.Time) aiorchestrator.RunInput {
	return aiorchestrator.RunInput{
		Message:       buildEventFilterContext(req, label, summary),
		TaskType:      aiorchestrator.TaskEventAnalysis,
		StructuredIDs: true,
		EventIDs:      sliceIfNonEmpty(req.EventID),
		RuleIDs:       intSliceIfPos(req.RuleID),
		IPs:           sliceIfNonEmpty(req.IP),
		URI:           req.URI,
		ApplicationID: req.ApplicationID,
		TimeRange:     explicitAnalyzeTimeRange(req.TimeRange, "24h", now),
	}
}

func buildEventIDRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	return aiorchestrator.RunInput{
		Message:       buildEventIDAnalyzeMessage(req),
		TaskType:      aiorchestrator.TaskEventAnalysis,
		StructuredIDs: true,
		EventIDs:      []string{req.EventID},
	}
}

func buildEventQuestionRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	return aiorchestrator.RunInput{
		Message:       "请分析安全事件：" + req.Question,
		TaskType:      aiorchestrator.TaskEventAnalysis,
		StructuredIDs: false,
	}
}

func buildFalsePositiveRunInput(req *analyzeRequest, parts []string) aiorchestrator.RunInput {
	if len(parts) == 0 {
		if req.EventID != "" {
			parts = append(parts, "事件 "+req.EventID)
		}
		if req.RuleID > 0 {
			parts = append(parts, "规则 "+itoa(req.RuleID))
		}
	}
	return aiorchestrator.RunInput{
		Message:       "请对以下对象做误报研判：" + strings.Join(parts, "，") + "，给出误报可能性、推荐例外范围与验证方法",
		TaskType:      aiorchestrator.TaskFalsePositive,
		StructuredIDs: true,
		EventIDs:      sliceIfNonEmpty(req.EventID),
		RuleIDs:       intSliceIfPos(req.RuleID),
	}
}

func buildIPProfileRunInput(req *analyzeRequest, now time.Time) aiorchestrator.RunInput {
	var tr aiorchestrator.QueryTimeRange
	if req.TimeRange != "" {
		tr = explicitAnalyzeTimeRange(req.TimeRange, "7d", now)
	}
	return aiorchestrator.RunInput{
		Message:       buildIPProfileMessage(req),
		TaskType:      aiorchestrator.TaskAttackProfile,
		StructuredIDs: true,
		IPs:           []string{req.IP},
		TimeRange:     tr,
	}
}

func buildURIProfileRunInput(req *analyzeRequest, label string, profile *uriProfileSummary, now time.Time) aiorchestrator.RunInput {
	msg := buildURIProfileContext(label, profile)
	if req.Question != "" {
		msg += "\n分析侧重点：" + req.Question
	}
	return aiorchestrator.RunInput{
		Message:       msg,
		TaskType:      aiorchestrator.TaskAttackProfile,
		StructuredIDs: true,
		URI:           req.URI,
		TimeRange:     explicitAnalyzeTimeRange(req.TimeRange, "7d", now),
	}
}

func buildAppProfileRunInput(req *analyzeRequest, label string, profile *appProfileSummary, now time.Time) aiorchestrator.RunInput {
	msg := buildAppProfileContext(label, profile)
	if req.Question != "" {
		msg += "\n分析侧重点：" + req.Question
	}
	return aiorchestrator.RunInput{
		Message:       msg,
		TaskType:      aiorchestrator.TaskAttackProfile,
		StructuredIDs: true,
		ApplicationID: req.ApplicationID,
		TimeRange:     explicitAnalyzeTimeRange(req.TimeRange, "7d", now),
	}
}

func buildProfileQuestionRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	return aiorchestrator.RunInput{
		Message:       "请做攻击画像分析：" + req.Question,
		TaskType:      aiorchestrator.TaskAttackProfile,
		StructuredIDs: false,
	}
}

func buildAttackChainRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	msg := ""
	var ips, eventIDs []string
	if req.IP != "" {
		msg = "请对 IP " + req.IP + " 做攻击链关联分析，输出攻击时间线、阶段、置信度与排查建议"
		ips = []string{req.IP}
	} else if req.EventID != "" {
		msg = "请对事件 " + req.EventID + " 做攻击链关联分析（提取同源IP的连续攻击行为）"
		eventIDs = []string{req.EventID}
	}
	return aiorchestrator.RunInput{
		Message:       msg,
		TaskType:      aiorchestrator.TaskAttackChain,
		StructuredIDs: true,
		IPs:           ips,
		EventIDs:      eventIDs,
	}
}

func buildPolicyRecommendationRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	msg := "请基于最近事件与误报统计，给出 WAF 策略优化建议（阈值、例外收敛、规则启停），不得建议直接关闭高风险规则"
	if req.Question != "" {
		msg += "；关注点：" + req.Question
	}
	return aiorchestrator.RunInput{
		Message:       msg,
		TaskType:      aiorchestrator.TaskPolicyRec,
		StructuredIDs: false,
	}
}

func buildWhatIfRunInput(req *analyzeRequest, msg, defPreset string, now time.Time) aiorchestrator.RunInput {
	var tr aiorchestrator.QueryTimeRange
	if req.TimeRange != "" {
		tr = explicitAnalyzeTimeRange(req.TimeRange, defPreset, now)
	}
	return aiorchestrator.RunInput{
		Message:       msg,
		TaskType:      aiorchestrator.TaskWhatIf,
		StructuredIDs: true,
		RuleIDs:       intSliceIfPos(req.RuleID),
		URI:           req.URI,
		ApplicationID: req.ApplicationID,
		TimeRange:     tr,
	}
}

func buildRootCauseRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	q := req.Question
	if q == "" {
		q = "当前系统运行状态"
	}
	return aiorchestrator.RunInput{
		Message:       "请做根因分析：" + q + "，结合组件健康、系统告警与最近发布记录，区分已确认/高概率/待验证原因",
		TaskType:      aiorchestrator.TaskRootCause,
		StructuredIDs: false,
	}
}

// buildEventIDAnalyzeMessage 构造仅按事件 ID 分析的提示词；保持 EventID 在 Question 之前以保证 ExtractIDs 优先提取。
func buildEventIDAnalyzeMessage(req *analyzeRequest) string {
	msg := "请分析安全事件 " + req.EventID + "，给出攻击类型、命中规则、风险等级、是否阻断与处置建议"
	if req.Question != "" {
		msg += "\n分析侧重点：" + req.Question
	}
	return msg
}

// buildIPProfileMessage 构造 IP 攻击画像提示词；保持 IP 在 Question 之前以保证 ExtractIDs 优先提取目标 IP。
func buildIPProfileMessage(req *analyzeRequest) string {
	msg := "请对 IP " + req.IP + " 做攻击画像分析，给出首次/最近出现、攻击类型、目标、阻断与封禁情况及处置建议"
	if req.Question != "" {
		msg += "\n分析侧重点：" + req.Question
	}
	return msg
}

// buildReportSummaryMessage 构造安全报告总结提示词，附加可选补充说明。
func buildReportSummaryMessage(req *analyzeRequest) string {
	period := req.Period
	if period == "" {
		period = "近7天"
	}
	msg := "请总结" + period + "安全运营情况，生成安全报告总结（事件、阻断、主要攻击类型、攻击源、例外与处置建议）"
	if req.Question != "" {
		msg += "\n补充说明：" + req.Question
	}
	return msg
}

func buildReportSummaryRunInput(req *analyzeRequest) aiorchestrator.RunInput {
	return aiorchestrator.RunInput{
		Message:       buildReportSummaryMessage(req),
		TaskType:      aiorchestrator.TaskReportSummary,
		StructuredIDs: true,
	}
}

// AnalyzeReportSummary AI 报告总结（日报/周报/月报摘要）。
func (d *Deps) AnalyzeReportSummary(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeAnalyze(w, r)
	if !ok {
		return
	}
	d.runAnalyze(w, r, "报告总结", buildReportSummaryRunInput(req))
}

// runAnalyze 一次性分析执行（非流式；一次性会话用完即删）。
func (d *Deps) runAnalyze(w http.ResponseWriter, r *http.Request, label string, runIn aiorchestrator.RunInput) {
	p := authz.PrincipalFrom(r.Context())
	ctx := r.Context()
	message := runIn.Message
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
	runIn.SessionID = sess.ID
	runIn.UserID = p.UserID
	runIn.Username = p.Username
	runIn.RoleCodes = p.Roles
	runIn.Permissions = p.PermsSet
	result, err := d.Orch.Run(ctx, runIn, onStep)
	durMs := int(time.Since(start).Milliseconds())
	if err != nil {
		if errors.Is(err, aicost.ErrQuotaExceeded) {
			d.recordAIAudit(p, aiaudit.Record{
				SessionID: &sess.ID, Action: "analyze", RequestSummary: trunc(message, 400),
				ResultSummary: "高成本任务配额超限", DurationMs: durMs,
			})
			response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, "高成本任务次数已达今日上限，请明日再试或联系管理员")
			return
		}
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
		"task_id":  result.TaskID,
		"answer":   result.Answer,
		"plan":     result.Plan,
		"steps":    steps,
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
