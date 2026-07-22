// chat_handler.go AI 安全助手会话与消息：多轮对话、SSE 流式输出、停止/重试/继续、反馈。
// 会话严格属主隔离；配额服务端强制；消息/用量/审计由本层落库（编排器不重复记账）。
package aihandlers

import (
	"context"
	"errors"
	"log/slog"
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

// sessionDTO 会话输出。
type sessionDTO struct {
	ID                uuid.UUID `json:"id"`
	Title             string    `json:"title"`
	Status            string    `json:"status"`
	ContextTokenCount int       `json:"context_token_count"`
}

func toSessionDTO(s *aiorchestrator.Session) sessionDTO {
	return sessionDTO{ID: s.ID, Title: s.Title, Status: s.Status, ContextTokenCount: s.ContextTokenCount}
}

// messageDTO 消息输出。
type messageDTO struct {
	ID        uuid.UUID `json:"id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

// SessionList 本人会话分页列表（include_archived 可选含归档）。
func (d *Deps) SessionList(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := d.Sessions.List(r.Context(), p.UserID, queryBool(r, "include_archived"), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out := make([]sessionDTO, 0, len(list))
	for i := range list {
		out = append(out, toSessionDTO(&list[i]))
	}
	response.Page(w, r, out, total, page, pageSize)
}

// SessionCreate 创建会话（title 可选）。
func (d *Deps) SessionCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		Title string `json:"title"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	title := strings.TrimSpace(req.Title)
	if len([]rune(title)) > 200 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "会话标题过长（≤200 字）")
		return
	}
	sess, err := d.Sessions.Create(r.Context(), p.UserID, title)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"session": toSessionDTO(sess)})
}

// SessionGet 会话详情（属主隔离）。
func (d *Deps) SessionGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"session": toSessionDTO(sess)})
}

// SessionPatch 重命名会话。
func (d *Deps) SessionPatch(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Title string `json:"title"`
	}
	if err := decodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	title := strings.TrimSpace(req.Title)
	if title == "" || len([]rune(title)) > 200 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "会话标题不能为空且不超过 200 字")
		return
	}
	if err := d.Sessions.Rename(r.Context(), sess.ID, title); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "会话已重命名"})
}

// SessionDelete 删除会话（含消息级联删除）。
func (d *Deps) SessionDelete(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	// 删除前停止正在运行的任务
	d.chat.stop(sess.ID)
	if err := d.Sessions.Delete(r.Context(), sess.ID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "会话已删除"})
}

// SessionArchive 归档会话（归档后不可继续对话）。
func (d *Deps) SessionArchive(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	if err := d.Sessions.Archive(r.Context(), sess.ID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "会话已归档"})
}

// MessageList 会话消息列表（limit 默认 50，最大 100，正序）。
func (d *Deps) MessageList(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	limit := queryInt(r, "limit", 50)
	msgs, err := d.Sessions.RecentMessages(r.Context(), sess.ID, limit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out := make([]messageDTO, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, messageDTO{ID: m.ID, Role: m.Role, Content: m.Content, CreatedAt: m.CreatedAt})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

// MessageSend 发送消息（SSE 流式输出任务步骤与结果）。
func (d *Deps) MessageSend(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	var req struct {
		Content string `json:"content"`
		// TaskType 预留字段：任务类型由服务端意图分类判定，不采信前端声明
		TaskType string `json:"task_type"`
	}
	if err := decodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "消息内容不能为空")
		return
	}
	if len([]rune(content)) > 4000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "消息内容过长（≤4000 字）")
		return
	}
	if sess.Status != "ACTIVE" {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "会话已归档，无法继续对话")
		return
	}
	d.runStream(w, r, sess, p, content, true)
}

// MessageRetry 重试：取最后一条用户消息重跑（SSE）。
func (d *Deps) MessageRetry(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	msgs, err := d.Sessions.RecentMessages(r.Context(), sess.ID, 50)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	content := ""
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			content = msgs[i].Content
			break
		}
	}
	if content == "" {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "会话中没有可重试的用户消息")
		return
	}
	d.runStream(w, r, sess, p, content, false)
}

// MessageContinue 继续输出：最后一条 assistant 回复中断时以「请继续」续跑（SSE）。
func (d *Deps) MessageContinue(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	msgs, err := d.Sessions.RecentMessages(r.Context(), sess.ID, 1)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if len(msgs) == 0 || msgs[len(msgs)-1].Role != "assistant" {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "仅最后一条助手回复后可继续输出")
		return
	}
	d.runStream(w, r, sess, p, "请继续", true)
}

// MessageStop 停止会话正在运行的任务。
func (d *Deps) MessageStop(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.loadOwnedSession(w, r)
	if !ok {
		return
	}
	if !d.chat.stop(sess.ID) {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "当前会话没有正在运行的分析任务")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "已发送停止信号"})
}

// MessageFeedback 消息反馈（点赞/点踩；校验消息所属会话属主）。
func (d *Deps) MessageFeedback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	mid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的消息ID")
		return
	}
	var req struct {
		Rating       int    `json:"rating"`
		FeedbackType string `json:"feedback_type"`
		Comment      string `json:"comment"`
	}
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Rating != 1 && req.Rating != -1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "rating 仅支持 1（有用）或 -1（无用）")
		return
	}
	switch req.FeedbackType {
	case "", "GENERAL", "WRONG_FACT", "MISSING_EVIDENCE", "HALLUCINATION", "OTHER":
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的反馈类型")
		return
	}
	if req.FeedbackType == "" {
		req.FeedbackType = "GENERAL"
	}
	msg, sessID, err := d.Sessions.GetMessage(r.Context(), mid)
	if err != nil {
		if errors.Is(err, aiorchestrator.ErrSessionNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "消息不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return
	}
	_ = msg
	sess, err := d.Sessions.Get(r.Context(), *sessID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if sess.UserID != p.UserID {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "消息不存在")
		return
	}
	if err := d.Sessions.AddFeedback(r.Context(), sess.ID, mid, p.UserID, req.Rating, req.FeedbackType, trunc(req.Comment, 500)); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "反馈已记录"})
}

// runStream 执行一轮对话并以 SSE 流式输出。
// persistUser=true 时先把用户消息落库（retry 场景消息已存在，不重复落库）。
func (d *Deps) runStream(w http.ResponseWriter, r *http.Request, sess *aiorchestrator.Session, p *authz.Principal, content string, persistUser bool) {
	ctx := r.Context()
	// 配额检查（服务端强制，超限直接拒绝）
	est := aiorchestrator.EstimateTokens(content) + 512
	if err := d.Cost.CheckQuota(ctx, p.UserID, firstRole(p), est); err != nil {
		if errors.Is(err, aicost.ErrQuotaExceeded) {
			response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, "AI 用量配额超限，请明日再试或联系管理员")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	// 用户消息落库（SSE 响应开始前失败可按普通错误返回）
	if persistUser {
		if _, err := d.Sessions.AppendMessage(ctx, sess.ID, "user", content, nil, nil, est, 0, ""); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	// SSE 响应头
	flusher, ok := w.(http.Flusher)
	if !ok {
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "当前环境不支持流式输出")
		return
	}
	// 覆盖服务器 WriteTimeout（默认 30s 会掐断 LLM 推理期间的长静默流）：
	// 为本连接写入期限放宽到编排上限之外的充足窗口。
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Minute))
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	runCtx, cancel := context.WithCancel(ctx)
	seq := d.chat.register(sess.ID, cancel)
	defer d.chat.unregister(sess.ID, seq)
	defer cancel()

	onStep := func(s aiorchestrator.Step) error {
		return writeSSE(w, flusher, sseEvent{Type: s.Kind, Text: s.Text, Payload: s.Payload})
	}
	start := time.Now()
	result, err := d.Orch.Run(runCtx, aiorchestrator.RunInput{
		SessionID: sess.ID, UserID: p.UserID, Username: p.Username,
		RoleCodes: p.Roles, Permissions: p.PermsSet, Message: content,
	}, onStep)
	durMs := int(time.Since(start).Milliseconds())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			d.recordAIAudit(p, aiaudit.Record{
				SessionID: &sess.ID, Action: "chat", RequestSummary: trunc(content, 400),
				ResultSummary: "用户停止", DurationMs: durMs,
			})
			_ = writeSSE(w, flusher, sseEvent{Type: "done", Text: "已停止", Payload: map[string]interface{}{"finish_reason": "cancelled"}})
			return
		}
		slog.Error("ai run failed", "session_id", sess.ID, "error", err)
		d.recordAIAudit(p, aiaudit.Record{
			SessionID: &sess.ID, Action: "chat", RequestSummary: trunc(content, 400),
			ResultSummary: "执行失败", DurationMs: durMs,
		})
		_ = writeSSE(w, flusher, sseEvent{Type: "error", Text: "分析执行失败，请稍后重试"})
		return
	}
	// 结果落库（独立短超时 ctx：客户端断连也要保存已生成内容）
	pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pcancel()
	outTok := aiorchestrator.EstimateTokens(result.Answer)
	msgID, aErr := d.Sessions.AppendMessage(pctx, sess.ID, "assistant", result.Answer, nil, nil, 0, outTok, result.FinishReason)
	if aErr != nil {
		slog.Error("append assistant message failed", "session_id", sess.ID, "error", aErr)
	}
	// 用量记录（本地模型单价为 0，成本记 0；Token 为估算值）
	if uErr := d.Cost.RecordUsage(pctx, p.UserID, &sess.ID, &result.TaskID, nil, est, outTok, 0, 0); uErr != nil {
		slog.Error("record ai usage failed", "session_id", sess.ID, "error", uErr)
	}
	// 上下文超阈值自动压缩
	if compressed, cErr := d.Sessions.MaybeCompress(pctx, sess.ID, 0); cErr != nil {
		slog.Warn("ai context compress failed", "session_id", sess.ID, "error", cErr)
	} else if compressed {
		_ = writeSSE(w, flusher, sseEvent{Type: "compressed", Text: "会话上下文已自动压缩"})
	}
	d.recordAIAudit(p, aiaudit.Record{
		SessionID: &sess.ID, TaskID: &result.TaskID, Action: "chat",
		TaskType: string(result.Plan.TaskType), InputTokens: est, OutputTokens: outTok,
		DurationMs: durMs, RequestSummary: trunc(content, 400), ResultSummary: trunc(result.Answer, 800),
	})
	_ = writeSSE(w, flusher, sseEvent{Type: "done", Payload: map[string]interface{}{
		"task_id": result.TaskID, "message_id": msgID, "finish_reason": result.FinishReason,
	}})
}
