// handler.go 安全回归证据登记管理面接口（WDSP P1-04 R3；任务书 §7.1 六个 API
// + 受控对象登记上传端点；路由在 app.go 注册，鉴权/CSRF/响应封装/审计沿用现有惯例）：
//
//	GET  /api/v1/security/regressions                  分页（候选指纹/级别/状态/时间过滤；默认 20 最多 100）
//	GET  /api/v1/security/regressions/{id}             摘要 + 门禁可用性评估理由
//	GET  /api/v1/security/regressions/{id}/cases       用例索引分页（不含原始正文）
//	POST /api/v1/security/regressions/imports          通过已登记受控对象 ID 登记已签名报告
//	GET  /api/v1/security/regression-policy            门禁模式/要求级别/语料/有效期
//	PUT  /api/v1/security/regression-policy            expected_version 乐观锁，冲突 409，留审计
//	POST /api/v1/security/regression-objects?kind=...  受控对象登记上传（流式哈希 + 类别限额；
//	      任务书 §7.1「优先复用 P0-01 证据存储；如不存在，提供双方共用的受控本地存储
//	      适配器」——P0-01 服务端存储不存在（S0 协调表），本端点即受控写入登记接口，
//	      属上述「最小管理 API」的存储适配器通道，不执行任何测试命令）
package regression

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 安全回归处理器。
type Handler struct {
	store    *Store
	evidence *LocalEvidenceStore
	importer *Importer
	audits   *audits.Service
	now      func() time.Time
}

// NewHandler 创建处理器。
func NewHandler(store *Store, evidence *LocalEvidenceStore, importer *Importer, au *audits.Service) *Handler {
	return &Handler{store: store, evidence: evidence, importer: importer, audits: au, now: time.Now}
}

// ---------- 分页参数 ----------

func pageParams(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

// ---------- GET /api/v1/security/regressions ----------

// List 分页查询（fingerprint/level/status/since/until 过滤）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, size := pageParams(r)
	f := ListFilter{Page: page, PageSize: size}
	if v := r.URL.Query().Get("fingerprint"); v != "" {
		f.Fingerprint = v
	}
	if v := strings.ToUpper(r.URL.Query().Get("level")); v != "" {
		switch v {
		case LevelSmoke, LevelFull, LevelRelease:
			f.Level = v
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的运行级别")
			return
		}
	}
	if v := strings.ToUpper(r.URL.Query().Get("status")); v != "" {
		switch v {
		case VerifyPending, VerifyPassed, VerifyFailed:
			f.Status = v
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的核验状态")
			return
		}
	}
	for _, p := range []struct {
		name string
		slot **time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := r.URL.Query().Get(p.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的时间参数 "+p.name)
				return
			}
			*p.slot = &t
		}
	}
	items, total, err := h.store.ListRuns(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, size)
}

// ---------- GET /api/v1/security/regressions/{id} ----------

// Get 运行摘要 + 门禁可用性评估（按当前策略实时评估，给出可比较状态与理由，
// 不产生判定留痕）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的运行 ID")
		return
	}
	run, err := h.store.GetRun(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "回归运行不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	assessment, aerr := h.assess(r.Context(), run)
	if aerr != nil {
		response.InternalError(w, r, aerr)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"run":             run,
		"gate_assessment": assessment,
	})
}

// assess 按当前门禁策略评估某运行对「其绑定指纹」的可用性（只读评估，不留痕）。
func (h *Handler) assess(ctx context.Context, run *Run) (map[string]any, error) {
	policy, err := h.store.GetPolicy(ctx)
	if err != nil {
		return nil, err
	}
	var reasons []string
	usable := run.VerificationStatus == VerifyPassed
	if run.VerificationStatus != VerifyPassed {
		reasons = append(reasons, "服务端核验未通过")
	}
	if levelRank(run.Level) < levelRank(policy.RequiredLevel) {
		usable = false
		reasons = append(reasons, fmt.Sprintf("级别 %s 低于门禁要求 %s", run.Level, policy.RequiredLevel))
	}
	if policy.RequiredCorpusID != "" && run.CorpusID != policy.RequiredCorpusID {
		usable = false
		reasons = append(reasons, "语料与门禁要求不一致")
	}
	if run.DeclaredStatus != StatusPass {
		usable = false
		reasons = append(reasons, "回归声明状态非 PASS")
	}
	if run.Counts.Executed == 0 {
		usable = false
		reasons = append(reasons, "执行数为 0")
	}
	if run.Counts.MandatoryFailed > 0 {
		usable = false
		reasons = append(reasons, fmt.Sprintf("强制用例未全部通过（%d）", run.Counts.MandatoryFailed))
	}
	age := h.now().Sub(run.CreatedAt)
	expired := policy.EvidenceMaxAgeSeconds > 0 && age > time.Duration(policy.EvidenceMaxAgeSeconds)*time.Second
	if expired {
		usable = false
		reasons = append(reasons, "证据已超有效期")
	}
	return map[string]any{
		"usable_for_publish":       usable,
		"reasons":                  reasons,
		"policy_mode":              policy.Mode,
		"required_level":           policy.RequiredLevel,
		"evidence_max_age_seconds": policy.EvidenceMaxAgeSeconds,
		"age_seconds":              int64(age.Seconds()),
		"expired":                  expired,
	}, nil
}

// ---------- GET /api/v1/security/regressions/{id}/cases ----------

// ListCases 用例索引分页（status 过滤；禁止一次返回全部——分页上限 100）。
func (h *Handler) ListCases(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的运行 ID")
		return
	}
	if _, err := h.store.GetRun(r.Context(), id); errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "回归运行不存在")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	status := strings.ToUpper(r.URL.Query().Get("status"))
	if status != "" {
		switch status {
		case StatusPass, StatusFail, StatusSkip, StatusBlocked, StatusNotRun:
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的用例状态")
			return
		}
	}
	page, size := pageParams(r)
	items, total, err := h.store.ListCases(r.Context(), id, status, page, size)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, size)
}

// ---------- POST /api/v1/security/regressions/imports ----------

// Import 登记已签名报告（security_regression.import；核验失败 400 带逐项理由
// 且不落库，冲突 409 记失败审计，成功 201/幂等 200）。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ImportRequest
	if err := response.DecodeJSON(w, r, &req, MaxImportRequestBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	result, reasons, err := h.importer.Import(r.Context(), req, p.Username)
	switch {
	case err != nil && errors.Is(err, ErrConflict):
		h.recordAudit(r, p, "import", "security_regression_run", "", "",
			"", "run_id 冲突: "+err.Error(), audits.ResultFailure, err.Error(), audits.RiskMedium)
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同 run_id 已登记不同内容的报告")
		return
	case err != nil:
		response.InternalError(w, r, err)
		return
	case reasons != nil:
		h.recordAudit(r, p, "import", "security_regression_run", "", "",
			"", "核验拒绝: "+strings.Join(reasons, "; "), audits.ResultFailure,
			strings.Join(reasons, "; "), audits.RiskHigh)
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"报告核验未通过，未登记", reasons)
		return
	}
	run := result.Run
	summary := fmt.Sprintf("run_id=%s level=%s declared=%s verification=%s key_id=%s fingerprint=%s",
		run.RunID, run.Level, run.DeclaredStatus, run.VerificationStatus, run.SignatureKeyID, run.ConfigFingerprint)
	h.recordAudit(r, p, "import", "security_regression_run", run.ID.String(), run.RunID,
		"", summary, audits.ResultSuccess, "", audits.RiskMedium)
	status := http.StatusCreated
	if result.Idempotent {
		status = http.StatusOK
	}
	response.JSON(w, r, status, result)
}

// ---------- GET/PUT /api/v1/security/regression-policy ----------

// GetPolicy 查询门禁策略。
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := h.store.GetPolicy(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"policy": policy})
}

// policyPutRequest 门禁策略修改请求（无 skip_gate 类参数）。
type policyPutRequest struct {
	Mode                  string `json:"mode"`
	RequiredLevel         string `json:"required_level"`
	RequiredCorpusID      string `json:"required_corpus_id"`
	EvidenceMaxAgeSeconds int64  `json:"evidence_max_age_seconds"`
	ExpectedVersion       int    `json:"expected_version"`
	Reason                string `json:"reason"`
}

// PutPolicy 修改门禁策略（security_regression.policy；启用/降级 ENFORCE 均为
// 高风险审计；expected_version 冲突 409）。
func (h *Handler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	before, err := h.store.GetPolicy(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var req policyPutRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Mode = strings.ToUpper(strings.TrimSpace(req.Mode))
	req.RequiredLevel = strings.ToUpper(strings.TrimSpace(req.RequiredLevel))
	var fe []FieldErrorItem
	switch req.Mode {
	case ModeOff, ModeObserve, ModeEnforce:
	default:
		fe = append(fe, FieldErrorItem{Field: "mode", Message: "非法门禁模式（OFF/OBSERVE/ENFORCE）"})
	}
	switch req.RequiredLevel {
	case LevelSmoke, LevelFull, LevelRelease:
	default:
		fe = append(fe, FieldErrorItem{Field: "required_level", Message: "非法要求级别（SMOKE/FULL/RELEASE）"})
	}
	if req.EvidenceMaxAgeSeconds < MinEvidenceMaxAge || req.EvidenceMaxAgeSeconds > MaxEvidenceMaxAge {
		fe = append(fe, FieldErrorItem{Field: "evidence_max_age_seconds",
			Message: fmt.Sprintf("有效期须在 %d~%d 秒之间", MinEvidenceMaxAge, MaxEvidenceMaxAge)})
	}
	if len(req.RequiredCorpusID) > 128 {
		fe = append(fe, FieldErrorItem{Field: "required_corpus_id", Message: "长度超限"})
	}
	if req.ExpectedVersion < 0 {
		fe = append(fe, FieldErrorItem{Field: "expected_version", Message: "不能为负"})
	}
	if strings.TrimSpace(req.Reason) == "" {
		fe = append(fe, FieldErrorItem{Field: "reason", Message: "变更理由不能为空"})
	}
	if len(fe) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", fe)
		return
	}
	// 并发冲突口径与 botpolicy 一致：当前版本与声明不符即 409
	if req.ExpectedVersion != before.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	next := &Policy{
		Mode:                  req.Mode,
		RequiredLevel:         req.RequiredLevel,
		RequiredCorpusID:      req.RequiredCorpusID,
		EvidenceMaxAgeSeconds: req.EvidenceMaxAgeSeconds,
	}
	if err := h.store.PutPolicy(r.Context(), next, req.ExpectedVersion, p.Username); err != nil {
		if errors.Is(err, ErrConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, err := h.store.GetPolicy(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	risk := audits.RiskHigh
	h.recordAudit(r, p, "update", "security_regression_policy", "1", "regression-policy",
		fmt.Sprintf("mode=%s required_level=%s version=%d", before.Mode, before.RequiredLevel, before.Version),
		fmt.Sprintf("mode=%s required_level=%s max_age=%d version=%d reason=%s",
			after.Mode, after.RequiredLevel, after.EvidenceMaxAgeSeconds, after.Version, req.Reason),
		audits.ResultSuccess, "", risk)
	response.JSON(w, r, http.StatusOK, map[string]any{"policy": after})
}

// ---------- POST /api/v1/security/regression-objects ----------

// UploadObject 受控对象登记上传（原始字节流；类别由 ?kind= 指定，服务端计算
// sha256 与大小，调用方无法声明；流式 + 类别限额，PERF 大对象不全量读入内存）。
func (h *Handler) UploadObject(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	kind := strings.ToUpper(r.URL.Query().Get("kind"))
	if !ValidKind(kind) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"非法的对象类别（MANIFEST/CASES_CHUNK/REPORT/PERF/LOG）")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, KindLimit(kind)+1)
	obj, err := h.evidence.Register(r.Context(), kind, p.Username, r.Body)
	if err != nil {
		if errors.Is(err, ErrObjectLimit) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "对象超过类别大小限额")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "upload", "security_regression_object", obj.ID.String(), kind,
		"", fmt.Sprintf("kind=%s sha256=%s size=%d", obj.Kind, obj.SHA256, obj.SizeBytes),
		audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusCreated, obj)
}

// ---------- 审计 ----------

// FieldErrorItem 校验错误项（与 botpolicy.FieldError 形状一致）。
type FieldErrorItem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// recordAudit 操作审计（仅记录摘要与引用，不记录任何对象内容）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName,
	before, after, result, failReason, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "security",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
