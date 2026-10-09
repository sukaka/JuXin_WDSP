// handler.go gRPC 描述符集 CRUD（上传 protoset / 列表 / 删除；权限 api_spec.manage 复用）。
package apigrpcdesc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 描述符集名称护栏（唯一键；展示与网关观测证据 descriptor 字段直接引用）。
const (
	maxNameLen  = 128
	formFileKey = "file"
)

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 描述符集管理面处理器（含 per-app 绑定（NG-GRPC G1 批次 B1）——
// bindRepo 经 NewHandler 类型断言注入（Store 同时实现两接口；fake 可分别注入））。
type Handler struct {
	repo     Repository
	bindRepo BindingRepository
	audits   auditRecorder
}

// NewHandler 创建处理器（audit 为 nil 时跳过审计，不影响主流程；与 apisecurity 同一纪律）。
func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if br, ok := repo.(BindingRepository); ok {
		h.bindRepo = br
	}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// Upload POST /api/v1/api-security/grpc-descriptors
// multipart/form-data：file=protoset 文件（FileDescriptorSet 字节，≤1MiB），name=可选
// 描述符集名称（缺省取上传文件名去 .pb/.protoset/.bin 后缀）。线格式非法 400，
// 同名 409；上传即 ENABLED（v1 无启停接口，删除即下线）。写操作审计。
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, MaxContentBytes+64<<10) // 表单开销余量，文件本体在下方精确拦截
	if err := r.ParseMultipartForm(MaxContentBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"multipart 表单解析失败或请求体过大（文件上限 1MiB）")
		return
	}
	f, fh, err := r.FormFile(formFileKey)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少上传文件（表单字段 file）")
		return
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, MaxContentBytes+1))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取上传文件失败")
		return
	}
	if len(content) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "上传文件为空")
		return
	}
	if len(content) > MaxContentBytes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "描述符集文件超过 1MiB 上限")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" && fh != nil {
		name = defaultNameFromFile(fh.Filename)
	}
	if !validName(name) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"名称必填且为 1-128 字符（字母/数字/._- 与空白）")
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	d, err := h.repo.Create(r.Context(), name, content, createdBy)
	if err != nil {
		switch {
		case errors.Is(err, ErrDuplicateName):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同名描述符集已存在")
		case errors.Is(err, ErrBadDescriptorSet):
			slog.Warn("FileDescriptorSet 解析失败", "request_id", response.RequestIDFrom(r), "name", name, "error", err)
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"FileDescriptorSet 线格式非法，请上传 protoc --descriptor_set_out 生成的描述符集文件")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "create", "api_grpc_descriptor", d.ID.String(), d.Name, "",
		"size="+strconv.Itoa(d.SizeBytes)+" services="+strconv.Itoa(len(d.Services)), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, d)
}

// List GET /api/v1/api-security/grpc-descriptors（含服务/方法摘要，不携带 content 字节）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.repo.List(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// Delete DELETE /api/v1/api-security/grpc-descriptors/{id}（写操作审计）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "id 非法")
		return
	}
	if err := h.repo.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "描述符集不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_grpc_descriptor", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// defaultNameFromFile 从上传文件名推导缺省名称（去常见 protoset 后缀）。
func defaultNameFromFile(filename string) string {
	base := filename
	if i := strings.LastIndexAny(base, `/\\`); i >= 0 {
		base = base[i+1:]
	}
	for _, suffix := range []string{".pb", ".protoset", ".bin", ".fds"} {
		if strings.HasSuffix(strings.ToLower(base), suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	return strings.TrimSpace(base)
}

// validName 名称校验：1-128 字符，限定可打印安全字符集（名称进事件证据与展示面）。
func validName(s string) bool {
	if s == "" || len([]rune(s)) > maxNameLen {
		return false
	}
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-' || c == ' ' {
			continue
		}
		return false
	}
	return true
}

// recordAudit 写操作审计（构造注入 audits.Service；含操作者、动作、对象、摘要、风险等级）。
// 审计服务未注入或无操作者上下文时跳过，不影响主流程（与 apisecurity 同一纪律）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
