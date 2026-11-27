// handler.go 向导端点（§1.1~§1.4）：readiness 派生、影响评估、确认单签署/查询、
// OPEN 冲突独立查询。权限全部沿用既有点（零新增）：read 查询与评估、
// evidence_read 样本明细、manage token 签发/签署/PATCH 消费。
package apiauthzwizard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/apiauthzacks"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// AcksStore 节点 ACK 事实源（*apiauthzacks.Store 满足）。
type AcksStore interface {
	ListNodeAcks(context.Context) ([]apiauthzacks.AckRow, error)
	ManagementWatermark(context.Context) (apiruntime.VectorWatermark, error)
}

// SettingsReader 时钟漂移上限读取（同 apiauthzacks 口径）。
type SettingsReader interface {
	GetInt(ctx context.Context, group, key string, def int) int
}

// CapabilityChecker 主节点能力检查（§1.2 BLOCKED_BY_NODE 判定输入；
// requiredAZ 按模型取 3 或 4；默认实现读 sidecar capability.json——发布门同一事实源）。
type CapabilityChecker func(ctx context.Context, requiredAZ int) (ok bool, reason string)

// Handler 向导处理器。
type Handler struct {
	store      *Store
	acks       AcksStore
	settings   SettingsReader
	capability CapabilityChecker
	now        func() time.Time // 测试注入；nil = time.Now
}

// NewHandler 创建。
func NewHandler(store *Store, acks AcksStore, settings SettingsReader, capability CapabilityChecker) *Handler {
	return &Handler{store: store, acks: acks, settings: settings, capability: capability}
}

// SetNow 测试注入时钟。
func (h *Handler) SetNow(f func() time.Time) { h.now = f }

func (h *Handler) utcNow() time.Time {
	if h.now != nil {
		return h.now().UTC()
	}
	return time.Now().UTC()
}

// RegisterRoutes 注册路由（/api/v1/api-security/authz 命名空间；权限中间件同 apiauthz 惯例）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/authz/enforcement-readiness",
		authzFn(middleware.RequirePermission(apiauthz.PermAuthzRead)(http.HandlerFunc(h.ListReadiness))))
	mux.Handle("POST /api/v1/api-security/authz/enforcement-impact",
		authzFn(middleware.RequirePermission(apiauthz.PermAuthzRead)(http.HandlerFunc(h.EvaluateImpact))))
	mux.Handle("GET /api/v1/api-security/authz/enforcement-confirmations",
		authzFn(middleware.RequirePermission(apiauthz.PermAuthzRead)(http.HandlerFunc(h.ListConfirmations))))
	mux.Handle("POST /api/v1/api-security/authz/enforcement-confirmations/{confirm_token}/sign",
		authzFn(middleware.RequirePermission(apiauthz.PermAuthzManage)(http.HandlerFunc(h.SignConfirmation))))
	mux.Handle("GET /api/v1/api-security/authz/conflicts",
		authzFn(middleware.RequirePermission(apiauthz.PermAuthzRead)(http.HandlerFunc(h.ListConflicts))))
}

// ---------- 节点事实聚合（readiness 时效/通道输入；按请求一次采集全应用共享） ----------

// nodeFacts 节点事实（§1.2 时效/通道因子 + 状态明细原文）。
type nodeFacts struct {
	snapshotExpired   bool
	clockSkew         bool
	nodeNotFresh      bool
	leaseExpiredNodes bool
	capabilityLow     bool
	stateReasons      []string
}

// collectNodeFacts 采集节点事实（ACK 视图派生复用 apiauthzacks.BuildView——
// ack_state 五态唯一事实源不重复实现；能力版本在 readinessForRow 按模型检查）。
func (h *Handler) collectNodeFacts(ctx context.Context, now time.Time) (nodeFacts, error) {
	var f nodeFacts
	if h.acks == nil {
		f.nodeNotFresh = true
		f.stateReasons = append(f.stateReasons, "节点状态：ACK 数据源未装配（保守按不可实断）")
		return f, nil
	}
	rows, err := h.acks.ListNodeAcks(ctx)
	if err != nil {
		return f, err
	}
	mgmt, err := h.acks.ManagementWatermark(ctx)
	if err != nil {
		return f, err
	}
	skewMax := int64(apiauthzacks.DefaultClockSkewMaxSeconds)
	if h.settings != nil {
		skewMax = apiauthzacks.ClampClockSkewMax(h.settings.GetInt(
			ctx,
			apiauthzacks.ClockSkewSettingGroup,
			apiauthzacks.ClockSkewSettingKey,
			apiauthzacks.DefaultClockSkewMaxSeconds,
		))
	}
	view := apiauthzacks.BuildView(rows, mgmt, now, skewMax)
	if len(view.Items) == 0 {
		f.nodeNotFresh = true
		f.stateReasons = append(f.stateReasons, "节点状态：无任何网关节点在册（无节点可应用实断配置）")
	}
	for _, n := range view.Items {
		switch n.AckState {
		case apiauthzacks.StateClockSkew:
			f.clockSkew = true
			f.stateReasons = append(f.stateReasons, "节点 "+n.NodeName+"：CLOCK_SKEW（时钟偏差超上限，时效判定不可信）")
		case apiauthzacks.StateStaleExpired:
			f.leaseExpiredNodes = true
			f.stateReasons = append(f.stateReasons, "节点 "+n.NodeName+"：STALE_EXPIRED（陈旧越出租约——strict 端点 UNKNOWN 不阻断）")
		case apiauthzacks.StateStaleWithinLease, apiauthzacks.StateNeverAcked:
			f.nodeNotFresh = true
			f.stateReasons = append(f.stateReasons, "节点 "+n.NodeName+"："+n.AckState+"（授权快照未达最新）")
		}
	}
	// 快照过期（api_node_authz_acks.authz_snapshot_expires_at；ACK 视图未含该列，直查）
	if err := h.store.db.QueryRow(ctx, `SELECT COALESCE(bool_or(authz_snapshot_expires_at IS NOT NULL AND authz_snapshot_expires_at < $1), false)
		FROM api_node_authz_acks`, now).Scan(&f.snapshotExpired); err != nil {
		return f, err
	}
	if f.snapshotExpired {
		f.stateReasons = append(f.stateReasons, "节点状态：存在授权快照已过期的节点")
	}
	return f, nil
}

// readinessForRow 单行 readiness 派生（装配输入→DeriveReadiness 纯函数）。
func (h *Handler) readinessForRow(ctx context.Context, row ObjectModelRow, nf nodeFacts, now time.Time) (string, []string, error) {
	hasRelation, err := h.store.HasEffectiveOwnerRelation(ctx, row.ApplicationID, row.ObjectType, now)
	if err != nil {
		return "", nil, err
	}
	hasConflict, err := h.store.HasOpenConflict(ctx, row.ApplicationID, row.ObjectType)
	if err != nil {
		return "", nil, err
	}
	if h.capability != nil {
		ok, reason := h.capability(ctx, requiredAuthzAZ(row.RequiredRelation))
		if !ok {
			nf.capabilityLow = true
			nf.stateReasons = append(nf.stateReasons, "节点能力："+reason)
		}
	}
	badge, reasons := DeriveReadiness(ReadinessInput{
		Publishable:               row.Publishable,
		RequiredRelation:          row.RequiredRelation,
		RequiredRelations:         row.RequiredRelations,
		OwnerExclusive:            row.OwnerExclusive,
		EndpointConfirmed:         row.EndpointConfirmed,
		Enforcement:               row.Enforcement,
		HasEffectiveOwnerRelation: hasRelation,
		HasOpenConflict:           hasConflict,
		SnapshotExpired:           nf.snapshotExpired,
		LeaseExpired:              nf.leaseExpiredNodes,
		ClockSkew:                 nf.clockSkew,
		NodeNotFresh:              nf.nodeNotFresh,
		NodeCapabilityLow:         nf.capabilityLow,
		NodeStateReasons:          nf.stateReasons,
	})
	return badge, reasons, nil
}

// ---------- GET /enforcement-readiness（§1.2） ----------

// ReadinessItem readiness 出参行（§1.2 冻结字段集）。
type ReadinessItem struct {
	EndpointID    uuid.UUID `json:"endpoint_id"`
	EndpointKey   string    `json:"endpoint_key"`
	ObjectSegment string    `json:"object_segment"`
	Enforcement   string    `json:"enforcement"`
	Readiness     string    `json:"readiness"`
	Reasons       []string  `json:"reasons"`
	CheckedAt     time.Time `json:"checked_at"`
}

// ListReadiness GET /api/v1/api-security/authz/enforcement-readiness
// ?application_id=<uuid>&endpoint_id=<uuid>（application_id 与 endpoint_id 至少提供一个）
func (h *Handler) ListReadiness(w http.ResponseWriter, r *http.Request) {
	applicationID, ok := parseOptionalUUID(w, r, "application_id", "站点ID")
	if !ok {
		return
	}
	endpointID, ok := parseOptionalUUID(w, r, "endpoint_id", "接口ID")
	if !ok {
		return
	}
	if applicationID == uuid.Nil && endpointID == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少站点ID或接口ID（至少提供一个）")
		return
	}
	now := h.utcNow()
	nf, err := h.collectNodeFacts(r.Context(), now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	rows, err := h.store.ListObjectModelRows(r.Context(), applicationID, endpointID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := []ReadinessItem{}
	for _, row := range rows {
		badge, reasons, err := h.readinessForRow(r.Context(), row, nf, now)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		items = append(items, ReadinessItem{
			EndpointID: row.EndpointID, EndpointKey: row.EndpointKey, ObjectSegment: row.ObjectSegment,
			Enforcement: row.Enforcement, Readiness: badge, Reasons: reasons, CheckedAt: now,
		})
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items})
}

// ---------- POST /enforcement-impact（§1.3） ----------

// EvaluateImpact POST /api/v1/api-security/authz/enforcement-impact
// 只读评估；api_authorization.manage 调用同时签发一次性 confirm_token（15 分钟 TTL）。
func (h *Handler) EvaluateImpact(w http.ResponseWriter, r *http.Request) {
	var req ImpactRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	endpointID, err := uuid.Parse(strings.TrimSpace(req.EndpointID))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
		return
	}
	if msg := validateWindow(req.WindowDays); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	ctx := r.Context()
	applicationID, endpointKey, err := h.store.endpointKeys(ctx, endpointID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	rows, err := h.store.ListObjectModelRows(ctx, applicationID, endpointID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	row, msg := selectModelRow(rows, strings.TrimSpace(req.ObjectSegment))
	if msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	now := h.utcNow()
	since := now.Add(-time.Duration(req.WindowDays) * 24 * time.Hour)
	observeViolation, unknownTotal, verifiedViolation, err := h.store.decisionCounts(ctx, applicationID, endpointKey, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	buckets, err := h.store.unknownByReason(ctx, applicationID, endpointKey, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	principals, err := h.store.distinctPrincipalCount(ctx, endpointKey, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	nf, err := h.collectNodeFacts(ctx, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	badge, reasons, err := h.readinessForRow(ctx, row, nf, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	result := ImpactResult{
		EndpointID: endpointID, EndpointKey: endpointKey, ObjectSegment: row.ObjectSegment,
		WindowDays: req.WindowDays, EvaluatedAt: now,
		ObserveViolationCount: observeViolation, UnknownTotal: unknownTotal, UnknownByReason: buckets,
		DistinctPrincipalCount: principals, VerifiedViolationCount: verifiedViolation,
		Readiness: badge, ReadinessReasons: reasons,
	}
	// 样本明细按 evidence_read 裁剪（分权纪律：只读可见数字，证据明细另需证据权限）
	p := authz.PrincipalFrom(ctx)
	if p != nil && p.HasPermission(apiauthz.PermEvidenceRead) {
		samples, err := h.store.recentSamples(ctx, applicationID, endpointKey, since)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		result.RecentSamples = samples
	}
	// manage 评估同时签发一次性 confirm_token（§1.3；token 绑定粒度=对象模型行）
	if p != nil && p.HasPermission(apiauthz.PermAuthzManage) {
		snapshot, err := json.Marshal(result)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		token, expires, err := h.store.IssueConfirmation(ctx, applicationID, endpointID, row.ObjectSegment, req.WindowDays, snapshot, now)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		result.ConfirmToken = &token
		result.ConfirmTokenExpiresAt = &expires
	}
	response.JSON(w, r, http.StatusOK, result)
}

// ---------- 确认单（§1.4） ----------

// ListConfirmations GET /api/v1/api-security/authz/enforcement-confirmations
func (h *Handler) ListConfirmations(w http.ResponseWriter, r *http.Request) {
	applicationID, ok := parseOptionalUUID(w, r, "application_id", "站点ID")
	if !ok {
		return
	}
	endpointID, ok := parseOptionalUUID(w, r, "endpoint_id", "接口ID")
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := h.store.ListConfirmations(r.Context(), applicationID, endpointID, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// signRequest 确认单签署请求（四要素随签署同批回填）。
type signRequest struct {
	EnforcementOwner string `json:"enforcement_owner"`
	EvidenceSource   string `json:"evidence_source"`
	OnUnknown        string `json:"on_unknown"`
}

// SignConfirmation POST /api/v1/api-security/authz/enforcement-confirmations/{id}/sign
// 向导第 4 步签署动作：冻结文案 v1 按确认单影响摘要生成，signed_at + 四要素同批落库；
// 不存在/已消费/已过期/已签署精确区分。
func (h *Handler) SignConfirmation(w http.ResponseWriter, r *http.Request) {
	// 按 confirm_token 语义查找（向导/前端只持有令牌——§1.3 影响评估响应无行 id）
	token, err := uuid.Parse(r.PathValue("confirm_token"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 confirm_token")
		return
	}
	var req signRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	owner := strings.TrimSpace(req.EnforcementOwner)
	if owner == "" || len(owner) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "enforcement_owner 必填非空且不超过 128 字符")
		return
	}
	evidenceSource := strings.ToUpper(strings.TrimSpace(req.EvidenceSource))
	if evidenceSource != "AUTHORITY_SYNC" && evidenceSource != "MANUAL_CONFIRMED" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "evidence_source 非法（AUTHORITY_SYNC|MANUAL_CONFIRMED）")
		return
	}
	onUnknown := strings.ToUpper(strings.TrimSpace(req.OnUnknown))
	if onUnknown != "ALLOW_UNKNOWN" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "on_unknown 非法（首批仅 ALLOW_UNKNOWN——UNKNOWN 永不阻断）")
		return
	}
	// 冻结文案 v1 按签发时落库的影响摘要生成（签署确认的就是这份影响面）
	var snapshot struct {
		WindowDays             int `json:"window_days"`
		ObserveViolationCount  int `json:"observe_violation_count"`
		DistinctPrincipalCount int `json:"distinct_principal_count"`
	}
	var raw []byte
	err = h.store.db.QueryRow(r.Context(), `SELECT impact_snapshot FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "确认单不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	_ = json.Unmarshal(raw, &snapshot)
	p := authz.PrincipalFrom(r.Context())
	var signedBy uuid.UUID
	signedByName := ""
	if p != nil {
		signedBy = p.UserID
		signedByName = p.Username
	}
	c, err := h.store.SignConfirmation(r.Context(), token, owner, evidenceSource, onUnknown,
		confirmTextV1(snapshot.WindowDays, snapshot.ObserveViolationCount, snapshot.DistinctPrincipalCount, signedByName),
		signedBy, signedByName, h.utcNow())
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "确认单不存在")
		case errors.Is(err, ErrConsumed):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "确认单已被消费（不可重复签署）")
		case errors.Is(err, ErrExpired):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 已过期（请重新发起影响评估）")
		case errors.Is(err, ErrAlreadySigned):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "确认单已签署（不可重复签署）")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, c)
}

// ---------- GET /conflicts（D1 注：OPEN 冲突独立分页查询） ----------

// ConflictItem 冲突出参行（列同 api_authority_conflicts）。
type ConflictItem struct {
	ID            uuid.UUID       `json:"id"`
	ApplicationID uuid.UUID       `json:"application_id"`
	ObjectType    string          `json:"object_type"`
	TenantDomain  string          `json:"tenant_domain"`
	ObjectRef     string          `json:"object_ref"`
	Principals    json.RawMessage `json:"principals"`
	Status        string          `json:"status"`
	FirstSeen     time.Time       `json:"first_seen"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// ListConflicts GET /api/v1/api-security/authz/conflicts?application_id=&status=OPEN
func (h *Handler) ListConflicts(w http.ResponseWriter, r *http.Request) {
	applicationID, ok := parseOptionalUUID(w, r, "application_id", "站点ID")
	if !ok {
		return
	}
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if status == "" {
		status = "OPEN"
	}
	if status != "OPEN" && status != "RESOLVED" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 非法（OPEN|RESOLVED）")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	ctx := r.Context()
	where, args := " WHERE status=$1", []any{status}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		where += " AND application_id=$2"
	}
	var total int64
	if err := h.store.db.QueryRow(ctx, "SELECT count(*) FROM api_authority_conflicts"+where, args...).Scan(&total); err != nil {
		response.InternalError(w, r, err)
		return
	}
	args = append(args, pageSize, (page-1)*pageSize)
	lim := len(args) - 1
	rows, err := h.store.db.Query(ctx, `SELECT id, application_id, object_type, tenant_domain, object_ref, principals, status, first_seen, updated_at
	FROM api_authority_conflicts`+where+" ORDER BY first_seen DESC, id LIMIT $"+itoa(lim)+" OFFSET $"+itoa(lim+1), args...)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	items := []ConflictItem{}
	for rows.Next() {
		var c ConflictItem
		var principals []byte
		if err := rows.Scan(&c.ID, &c.ApplicationID, &c.ObjectType, &c.TenantDomain, &c.ObjectRef, &principals, &c.Status, &c.FirstSeen, &c.UpdatedAt); err != nil {
			response.InternalError(w, r, err)
			return
		}
		if len(principals) > 0 {
			c.Principals = json.RawMessage(principals)
		} else {
			c.Principals = json.RawMessage("[]")
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// ---------- 小工具 ----------

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func queryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n := 0
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func parseRequiredUUID(w http.ResponseWriter, r *http.Request, key, label string) (uuid.UUID, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少"+label)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(v)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的"+label)
		return uuid.Nil, false
	}
	return id, true
}

func parseOptionalUUID(w http.ResponseWriter, r *http.Request, key, label string) (uuid.UUID, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return uuid.Nil, true
	}
	id, err := uuid.Parse(v)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的"+label)
		return uuid.Nil, false
	}
	return id, true
}
