// object_models_update.go 对象模型发布状态管理（NG-AZ-02 D5/D7 管理写入路径）：
//
//	PATCH /api/v1/api-security/object-models/{id}
//
// 字段三分态（nil 指针=不变更）：publishable（发布资格）/ required_relation（首批仅 OWNER
// 词表）/ owner_exclusive（排他所有权——VERIFIED_VIOLATION 语义前提）/ on_lease_expired
// （租约过期策略 strict|degraded，缺省 strict）。
// 纪律：词表外取值 400 不降级猜义；行不存在 404；写操作审计（发布状态变更属授权事实管理）。
package apisecurity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/apiauthzwizard"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 词表（首批冻结：required_relation 仅 OWNER——其余关系词首批不支持拒收，不降级猜义）。
const (
	objectRelationOwner     = "OWNER"
	leaseExpiredStrict      = "strict"
	leaseExpiredDegraded    = "degraded"
	permAuthorizationManage = "api_authorization.manage"
	// NG-AZ-03 D3：enforcement 与 §8.4 四要素词表（首批冻结）。
	enforcementObserve      = "OBSERVE"
	enforcementProtect      = "PROTECT"
	evidenceSourceAuthority = "AUTHORITY_SYNC"
	evidenceSourceManual    = "MANUAL_CONFIRMED"
	onUnknownAllow          = "ALLOW_UNKNOWN" // 首批唯一 UNKNOWN 处理方式：UNKNOWN 永不阻断
	maxEnforcementOwnerLen  = 128
)

// ErrObjectModelNotFound 对象模型不存在。
var ErrObjectModelNotFound = errors.New("object model not found")

// ObjectModelPatch 发布状态变更（nil=不变更）。
type ObjectModelPatch struct {
	Publishable      *bool   `json:"publishable"`
	RequiredRelation *string `json:"required_relation"`
	OwnerExclusive   *bool   `json:"owner_exclusive"`
	OnLeaseExpired   *string `json:"on_lease_expired"`
	// ---- NG-AZ-03 D3 阻断开关与 §8.4 四要素 ----
	Enforcement      *string `json:"enforcement"`       // OBSERVE|PROTECT
	EnforcementOwner *string `json:"enforcement_owner"` // 业务负责人标识（PROTECT 必填非空 ≤128）
	EvidenceSource   *string `json:"evidence_source"`   // 证据来源声明（PROTECT 必填 AUTHORITY_SYNC|MANUAL_CONFIRMED）
	OnUnknown        *string `json:"on_unknown"`        // UNKNOWN 处理方式（首批仅 ALLOW_UNKNOWN）
	// ---- NG-AZ-04 D4：业务确认单一次性令牌（PROTECT 必填；切回 OBSERVE 免）----
	ConfirmToken *string `json:"confirm_token"`
}

// validate 词表校验（返回首个违规描述，空串=合法）。
func (p ObjectModelPatch) validate() string {
	if p.RequiredRelation != nil && strings.ToUpper(strings.TrimSpace(*p.RequiredRelation)) != objectRelationOwner {
		return "required_relation 首批仅支持 OWNER（共享/委托/组继承不支持，不降级猜义）"
	}
	if p.OnLeaseExpired != nil {
		v := strings.ToLower(strings.TrimSpace(*p.OnLeaseExpired))
		if v != leaseExpiredStrict && v != leaseExpiredDegraded {
			return "on_lease_expired 非法（strict|degraded；缺省 strict）"
		}
	}
	if p.Publishable != nil && *p.Publishable {
		// 发布资格的前置约束：排他所有权必须同批声明（防把非排他模型误发布——
		// 决策语义「有效 OWNER 是别人不代表所有共享业务都越权」（RD_PLAN §8.3））
		if p.OwnerExclusive != nil && !*p.OwnerExclusive {
			return "publishable=true 要求 owner_exclusive=true（排他所有权是发布语义前提）"
		}
	}
	// ---- NG-AZ-03 D3：enforcement 词表与 §8.4 四要素强制前置 ----
	if p.Enforcement != nil {
		v := strings.ToUpper(strings.TrimSpace(*p.Enforcement))
		if v != enforcementObserve && v != enforcementProtect {
			return "enforcement 非法（OBSERVE|PROTECT；缺省 OBSERVE）"
		}
		if v == enforcementProtect {
			// 切换 PROTECT：四要素缺一拒绝（① endpoint 行本身隐式满足；②③④ 必须同请求显式给出——
			// 不接受沿用历史值（切换动作必须自带全部声明，防「顺手切换」））
			if p.EnforcementOwner == nil || strings.TrimSpace(*p.EnforcementOwner) == "" {
				return "切换 PROTECT 必须同请求提供 enforcement_owner（业务负责人标识）"
			}
			if len(strings.TrimSpace(*p.EnforcementOwner)) > maxEnforcementOwnerLen {
				return "enforcement_owner 超过 128 字符"
			}
			if p.EvidenceSource == nil || strings.TrimSpace(*p.EvidenceSource) == "" {
				return "切换 PROTECT 必须同请求提供 evidence_source（证据来源声明 AUTHORITY_SYNC|MANUAL_CONFIRMED）"
			}
			if p.OnUnknown == nil || strings.TrimSpace(*p.OnUnknown) == "" {
				return "切换 PROTECT 必须同请求提供 on_unknown（UNKNOWN 处理方式声明，首批仅 ALLOW_UNKNOWN）"
			}
			// NG-AZ-04 D4：业务确认单强制引用（先评估后切换是系统约束而非流程倡议）
			if p.ConfirmToken == nil || strings.TrimSpace(*p.ConfirmToken) == "" {
				return "切换 PROTECT 必须携带 confirm_token（业务确认单一次性令牌——经影响评估签发并签署）"
			}
		}
	}
	if p.EvidenceSource != nil {
		v := strings.ToUpper(strings.TrimSpace(*p.EvidenceSource))
		if v != evidenceSourceAuthority && v != evidenceSourceManual {
			return "evidence_source 非法（AUTHORITY_SYNC|MANUAL_CONFIRMED）"
		}
	}
	if p.OnUnknown != nil && strings.ToUpper(strings.TrimSpace(*p.OnUnknown)) != onUnknownAllow {
		return "on_unknown 非法（首批仅 ALLOW_UNKNOWN——UNKNOWN 永不阻断）"
	}
	return ""
}

// UpdateObjectModel 更新对象模型发布状态（行不存在 ErrObjectModelNotFound）。
// NG-AZ-04 D4：enforcement=PROTECT 时携带 confirm_token——同一事务内校验
// （存在/未消费/未过期/端点×对象段绑定/已签署，五类哨兵精确区分）+ 切换 +
// 消费（consumed_at + consumed_audit_id=request_id）；任一校验失败整体回滚
// ——不留半切换状态。requestID 贯穿审计与确认单（溯源闭环）。
func (s *Store) UpdateObjectModel(ctx context.Context, id uuid.UUID, p ObjectModelPatch, requestID string) error {
	sets := []string{"updated_at = now()"}
	args := []any{id}
	if p.Publishable != nil {
		args = append(args, *p.Publishable)
		sets = append(sets, fmt.Sprintf("publishable = $%d", len(args)))
	}
	if p.RequiredRelation != nil {
		args = append(args, strings.ToUpper(strings.TrimSpace(*p.RequiredRelation)))
		sets = append(sets, fmt.Sprintf("required_relation = $%d", len(args)))
	}
	if p.OwnerExclusive != nil {
		args = append(args, *p.OwnerExclusive)
		sets = append(sets, fmt.Sprintf("owner_exclusive = $%d", len(args)))
	}
	if p.OnLeaseExpired != nil {
		args = append(args, strings.ToLower(strings.TrimSpace(*p.OnLeaseExpired)))
		sets = append(sets, fmt.Sprintf("on_lease_expired = $%d", len(args)))
	}
	// NG-AZ-03 D3：enforcement 四列（nil=不变更；PROTECT→OBSERVE 保留历史值供审计）
	if p.Enforcement != nil {
		args = append(args, strings.ToUpper(strings.TrimSpace(*p.Enforcement)))
		sets = append(sets, fmt.Sprintf("enforcement = $%d", len(args)))
	}
	if p.EnforcementOwner != nil {
		args = append(args, strings.TrimSpace(*p.EnforcementOwner))
		sets = append(sets, fmt.Sprintf("enforcement_owner = $%d", len(args)))
	}
	if p.EvidenceSource != nil {
		args = append(args, strings.ToUpper(strings.TrimSpace(*p.EvidenceSource)))
		sets = append(sets, fmt.Sprintf("evidence_source = $%d", len(args)))
	}
	if p.OnUnknown != nil {
		args = append(args, strings.ToUpper(strings.TrimSpace(*p.OnUnknown)))
		sets = append(sets, fmt.Sprintf("on_unknown = $%d", len(args)))
	}
	switchProtect := p.Enforcement != nil && strings.ToUpper(strings.TrimSpace(*p.Enforcement)) == enforcementProtect

	run := func(ctx context.Context, db apiauthzwizard.DBTX) error {
		if switchProtect {
			token, err := uuid.Parse(strings.TrimSpace(*p.ConfirmToken))
			if err != nil {
				return apiauthzwizard.ErrInvalidTokenID
			}
			// token 绑定核对需要对象模型行的 endpoint_id/object_segment（同事务内读）
			var endpointID uuid.UUID
			var segment string
			err = db.QueryRow(ctx, `SELECT endpoint_id, object_segment FROM api_object_models WHERE id=$1`, id).
				Scan(&endpointID, &segment)
			if err == pgx.ErrNoRows {
				return ErrObjectModelNotFound
			}
			if err != nil {
				return fmt.Errorf("load object model for token binding: %w", err)
			}
			if err := apiauthzwizard.ConsumeConfirmToken(ctx, db, token, endpointID, segment, requestID, time.Now().UTC()); err != nil {
				return err
			}
		}
		ct, err := db.Exec(ctx, `
UPDATE api_object_models SET `+strings.Join(sets, ", ")+` WHERE id = $1`, args...)
		if err != nil {
			return fmt.Errorf("update api_object_models: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return ErrObjectModelNotFound
		}
		return nil
	}

	if !switchProtect {
		return run(ctx, s.db)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin enforcement switch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := run(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit enforcement switch tx: %w", err)
	}
	return nil
}

// GetObjectModel 按 ID 读对象模型（PATCH 回显与审计 before 用）。
func (s *Store) GetObjectModel(ctx context.Context, id uuid.UUID) (*ObjectModel, error) {
	var m ObjectModel
	err := s.db.QueryRow(ctx, `
SELECT m.id, m.endpoint_id, COALESCE(e.endpoint_key, ''), COALESCE(a.name, ''),
       COALESCE((SELECT d.hostname FROM application_domains d
         WHERE d.application_id = a.id ORDER BY d.is_primary DESC, d.created_at LIMIT 1), ''),
       m.object_segment, m.identifier_type,
       m.example_hash, m.sample_count, m.first_seen, m.last_seen, m.updated_at,
       m.publishable, COALESCE(m.required_relation, ''), m.owner_exclusive, m.on_lease_expired,
       m.enforcement, m.enforcement_owner, m.evidence_source, m.on_unknown
FROM api_object_models m
LEFT JOIN api_endpoints e ON e.id = m.endpoint_id
LEFT JOIN applications a ON a.id = e.application_id
WHERE m.id = $1`, id).Scan(&m.ID, &m.EndpointID, &m.EndpointKey, &m.ApplicationName, &m.ApplicationDomain,
		&m.ObjectSegment, &m.IdentifierType,
		&m.ExampleHash, &m.SampleCount, &m.FirstSeen, &m.LastSeen, &m.UpdatedAt,
		&m.Publishable, &m.RequiredRelation, &m.OwnerExclusive, &m.OnLeaseExpired,
		&m.Enforcement, &m.EnforcementOwner, &m.EvidenceSource, &m.OnUnknown)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// PatchObjectModel PATCH /api/v1/api-security/object-models/{id}
// 对象模型发布状态管理（NG-AZ-02 D5/D7 管理写入路径；权限 api_authorization.manage；审计）。
func (h *Handler) PatchObjectModel(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的对象模型ID")
		return
	}
	var req ObjectModelPatch
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := req.validate(); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	before, err := h.store.GetObjectModel(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "对象模型不存在")
		return
	}
	if err := h.store.UpdateObjectModel(r.Context(), id, req, response.RequestIDFrom(r)); err != nil {
		if errors.Is(err, ErrObjectModelNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "对象模型不存在")
			return
		}
		// NG-AZ-04 D4：confirm_token 五类校验失败精确区分（400；哨兵由 apiauthzwizard 定义）
		switch {
		case errors.Is(err, apiauthzwizard.ErrInvalidTokenID):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 不存在（须经影响评估签发）")
		case errors.Is(err, apiauthzwizard.ErrConsumed):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 已被消费（一次性令牌不可复用——请重新发起影响评估）")
		case errors.Is(err, apiauthzwizard.ErrExpired):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 已过期（15 分钟 TTL——请重新发起影响评估）")
		case errors.Is(err, apiauthzwizard.ErrTokenMismatch):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 与本对象模型行绑定不符（端点×对象段不一致）")
		case errors.Is(err, apiauthzwizard.ErrNotSigned):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "confirm_token 未签署（须先完成确认单签署）")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	after, err := h.store.GetObjectModel(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 审计 after 追加 confirm_token（NG-AZ-04 D8：切换与确认单溯源闭环）
	afterSummary := objectModelSummary(after)
	if req.ConfirmToken != nil && strings.TrimSpace(*req.ConfirmToken) != "" {
		afterSummary += " confirm_token=" + strings.TrimSpace(*req.ConfirmToken)
	}
	h.recordAudit(r, p, "update", "api_object_model", id.String(), before.EndpointKey,
		objectModelSummary(before), afterSummary, "SUCCESS", "HIGH")
	response.JSON(w, r, http.StatusOK, after)
}

// objectModelSummary 审计摘要（发布状态 + NG-AZ-03 四要素全值 + 端点键）。
func objectModelSummary(m *ObjectModel) string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%s %s publishable=%v required_relation=%s owner_exclusive=%v on_lease_expired=%s enforcement=%s enforcement_owner=%s evidence_source=%s on_unknown=%s",
		m.EndpointKey, m.ObjectSegment, m.Publishable, m.RequiredRelation, m.OwnerExclusive, m.OnLeaseExpired,
		m.Enforcement, m.EnforcementOwner, m.EvidenceSource, m.OnUnknown)
}

var _ = middleware.RemoteIP
