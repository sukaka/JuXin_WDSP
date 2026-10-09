package guardconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// authzRelationsPerObjectType 授权关系每对象类型上限。
const authzRelationsPerObjectType = 200000

// authzConflictedObjectsCap 决策侧排除集上限（NG-AZ-02 D2/D7；超限发布失败 fail-hard——
// 截断等于对超限部分静默放行冲突对象，绝不截断）。
const authzConflictedObjectsCap = 10000

// authzLeaseClamp 租约秒数夹紧（NG-AZ-02 D5：15~300；读取侧执行，配置值不参与版本戳漂移）。
const (
	authzLeaseMinSeconds = 15
	authzLeaseMaxSeconds = 300
)

// clampAuthzLeaseSeconds 租约夹紧（≤0 视为未配置返回 0；超界夹紧）。
func clampAuthzLeaseSeconds(sec int) int {
	if sec <= 0 {
		return 0
	}
	if sec < authzLeaseMinSeconds {
		return authzLeaseMinSeconds
	}
	if sec > authzLeaseMaxSeconds {
		return authzLeaseMaxSeconds
	}
	return sec
}

const listPublishableAuthzModelsQuery = `
SELECT ep.application_id, ep.endpoint_key, ep.http_method, ep.normalized_path, om.object_segment,
       om.required_relation, om.owner_exclusive, om.updated_at, om.on_lease_expired,
       om.enforcement, om.enforcement_owner, om.evidence_source, om.on_unknown
FROM api_object_models om
JOIN api_endpoints ep ON ep.id=om.endpoint_id
WHERE om.publishable AND om.required_relation='OWNER' AND om.owner_exclusive
  AND ep.asset_status='CONFIRMED'
ORDER BY ep.endpoint_key, om.object_segment`

// AuthzSnapshotLister compiles only approved authorization facts. Candidate
// evidence and OBSERVED role claims are intentionally outside this interface.
type AuthzSnapshotLister interface {
	ListPublishableAuthzModels(context.Context, time.Time) ([]gatewayconfig.GuardAuthzObjectModel, error)
	ListConfirmedAuthzRelations(context.Context) ([]gatewayconfig.GuardAuthzObjectRelation, error)
	ListVerifiedAuthzRoleBaselines(context.Context) ([]gatewayconfig.GuardAuthzRoleBaseline, error)
}

// AuthzSnapshotV2Lister NG-AZ-02 v2 快照元数据读取（*AuthzSnapshotStore 实现；
// 可选接口——装配/测试形态未实现时发布按 v1 零行为跳过，不强制既有 fake 扩展）。
type AuthzSnapshotV2Lister interface {
	LoadManagementRevocationWatermark(context.Context) (*gatewayconfig.RevocationWatermark, error)
	ListOpenAuthzConflicts(context.Context) ([]gatewayconfig.GuardAuthzConflictedObject, error)
	ListAuthzLeaseSeconds(context.Context) (map[string]int, error)
}

type AuthzSnapshotStore struct{ db *pgxpool.Pool }

func NewAuthzSnapshotStore(db *pgxpool.Pool) *AuthzSnapshotStore { return &AuthzSnapshotStore{db: db} }

func (s *AuthzSnapshotStore) ListPublishableAuthzModels(ctx context.Context, expires time.Time) ([]gatewayconfig.GuardAuthzObjectModel, error) {
	rows, err := s.db.Query(ctx, listPublishableAuthzModelsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gatewayconfig.GuardAuthzObjectModel
	seen := map[string]bool{}
	for rows.Next() {
		var applicationID, endpointKey, method, pathTemplate, segment, required string
		var exclusive bool
		var updated time.Time
		var onLeaseExpired string
		var enforcement, enforcementOwner, evidenceSource, onUnknown string
		if err := rows.Scan(&applicationID, &endpointKey, &method, &pathTemplate, &segment, &required, &exclusive, &updated, &onLeaseExpired,
			&enforcement, &enforcementOwner, &evidenceSource, &onUnknown); err != nil {
			return nil, err
		}
		location, name, objectType, ok := compileObjectSegment(pathTemplate, segment)
		if !ok {
			return nil, fmt.Errorf("authz model %s has unsupported object_segment %q", endpointKey, segment)
		}
		conflictKey := applicationID + "\x00" + endpointKey + "\x00" + objectType
		if seen[conflictKey] {
			return nil, fmt.Errorf("authz model conflict: endpoint %s object_type %s is not unique", endpointKey, objectType)
		}
		seen[conflictKey] = true
		// D5 缺省严格（安全保守项）：词表外/空值按 strict 归一（DDL 已有 CHECK，此处防御归一）
		if onLeaseExpired != "degraded" {
			onLeaseExpired = "strict"
		}
		// NG-AZ-03 D3 防御归一（DDL 已有 CHECK）：enforcement 词表外按 OBSERVE 归一（缺省安全侧）；
		// on_unknown 词表外按 ALLOW_UNKNOWN 归一（首批唯一值——UNKNOWN 永不阻断）
		if enforcement != "PROTECT" {
			enforcement = "OBSERVE"
		}
		if onUnknown != "ALLOW_UNKNOWN" {
			onUnknown = "ALLOW_UNKNOWN"
		}
		versionSum := sha256.Sum256([]byte(endpointKey + "\x00" + segment + "\x00" + updated.UTC().Format(time.RFC3339Nano)))
		out = append(out, gatewayconfig.GuardAuthzObjectModel{
			ApplicationID: applicationID,
			EndpointKey:   endpointKey, Method: strings.ToUpper(method), PathTemplate: pathTemplate,
			ObjectType: objectType, Identifiers: []gatewayconfig.GuardAuthzObjectIdentifier{{Location: location, Name: name, Primary: true}},
			RequiredRelation: required, OwnerExclusive: exclusive, Publishable: true,
			UniqueEndpointTemplate: true, ModelVersion: hex.EncodeToString(versionSum[:8]), SnapshotExpiresAt: &expires,
			OnLeaseExpired: onLeaseExpired,
			Enforcement:    enforcement, EnforcementOwner: enforcementOwner,
			EvidenceSource: evidenceSource, OnUnknown: onUnknown,
		})
	}
	return out, rows.Err()
}

func compileObjectSegment(pathTemplate, segment string) (location, name, objectType string, ok bool) {
	if strings.HasPrefix(segment, "query:") {
		name = strings.TrimSpace(strings.TrimPrefix(segment, "query:"))
		return "query", name, name, name != ""
	}
	if !strings.HasPrefix(segment, "path:") {
		return "", "", "", false
	}
	pos, err := strconv.Atoi(strings.TrimPrefix(segment, "path:"))
	parts := strings.Split(strings.Trim(pathTemplate, "/"), "/")
	if err != nil || pos < 0 || pos >= len(parts) {
		return "", "", "", false
	}
	name = strings.TrimSuffix(strings.TrimPrefix(parts[pos], "{"), "}")
	if name == parts[pos] || name == "" {
		return "", "", "", false
	}
	objectType = name
	if pos > 0 && !strings.ContainsAny(parts[pos-1], "{}") {
		objectType = parts[pos-1]
	}
	return "path", name, objectType, true
}

func (s *AuthzSnapshotStore) ListConfirmedAuthzRelations(ctx context.Context) ([]gatewayconfig.GuardAuthzObjectRelation, error) {
	rows, err := s.db.Query(ctx, `SELECT application_id, principal_id, object_type, object_ref, relation, status,
COALESCE(tenant_id,''), valid_from, valid_until FROM api_object_relations
WHERE status='CONFIRMED' AND relation='OWNER'
  AND (valid_until IS NULL OR valid_until>now()) ORDER BY object_type, object_ref, principal_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{}
	var out []gatewayconfig.GuardAuthzObjectRelation
	for rows.Next() {
		var r gatewayconfig.GuardAuthzObjectRelation
		if err := rows.Scan(&r.ApplicationID, &r.PrincipalID, &r.ObjectType, &r.ObjectRef, &r.Relation, &r.Status, &r.TenantID, &r.ValidFrom, &r.ValidUntil); err != nil {
			return nil, err
		}
		countKey := r.ApplicationID + "\x00" + r.ObjectType
		counts[countKey]++
		if counts[countKey] > authzRelationsPerObjectType {
			return nil, fmt.Errorf("authz relations for object_type %s exceed %d", r.ObjectType, authzRelationsPerObjectType)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *AuthzSnapshotStore) ListVerifiedAuthzRoleBaselines(ctx context.Context) ([]gatewayconfig.GuardAuthzRoleBaseline, error) {
	rows, err := s.db.Query(ctx, `SELECT ep.application_id, ep.endpoint_key, rb.method, rb.role, rb.action, rb.allowed, rb.confirmed, rb.enforcement
FROM api_role_baselines rb JOIN api_endpoints ep ON ep.id=rb.endpoint_id
WHERE rb.confirmed AND rb.identity_assurance='VERIFIED'
ORDER BY ep.endpoint_key, rb.method, rb.role, rb.action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []gatewayconfig.GuardAuthzRoleBaseline
	for rows.Next() {
		var b gatewayconfig.GuardAuthzRoleBaseline
		if err := rows.Scan(&b.ApplicationID, &b.EndpointKey, &b.Method, &b.Role, &b.Action, &b.Allowed, &b.Confirmed, &b.Enforcement); err != nil {
			return nil, err
		}
		// NG-AZ-03 D3 继承语义（§1.3「无行级配置时端点继承 object model 值」）：
		// DB 列 NOT NULL DEFAULT 'OBSERVE'——缺省 OBSERVE 即「未配置」，归一为空串下发
		// （omitempty 省略），网关消费侧空值继承端点 object model 值；仅行级显式
		// PROTECT 非空下发（行级实断声明）。管理面当前无角色基线 enforcement 写通道，
		// 「显式行级 OBSERVE 覆盖端点」语义本批不表达（fail-safe：词表外同归未配置不实断）。
		if b.Enforcement != "PROTECT" {
			b.Enforcement = ""
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (p *Provider) SetAuthzSnapshotLister(l AuthzSnapshotLister)           { p.authzSnapshot = l }
func (p *Provider) SetAuthzObjectHMACKeyLoader(l AuthzObjectHMACKeyLoader) { p.authzObjectHMACKey = l }

func (p *Provider) loadAPIAuthzSnapshot(ctx context.Context) ([]gatewayconfig.GuardAuthzObjectModel, []gatewayconfig.GuardAuthzObjectRelation, []gatewayconfig.GuardAuthzRoleBaseline, string, error) {
	if p.authzSnapshot == nil {
		return nil, nil, nil, "", nil
	}
	now := time.Now().UTC()
	expires := now.Add(24 * time.Hour)
	models, err := p.authzSnapshot.ListPublishableAuthzModels(ctx, expires)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("compile authz object models: %w", err)
	}
	// BFLA 角色基线独立于 BOLA 对象模型；即使当前没有可发布对象模型，
	// VERIFIED 角色仍必须进入同一发布通道。
	baselines, err := p.authzSnapshot.ListVerifiedAuthzRoleBaselines(ctx)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("compile verified authz role baselines: %w", err)
	}
	if err := validateVerifiedRoleBaselineConflicts(baselines); err != nil {
		return nil, nil, nil, "", fmt.Errorf("compile verified authz role baselines: %w", err)
	}
	if len(models) == 0 {
		return nil, nil, baselines, "", nil
	}
	relations, err := p.authzSnapshot.ListConfirmedAuthzRelations(ctx)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("compile authz relations: %w", err)
	}
	if err := validateConfirmedAuthzRelations(relations, now); err != nil {
		return nil, nil, nil, "", fmt.Errorf("compile authz relations: %w", err)
	}
	if p.authzObjectHMACKey == nil {
		return nil, nil, nil, "", fmt.Errorf("publishable authz models require dedicated object HMAC key loader")
	}
	keyHex, err := p.authzObjectHMACKey(ctx)
	if err != nil {
		return nil, nil, nil, "", err
	}
	if keyHex == "" {
		return nil, nil, nil, "", fmt.Errorf("publishable authz models require api_authz.object_hmac_key")
	}
	versionInput := make([]string, 0, len(models))
	for _, m := range models {
		versionInput = append(versionInput, m.EndpointKey+"\x00"+m.ObjectType+"\x00"+m.ModelVersion)
	}
	sort.Strings(versionInput)
	v := sha256.Sum256([]byte(strings.Join(versionInput, "\n")))
	policyVersion := "authz-" + hex.EncodeToString(v[:8])
	for i := range models {
		models[i].PolicyVersion = policyVersion
	}
	return models, relations, baselines, keyHex, nil
}

// validateConfirmedAuthzRelations is the publish boundary for the relation
// lister contract. The SQL implementation already applies these predicates,
// but keeping them here prevents a future cross-process/alternate lister from
// turning candidate or stale evidence into an authorization snapshot.
func validateConfirmedAuthzRelations(relations []gatewayconfig.GuardAuthzObjectRelation, now time.Time) error {
	now = now.UTC()
	for i, relation := range relations {
		if !strings.EqualFold(strings.TrimSpace(relation.Status), "CONFIRMED") {
			return fmt.Errorf("relation[%d] status %q is not CONFIRMED", i, relation.Status)
		}
		if !strings.EqualFold(strings.TrimSpace(relation.Relation), "OWNER") {
			return fmt.Errorf("relation[%d] relation %q is not OWNER", i, relation.Relation)
		}
		if strings.TrimSpace(relation.ApplicationID) == "" || strings.TrimSpace(relation.PrincipalID) == "" || strings.TrimSpace(relation.ObjectType) == "" {
			return fmt.Errorf("relation[%d] has an empty application, principal, or object type", i)
		}
		if !strings.HasPrefix(relation.ObjectRef, "objref:") || len(relation.ObjectRef) <= len("objref:") {
			return fmt.Errorf("relation[%d] object_ref is not an HMAC reference", i)
		}
		if relation.ValidUntil != nil && !relation.ValidUntil.UTC().After(now) {
			return fmt.Errorf("relation[%d] is expired", i)
		}
	}
	return nil
}

func validateVerifiedRoleBaselineConflicts(baselines []gatewayconfig.GuardAuthzRoleBaseline) error {
	seen := make(map[string]bool, len(baselines))
	for _, baseline := range baselines {
		key := strings.Join([]string{
			strings.TrimSpace(baseline.ApplicationID),
			strings.TrimSpace(baseline.EndpointKey),
			strings.ToUpper(strings.TrimSpace(baseline.Method)),
			strings.TrimSpace(baseline.Role),
			strings.ToUpper(strings.TrimSpace(baseline.Action)),
		}, "\x00")
		if allowed, ok := seen[key]; ok && allowed != baseline.Allowed {
			return fmt.Errorf("conflicting verified authz role baseline for application %q endpoint %q method %q role %q action %q", baseline.ApplicationID, baseline.EndpointKey, baseline.Method, baseline.Role, baseline.Action)
		}
		seen[key] = baseline.Allowed
	}
	return nil
}

// ---------- NG-AZ-02 v2 快照元数据（D1/D2/D5 编译侧） ----------

// LoadManagementRevocationWatermark 读管理面向量撤销水位（D1：manual_seq 单行 +
// api_authority_watermarks 逐来源；行缺失按 0 计——从未撤销即全零水位）。
// 由发布编译与 PreviousValid 资格过滤（authz_lifecycle）共用，单一事实源。
func (s *AuthzSnapshotStore) LoadManagementRevocationWatermark(ctx context.Context) (*gatewayconfig.RevocationWatermark, error) {
	wm := &gatewayconfig.RevocationWatermark{Sources: map[string]int64{}}
	if err := s.db.QueryRow(ctx,
		`SELECT seq FROM api_authz_manual_revocation_seq WHERE id = 1`).Scan(&wm.ManualSeq); err != nil {
		return nil, fmt.Errorf("load manual revocation watermark: %w", err)
	}
	rows, err := s.db.Query(ctx,
		`SELECT source_id, revocation_watermark FROM api_authority_watermarks WHERE revocation_watermark > 0 ORDER BY source_id`)
	if err != nil {
		return nil, fmt.Errorf("load authority revocation watermarks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sourceID string
		var seq int64
		if err := rows.Scan(&sourceID, &seq); err != nil {
			return nil, err
		}
		wm.Sources[sourceID] = seq
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return wm, nil
}

// ListOpenAuthzConflicts 决策侧排除集（D2/D7：api_authority_conflicts OPEN 行；
// 超上限即错误——发布失败 fail-hard，绝不截断静默放行冲突对象）。
func (s *AuthzSnapshotStore) ListOpenAuthzConflicts(ctx context.Context) ([]gatewayconfig.GuardAuthzConflictedObject, error) {
	rows, err := s.db.Query(ctx, `
SELECT application_id, object_type, tenant_domain, object_ref
FROM api_authority_conflicts WHERE status = 'OPEN'
ORDER BY application_id, object_type, object_ref`)
	if err != nil {
		return nil, fmt.Errorf("list open authz conflicts: %w", err)
	}
	defer rows.Close()
	out := []gatewayconfig.GuardAuthzConflictedObject{}
	for rows.Next() {
		var c gatewayconfig.GuardAuthzConflictedObject
		if err := rows.Scan(&c.ApplicationID, &c.ObjectType, &c.TenantDomain, &c.ObjectRef); err != nil {
			return nil, err
		}
		out = append(out, c)
		if len(out) > authzConflictedObjectsCap {
			return nil, fmt.Errorf("open authz conflicts exceed %d（超限发布失败 fail-hard，不截断）", authzConflictedObjectsCap)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListAuthzLeaseSeconds per-app 租约配置（D5：applications.authz_lease_seconds 非空行；
// 读取侧夹紧 15~300，非法值（≤0 已在 DDL 外）按未配置跳过）。
func (s *AuthzSnapshotStore) ListAuthzLeaseSeconds(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.Query(ctx, `
SELECT id, authz_lease_seconds FROM applications
WHERE authz_lease_seconds IS NOT NULL AND deleted_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list authz lease seconds: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var appID string
		var sec int
		if err := rows.Scan(&appID, &sec); err != nil {
			return nil, err
		}
		if clamped := clampAuthzLeaseSeconds(sec); clamped > 0 {
			out[appID] = clamped
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
