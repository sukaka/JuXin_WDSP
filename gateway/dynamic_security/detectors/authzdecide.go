package detectors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// ObjectIdentifier identifies one object reference in the request. Only the
// primary path/query identifier is accepted by the authorization decision.
type ObjectIdentifier struct {
	Location string `json:"location"`
	Name     string `json:"name"`
	Primary  bool   `json:"primary,omitempty"`
}

// ObjectModel is the deliberately narrow BOLA model accepted by the gateway.
// A model must be publishable and unique and declare either legacy OWNER-only
// authorization or a validated ANY_OF relation set before it can authorize.
type ObjectModel struct {
	ApplicationID    string             `json:"application_id,omitempty"`
	EndpointKey      string             `json:"endpoint_key"`
	Endpoint         string             `json:"endpoint,omitempty"`
	Method           string             `json:"method,omitempty"`
	PathTemplate     string             `json:"path_template,omitempty"`
	ObjectType       string             `json:"object_type"`
	Identifiers      []ObjectIdentifier `json:"identifiers"`
	RequiredRelation string             `json:"required_relation"`
	// RequiredRelations is used only by ANY_OF. The canonical runtime order is
	// OWNER, SHARED_WITH; legacy OWNER models omit this field.
	RequiredRelations      []string   `json:"required_relations,omitempty"`
	OwnerExclusive         bool       `json:"owner_exclusive"`
	Publishable            bool       `json:"publishable"`
	UniqueEndpointTemplate bool       `json:"unique_endpoint_template"`
	TenantID               string     `json:"tenant_id,omitempty"`
	PolicyVersion          string     `json:"policy_version,omitempty"`
	ModelVersion           string     `json:"model_version,omitempty"`
	Stale                  bool       `json:"stale,omitempty"`
	SnapshotExpiresAt      *time.Time `json:"snapshot_expires_at,omitempty"`
	// OnLeaseExpired per-endpoint 租约过期策略（NG-AZ-02 D5；
	// "strict"（缺省，过期 UNKNOWN 不做授权性放行）| "degraded"（评估继续强制 OBSERVE 标记））
	OnLeaseExpired string `json:"on_lease_expired,omitempty"`
	// ---- NG-AZ-03 实断资格字段（线契约；omitempty——v1/v2 快照无字段零变化）----
	// Enforcement per-endpoint 实断开关（§1.3/D3："OBSERVE"（缺省/未知值同义，不
	// 实断）| "PROTECT"（八因子资格全真时 VERIFIED_VIOLATION 可实断））。
	Enforcement string `json:"enforcement,omitempty"`
	// EnforcementOwner 切换 PROTECT 的业务负责人标识（§8.4 四要素②；审计随行）。
	EnforcementOwner string `json:"enforcement_owner,omitempty"`
	// EvidenceSource 证据来源声明（§8.4 四要素③；词表 AUTHORITY_SYNC|MANUAL_CONFIRMED）。
	EvidenceSource string `json:"evidence_source,omitempty"`
	// OnUnknown UNKNOWN 处理方式声明（§8.4 四要素④；首批仅 ALLOW_UNKNOWN——
	// UNKNOWN 放行并记录；网关 UNKNOWN 永不阻断红线与之天然一致，消费侧仅随行不动作）。
	OnUnknown string `json:"on_unknown,omitempty"`
}

// AuthzObjectModel is retained as a descriptive alias for callers.
type AuthzObjectModel = ObjectModel

type ObjectRelation struct {
	ApplicationID      string     `json:"application_id,omitempty"`
	PrincipalID        string     `json:"principal_id,omitempty"`
	SubjectPrincipalID string     `json:"subject_principal_id,omitempty"`
	ObjectType         string     `json:"object_type"`
	ObjectRef          string     `json:"object_ref"`
	Relation           string     `json:"relation"`
	RelationType       string     `json:"relation_type,omitempty"`
	Status             string     `json:"status"`
	TenantID           string     `json:"tenant_id,omitempty"`
	ValidFrom          *time.Time `json:"valid_from,omitempty"`
	ValidUntil         *time.Time `json:"valid_until,omitempty"`
}

type AuthzObjectRelation = ObjectRelation

// VerifiedRoleBaseline is a confirmed role-to-endpoint decision baseline.
// Role claims are supplied only by jwtverify.VerificationResult.VerifiedRoles.
type VerifiedRoleBaseline struct {
	ApplicationID string `json:"application_id,omitempty"`
	EndpointKey   string `json:"endpoint_key"`
	Method        string `json:"method,omitempty"`
	Role          string `json:"role"`
	Action        string `json:"action,omitempty"`
	Allowed       bool   `json:"allowed"`
	Confirmed     bool   `json:"confirmed"`
	// Enforcement per-角色基线行实断开关（NG-AZ-03 §1.3/D3；"OBSERVE"|"PROTECT"；
	// 空 = 无行级配置，继承端点 object model 值；omitempty——旧快照无字段零变化）。
	Enforcement string `json:"enforcement,omitempty"`
}

type AuthzRoleBaseline = VerifiedRoleBaseline

// AuthorizationConfig is the immutable per-request authorization snapshot.
type AuthorizationConfig struct {
	ApplicationID string
	EndpointKey   string
	Models        []ObjectModel
	Relations     []ObjectRelation
	// RelationIndex is an optional immutable lookup table built when a
	// snapshot is published. Its key is application/object type/object ref;
	// callers that do not build an index retain the compatibility linear scan.
	RelationIndex    map[string][]ObjectRelation `json:"-"`
	RoleBaselines    []VerifiedRoleBaseline
	ObjectRefHMACKey []byte
	PolicyVersion    string
	// Stale and SnapshotExpiresAt describe the compiled snapshot as a whole.
	// Model-level freshness remains supported for mixed snapshots.
	Stale             bool
	SnapshotExpiresAt *time.Time
	// PreviousValid is the last snapshot known to be usable. It is optional so
	// callers can keep the current fail-closed UNKNOWN behavior when no prior
	// snapshot is available.
	PreviousValid *AuthorizationConfig
	Now           func() time.Time

	// ---- NG-AZ-02 v2 快照字段（零值即 v1 快照，D4-3 逐字节兼容）----
	// Schema 快照 schema 闸门（D4-3）：恒 "authz-snap/2" 时启用 v2 语义。
	Schema string
	// RevocationWatermark 本快照编译时刻管理面向量水位（D1/D2）。
	RevocationWatermark *RevocationWatermark
	// LeaseSeconds 租约秒数（D5；0=未启用租约约束）。
	LeaseSeconds int
	// AppliedAt 快照应用时刻（租约判定基准——节点本地时钟，不依赖管理面时钟）。
	AppliedAt time.Time
	// ConflictedObjects 决策侧排除集（D7；ConflictedIndex 为其 O(1) 索引）。
	ConflictedObjects []ConflictedObject
	ConflictedIndex   map[string]struct{} `json:"-"`
	// ProducedAt 快照编译时刻（D8 漂移自检基准）。
	ProducedAt *time.Time
	// ClockSkewMaxSeconds 漂移上限（D8；0=缺省 60，装配侧已夹紧 10~300）。
	ClockSkewMaxSeconds int
	// EngineProtect 决策引擎 PROTECT 语义（NG-AZ-03 §1.1 双闸之一：VERIFIED_VIOLATION
	// 仅在端点 enforcement=PROTECT 且本标记为真时产出并实断；false（零值）= OBSERVE
	// 语义——资格全真也降级 OBSERVE_VIOLATION 同语义记录，不实断）。
	EngineProtect bool
}

// BuildAuthorizationRelationIndex prepares the relation lookup used by the
// gateway hot path. The returned map owns its slices and can be shared by an
// immutable authorization snapshot.
func BuildAuthorizationRelationIndex(relations []ObjectRelation) map[string][]ObjectRelation {
	if len(relations) == 0 {
		return nil
	}
	index := make(map[string][]ObjectRelation, len(relations))
	for _, relation := range relations {
		key := authorizationRelationIndexKey(relation.ApplicationID, relation.ObjectType, relation.ObjectRef)
		index[key] = append(index[key], relation)
	}
	return index
}

func cloneAuthorizationSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	out := make([]T, len(values))
	copy(out, values)
	return out
}

func cloneAuthorizationModels(models []ObjectModel) []ObjectModel {
	out := cloneAuthorizationSlice(models)
	for i := range out {
		out[i].Identifiers = cloneAuthorizationSlice(models[i].Identifiers)
		out[i].RequiredRelations = cloneAuthorizationSlice(models[i].RequiredRelations)
	}
	return out
}

func cloneAuthorizationRelationIndex(index map[string][]ObjectRelation) map[string][]ObjectRelation {
	if index == nil {
		return nil
	}
	out := make(map[string][]ObjectRelation, len(index))
	for key, relations := range index {
		out[key] = cloneAuthorizationSlice(relations)
	}
	return out
}

// CloneAuthorizationConfig isolates every slice in a retained snapshot before
// request-scoped fallback evaluation. Model arrays are copied recursively so
// normalizing or extending one snapshot cannot mutate another.
func CloneAuthorizationConfig(cfg AuthorizationConfig) AuthorizationConfig {
	out := cfg
	out.Models = cloneAuthorizationModels(cfg.Models)
	out.Relations = cloneAuthorizationSlice(cfg.Relations)
	out.RelationIndex = cloneAuthorizationRelationIndex(cfg.RelationIndex)
	out.RoleBaselines = cloneAuthorizationSlice(cfg.RoleBaselines)
	out.ObjectRefHMACKey = cloneAuthorizationSlice(cfg.ObjectRefHMACKey)
	out.ConflictedObjects = cloneAuthorizationSlice(cfg.ConflictedObjects)
	return out
}

func authorizationRelationIndexKey(applicationID, objectType, objectRef string) string {
	return applicationID + "\x00" + strings.ToUpper(objectType) + "\x00" + objectRef
}

type AuthorizationDecision = dsevents.AuthorizationDecision

const (
	AuthorizationAllow             = dsevents.AuthorizationAllow
	AuthorizationObserveViolation  = dsevents.AuthorizationObserveViolation
	AuthorizationUnknown           = dsevents.AuthorizationUnknown
	AuthorizationVerifiedViolation = dsevents.AuthorizationVerifiedViolation
)

type AuthorizationCheck = dsevents.AuthorizationCheck
type AuthorizationDecisionGroup = dsevents.AuthorizationDecisionGroup

// ObjectRefHMAC returns the only object identity representation allowed in a
// decision or event. The raw identifier is never retained by this package.
func ObjectRefHMAC(key []byte, raw string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte("jiuzhang-wdsp-authz-objref-v1\x00"))
	_, _ = m.Write([]byte(raw))
	return "objref:" + hex.EncodeToString(m.Sum(nil))
}

// EvaluateAuthorization runs independent BFLA and BOLA checks. Decisions other
// than VERIFIED_VIOLATION never change the request action: violation and unknown
// are OBSERVE signals. NG-AZ-03：仅当八因子资格全真、端点 enforcement=PROTECT 且
// 决策引擎 PROTECT 语义（cfg.EngineProtect）时产出 VERIFIED_VIOLATION——它以
// category=BLOCK finding 写 ctx，由既有 BLOCK 定案链实断；UNKNOWN 永不映射 BLOCK。
func EvaluateAuthorization(ctx *dsctx.RequestContext, parsed *parser.Parsed, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult) *AuthorizationDecisionGroup {
	if ctx == nil || parsed == nil {
		return nil
	}
	now := time.Now().UTC()
	if cfg.Now != nil {
		now = cfg.Now().UTC()
	}
	group := &AuthorizationDecisionGroup{DecisionID: authorizationDecisionID(ctx, cfg.EndpointKey), PolicyVersion: cfg.PolicyVersion, Decision: AuthorizationAllow, Checks: []AuthorizationCheck{}}
	if group.PolicyVersion == "" && jwt != nil {
		group.PolicyVersion = jwt.PolicyVersion
	}
	effectiveCfg := cfg
	snapshotStale := authorizationSnapshotExpired(cfg, parsed, now)
	fallbackSelected := false
	if snapshotStale {
		// NG-AZ-02 D4-2：PreviousValid 回退二次水位校验——候选水位必须 ≥ 节点已应用
		// （当前）快照水位，否则拒绝回退（v1 候选在 v2 当前水位非零时天然不合格——
		// 旧许可不得借回退复活；不合格即落 AUTHZ-POLICY-002 UNKNOWN 现状语义延伸）。
		fallbackEligible := cfg.PreviousValid != nil && !authorizationSnapshotExpired(*cfg.PreviousValid, parsed, now)
		if fallbackEligible && authzV2(cfg) && !cfg.PreviousValid.RevocationWatermark.AtLeast(cfg.RevocationWatermark) {
			fallbackEligible = false
		}
		if fallbackEligible {
			effectiveCfg = CloneAuthorizationConfig(*cfg.PreviousValid)
			// PreviousValid is a snapshot of authorization data. Keep the
			// request-scoped application and endpoint selectors from the active
			// configuration so the snapshot can still match the current request.
			effectiveCfg.ApplicationID = cfg.ApplicationID
			effectiveCfg.EndpointKey = cfg.EndpointKey
			// NG-AZ-03：决策引擎 PROTECT 语义是请求级输入而非快照事实，
			// 回退后随当前配置保留（双闸之二不随历史快照失效）。
			effectiveCfg.EngineProtect = cfg.EngineProtect
			fallbackSelected = true
			// A fallback is selected once per request. Do not recursively follow
			// another pointer if the retained config was itself assembled from a
			// previous fallback.
			effectiveCfg.PreviousValid = nil
		}
		group.Checks = append(group.Checks, AuthorizationCheck{
			Type: "POLICY", Decision: AuthorizationUnknown, ReasonCode: "AUTHZ-POLICY-002",
			PolicyVersion: cfg.PolicyVersion,
		})
	}
	if snapshotStale && !fallbackSelected {
		return finalizeAuthorizationDecision(ctx, group)
	}

	// NG-AZ-02 D5/D8 时效前置：漂移自检与租约过期（v1 快照恒 false，零介入）。
	skewExceeded := authzClockSkewExceeded(effectiveCfg, now)
	leaseExpired := authzLeaseExpired(effectiveCfg, now)
	// NG-AZ-03：端点模型单次匹配——BFLA enforcement 继承（无行级配置时端点继承
	// object model 值）与 BOLA 判定共用同一匹配视图，避免双扫口径漂移。
	endpointModels := matchingModels(effectiveCfg.Models, effectiveCfg.ApplicationID, effectiveCfg.EndpointKey, parsed)
	if skewExceeded || leaseExpired {
		// BFLA 无端点策略标志位，按 strict 缺省——时效异常时不做授权性放行
		// （D8「禁止严格授权放行」对角色基线同义：基线同为时效快照事实）；
		// 无角色基线时不产空载检查（避免无 BFLA 端点被租约噪声污染）
		if len(effectiveCfg.RoleBaselines) > 0 {
			check := AuthorizationCheck{Type: "BFLA", Confidence: 1, RelationState: "N/A"}
			if skewExceeded {
				check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-CLOCK-001"
			} else {
				check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-LEASE-001"
				check.DependencyUnavailable = true
			}
			group.Checks = append(group.Checks, check)
		}
	} else if c, ok := evaluateBFLA(ctx, effectiveCfg, jwt, authzEndpointModel(endpointModels), now, skewExceeded, leaseExpired); ok {
		c.PolicyVersion = authorizationPolicyVersion(c.PolicyVersion, effectiveCfg, jwt)
		group.Checks = append(group.Checks, c)
	}
	bolaChecks, bolaOK := evaluateBOLA(ctx, parsed, effectiveCfg, jwt, now, skewExceeded, leaseExpired, endpointModels)
	if bolaOK {
		for _, c := range bolaChecks {
			c.PolicyVersion = authorizationPolicyVersion(c.PolicyVersion, effectiveCfg, jwt)
			group.Checks = append(group.Checks, c)
		}
	}
	return finalizeAuthorizationDecision(ctx, group)
}

func finalizeAuthorizationDecision(ctx *dsctx.RequestContext, group *AuthorizationDecisionGroup) *AuthorizationDecisionGroup {
	for _, c := range group.Checks {
		switch c.Decision {
		case AuthorizationVerifiedViolation:
			// NG-AZ-03：VERIFIED_VIOLATION 组决策优先级最高（判定结论非动作——
			// 动作经下方 category=BLOCK finding 走既有 BLOCK 定案链，final_action
			// 恒为既有词表）
			group.Decision = AuthorizationVerifiedViolation
		case AuthorizationObserveViolation:
			if group.Decision != AuthorizationVerifiedViolation {
				group.Decision = AuthorizationObserveViolation
			}
		case AuthorizationUnknown:
			if group.Decision == AuthorizationAllow {
				group.Decision = AuthorizationUnknown
			}
		}
		if c.PolicyVersion != "" && group.PolicyVersion == "" {
			group.PolicyVersion = c.PolicyVersion
		}
	}
	if len(group.Checks) == 0 {
		return nil
	}
	ctx.SetExtension("authz.decision_group", group)
	for _, c := range group.Checks {
		if c.Decision == AuthorizationAllow {
			continue
		}
		evidence := map[string]string{"decision": string(c.Decision), "check_type": c.Type}
		if c.ReasonCode != "" {
			evidence["reason_code"] = c.ReasonCode
		}
		if c.ObjectRef != "" {
			evidence["object_ref"] = c.ObjectRef
		}
		if c.RelationState != "" {
			evidence["relation_state"] = c.RelationState
		}
		if c.TenantState != "" {
			evidence["tenant_state"] = c.TenantState
		}
		if c.DependencyUnavailable {
			// NG-AZ-02 D5：依赖不可用如实披露（租约过期 strict——授权事实源失效，
			// 与「不静默降级」区分，事件可检索）
			evidence["dependency_unavailable"] = "true"
		}
		if c.ProposedDecision != "" {
			// NG-AZ-03 §1.1 拟动作保留：OBSERVE 形态降级的 VERIFIED_VIOLATION 留痕
			evidence["proposed_decision"] = string(c.ProposedDecision)
		}
		category, severity := "OBSERVE", "MEDIUM"
		if c.Decision == AuthorizationVerifiedViolation {
			// NG-AZ-03 D4：VERIFIED_VIOLATION 以 category=BLOCK + enforced=true
			// 写 ctx——决策引擎按既有 BLOCK 资格定案（category=BLOCK 即资格，
			// 与其他防护域同一执行平面；OBSERVE 模式由决策引擎既有降级链兜底）
			category, severity = "BLOCK", "HIGH"
			evidence["enforced"] = "true"
		}
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_authz", RuleID: c.ReasonCode, Category: category, Severity: severity, Evidence: evidence})
	}
	return group
}

func authorizationSnapshotExpired(cfg AuthorizationConfig, parsed *parser.Parsed, now time.Time) bool {
	if cfg.Stale || (cfg.SnapshotExpiresAt != nil && !now.Before(cfg.SnapshotExpiresAt.UTC())) {
		return true
	}
	for _, model := range matchingModels(cfg.Models, cfg.ApplicationID, cfg.EndpointKey, parsed) {
		if model.Stale || (model.SnapshotExpiresAt != nil && !now.Before(model.SnapshotExpiresAt.UTC())) {
			return true
		}
	}
	return false
}

func authorizationPolicyVersion(checkVersion string, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult) string {
	if cfg.PolicyVersion != "" {
		return cfg.PolicyVersion
	}
	if checkVersion != "" {
		return checkVersion
	}
	if jwt != nil {
		return jwt.PolicyVersion
	}
	return ""
}

func authorizationDecisionID(ctx *dsctx.RequestContext, endpoint string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(ctx.RequestID))
	_, _ = h.Write([]byte("\x00"))
	_, _ = h.Write([]byte(endpoint))
	_, _ = h.Write([]byte("\x00"))
	_, _ = h.Write([]byte(ctx.OccurredAt.UTC().Format(time.RFC3339Nano)))
	raw := hex.EncodeToString(h.Sum(nil)[:16])
	return raw[0:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:32]
}

func trustedIdentity(jwt *jwtverify.VerificationResult) bool {
	return jwt != nil && jwt.Status == jwtverify.StatusVerified && strings.TrimSpace(jwt.VerifiedPrincipalID) != ""
}

// evaluateBFLA 角色基线判定。NG-AZ-03 资格段：违规成立（显式 deny 行或无覆盖
// 角色行）且相关行有效 enforcement=PROTECT（无行级配置继承端点 object model 值）
// 且决策引擎 PROTECT 语义时升级 VERIFIED_VIOLATION——同资格门槛（身份可信/时效
// 新鲜/水位未回退）由入口前置闸保证（时效异常已在 EvaluateAuthorization 前置
// UNKNOWN 短路，水位回退装配期 fail-closed 拒载，身份上方 IDENTITY-001 拦截）。
func evaluateBFLA(ctx *dsctx.RequestContext, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult, endpointModel *ObjectModel, now time.Time, skewExceeded, leaseExpired bool) (AuthorizationCheck, bool) {
	var matched []VerifiedRoleBaseline
	for _, b := range cfg.RoleBaselines {
		if !sameApplication(cfg.ApplicationID, b.ApplicationID) || !b.Confirmed || (b.EndpointKey != "" && b.EndpointKey != cfg.EndpointKey) || (b.Method != "" && !strings.EqualFold(b.Method, methodFromEndpoint(cfg.EndpointKey))) {
			continue
		}
		matched = append(matched, b)
	}
	if len(matched) == 0 {
		return AuthorizationCheck{}, false
	}
	base := AuthorizationCheck{Type: "BFLA", Confidence: 1, RelationState: "N/A"}
	if hasConflictingBFLABaselines(matched) {
		base.Decision, base.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-001"
		return base, true
	}
	if !trustedIdentity(jwt) {
		base.Decision, base.ReasonCode = AuthorizationUnknown, "AUTHZ-IDENTITY-001"
		return base, true
	}
	base.RoleSource = "VERIFIED"
	roles := make(map[string]bool, len(jwt.VerifiedRoles))
	for _, role := range jwt.VerifiedRoles {
		roles[strings.TrimSpace(role)] = true
	}
	if len(roles) == 0 {
		base.Decision, base.ReasonCode = AuthorizationUnknown, "AUTHZ-ROLE-001"
		return base, true
	}
	allowed, denied := false, false
	for _, b := range matched {
		if !roles[strings.TrimSpace(b.Role)] {
			continue
		}
		if b.Allowed {
			allowed = true
		} else {
			denied = true
		}
	}
	if allowed {
		base.Decision = AuthorizationAllow
		return base, true
	}
	// 违规事实本体：显式 deny 行（角色被基线明确拒绝）；无覆盖角色行时端点基线
	// 集整体构成违规事实（该端点的允许角色集不含本主体任何已验证角色）。
	var violating []VerifiedRoleBaseline
	for _, b := range matched {
		if roles[strings.TrimSpace(b.Role)] && !b.Allowed {
			violating = append(violating, b)
		}
	}
	if len(violating) == 0 {
		violating = matched
	}
	base.Decision, base.ReasonCode = AuthorizationObserveViolation, "AUTHZ-BFLA-001"
	enf := resolveBFLAEnforcement(violating, endpointModel)
	if !enf.configured {
		// enforcement 全未配置（v1/v2 旧快照）：既有 OBSERVE 语义零变化，不留拟动作痕
		return base, true
	}
	eligibility := map[string]bool{
		"trusted_identity":     trustedIdentity(jwt),
		"baselines_applicable": len(matched) > 0 && !hasConflictingBFLABaselines(matched),
		"evidence_fresh":       !skewExceeded && !leaseExpired,
		"role_violation":       denied || len(violating) > 0,
	}
	if authzEligibilityAllTrue(eligibility) && enf.protect && cfg.EngineProtect {
		base.Decision = AuthorizationVerifiedViolation
		authzAppendEnforcementEvidence(ctx, buildBFLAEnforcementEvidence(cfg, enf, eligibility, jwt, now))
		return base, true
	}
	// 拟动作保留（§1.1）：资格全真但 OBSERVE 形态（enforcement 或决策引擎未双
	// PROTECT）降级 OBSERVE_VIOLATION 同语义记录
	if authzEligibilityAllTrue(eligibility) {
		base.ProposedDecision = AuthorizationVerifiedViolation
	}
	return base, true
}

// authzBFLAEnforcement BFLA 实断资格来源解析（行级显式优先，缺省继承端点模型）。
type authzBFLAEnforcement struct {
	configured     bool   // 相关行或端点模型声明了 enforcement（全空 = 未配置，零变化路径）
	protect        bool   // 存在有效 PROTECT 声明（取首个）
	inherited      bool   // PROTECT 来自端点模型继承（false = 行级显式）
	owner          string // 继承来源模型的 enforcement_owner（行级无伴随列，留空）
	evidenceSource string // 继承来源模型的 evidence_source
	modelVersion   string // 继承来源模型的 model_version
}

// resolveBFLAEnforcement 解析违规相关行的有效 enforcement：行级非空值优先，
// 空值继承端点 object model（§1.3「无行级配置时端点继承 object model 值」）；
// 词表外值不视为 PROTECT（fail-safe 不实断），但构成已配置声明。
func resolveBFLAEnforcement(rows []VerifiedRoleBaseline, endpointModel *ObjectModel) authzBFLAEnforcement {
	var out authzBFLAEnforcement
	modelEnforcement := ""
	if endpointModel != nil {
		modelEnforcement = strings.TrimSpace(endpointModel.Enforcement)
	}
	for _, b := range rows {
		effective := strings.TrimSpace(b.Enforcement)
		inherited := false
		if effective == "" {
			effective, inherited = modelEnforcement, true
		}
		if effective == "" {
			continue
		}
		out.configured = true
		if authzEnforcementProtect(effective) && !out.protect {
			out.protect, out.inherited = true, inherited
			if inherited && endpointModel != nil {
				out.owner = endpointModel.EnforcementOwner
				out.evidenceSource = endpointModel.EvidenceSource
				out.modelVersion = endpointModel.ModelVersion
			}
		}
	}
	return out
}

func hasConflictingBFLABaselines(baselines []VerifiedRoleBaseline) bool {
	seen := make(map[string]bool, len(baselines))
	for _, baseline := range baselines {
		// Action is retained as snapshot metadata, but the gateway cannot
		// observe the business action. Opposite decisions for one role on the
		// same matched endpoint are therefore ambiguous at runtime, regardless
		// of the action labels attached to the rows.
		key := strings.TrimSpace(baseline.Role)
		if allowed, ok := seen[key]; ok && allowed != baseline.Allowed {
			return true
		}
		seen[key] = baseline.Allowed
	}
	return false
}

func methodFromEndpoint(endpoint string) string {
	if i := strings.IndexByte(endpoint, ' '); i >= 0 {
		return endpoint[:i]
	}
	return ""
}

// evaluateBOLA BOLA 判定（可返回评估结论 + degraded 时效标记两条检查）。
// NG-AZ-02 注入点：strict 端点时效拒绝（D5/D8 先于对象提取）、冲突对象排除
// （D7 先于关系判定——冲突对象既不出 VERIFIED/ALLOW 也不出其他可信判定）、
// degraded 端点评估继续但强制 OBSERVE 级 + UNKNOWN 标记（作为第二条检查返回）。
// NG-AZ-03 注入点：OTHER_OWNER 成立后过 §1.2 八因子资格段——全真且端点
// enforcement=PROTECT 且决策引擎 PROTECT 语义才落 VERIFIED_VIOLATION 并生成
// authz_enforcement 证据；任一不真按既有 reason code 落 UNKNOWN（或 TENANT-001
// 的 OBSERVE_VIOLATION），绝不折算；OBSERVE 形态降级 OBSERVE_VIOLATION 同语义
// 记录（拟动作保留）。models 由 EvaluateAuthorization 单次匹配后传入。
func evaluateBOLA(ctx *dsctx.RequestContext, parsed *parser.Parsed, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult, now time.Time, skewExceeded, leaseExpired bool, models []ObjectModel) ([]AuthorizationCheck, bool) {
	if len(models) == 0 {
		return nil, false
	}
	check := AuthorizationCheck{Type: "BOLA", Confidence: 1}
	if !trustedIdentity(jwt) {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-IDENTITY-001"
		return []AuthorizationCheck{check}, true
	}
	if len(models) != 1 {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-001"
		return []AuthorizationCheck{check}, true
	}
	model := models[0]
	allowedRelations, relationPolicyOK := authorizationAllowedRelations(model)
	if !model.UniqueEndpointTemplate || !model.Publishable || !model.OwnerExclusive || !relationPolicyOK {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-001"
		return []AuthorizationCheck{check}, true
	}
	check.ObjectType, check.ModelVersion = model.ObjectType, model.ModelVersion
	// NG-AZ-02 D5/D8：strict 端点时效拒绝（不做授权性放行；租约附依赖不可用披露）
	if reason := authzTimedOutReason(model, skewExceeded, leaseExpired); reason != "" {
		check.Decision, check.ReasonCode = AuthorizationUnknown, reason
		check.DependencyUnavailable = leaseExpired && reason == "AUTHZ-LEASE-001"
		return []AuthorizationCheck{check}, true
	}
	if model.Stale || (model.SnapshotExpiresAt != nil && !now.Before(*model.SnapshotExpiresAt)) {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-002"
		return []AuthorizationCheck{check}, true
	}
	ref, reason := extractObjectRef(parsed, model, cfg.ObjectRefHMACKey)
	if reason != "" {
		check.Decision, check.ReasonCode = AuthorizationUnknown, reason
		return []AuthorizationCheck{check}, true
	}
	check.ObjectRef = ref
	// NG-AZ-02 D7：冲突对象排除（schema 闸门 + O(1) 查找；OPEN 冲突 = 事实不可信如实 UNKNOWN，
	// 不出 VERIFIED_VIOLATION 也不出授权性 ALLOW——冲突不得被用作放行通道）
	if authzV2(cfg) && Conflicted(cfg.ConflictedIndex, cfg.ApplicationID, model.ObjectType, ref) {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-CONFLICT-001"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	relations := cfg.Relations
	if cfg.RelationIndex != nil {
		relations = cfg.RelationIndex[authorizationRelationIndexKey(cfg.ApplicationID, model.ObjectType, ref)]
	}
	var ownerRels, sharedRels []ObjectRelation
	for _, r := range relations {
		if !sameApplication(cfg.ApplicationID, r.ApplicationID) || r.ObjectRef != ref || !strings.EqualFold(r.ObjectType, model.ObjectType) || !strings.EqualFold(r.Status, "CONFIRMED") || !relationValid(r, now) {
			continue
		}
		switch relation := strings.ToUpper(relationName(r)); relation {
		case "OWNER":
			ownerRels = append(ownerRels, r)
		case "SHARED_WITH":
			if authorizationRelationAllowed(allowedRelations, relation) {
				sharedRels = append(sharedRels, r)
			}
		}
	}
	// Sharing is never a standalone ownership fact: without a valid OWNER row the
	// object remains indeterminate even when the requester has a valid share.
	if len(ownerRels) == 0 {
		check.Decision, check.ReasonCode, check.RelationState = AuthorizationUnknown, "AUTHZ-RELATION-001", "NONE"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	identityTenant := strings.TrimSpace(jwt.VerifiedTenantID)
	tenantIDs := make(map[string]struct{}, len(ownerRels)+len(sharedRels)+1)
	if tenant := strings.TrimSpace(model.TenantID); tenant != "" {
		tenantIDs[tenant] = struct{}{}
	}
	for _, rels := range [][]ObjectRelation{ownerRels, sharedRels} {
		for _, r := range rels {
			if tenant := strings.TrimSpace(r.TenantID); tenant != "" {
				tenantIDs[tenant] = struct{}{}
			}
		}
	}
	if len(tenantIDs) > 1 {
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationUnknown, "AUTHZ-TENANT-002", "CONFLICT"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	objectTenant := ""
	for tenant := range tenantIDs {
		objectTenant = tenant
	}
	if identityTenant != "" && objectTenant != "" && identityTenant != objectTenant {
		eligibility := map[string]bool{
			"trusted_identity": trustedIdentity(jwt),
			"model_applicable": len(models) == 1 && model.UniqueEndpointTemplate && model.Publishable && relationPolicyOK &&
				!model.Stale && (model.SnapshotExpiresAt == nil || now.Before(model.SnapshotExpiresAt.UTC())),
			"relation_valid":  len(ownerRels) > 0,
			"no_conflict":     !authzV2(cfg) || !Conflicted(cfg.ConflictedIndex, cfg.ApplicationID, model.ObjectType, ref),
			"tenant_mismatch": true,
			"evidence_fresh":  !skewExceeded && !leaseExpired,
		}
		if authzEligibilityAllTrue(eligibility) && authzEnforcementProtect(model.Enforcement) && cfg.EngineProtect {
			check.Decision, check.ReasonCode, check.TenantState = AuthorizationVerifiedViolation, "AUTHZ-TENANT-001", "MISMATCH"
			authzAppendEnforcementEvidence(ctx, buildBOLAEnforcementEvidence(cfg, model, ref, "AUTHZ-TENANT-001", eligibility, jwt, now))
			return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
		}
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationObserveViolation, "AUTHZ-TENANT-001", "MISMATCH"
		if authzEligibilityAllTrue(eligibility) && strings.TrimSpace(model.Enforcement) != "" {
			check.ProposedDecision = AuthorizationVerifiedViolation
		}
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	if (identityTenant == "") != (objectTenant == "") {
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationUnknown, "AUTHZ-TENANT-002", "INCOMPLETE"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	var own, other, shared bool
	for _, r := range ownerRels {
		pid := authorizationRelationPrincipal(r)
		if pid == jwt.VerifiedPrincipalID {
			own = true
		} else if pid != "" {
			other = true
		}
	}
	for _, r := range sharedRels {
		if authorizationRelationPrincipal(r) == jwt.VerifiedPrincipalID {
			shared = true
		}
	}
	if own {
		check.Decision, check.RelationState = AuthorizationAllow, "EFFECTIVE_OWNER"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	if shared && other {
		check.Decision, check.RelationState = AuthorizationAllow, "EFFECTIVE_SHARED_WITH"
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	if other {
		// NG-AZ-03 §1.2 八因子资格段：到达本分支时各因子已在上方按既有 reason
		// code 逐一把守（任一不真已提前返回 UNKNOWN / TENANT-001 OBSERVE_VIOLATION）。
		// 此处逐因子显式重算留证——资格判定可执行化，既作证据（§1.4 eligibility）
		// 又防未来改动静默放大实断面；「部分满足」绝无折算空间。
		eligibility := map[string]bool{
			"trusted_identity": trustedIdentity(jwt),
			"model_applicable": len(models) == 1 && model.UniqueEndpointTemplate && model.Publishable && relationPolicyOK &&
				!model.Stale && (model.SnapshotExpiresAt == nil || now.Before(model.SnapshotExpiresAt.UTC())),
			"relation_valid":    len(ownerRels) > 0,
			"no_conflict":       !authzV2(cfg) || !Conflicted(cfg.ConflictedIndex, cfg.ApplicationID, model.ObjectType, ref),
			"tenant_consistent": authzBOLATenantConsistent(identityTenant, objectTenant, tenantIDs),
			// 证据新鲜（授权事实）：租约未过期 + 无负向漂移；水位回退由装配期
			// fail-closed 拒载（NG-AZ-02 D4-1）与回退二次校验（D4-2）保证不入请求路径
			"evidence_fresh":  !skewExceeded && !leaseExpired,
			"other_owner":     other,
			"owner_exclusive": model.OwnerExclusive,
		}
		if authzEligibilityAllTrue(eligibility) && authzEnforcementProtect(model.Enforcement) && cfg.EngineProtect {
			check.Decision, check.ReasonCode, check.RelationState = AuthorizationVerifiedViolation, "AUTHZ-BOLA-001", "OTHER_OWNER"
			authzAppendEnforcementEvidence(ctx, buildBOLAEnforcementEvidence(cfg, model, ref, "AUTHZ-BOLA-001", eligibility, jwt, now))
			return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
		}
		check.Decision, check.ReasonCode, check.RelationState = AuthorizationObserveViolation, "AUTHZ-BOLA-001", "OTHER_OWNER"
		// 拟动作保留（§1.1）：资格全真但 OBSERVE 形态（enforcement 或决策引擎未
		// 双 PROTECT）降级 OBSERVE_VIOLATION 同语义记录；enforcement 未配置
		// （v1/v2 旧快照无字段）零变化不留痕
		if authzEligibilityAllTrue(eligibility) && strings.TrimSpace(model.Enforcement) != "" {
			check.ProposedDecision = AuthorizationVerifiedViolation
		}
		return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
	}
	check.Decision, check.ReasonCode, check.RelationState = AuthorizationUnknown, "AUTHZ-BOLA-002", "INSUFFICIENT"
	return authzBOLAWithDegradedMarker(check, model, skewExceeded, leaseExpired), true
}

// authzBOLAWithDegradedMarker degraded 端点时效标记（D5/D8：评估结论照常返回，
// 另附 UNKNOWN 标记检查——标记检查使组决策如实落 UNKNOWN/OBSERVE，不放行不静默）。
func authzBOLAWithDegradedMarker(check AuthorizationCheck, model ObjectModel, skewExceeded, leaseExpired bool) []AuthorizationCheck {
	marker := authzDegradedMarkerReason(model, skewExceeded, leaseExpired)
	if marker == "" {
		return []AuthorizationCheck{check}
	}
	return []AuthorizationCheck{check, {
		Type: "BOLA", Decision: AuthorizationUnknown, ReasonCode: marker,
		DependencyUnavailable: marker == "AUTHZ-LEASE-002",
	}}
}

// ---------- NG-AZ-03 阻断资格与实断证据（§1.1/§1.2/§1.4/D2/D4）----------

// authzEnforcementProtect 实断开关判定：仅精确 "PROTECT" 视为实断声明
// （缺省/词表外值一律 OBSERVE 语义——fail-safe 不拦截优于误拦截）。
func authzEnforcementProtect(enforcement string) bool {
	return strings.TrimSpace(enforcement) == "PROTECT"
}

// authzEligibilityAllTrue 八因子全真判定（资格段唯一升级闸；任一不真绝不折算）。
func authzEligibilityAllTrue(eligibility map[string]bool) bool {
	for _, ok := range eligibility {
		if !ok {
			return false
		}
	}
	return true
}

// authzBOLATenantConsistent 范围一致因子（§1.2：租户冲突/不一致/不完整均已
// 在上方提前返回，此处显式重算留证）。
func authzBOLATenantConsistent(identityTenant, objectTenant string, tenantIDs map[string]struct{}) bool {
	if len(tenantIDs) > 1 {
		return false
	}
	if identityTenant != "" && objectTenant != "" && identityTenant != objectTenant {
		return false
	}
	return (identityTenant == "") == (objectTenant == "")
}

// authzEndpointModel BFLA enforcement 继承来源：恰一匹配的端点 object model
// （零/多匹配时端点模型歧义，不继承——保守不落 PROTECT）。
func authzEndpointModel(models []ObjectModel) *ObjectModel {
	if len(models) != 1 {
		return nil
	}
	return &models[0]
}

// authzEnforcementEvidenceExtension 实断证据在请求上下文的扩展键
// （值为 []*dsevents.AuthzEnforcementEvidence；同一请求 BOLA/BFLA 可各产一条）。
const authzEnforcementEvidenceExtension = "authz.enforcement"

// authzAppendEnforcementEvidence 追加实断证据进请求上下文（仅 VERIFIED_VIOLATION
// 实断路径调用——§1.4「每次 VERIFIED_VIOLATION 实断生成一条证据记录」）。
func authzAppendEnforcementEvidence(ctx *dsctx.RequestContext, ev *dsevents.AuthzEnforcementEvidence) {
	if ctx == nil || ev == nil {
		return
	}
	var list []*dsevents.AuthzEnforcementEvidence
	if v, ok := ctx.GetExtension(authzEnforcementEvidenceExtension); ok {
		list, _ = v.([]*dsevents.AuthzEnforcementEvidence)
	}
	ctx.SetExtension(authzEnforcementEvidenceExtension, append(list, ev))
}

// AuthzEnforcementEvidenceFromContext 取本请求首条实断证据（确定性：BFLA 先于
// BOLA 评估，同请求多条的其余明细仍完整保留于 authz_decision 与 details）。
func AuthzEnforcementEvidenceFromContext(ctx *dsctx.RequestContext) *dsevents.AuthzEnforcementEvidence {
	if ctx == nil {
		return nil
	}
	v, ok := ctx.GetExtension(authzEnforcementEvidenceExtension)
	if !ok {
		return nil
	}
	list, _ := v.([]*dsevents.AuthzEnforcementEvidence)
	if len(list) == 0 {
		return nil
	}
	return list[0]
}

// buildBOLAEnforcementEvidence BOLA VERIFIED_VIOLATION 实断证据（§1.4 逐键冻结；
// object_ref 恒 HMAC 指纹——不落明文对象/主体标识）。
func buildBOLAEnforcementEvidence(cfg AuthorizationConfig, model ObjectModel, ref, reasonCode string, eligibility map[string]bool, jwt *jwtverify.VerificationResult, now time.Time) *dsevents.AuthzEnforcementEvidence {
	endpointKey := model.EndpointKey
	if endpointKey == "" {
		endpointKey = model.Endpoint
	}
	if endpointKey == "" {
		endpointKey = cfg.EndpointKey
	}
	if reasonCode == "" {
		reasonCode = "AUTHZ-BOLA-001"
	}
	return &dsevents.AuthzEnforcementEvidence{
		Decision:            string(AuthorizationVerifiedViolation),
		ReasonCode:          reasonCode,
		Enforced:            true,
		EndpointKey:         endpointKey,
		ModelVersion:        model.ModelVersion,
		PolicyVersion:       authorizationPolicyVersion("", cfg, jwt),
		RevocationWatermark: authzEvidenceWatermark(cfg.RevocationWatermark),
		PrincipalSource:     "JWT_VERIFIED",
		ObjectRef:           ref,
		Eligibility:         eligibility,
		LeaseSeconds:        cfg.LeaseSeconds,
		AppliedAtAgeSeconds: authzAppliedAtAgeSeconds(cfg, now),
		EnforcementOwner:    model.EnforcementOwner,
		EvidenceSource:      model.EvidenceSource,
		RecordedAt:          now.UTC().Format(time.RFC3339Nano),
	}
}

// buildBFLAEnforcementEvidence BFLA VERIFIED_VIOLATION 实断证据（顶层键与 §1.4
// 同构；BFLA 无对象维度——object_ref 置空，enforcement_owner/evidence_source/
// model_version 仅继承端点模型时有值（角色基线行无伴随列，行级 PROTECT 置空）；
// eligibility 为 BFLA 实际评估的资格键集）。
func buildBFLAEnforcementEvidence(cfg AuthorizationConfig, enf authzBFLAEnforcement, eligibility map[string]bool, jwt *jwtverify.VerificationResult, now time.Time) *dsevents.AuthzEnforcementEvidence {
	return &dsevents.AuthzEnforcementEvidence{
		Decision:            string(AuthorizationVerifiedViolation),
		ReasonCode:          "AUTHZ-BFLA-001",
		Enforced:            true,
		EndpointKey:         cfg.EndpointKey,
		ModelVersion:        enf.modelVersion,
		PolicyVersion:       authorizationPolicyVersion("", cfg, jwt),
		RevocationWatermark: authzEvidenceWatermark(cfg.RevocationWatermark),
		PrincipalSource:     "JWT_VERIFIED",
		ObjectRef:           "",
		Eligibility:         eligibility,
		LeaseSeconds:        cfg.LeaseSeconds,
		AppliedAtAgeSeconds: authzAppliedAtAgeSeconds(cfg, now),
		EnforcementOwner:    enf.owner,
		EvidenceSource:      enf.evidenceSource,
		RecordedAt:          now.UTC().Format(time.RFC3339Nano),
	}
}

// authzEvidenceWatermark 决策侧水位 → 证据水位视图（逐键拷贝不共享；
// v1 快照 nil → 零水位，键恒在）。
func authzEvidenceWatermark(w *RevocationWatermark) dsevents.AuthzEnforcementWatermark {
	if w == nil {
		return dsevents.AuthzEnforcementWatermark{}
	}
	out := dsevents.AuthzEnforcementWatermark{ManualSeq: w.ManualSeq}
	if len(w.Sources) > 0 {
		out.Sources = make(map[string]int64, len(w.Sources))
		for k, v := range w.Sources {
			out.Sources[k] = v
		}
	}
	return out
}

// authzAppliedAtAgeSeconds 快照应用时长秒数（§1.4 applied_at_age_seconds；
// 未启用租约（v1/无应用时刻）为 0，负值（时钟异常）归 0 不编造）。
func authzAppliedAtAgeSeconds(cfg AuthorizationConfig, now time.Time) int64 {
	if cfg.AppliedAt.IsZero() {
		return 0
	}
	age := int64(now.Sub(cfg.AppliedAt).Seconds())
	if age < 0 {
		return 0
	}
	return age
}

// authorizationAllowedRelations validates the narrow relation vocabulary and
// returns a canonical OWNER, SHARED_WITH order independent of snapshot order.
func authorizationAllowedRelations(model ObjectModel) ([]string, bool) {
	if strings.EqualFold(model.RequiredRelation, "OWNER") {
		if len(model.RequiredRelations) != 0 {
			return nil, false
		}
		return []string{"OWNER"}, true
	}
	if !strings.EqualFold(model.RequiredRelation, "ANY_OF") || len(model.RequiredRelations) != 2 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(model.RequiredRelations))
	for _, raw := range model.RequiredRelations {
		relation := strings.ToUpper(strings.TrimSpace(raw))
		if relation != "OWNER" && relation != "SHARED_WITH" {
			return nil, false
		}
		if _, duplicate := seen[relation]; duplicate {
			return nil, false
		}
		seen[relation] = struct{}{}
	}
	if _, ok := seen["OWNER"]; !ok {
		return nil, false
	}
	out := make([]string, 0, len(seen))
	for _, relation := range []string{"OWNER", "SHARED_WITH"} {
		if _, ok := seen[relation]; ok {
			out = append(out, relation)
		}
	}
	return out, true
}

func authorizationRelationAllowed(allowed []string, relation string) bool {
	for _, candidate := range allowed {
		if candidate == relation {
			return true
		}
	}
	return false
}

func authorizationRelationPrincipal(r ObjectRelation) string {
	if r.PrincipalID != "" {
		return r.PrincipalID
	}
	return r.SubjectPrincipalID
}

func relationName(r ObjectRelation) string {
	if r.Relation != "" {
		return r.Relation
	}
	return r.RelationType
}
func relationValid(r ObjectRelation, now time.Time) bool {
	return (r.ValidFrom == nil || !now.Before(r.ValidFrom.UTC())) && (r.ValidUntil == nil || now.Before(r.ValidUntil.UTC()))
}

func matchingModels(models []ObjectModel, applicationID, endpoint string, parsed *parser.Parsed) []ObjectModel {
	reqMethod := strings.ToUpper(strings.TrimSpace(parsed.Method))
	if reqMethod == "" {
		reqMethod = endpointMethod(endpoint)
	}
	var out []ObjectModel
	for _, m := range models {
		if !sameApplication(applicationID, m.ApplicationID) {
			continue
		}
		key := m.EndpointKey
		if key == "" {
			key = m.Endpoint
		}
		// A compiled model with an explicit method — or a method embedded in
		// EndpointKey/Endpoint — must never match a request of another method
		// through the path template fallback below.
		modelMethod := strings.TrimSpace(m.Method)
		if modelMethod == "" {
			modelMethod = endpointMethod(key)
		}
		if modelMethod != "" && reqMethod != "" && !strings.EqualFold(modelMethod, reqMethod) {
			continue
		}
		if key == endpoint ||
			(m.PathTemplate != "" && pathTemplateMatches(m.PathTemplate, parsed.RawPath)) ||
			(key != "" && pathTemplateMatches(endpointPath(key), endpointPath(endpoint))) {
			m.Identifiers = cloneAuthorizationSlice(m.Identifiers)
			m.RequiredRelations = cloneAuthorizationSlice(m.RequiredRelations)
			out = append(out, m)
		}
	}
	return out
}

func sameApplication(requestApplicationID, snapshotApplicationID string) bool {
	// Empty application IDs are only compatible with another unscoped
	// snapshot. A request with no application context must not consume facts
	// compiled for an arbitrary application, and an app-scoped request must
	// not consume an unscoped fallback snapshot.
	return requestApplicationID == snapshotApplicationID
}

func endpointMethod(endpoint string) string {
	if i := strings.IndexByte(endpoint, ' '); i > 0 {
		return strings.ToUpper(strings.TrimSpace(endpoint[:i]))
	}
	return ""
}

func endpointPath(endpoint string) string {
	if i := strings.IndexByte(endpoint, ' '); i >= 0 {
		return endpoint[i+1:]
	}
	return endpoint
}
func pathTemplateMatches(template, path string) bool {
	t := normalizer.CanonicalSegments(template)
	p := normalizer.CanonicalSegments(path)
	if len(t) != len(p) {
		return false
	}
	for i := range t {
		if strings.HasPrefix(t[i], "{") && strings.HasSuffix(t[i], "}") {
			continue
		}
		if t[i] != p[i] {
			return false
		}
	}
	return true
}

func extractObjectRef(parsed *parser.Parsed, model ObjectModel, key []byte) (string, string) {
	if len(key) == 0 {
		return "", "AUTHZ-OBJECT-003"
	}
	var id *ObjectIdentifier
	for i := range model.Identifiers {
		if model.Identifiers[i].Primary {
			if id != nil {
				return "", "AUTHZ-OBJECT-002"
			}
			id = &model.Identifiers[i]
		}
	}
	if id == nil && len(model.Identifiers) == 1 {
		id = &model.Identifiers[0]
	}
	if id == nil || id.Name == "" {
		return "", "AUTHZ-OBJECT-001"
	}
	var raw string
	switch strings.ToLower(id.Location) {
	case "query":
		for _, a := range parsed.Ambiguities {
			if a.Location == parser.AmbLocationQuery && a.ParameterName == id.Name {
				return "", "AUTHZ-OBJECT-002"
			}
		}
		raw = parsed.Query[id.Name]
	case "path":
		template := model.PathTemplate
		if template == "" {
			template = endpointPath(model.EndpointKey)
		}
		t, p := normalizer.CanonicalSegments(template), normalizer.CanonicalSegments(parsed.RawPath)
		for i := range t {
			if t[i] == "{"+id.Name+"}" && i < len(p) {
				raw = p[i]
				break
			}
		}
	default:
		return "", "AUTHZ-OBJECT-001"
	}
	if strings.TrimSpace(raw) == "" || len(raw) > 256 {
		return "", "AUTHZ-OBJECT-001"
	}
	return ObjectRefHMAC(key, raw), ""
}
