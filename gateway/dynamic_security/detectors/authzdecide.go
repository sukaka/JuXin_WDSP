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
// A model must be OWNER-only, publishable and unique before it can authorize.
type ObjectModel struct {
	ApplicationID          string             `json:"application_id,omitempty"`
	EndpointKey            string             `json:"endpoint_key"`
	Endpoint               string             `json:"endpoint,omitempty"`
	Method                 string             `json:"method,omitempty"`
	PathTemplate           string             `json:"path_template,omitempty"`
	ObjectType             string             `json:"object_type"`
	Identifiers            []ObjectIdentifier `json:"identifiers"`
	RequiredRelation       string             `json:"required_relation"`
	OwnerExclusive         bool               `json:"owner_exclusive"`
	Publishable            bool               `json:"publishable"`
	UniqueEndpointTemplate bool               `json:"unique_endpoint_template"`
	TenantID               string             `json:"tenant_id,omitempty"`
	PolicyVersion          string             `json:"policy_version,omitempty"`
	ModelVersion           string             `json:"model_version,omitempty"`
	Stale                  bool               `json:"stale,omitempty"`
	SnapshotExpiresAt      *time.Time         `json:"snapshot_expires_at,omitempty"`
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

func authorizationRelationIndexKey(applicationID, objectType, objectRef string) string {
	return applicationID + "\x00" + strings.ToUpper(objectType) + "\x00" + objectRef
}

type AuthorizationDecision = dsevents.AuthorizationDecision

const (
	AuthorizationAllow            = dsevents.AuthorizationAllow
	AuthorizationObserveViolation = dsevents.AuthorizationObserveViolation
	AuthorizationUnknown          = dsevents.AuthorizationUnknown
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

// EvaluateAuthorization runs independent BFLA and BOLA checks. It never
// changes the request action: violation and unknown are OBSERVE signals.
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
		if cfg.PreviousValid != nil && !authorizationSnapshotExpired(*cfg.PreviousValid, parsed, now) {
			effectiveCfg = *cfg.PreviousValid
			// PreviousValid is a snapshot of authorization data. Keep the
			// request-scoped application and endpoint selectors from the active
			// configuration so the snapshot can still match the current request.
			effectiveCfg.ApplicationID = cfg.ApplicationID
			effectiveCfg.EndpointKey = cfg.EndpointKey
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
	if c, ok := evaluateBFLA(effectiveCfg, jwt); ok {
		c.PolicyVersion = authorizationPolicyVersion(c.PolicyVersion, effectiveCfg, jwt)
		group.Checks = append(group.Checks, c)
	}
	if c, ok := evaluateBOLA(parsed, effectiveCfg, jwt, now); ok {
		c.PolicyVersion = authorizationPolicyVersion(c.PolicyVersion, effectiveCfg, jwt)
		group.Checks = append(group.Checks, c)
	}
	return finalizeAuthorizationDecision(ctx, group)
}

func finalizeAuthorizationDecision(ctx *dsctx.RequestContext, group *AuthorizationDecisionGroup) *AuthorizationDecisionGroup {
	for _, c := range group.Checks {
		switch c.Decision {
		case AuthorizationObserveViolation:
			group.Decision = AuthorizationObserveViolation
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
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "api_authz", RuleID: c.ReasonCode, Category: "OBSERVE", Severity: "MEDIUM", Evidence: evidence})
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

func evaluateBFLA(cfg AuthorizationConfig, jwt *jwtverify.VerificationResult) (AuthorizationCheck, bool) {
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
	if denied {
		base.Decision, base.ReasonCode = AuthorizationObserveViolation, "AUTHZ-BFLA-001"
		return base, true
	}
	base.Decision, base.ReasonCode = AuthorizationObserveViolation, "AUTHZ-BFLA-001"
	return base, true
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

func evaluateBOLA(parsed *parser.Parsed, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult, now time.Time) (AuthorizationCheck, bool) {
	models := matchingModels(cfg.Models, cfg.ApplicationID, cfg.EndpointKey, parsed)
	if len(models) == 0 {
		return AuthorizationCheck{}, false
	}
	check := AuthorizationCheck{Type: "BOLA", Confidence: 1}
	if !trustedIdentity(jwt) {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-IDENTITY-001"
		return check, true
	}
	if len(models) != 1 || !models[0].UniqueEndpointTemplate || !models[0].Publishable || !models[0].OwnerExclusive || !strings.EqualFold(models[0].RequiredRelation, "OWNER") {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-001"
		return check, true
	}
	model := models[0]
	check.ObjectType, check.ModelVersion = model.ObjectType, model.ModelVersion
	if model.Stale || (model.SnapshotExpiresAt != nil && !now.Before(*model.SnapshotExpiresAt)) {
		check.Decision, check.ReasonCode = AuthorizationUnknown, "AUTHZ-POLICY-002"
		return check, true
	}
	ref, reason := extractObjectRef(parsed, model, cfg.ObjectRefHMACKey)
	if reason != "" {
		check.Decision, check.ReasonCode = AuthorizationUnknown, reason
		return check, true
	}
	check.ObjectRef = ref
	relations := cfg.Relations
	if cfg.RelationIndex != nil {
		relations = cfg.RelationIndex[authorizationRelationIndexKey(cfg.ApplicationID, model.ObjectType, ref)]
	}
	var rels []ObjectRelation
	for _, r := range relations {
		if !sameApplication(cfg.ApplicationID, r.ApplicationID) || r.ObjectRef != ref || !strings.EqualFold(r.ObjectType, model.ObjectType) || !strings.EqualFold(relationName(r), "OWNER") || !strings.EqualFold(r.Status, "CONFIRMED") || !relationValid(r, now) {
			continue
		}
		rels = append(rels, r)
	}
	if len(rels) == 0 {
		check.Decision, check.ReasonCode, check.RelationState = AuthorizationUnknown, "AUTHZ-RELATION-001", "NONE"
		return check, true
	}
	identityTenant := strings.TrimSpace(jwt.VerifiedTenantID)
	tenantIDs := make(map[string]struct{}, len(rels)+1)
	if tenant := strings.TrimSpace(model.TenantID); tenant != "" {
		tenantIDs[tenant] = struct{}{}
	}
	for _, r := range rels {
		if tenant := strings.TrimSpace(r.TenantID); tenant != "" {
			tenantIDs[tenant] = struct{}{}
		}
	}
	if len(tenantIDs) > 1 {
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationUnknown, "AUTHZ-TENANT-002", "CONFLICT"
		return check, true
	}
	objectTenant := ""
	for tenant := range tenantIDs {
		objectTenant = tenant
	}
	if identityTenant != "" && objectTenant != "" && identityTenant != objectTenant {
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationObserveViolation, "AUTHZ-TENANT-001", "MISMATCH"
		return check, true
	}
	if (identityTenant == "") != (objectTenant == "") {
		check.Decision, check.ReasonCode, check.TenantState = AuthorizationUnknown, "AUTHZ-TENANT-002", "INCOMPLETE"
		return check, true
	}
	var own, other bool
	for _, r := range rels {
		pid := r.PrincipalID
		if pid == "" {
			pid = r.SubjectPrincipalID
		}
		if pid == jwt.VerifiedPrincipalID {
			own = true
		} else if pid != "" {
			other = true
		}
	}
	if own {
		check.Decision, check.RelationState = AuthorizationAllow, "EFFECTIVE_OWNER"
		return check, true
	}
	if other {
		check.Decision, check.ReasonCode, check.RelationState = AuthorizationObserveViolation, "AUTHZ-BOLA-001", "OTHER_OWNER"
		return check, true
	}
	check.Decision, check.ReasonCode, check.RelationState = AuthorizationUnknown, "AUTHZ-BOLA-002", "INSUFFICIENT"
	return check, true
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
	var out []ObjectModel
	for _, m := range models {
		if !sameApplication(applicationID, m.ApplicationID) {
			continue
		}
		// A compiled model with an explicit method must never match a request
		// of another method through the endpoint-path fallback below.
		if m.Method != "" && !strings.EqualFold(m.Method, parsed.Method) {
			continue
		}
		key := m.EndpointKey
		if key == "" {
			key = m.Endpoint
		}
		if key == endpoint ||
			(m.PathTemplate != "" && pathTemplateMatches(m.PathTemplate, parsed.RawPath)) ||
			(key != "" && pathTemplateMatches(endpointPath(key), endpointPath(endpoint))) {
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

func endpointPath(endpoint string) string {
	if i := strings.IndexByte(endpoint, ' '); i >= 0 {
		return endpoint[i+1:]
	}
	return endpoint
}
func pathTemplateMatches(template, path string) bool {
	t := strings.Split(strings.Trim(template, "/"), "/")
	p := strings.Split(strings.Trim(path, "/"), "/")
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
		t, p := strings.Split(strings.Trim(template, "/"), "/"), strings.Split(strings.Trim(parsed.RawPath, "/"), "/")
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
