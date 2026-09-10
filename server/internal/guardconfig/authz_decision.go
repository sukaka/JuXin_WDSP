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

const authzRelationsPerObjectType = 200000

// AuthzSnapshotLister compiles only approved authorization facts. Candidate
// evidence and OBSERVED role claims are intentionally outside this interface.
type AuthzSnapshotLister interface {
	ListPublishableAuthzModels(context.Context, time.Time) ([]gatewayconfig.GuardAuthzObjectModel, error)
	ListConfirmedAuthzRelations(context.Context) ([]gatewayconfig.GuardAuthzObjectRelation, error)
	ListVerifiedAuthzRoleBaselines(context.Context) ([]gatewayconfig.GuardAuthzRoleBaseline, error)
}

type AuthzSnapshotStore struct{ db *pgxpool.Pool }

func NewAuthzSnapshotStore(db *pgxpool.Pool) *AuthzSnapshotStore { return &AuthzSnapshotStore{db: db} }

func (s *AuthzSnapshotStore) ListPublishableAuthzModels(ctx context.Context, expires time.Time) ([]gatewayconfig.GuardAuthzObjectModel, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.application_id, ep.endpoint_key, ep.method, ep.path_template, om.object_segment,
       om.required_relation, om.owner_exclusive, om.updated_at
FROM api_object_models om
JOIN api_endpoints ep ON ep.id=om.endpoint_id
WHERE om.publishable AND om.required_relation='OWNER' AND om.owner_exclusive
  AND ep.status='CONFIRMED'
ORDER BY ep.endpoint_key, om.object_segment`)
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
		if err := rows.Scan(&applicationID, &endpointKey, &method, &pathTemplate, &segment, &required, &exclusive, &updated); err != nil {
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
		versionSum := sha256.Sum256([]byte(endpointKey + "\x00" + segment + "\x00" + updated.UTC().Format(time.RFC3339Nano)))
		out = append(out, gatewayconfig.GuardAuthzObjectModel{
			ApplicationID: applicationID,
			EndpointKey:   endpointKey, Method: strings.ToUpper(method), PathTemplate: pathTemplate,
			ObjectType: objectType, Identifiers: []gatewayconfig.GuardAuthzObjectIdentifier{{Location: location, Name: name, Primary: true}},
			RequiredRelation: required, OwnerExclusive: exclusive, Publishable: true,
			UniqueEndpointTemplate: true, ModelVersion: hex.EncodeToString(versionSum[:8]), SnapshotExpiresAt: &expires,
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
	rows, err := s.db.Query(ctx, `SELECT ep.application_id, ep.endpoint_key, rb.method, rb.role, rb.action, rb.allowed, rb.confirmed
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
		if err := rows.Scan(&b.ApplicationID, &b.EndpointKey, &b.Method, &b.Role, &b.Action, &b.Allowed, &b.Confirmed); err != nil {
			return nil, err
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
