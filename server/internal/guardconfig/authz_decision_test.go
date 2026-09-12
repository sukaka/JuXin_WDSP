package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeAuthzSnapshotLister struct {
	models      []gatewayconfig.GuardAuthzObjectModel
	relations   []gatewayconfig.GuardAuthzObjectRelation
	roles       []gatewayconfig.GuardAuthzRoleBaseline
	err         error
	relationErr error
	roleErr     error
	expiresAt   time.Time
}

func TestListPublishableAuthzModelsUsesCurrentEndpointColumns(t *testing.T) {
	for _, want := range []string{"ep.http_method", "ep.normalized_path", "ep.asset_status"} {
		if !strings.Contains(listPublishableAuthzModelsQuery, want) {
			t.Errorf("query does not reference %s: %s", want, listPublishableAuthzModelsQuery)
		}
	}
	for _, stale := range []string{"ep.method", "ep.path_template", "ep.status"} {
		if strings.Contains(listPublishableAuthzModelsQuery, stale) {
			t.Errorf("query still references removed endpoint column %s: %s", stale, listPublishableAuthzModelsQuery)
		}
	}
}

func (f *fakeAuthzSnapshotLister) ListPublishableAuthzModels(_ context.Context, expires time.Time) ([]gatewayconfig.GuardAuthzObjectModel, error) {
	f.expiresAt = expires
	return f.models, f.err
}

func (f *fakeAuthzSnapshotLister) ListConfirmedAuthzRelations(context.Context) ([]gatewayconfig.GuardAuthzObjectRelation, error) {
	if f.relationErr != nil {
		return nil, f.relationErr
	}
	return f.relations, nil
}

func (f *fakeAuthzSnapshotLister) ListVerifiedAuthzRoleBaselines(context.Context) ([]gatewayconfig.GuardAuthzRoleBaseline, error) {
	if f.roleErr != nil {
		return nil, f.roleErr
	}
	return f.roles, nil
}

func authzSnapshotTestModel() gatewayconfig.GuardAuthzObjectModel {
	return gatewayconfig.GuardAuthzObjectModel{
		ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", ObjectType: "ORDER",
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true,
		ModelVersion: "model-v1",
	}
}

func TestLoadAPIAuthzSnapshotFailsClosedOnIncompleteInputs(t *testing.T) {
	model := authzSnapshotTestModel()
	base := &fakeAuthzSnapshotLister{models: []gatewayconfig.GuardAuthzObjectModel{model}}

	tests := []struct {
		name string
		p    *Provider
		want string
	}{
		{name: "missing key loader", p: &Provider{authzSnapshot: base}, want: "dedicated object HMAC key loader"},
		{name: "empty key", p: &Provider{authzSnapshot: base, authzObjectHMACKey: func(context.Context) (string, error) { return "", nil }}, want: "api_authz.object_hmac_key"},
		{name: "model query failure", p: &Provider{authzSnapshot: &fakeAuthzSnapshotLister{models: []gatewayconfig.GuardAuthzObjectModel{model}, err: errors.New("db unavailable")}, authzObjectHMACKey: func(context.Context) (string, error) { return "deadbeef", nil }}, want: "compile authz object models"},
		{name: "relation query failure", p: &Provider{authzSnapshot: &fakeAuthzSnapshotLister{models: []gatewayconfig.GuardAuthzObjectModel{model}, relationErr: errors.New("relation db unavailable")}, authzObjectHMACKey: func(context.Context) (string, error) { return "deadbeef", nil }}, want: "compile authz relations"},
		{name: "role query failure", p: &Provider{authzSnapshot: &fakeAuthzSnapshotLister{models: []gatewayconfig.GuardAuthzObjectModel{model}, roleErr: errors.New("role db unavailable")}, authzObjectHMACKey: func(context.Context) (string, error) { return "deadbeef", nil }}, want: "compile verified authz role baselines"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := tc.p.loadAPIAuthzSnapshot(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestLoadAPIAuthzSnapshotAddsPolicyVersionAndPassesExpiry(t *testing.T) {
	model := authzSnapshotTestModel()
	lister := &fakeAuthzSnapshotLister{
		models:    []gatewayconfig.GuardAuthzObjectModel{model},
		relations: []gatewayconfig.GuardAuthzObjectRelation{{ApplicationID: "app-1", PrincipalID: "u-1", ObjectType: "ORDER", ObjectRef: "objref:abc", Relation: "OWNER", Status: "CONFIRMED"}},
		roles:     []gatewayconfig.GuardAuthzRoleBaseline{{ApplicationID: "app-1", EndpointKey: model.EndpointKey, Method: "GET", Role: "ops", Confirmed: true}},
	}
	provider := &Provider{
		authzSnapshot:      lister,
		authzObjectHMACKey: func(context.Context) (string, error) { return "001122", nil },
	}

	before := time.Now().UTC().Add(23 * time.Hour)
	models, relations, roles, key, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err != nil {
		t.Fatalf("loadAPIAuthzSnapshot() error = %v", err)
	}
	if len(models) != 1 || models[0].PolicyVersion == "" {
		t.Fatalf("models = %+v, want one model with policy version", models)
	}
	if lister.expiresAt.Before(before) {
		t.Fatalf("lister expiry = %v, want at least 23h from now", lister.expiresAt)
	}
	if len(relations) != 1 || len(roles) != 1 || key != "001122" {
		t.Fatalf("snapshot payload mismatch: models=%d relations=%d roles=%d key=%q", len(models), len(relations), len(roles), key)
	}
}

func TestLoadAPIAuthzSnapshotRejectsNonPublishableRelations(t *testing.T) {
	model := authzSnapshotTestModel()
	keyLoads := 0
	base := gatewayconfig.GuardAuthzObjectRelation{
		ApplicationID: "app-1", PrincipalID: "u-1", ObjectType: "ORDER", ObjectRef: "objref:abc",
		Relation: "OWNER", Status: "CONFIRMED",
	}
	tests := []struct {
		name   string
		mutate func(*gatewayconfig.GuardAuthzObjectRelation)
		want   string
	}{
		{name: "candidate status", mutate: func(r *gatewayconfig.GuardAuthzObjectRelation) { r.Status = "PENDING" }, want: "not CONFIRMED"},
		{name: "non owner relation", mutate: func(r *gatewayconfig.GuardAuthzObjectRelation) { r.Relation = "READER" }, want: "not OWNER"},
		{name: "plaintext object reference", mutate: func(r *gatewayconfig.GuardAuthzObjectRelation) { r.ObjectRef = "order-42" }, want: "HMAC reference"},
		{name: "expired relation", mutate: func(r *gatewayconfig.GuardAuthzObjectRelation) {
			v := time.Now().UTC().Add(-time.Minute)
			r.ValidUntil = &v
		}, want: "expired"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			relation := base
			tc.mutate(&relation)
			provider := &Provider{
				authzSnapshot: &fakeAuthzSnapshotLister{
					models: []gatewayconfig.GuardAuthzObjectModel{model}, relations: []gatewayconfig.GuardAuthzObjectRelation{relation},
				},
				authzObjectHMACKey: func(context.Context) (string, error) {
					keyLoads++
					return "001122", nil
				},
			}
			_, _, _, _, err := provider.loadAPIAuthzSnapshot(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadAPIAuthzSnapshot() error = %v, want substring %q", err, tc.want)
			}
		})
	}
	if keyLoads != 0 {
		t.Fatalf("object HMAC key loader called %d times after invalid relation input, want 0", keyLoads)
	}
}

func TestLoadAPIAuthzSnapshotRetainsFutureRelationsForGatewayFiltering(t *testing.T) {
	model := authzSnapshotTestModel()
	validFrom := time.Now().UTC().Add(time.Minute)
	validUntil := validFrom.Add(time.Minute)
	lister := &fakeAuthzSnapshotLister{
		models: []gatewayconfig.GuardAuthzObjectModel{model},
		relations: []gatewayconfig.GuardAuthzObjectRelation{{
			ApplicationID: "app-1", PrincipalID: "u-1", ObjectType: "ORDER", ObjectRef: "objref:abc",
			Relation: "OWNER", Status: "CONFIRMED", ValidFrom: &validFrom, ValidUntil: &validUntil,
		}},
	}
	provider := &Provider{
		authzSnapshot:      lister,
		authzObjectHMACKey: func(context.Context) (string, error) { return "001122", nil },
	}

	_, relations, _, _, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err != nil {
		t.Fatalf("loadAPIAuthzSnapshot() error = %v, want future relation retained", err)
	}
	if len(relations) != 1 || relations[0].ValidFrom == nil || !relations[0].ValidFrom.Equal(validFrom) {
		t.Fatalf("relations = %+v, want one future relation with valid_from %v", relations, validFrom)
	}
}

func TestLoadAPIAuthzSnapshotPublishesVerifiedRolesWithoutObjectModels(t *testing.T) {
	lister := &fakeAuthzSnapshotLister{
		roles: []gatewayconfig.GuardAuthzRoleBaseline{{
			ApplicationID: "app-1", EndpointKey: "GET /admin/users", Method: "GET",
			Role: "ops", Confirmed: true,
		}},
	}
	provider := &Provider{authzSnapshot: lister}

	models, relations, roles, key, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err != nil {
		t.Fatalf("loadAPIAuthzSnapshot() error = %v", err)
	}
	if len(models) != 0 || len(relations) != 0 || len(roles) != 1 || key != "" {
		t.Fatalf("snapshot payload mismatch: models=%d relations=%d roles=%d key=%q", len(models), len(relations), len(roles), key)
	}
}

func TestLoadAPIAuthzSnapshotRejectsConflictingVerifiedRoleBaselines(t *testing.T) {
	lister := &fakeAuthzSnapshotLister{
		roles: []gatewayconfig.GuardAuthzRoleBaseline{
			{ApplicationID: "app-1", EndpointKey: "GET /admin/users", Method: "GET", Role: "ops", Action: "READ", Allowed: true, Confirmed: true},
			{ApplicationID: "app-1", EndpointKey: "GET /admin/users", Method: "get", Role: "ops", Action: "read", Allowed: false, Confirmed: true},
		},
	}
	provider := &Provider{authzSnapshot: lister}

	_, _, _, _, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err == nil || !strings.Contains(err.Error(), "conflicting verified authz role baseline") {
		t.Fatalf("loadAPIAuthzSnapshot() error = %v, want conflicting baseline error", err)
	}
}

func TestCompileObjectSegment(t *testing.T) {
	tests := []struct {
		path, segment, location, name, objectType string
		ok                                        bool
	}{
		{path: "/v1/orders/{orderId}", segment: "path:2", location: "path", name: "orderId", objectType: "orders", ok: true},
		{path: "/v1/orders", segment: "query:order_id", location: "query", name: "order_id", objectType: "order_id", ok: true},
		{path: "/v1/orders/{id}", segment: "path:9", ok: false},
		{path: "/v1/orders/{id}", segment: "header:X-Object", ok: false},
	}
	for _, tc := range tests {
		location, name, objectType, ok := compileObjectSegment(tc.path, tc.segment)
		if ok != tc.ok || location != tc.location || name != tc.name || objectType != tc.objectType {
			t.Errorf("compileObjectSegment(%q, %q) = (%q, %q, %q, %t), want (%q, %q, %q, %t)", tc.path, tc.segment, location, name, objectType, ok, tc.location, tc.name, tc.objectType, tc.ok)
		}
	}
}
