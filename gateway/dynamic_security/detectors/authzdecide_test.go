package detectors

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestEvaluateAuthorizationDecisionMatrix(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	model := ObjectModel{
		EndpointKey: "GET /orders/{orderId}", ObjectType: "ORDER",
		PathTemplate: "/orders/{orderId}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "orderId", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	ref := ObjectRefHMAC([]byte("obj-secret"), "7")
	base := AuthorizationConfig{
		EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: []byte("obj-secret"),
		Relations: []ObjectRelation{{PrincipalID: "user-1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		Now:       func() time.Time { return now }, PolicyVersion: "authz-v3",
	}
	verified := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1"}
	other := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2"}
	unverified := &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedPrincipalID: "user-1"}

	cases := []struct {
		name         string
		cfg          AuthorizationConfig
		jwt          *jwtverify.VerificationResult
		path         string
		wantDecision string
		wantReason   string
	}{
		{name: "verified owner allows", cfg: base, jwt: verified, path: "/orders/7", wantDecision: "ALLOW"},
		{name: "verified other owner observes bola", cfg: base, jwt: other, path: "/orders/7", wantDecision: "OBSERVE_VIOLATION", wantReason: "AUTHZ-BOLA-001"},
		{name: "unverified identity is unknown", cfg: base, jwt: unverified, path: "/orders/7", wantDecision: "UNKNOWN", wantReason: "AUTHZ-IDENTITY-001"},
		{name: "missing object is unknown", cfg: base, jwt: verified, path: "/orders/", wantDecision: "UNKNOWN", wantReason: "AUTHZ-OBJECT-001"},
		{name: "ambiguous query is unknown", cfg: AuthorizationConfig{EndpointKey: "GET /orders", PolicyVersion: "authz-v3", Models: []ObjectModel{{EndpointKey: "GET /orders", ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "query", Name: "orderId", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}}, ObjectRefHMACKey: []byte("obj-secret"), Now: base.Now}, jwt: verified, path: "/orders?orderId=7&orderId=8", wantDecision: "UNKNOWN", wantReason: "AUTHZ-OBJECT-002"},
		{name: "bad model policy is unknown", cfg: func() AuthorizationConfig {
			c := base
			c.Models = append([]ObjectModel(nil), base.Models...)
			c.Models[0].Publishable = false
			return c
		}(), jwt: verified, path: "/orders/7", wantDecision: "UNKNOWN", wantReason: "AUTHZ-POLICY-001"},
		{name: "expired relation is unknown", cfg: func() AuthorizationConfig {
			c := base
			c.Relations = append([]ObjectRelation(nil), base.Relations...)
			until := now
			c.Relations[0].ValidUntil = &until
			return c
		}(), jwt: verified, path: "/orders/7", wantDecision: "UNKNOWN", wantReason: "AUTHZ-RELATION-001"},
		{name: "future relation is unknown", cfg: func() AuthorizationConfig {
			c := base
			c.Relations = append([]ObjectRelation(nil), base.Relations...)
			from := now.Add(time.Minute)
			c.Relations[0].ValidFrom = &from
			return c
		}(), jwt: verified, path: "/orders/7", wantDecision: "UNKNOWN", wantReason: "AUTHZ-RELATION-001"},
		{name: "revoked relation is unknown", cfg: func() AuthorizationConfig {
			c := base
			c.Relations = append([]ObjectRelation(nil), base.Relations...)
			c.Relations[0].Status = "REVOKED"
			return c
		}(), jwt: verified, path: "/orders/7", wantDecision: "UNKNOWN", wantReason: "AUTHZ-RELATION-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "https://example.test"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := dsctx.New("req-1", dsctx.DefaultParseLimits())
			parsed, err := parser.ParseRequest(r, ctx)
			if err != nil {
				t.Fatal(err)
			}
			group := EvaluateAuthorization(ctx, parsed, tc.cfg, tc.jwt)
			if group == nil || len(group.Checks) != 1 {
				t.Fatalf("group=%+v", group)
			}
			check := group.Checks[0]
			if string(check.Decision) != tc.wantDecision {
				t.Fatalf("decision=%s want %s", check.Decision, tc.wantDecision)
			}
			if tc.wantReason != "" && check.ReasonCode != tc.wantReason {
				t.Fatalf("reason=%s want %s", check.ReasonCode, tc.wantReason)
			}
			if group.DecisionID == "" || group.PolicyVersion != "authz-v3" {
				t.Fatalf("group metadata=%+v", group)
			}
			compact := strings.ReplaceAll(group.DecisionID, "-", "")
			if len(group.DecisionID) != 36 || len(compact) != 32 {
				t.Fatalf("decision_id must be UUID-shaped: %q", group.DecisionID)
			}
		})
	}
}

func TestAuthorizationRelationIndexMatchesRelations(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("obj-secret")
	ref := ObjectRefHMAC(key, "7")
	cfg := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7",
		Models:    []ObjectModel{{ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}},
		Relations: []ObjectRelation{{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}}, ObjectRefHMACKey: key, Now: func() time.Time { return now },
	}
	cfg.RelationIndex = BuildAuthorizationRelationIndex(cfg.Relations)
	r, err := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-index", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}
	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationAllow {
		t.Fatalf("indexed authorization=%+v", group)
	}
}

func BenchmarkEvaluateAuthorizationWithRelationIndex(b *testing.B) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("obj-secret")
	ref := ObjectRefHMAC(key, "200000")
	relations := make([]ObjectRelation, 0, 200000)
	for i := 0; i < 199999; i++ {
		relations = append(relations, ObjectRelation{ApplicationID: "app-a", PrincipalID: "other", ObjectType: "ORDER", ObjectRef: ObjectRefHMAC(key, "noise"), Relation: "OWNER", Status: "CONFIRMED"})
	}
	relations = append(relations, ObjectRelation{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"})
	cfg := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/200000", ObjectRefHMACKey: key, Now: func() time.Time { return now },
		Models:    []ObjectModel{{ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}},
		Relations: relations, RelationIndex: BuildAuthorizationRelationIndex(relations),
	}
	r, err := http.NewRequest(http.MethodGet, "https://example.test/orders/200000", nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := dsctx.New("bench-index", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		b.Fatal(err)
	}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
		if group == nil || group.Decision != AuthorizationAllow {
			b.Fatalf("authorization=%+v", group)
		}
	}
}

func BenchmarkEvaluateAuthorizationPaired(b *testing.B) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("obj-secret")
	ref := ObjectRefHMAC(key, "200000")
	relations := make([]ObjectRelation, 0, 200000)
	for i := 0; i < 199999; i++ {
		relations = append(relations, ObjectRelation{ApplicationID: "app-a", PrincipalID: "other", ObjectType: "ORDER", ObjectRef: ObjectRefHMAC(key, "noise"), Relation: "OWNER", Status: "CONFIRMED"})
	}
	relations = append(relations, ObjectRelation{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"})
	base := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/200000", ObjectRefHMACKey: key, Now: func() time.Time { return now },
		Models:    []ObjectModel{{ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}},
		Relations: relations,
	}
	indexed := base
	indexed.RelationIndex = BuildAuthorizationRelationIndex(relations)
	r, err := http.NewRequest(http.MethodGet, "https://example.test/orders/200000", nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := dsctx.New("bench-paired", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		b.Fatal(err)
	}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}
	for _, tc := range []struct {
		name string
		cfg  AuthorizationConfig
	}{
		{name: "relation_index", cfg: indexed},
		{name: "linear_scan", cfg: base},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				group := EvaluateAuthorization(ctx, parsed, tc.cfg, jwt)
				if group == nil || group.Decision != AuthorizationAllow {
					b.Fatalf("authorization=%+v", group)
				}
			}
		})
	}
}

// BenchmarkEvaluateAuthorizationAuthzPair measures the request-local cost of
// enabling AUTHZ against the same parsed request and verified identity. The
// disabled case is the no-model/no-baseline compatibility path; the enabled
// case exercises both BFLA and BOLA and must still allow the request.
// Results are intentionally emitted only through testing.B so callers can
// retain raw repetitions instead of turning one run into a fabricated claim.
func BenchmarkEvaluateAuthorizationAuthzPair(b *testing.B) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("obj-secret")
	ref := ObjectRefHMAC(key, "7")
	model := ObjectModel{
		ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}",
		ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	enabled := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", ObjectRefHMACKey: key,
		Models:        []ObjectModel{model},
		Relations:     []ObjectRelation{{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		RoleBaselines: []VerifiedRoleBaseline{{ApplicationID: "app-a", EndpointKey: "GET /orders/7", Method: "GET", Role: "reader", Allowed: true, Confirmed: true}},
		Now:           func() time.Time { return now }, PolicyVersion: "authz-v3",
	}
	disabled := AuthorizationConfig{ApplicationID: "app-a", EndpointKey: "GET /orders/7", Now: func() time.Time { return now }}
	r, err := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	if err != nil {
		b.Fatal(err)
	}
	ctx := dsctx.New("bench-authz-pair", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		b.Fatal(err)
	}
	jwt := &jwtverify.VerificationResult{
		Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"reader"},
	}

	for _, tc := range []struct {
		name string
		cfg  AuthorizationConfig
		want bool
	}{
		{name: "authz_disabled", cfg: disabled, want: false},
		{name: "authz_enabled", cfg: enabled, want: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				group := EvaluateAuthorization(ctx, parsed, tc.cfg, jwt)
				if tc.want {
					if group == nil || group.Decision != AuthorizationAllow || len(group.Checks) != 2 {
						b.Fatalf("enabled authorization=%+v", group)
					}
				} else if group != nil {
					b.Fatalf("disabled authorization=%+v", group)
				}
			}
		})
	}
}

func TestEvaluateAuthorizationBFLAIndependentAndTenantMatrix(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	cfg := AuthorizationConfig{
		EndpointKey: "POST /admin/users", PolicyVersion: "p1", Now: func() time.Time { return now },
		RoleBaselines: []VerifiedRoleBaseline{{EndpointKey: "POST /admin/users", Role: "admin", Allowed: true, Confirmed: true}},
	}
	r, _ := http.NewRequest(http.MethodPost, "https://example.test/admin/users", nil)
	ctx := dsctx.New("req-bfla", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	allow := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"admin"}}
	group := EvaluateAuthorization(ctx, parsed, cfg, allow)
	if group == nil || len(group.Checks) != 1 || group.Checks[0].Type != "BFLA" || group.Checks[0].Decision != AuthorizationAllow {
		t.Fatalf("BFLA=%+v", group)
	}

	// Tenant mismatch is a violation and must never be taken from request parameters.
	obj := ObjectModel{EndpointKey: "GET /orders/{id}", ObjectType: "ORDER", PathTemplate: "/orders/{id}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}
	cfg = AuthorizationConfig{EndpointKey: "GET /orders/7", Models: []ObjectModel{obj}, ObjectRefHMACKey: []byte("k"), Now: func() time.Time { return now }, Relations: []ObjectRelation{{PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ObjectRefHMAC([]byte("k"), "7"), Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-b"}}}
	allow.VerifiedTenantID = "tenant-a"
	orderReq, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	orderCtx := dsctx.New("req-order", dsctx.DefaultParseLimits())
	orderParsed, _ := parser.ParseRequest(orderReq, orderCtx)
	group = EvaluateAuthorization(orderCtx, orderParsed, cfg, allow)
	if group == nil || group.Checks[0].ReasonCode != "AUTHZ-TENANT-001" || group.Checks[0].Decision != AuthorizationObserveViolation {
		t.Fatalf("tenant=%+v", group)
	}
}

func TestEvaluateAuthorizationTenantCompletenessMatrix(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("tenant-matrix-key")
	model := ObjectModel{
		EndpointKey: "GET /orders/{id}", ObjectType: "ORDER", PathTemplate: "/orders/{id}",
		Identifiers:      []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	ref := ObjectRefHMAC(key, "7")
	cases := []struct {
		name           string
		identityTenant string
		objectTenant   string
		wantDecision   AuthorizationDecision
		wantReason     string
		wantTenant     string
	}{
		{name: "both absent remains owner allow", wantDecision: AuthorizationAllow, wantTenant: ""},
		{name: "identity only is incomplete", identityTenant: "tenant-a", wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002", wantTenant: "INCOMPLETE"},
		{name: "object only is incomplete", objectTenant: "tenant-a", wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002", wantTenant: "INCOMPLETE"},
		{name: "different tenants observe violation", identityTenant: "tenant-a", objectTenant: "tenant-b", wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-TENANT-001", wantTenant: "MISMATCH"},
		{name: "same tenants allow", identityTenant: "tenant-a", objectTenant: "tenant-a", wantDecision: AuthorizationAllow, wantTenant: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AuthorizationConfig{
				EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: key,
				Relations: []ObjectRelation{{PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED", TenantID: tc.objectTenant}},
				Now:       func() time.Time { return now },
			}
			r, err := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := dsctx.New("req-tenant-matrix", dsctx.DefaultParseLimits())
			parsed, err := parser.ParseRequest(r, ctx)
			if err != nil {
				t.Fatal(err)
			}
			jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedTenantID: tc.identityTenant}
			group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
			if group == nil || len(group.Checks) != 1 {
				t.Fatalf("group=%+v", group)
			}
			check := group.Checks[0]
			if check.Decision != tc.wantDecision || check.ReasonCode != tc.wantReason || check.TenantState != tc.wantTenant {
				t.Fatalf("check=%+v want decision=%s reason=%s tenant=%s", check, tc.wantDecision, tc.wantReason, tc.wantTenant)
			}
		})
	}
}

func TestEvaluateAuthorizationBOLAConflictingTenantsIsOrderIndependent(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("bola-tenant-order-key")
	ref := ObjectRefHMAC(key, "7")
	model := ObjectModel{
		EndpointKey: "GET /orders/{id}", ObjectType: "ORDER", PathTemplate: "/orders/{id}",
		Identifiers:      []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	request, err := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	if err != nil {
		t.Fatal(err)
	}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedTenantID: "tenant-a"}
	orders := [][]ObjectRelation{
		{
			{PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-a"},
			{PrincipalID: "u2", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-b"},
		},
		{
			{PrincipalID: "u2", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-b"},
			{PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED", TenantID: "tenant-a"},
		},
	}
	for i, relations := range orders {
		t.Run("order-"+strconv.Itoa(i), func(t *testing.T) {
			ctx := dsctx.New("req-bola-tenant-order", dsctx.DefaultParseLimits())
			parsed, err := parser.ParseRequest(request, ctx)
			if err != nil {
				t.Fatal(err)
			}
			group := EvaluateAuthorization(ctx, parsed, AuthorizationConfig{
				EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, Relations: relations,
				ObjectRefHMACKey: key, Now: func() time.Time { return now },
			}, jwt)
			if group == nil || len(group.Checks) != 1 {
				t.Fatalf("group=%+v", group)
			}
			check := group.Checks[0]
			if check.Decision != AuthorizationUnknown || check.ReasonCode != "AUTHZ-TENANT-002" || check.TenantState != "CONFLICT" {
				t.Fatalf("check=%+v; conflicting tenant relations must be indeterminate", check)
			}
		})
	}
}

func TestEvaluateAuthorizationBFLAMultipleRolesAreOrderIndependent(t *testing.T) {
	base := AuthorizationConfig{
		EndpointKey: "GET /admin/users",
	}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"reader", "auditor"}}
	request, err := http.NewRequest(http.MethodGet, "https://example.test/admin/users", nil)
	if err != nil {
		t.Fatal(err)
	}
	orders := [][]VerifiedRoleBaseline{
		{
			{EndpointKey: "GET /admin/users", Role: "reader", Allowed: true, Confirmed: true},
			{EndpointKey: "GET /admin/users", Role: "auditor", Allowed: false, Confirmed: true},
		},
		{
			{EndpointKey: "GET /admin/users", Role: "auditor", Allowed: false, Confirmed: true},
			{EndpointKey: "GET /admin/users", Role: "reader", Allowed: true, Confirmed: true},
		},
	}
	for i, baselines := range orders {
		t.Run("order-"+strconv.Itoa(i), func(t *testing.T) {
			ctx := dsctx.New("req-bfla-role-order", dsctx.DefaultParseLimits())
			parsed, err := parser.ParseRequest(request, ctx)
			if err != nil {
				t.Fatal(err)
			}
			cfg := base
			cfg.RoleBaselines = baselines
			group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
			if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationAllow {
				t.Fatalf("multiple verified roles with an allowed role must allow independent of row order: %+v", group)
			}
		})
	}
}

func TestEvaluateAuthorizationIsolatesApplications(t *testing.T) {
	key := []byte("app-isolation-secret")
	ref := ObjectRefHMAC(key, "7")
	model := func(appID string) ObjectModel {
		return ObjectModel{ApplicationID: appID, EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true}
	}
	cfg := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", ObjectRefHMACKey: key,
		Models: []ObjectModel{model("app-a"), model("app-b")},
		Relations: []ObjectRelation{
			{ApplicationID: "app-b", PrincipalID: "user-b", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"},
			{ApplicationID: "app-a", PrincipalID: "user-a", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"},
		},
	}
	r, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-app", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-a"}
	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationAllow {
		t.Fatalf("cross-application snapshot contamination: %+v", group)
	}
}

func TestEvaluateAuthorizationDoesNotUseScopedSnapshotWithoutApplicationContext(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	model := ObjectModel{
		ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", ObjectType: "ORDER",
		PathTemplate: "/orders/{id}", Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	ref := ObjectRefHMAC([]byte("k"), "7")
	cfg := AuthorizationConfig{
		EndpointKey: "GET /orders/7", Models: []ObjectModel{model},
		Relations:        []ObjectRelation{{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		ObjectRefHMACKey: []byte("k"), Now: func() time.Time { return now },
	}
	r, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-unscoped", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}
	if group := EvaluateAuthorization(ctx, parsed, cfg, jwt); group != nil {
		t.Fatalf("unscoped request consumed app-scoped snapshot: %+v", group)
	}
}

func TestEvaluateAuthorizationDoesNotMatchObjectModelAcrossMethods(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	model := ObjectModel{
		ApplicationID: "app-a", EndpointKey: "POST /orders/{id}", Method: http.MethodPost,
		ObjectType: "ORDER", PathTemplate: "/orders/{id}",
		Identifiers:      []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	cfg := AuthorizationConfig{ApplicationID: "app-a", EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: []byte("k"), Now: func() time.Time { return now }}
	r, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-method", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}
	if group := EvaluateAuthorization(ctx, parsed, cfg, jwt); group != nil {
		t.Fatalf("method-mismatched model was selected: %+v", group)
	}
}

func TestEvaluateAuthorizationRejectsConflictingBFLABaselines(t *testing.T) {
	cfg := AuthorizationConfig{
		EndpointKey: "GET /admin/users",
		RoleBaselines: []VerifiedRoleBaseline{
			{EndpointKey: "GET /admin/users", Method: "GET", Role: "ops", Action: "READ", Allowed: true, Confirmed: true},
			{EndpointKey: "GET /admin/users", Method: "get", Role: "ops", Action: "read", Allowed: false, Confirmed: true},
		},
		PolicyVersion: "authz-v4",
	}
	r, _ := http.NewRequest(http.MethodGet, "https://example.test/admin/users", nil)
	ctx := dsctx.New("req-bfla-conflict", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"ops"}}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationUnknown || group.Checks[0].ReasonCode != "AUTHZ-POLICY-001" {
		t.Fatalf("conflicting BFLA baselines must be unknown policy: %+v", group)
	}
}

func TestEvaluateAuthorizationRejectsUnobservableActionConflict(t *testing.T) {
	cfg := AuthorizationConfig{
		EndpointKey: "GET /admin/users",
		RoleBaselines: []VerifiedRoleBaseline{
			{EndpointKey: "GET /admin/users", Method: "GET", Role: "ops", Action: "READ", Allowed: true, Confirmed: true},
			{EndpointKey: "GET /admin/users", Method: "GET", Role: "ops", Action: "WRITE", Allowed: false, Confirmed: true},
		},
	}
	r, _ := http.NewRequest(http.MethodGet, "https://example.test/admin/users", nil)
	ctx := dsctx.New("req-bfla-action-conflict", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(r, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"ops"}}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationUnknown || group.Checks[0].ReasonCode != "AUTHZ-POLICY-001" {
		t.Fatalf("unobservable action conflict must be unknown policy: %+v", group)
	}
}

func TestEvaluateAuthorizationFallsBackToPreviousValidSnapshot(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	expiredAt := now
	key := []byte("fallback-key")
	model := ObjectModel{
		ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER",
		Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER",
		OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true, ModelVersion: "previous-model",
	}
	ref := ObjectRefHMAC(key, "7")
	previous := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: key,
		Relations:     []ObjectRelation{{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"}},
		PolicyVersion: "previous-policy", Now: func() time.Time { return now },
	}
	currentModel := model
	cfg := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", Models: []ObjectModel{currentModel}, ObjectRefHMACKey: key,
		PolicyVersion: "current-policy", SnapshotExpiresAt: &expiredAt, PreviousValid: &previous, Now: func() time.Time { return now },
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-fallback", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(request, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || group.Decision != AuthorizationUnknown || len(group.Checks) != 2 {
		t.Fatalf("stale snapshot should warn and evaluate previous snapshot: %+v", group)
	}
	if group.Checks[0].ReasonCode != "AUTHZ-POLICY-002" || group.Checks[0].Decision != AuthorizationUnknown {
		t.Fatalf("missing stale snapshot warning: %+v", group.Checks)
	}
	if group.Checks[1].Type != "BOLA" || group.Checks[1].Decision != AuthorizationAllow || group.Checks[1].ModelVersion != "previous-model" {
		t.Fatalf("previous snapshot was not used: %+v", group.Checks)
	}
}

func TestEvaluateAuthorizationExpiredSnapshotWithoutFallbackIsUnknown(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	model := ObjectModel{
		EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER",
		Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER",
		OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true, Stale: true,
	}
	cfg := AuthorizationConfig{EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: []byte("k"), Now: func() time.Time { return now }}
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-no-fallback", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(request, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || group.Decision != AuthorizationUnknown || len(group.Checks) != 1 || group.Checks[0].ReasonCode != "AUTHZ-POLICY-002" {
		t.Fatalf("stale snapshot without fallback must be policy unknown: %+v", group)
	}
}

func TestEvaluateAuthorizationFallbackFiltersExpiredRelations(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	key := []byte("relation-expiry-key")
	model := ObjectModel{
		ApplicationID: "app-a", EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER",
		Identifiers: []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}}, RequiredRelation: "OWNER",
		OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
	}
	expiresAt := now
	previous := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", Models: []ObjectModel{model}, ObjectRefHMACKey: key,
		Relations: []ObjectRelation{{ApplicationID: "app-a", PrincipalID: "u1", ObjectType: "ORDER", ObjectRef: ObjectRefHMAC(key, "7"), Relation: "OWNER", Status: "CONFIRMED", ValidUntil: &expiresAt}},
		Now:       func() time.Time { return now },
	}
	currentModel := model
	currentModel.Stale = true
	cfg := AuthorizationConfig{
		ApplicationID: "app-a", EndpointKey: "GET /orders/7", Models: []ObjectModel{currentModel}, ObjectRefHMACKey: key,
		PreviousValid: &previous, Now: func() time.Time { return now },
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.test/orders/7", nil)
	ctx := dsctx.New("req-expired-relation", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(request, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1"}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || group.Decision != AuthorizationUnknown || len(group.Checks) != 2 {
		t.Fatalf("expired relation must remain unknown after snapshot fallback: %+v", group)
	}
	if group.Checks[1].Type != "BOLA" || group.Checks[1].ReasonCode != "AUTHZ-RELATION-001" {
		t.Fatalf("expired relation was incorrectly accepted: %+v", group.Checks)
	}
}

func TestEvaluateAuthorizationFallbackCoversBFLA(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	previous := AuthorizationConfig{
		EndpointKey:   "POST /admin/users",
		RoleBaselines: []VerifiedRoleBaseline{{EndpointKey: "POST /admin/users", Role: "admin", Allowed: true, Confirmed: true}},
	}
	cfg := AuthorizationConfig{EndpointKey: "POST /admin/users", Stale: true, PreviousValid: &previous, Now: func() time.Time { return now }}
	request, _ := http.NewRequest(http.MethodPost, "https://example.test/admin/users", nil)
	ctx := dsctx.New("req-bfla-fallback", dsctx.DefaultParseLimits())
	parsed, _ := parser.ParseRequest(request, ctx)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "u1", VerifiedRoles: []string{"admin"}}

	group := EvaluateAuthorization(ctx, parsed, cfg, jwt)
	if group == nil || len(group.Checks) != 2 || group.Checks[0].ReasonCode != "AUTHZ-POLICY-002" || group.Checks[1].Type != "BFLA" || group.Checks[1].Decision != AuthorizationAllow {
		t.Fatalf("stale snapshot did not fall back for BFLA: %+v", group)
	}
}

var az4TestNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func newAZ4AuthorizationConfig() AuthorizationConfig {
	key := []byte("az4-object-secret")
	ref := ObjectRefHMAC(key, "7")
	return AuthorizationConfig{
		EndpointKey: "GET /orders/7", ObjectRefHMACKey: key,
		Models: []ObjectModel{{
			EndpointKey: "GET /orders/{id}", PathTemplate: "/orders/{id}", ObjectType: "ORDER",
			Identifiers:      []ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
			RequiredRelation: "ANY_OF", RequiredRelations: []string{"OWNER", "SHARED_WITH"},
			OwnerExclusive: true, Publishable: true, UniqueEndpointTemplate: true,
		}},
		Relations: []ObjectRelation{
			{PrincipalID: "user-owner", ObjectType: "ORDER", ObjectRef: ref, Relation: "OWNER", Status: "CONFIRMED"},
			{PrincipalID: "user-shared", ObjectType: "ORDER", ObjectRef: ref, Relation: "SHARED_WITH", Status: "CONFIRMED"},
		},
		Now: func() time.Time { return az4TestNow }, PolicyVersion: "authz-v4",
	}
}

func az4VerifiedJWT(principal string) *jwtverify.VerificationResult {
	return &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: principal}
}

func evalAZ4Authorization(t *testing.T, cfg AuthorizationConfig, jwt *jwtverify.VerificationResult, path string) (*AuthorizationDecisionGroup, *dsctx.RequestContext) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://example.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-az4", dsctx.DefaultParseLimits())
	parsed, err := parser.ParseRequest(req, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return EvaluateAuthorization(ctx, parsed, cfg, jwt), ctx
}

func az4BOLACheck(t *testing.T, group *AuthorizationDecisionGroup) AuthorizationCheck {
	t.Helper()
	if group == nil {
		t.Fatal("missing authorization group")
	}
	for _, check := range group.Checks {
		if check.Type == "BOLA" {
			return check
		}
	}
	t.Fatalf("missing primary BOLA check: %+v", group.Checks)
	return AuthorizationCheck{}
}

func TestEvaluateAuthorizationAnyOfPolicyValidationAndLegacyCompatibility(t *testing.T) {
	cases := []struct {
		name             string
		requiredRelation string
		required         []string
		wantDecision     AuthorizationDecision
		wantReason       string
		wantState        string
	}{
		{name: "canonical any_of allows shared", requiredRelation: "ANY_OF", required: []string{"OWNER", "SHARED_WITH"}, wantDecision: AuthorizationAllow, wantState: "EFFECTIVE_SHARED_WITH"},
		{name: "reverse any_of order allows shared", requiredRelation: "ANY_OF", required: []string{"SHARED_WITH", "OWNER"}, wantDecision: AuthorizationAllow, wantState: "EFFECTIVE_SHARED_WITH"},
		{name: "owner only any_of is unknown", requiredRelation: "ANY_OF", required: []string{"OWNER"}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "legacy owner ignores share", requiredRelation: "OWNER", wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001", wantState: "OTHER_OWNER"},
		{name: "legacy owner with relations is unknown", requiredRelation: "OWNER", required: []string{"OWNER"}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "empty any_of is unknown", requiredRelation: "ANY_OF", wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "any_of requires owner", requiredRelation: "ANY_OF", required: []string{"SHARED_WITH"}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "duplicate any_of relation is unknown", requiredRelation: "ANY_OF", required: []string{"OWNER", "owner", "SHARED_WITH"}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
		{name: "unsupported any_of relation is unknown", requiredRelation: "ANY_OF", required: []string{"OWNER", "DELEGATED_TO"}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-POLICY-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newAZ4AuthorizationConfig()
			cfg.Models[0].RequiredRelation = tc.requiredRelation
			cfg.Models[0].RequiredRelations = cloneAuthorizationSlice(tc.required)
			group, ctx := evalAZ4Authorization(t, cfg, az4VerifiedJWT("user-shared"), "/orders/7")
			check := az4BOLACheck(t, group)
			if check.Decision != tc.wantDecision || check.ReasonCode != tc.wantReason || check.RelationState != tc.wantState {
				t.Fatalf("check=%+v, want %s/%s/%s", check, tc.wantDecision, tc.wantReason, tc.wantState)
			}
			v3AssertNeverBlocked(t, group, ctx)
		})
	}
}

func TestEvaluateAuthorizationAnyOfSharedWithLifecycleAndDirection(t *testing.T) {
	t.Run("owner keeps legacy effective state", func(t *testing.T) {
		group, _ := evalAZ4Authorization(t, newAZ4AuthorizationConfig(), az4VerifiedJWT("user-owner"), "/orders/7")
		check := az4BOLACheck(t, group)
		if check.Decision != AuthorizationAllow || check.RelationState != "EFFECTIVE_OWNER" {
			t.Fatalf("owner check=%+v", check)
		}
	})

	t.Run("subject principal recipient alias is supported", func(t *testing.T) {
		cfg := newAZ4AuthorizationConfig()
		cfg.Relations[1].SubjectPrincipalID = cfg.Relations[1].PrincipalID
		cfg.Relations[1].PrincipalID = ""
		group, _ := evalAZ4Authorization(t, cfg, az4VerifiedJWT("user-shared"), "/orders/7")
		if check := az4BOLACheck(t, group); check.Decision != AuthorizationAllow || check.RelationState != "EFFECTIVE_SHARED_WITH" {
			t.Fatalf("shared recipient check=%+v", check)
		}
	})

	cases := []struct {
		name         string
		mutate       func(*AuthorizationConfig)
		wantDecision AuthorizationDecision
		wantReason   string
	}{
		{name: "missing owner anchor", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations = cfg.Relations[1:]
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "revoked owner anchor", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].Status = "REVOKED"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "expired owner anchor", mutate: func(cfg *AuthorizationConfig) {
			until := az4TestNow
			cfg.Relations[0].ValidUntil = &until
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "future owner anchor", mutate: func(cfg *AuthorizationConfig) {
			from := az4TestNow.Add(time.Minute)
			cfg.Relations[0].ValidFrom = &from
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "unidentified owner anchor", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].PrincipalID = ""
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-BOLA-002"},
		{name: "owner on another object is not an anchor", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].ObjectRef = ObjectRefHMAC(cfg.ObjectRefHMACKey, "8")
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-RELATION-001"},
		{name: "revoked share", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[1].Status = "REVOKED"
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
		{name: "expired share", mutate: func(cfg *AuthorizationConfig) {
			until := az4TestNow
			cfg.Relations[1].ValidUntil = &until
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
		{name: "future share", mutate: func(cfg *AuthorizationConfig) {
			from := az4TestNow.Add(time.Minute)
			cfg.Relations[1].ValidFrom = &from
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
		{name: "share recipient is someone else", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[1].PrincipalID = "user-other"
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
		{name: "share belongs to another object", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[1].ObjectRef = ObjectRefHMAC(cfg.ObjectRefHMACKey, "8")
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
		{name: "share belongs to another application", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[1].ApplicationID = "app-b"
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-BOLA-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newAZ4AuthorizationConfig()
			tc.mutate(&cfg)
			group, ctx := evalAZ4Authorization(t, cfg, az4VerifiedJWT("user-shared"), "/orders/7")
			check := az4BOLACheck(t, group)
			if check.Decision != tc.wantDecision || check.ReasonCode != tc.wantReason {
				t.Fatalf("check=%+v, want %s/%s", check, tc.wantDecision, tc.wantReason)
			}
			if check.Decision == AuthorizationAllow || check.RelationState == "EFFECTIVE_SHARED_WITH" {
				t.Fatalf("invalid or reverse share must not authorize: %+v", check)
			}
			v3AssertNeverBlocked(t, group, ctx)
		})
	}
}

func TestEvaluateAuthorizationAnyOfIsOrderAndIndexIndependent(t *testing.T) {
	base := newAZ4AuthorizationConfig()
	base.Models[0].RequiredRelations = []string{"SHARED_WITH", "OWNER"}
	for _, reverse := range []bool{false, true} {
		for _, indexed := range []bool{false, true} {
			t.Run("reverse="+strconv.FormatBool(reverse)+"/indexed="+strconv.FormatBool(indexed), func(t *testing.T) {
				cfg := CloneAuthorizationConfig(base)
				if reverse {
					cfg.Relations[0], cfg.Relations[1] = cfg.Relations[1], cfg.Relations[0]
				}
				if indexed {
					cfg.RelationIndex = BuildAuthorizationRelationIndex(cfg.Relations)
				}
				for _, tc := range []struct {
					principal string
					decision  AuthorizationDecision
					reason    string
					state     string
				}{
					{principal: "user-shared", decision: AuthorizationAllow, state: "EFFECTIVE_SHARED_WITH"},
					{principal: "user-other", decision: AuthorizationObserveViolation, reason: "AUTHZ-BOLA-001", state: "OTHER_OWNER"},
				} {
					group, _ := evalAZ4Authorization(t, cfg, az4VerifiedJWT(tc.principal), "/orders/7")
					check := az4BOLACheck(t, group)
					if check.Decision != tc.decision || check.ReasonCode != tc.reason || check.RelationState != tc.state {
						t.Fatalf("principal=%s check=%+v", tc.principal, check)
					}
				}
				if cfg.Models[0].RequiredRelations[0] != "SHARED_WITH" || cfg.Models[0].RequiredRelations[1] != "OWNER" {
					t.Fatalf("runtime normalization must not mutate source order: %+v", cfg.Models[0].RequiredRelations)
				}
			})
		}
	}
}

func TestEvaluateAuthorizationAnyOfSharedDoesNotBypassSafetyGates(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*AuthorizationConfig)
		mutateJWT    func(*jwtverify.VerificationResult)
		wantDecision AuthorizationDecision
		wantReason   string
		wantEnforced bool
	}{
		{name: "open conflict", mutate: func(cfg *AuthorizationConfig) {
			cfg.ConflictedIndex = BuildConflictedObjectIndex([]ConflictedObject{{ObjectType: "ORDER", ObjectRef: cfg.Relations[0].ObjectRef}})
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-CONFLICT-001"},
		{name: "tenant mismatch enforced under PROTECT", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].TenantID = "tenant-a"
			cfg.Relations[1].TenantID = "tenant-a"
		}, mutateJWT: func(jwt *jwtverify.VerificationResult) {
			jwt.VerifiedTenantID = "tenant-b"
		}, wantDecision: AuthorizationVerifiedViolation, wantReason: "AUTHZ-TENANT-001", wantEnforced: true},
		{name: "tenant mismatch observes under OBSERVE", mutate: func(cfg *AuthorizationConfig) {
			cfg.Models[0].Enforcement = "OBSERVE"
			cfg.Relations[0].TenantID = "tenant-a"
			cfg.Relations[1].TenantID = "tenant-a"
		}, mutateJWT: func(jwt *jwtverify.VerificationResult) {
			jwt.VerifiedTenantID = "tenant-b"
		}, wantDecision: AuthorizationObserveViolation, wantReason: "AUTHZ-TENANT-001"},
		{name: "tenant conflict includes share", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].TenantID = "tenant-a"
			cfg.Relations[1].TenantID = "tenant-b"
		}, mutateJWT: func(jwt *jwtverify.VerificationResult) {
			jwt.VerifiedTenantID = "tenant-a"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002"},
		{name: "tenant incomplete", mutate: func(cfg *AuthorizationConfig) {
			cfg.Relations[0].TenantID = "tenant-a"
			cfg.Relations[1].TenantID = "tenant-a"
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-TENANT-002"},
		{name: "untrusted recipient", mutateJWT: func(jwt *jwtverify.VerificationResult) {
			jwt.Status = jwtverify.StatusUnverified
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-IDENTITY-001"},
		{name: "strict lease expiry", mutate: func(cfg *AuthorizationConfig) {
			cfg.LeaseSeconds = 60
			cfg.AppliedAt = az4TestNow.Add(-2 * time.Minute)
		}, wantDecision: AuthorizationUnknown, wantReason: "AUTHZ-LEASE-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newAZ4AuthorizationConfig()
			cfg.Schema = AuthzSnapshotSchemaV2
			cfg.Models[0].Enforcement = "PROTECT"
			cfg.EngineProtect = true
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}
			jwt := az4VerifiedJWT("user-shared")
			if tc.mutateJWT != nil {
				tc.mutateJWT(jwt)
			}
			group, ctx := evalAZ4Authorization(t, cfg, jwt, "/orders/7")
			check := az4BOLACheck(t, group)
			if check.Decision != tc.wantDecision || check.ReasonCode != tc.wantReason {
				t.Fatalf("check=%+v, want %s/%s", check, tc.wantDecision, tc.wantReason)
			}
			if check.Decision == AuthorizationAllow {
				t.Fatalf("safety gate produced shared ALLOW: %+v", check)
			}
			if tc.wantEnforced {
				var sawBlock bool
				for _, m := range ctx.CopyMatches() {
					if m.RuleID == tc.wantReason && m.Category == "BLOCK" {
						sawBlock = true
					}
				}
				if !sawBlock {
					t.Fatalf("expected enforced BLOCK match for %s: %+v", tc.wantReason, ctx.CopyMatches())
				}
			} else {
				v3AssertNeverBlocked(t, group, ctx)
			}
		})
	}
}

func TestEvaluateAuthorizationAnyOfPreviousValidAndWatermark(t *testing.T) {
	t.Run("previous valid retains required relations and shared decision", func(t *testing.T) {
		previous := newAZ4AuthorizationConfig()
		previous.Schema = AuthzSnapshotSchemaV2
		previous.RevocationWatermark = &RevocationWatermark{ManualSeq: 5, Sources: map[string]int64{"src-a": 3}}
		previous.RelationIndex = BuildAuthorizationRelationIndex(previous.Relations)
		previous.Models[0].RequiredRelations = []string{"SHARED_WITH", "OWNER"}
		current := CloneAuthorizationConfig(previous)
		current.Stale = true
		current.PreviousValid = &previous
		current.RelationIndex = nil
		group, ctx := evalAZ4Authorization(t, current, az4VerifiedJWT("user-shared"), "/orders/7")
		if group.Decision != AuthorizationUnknown || len(group.Checks) != 2 || group.Checks[0].ReasonCode != "AUTHZ-POLICY-002" {
			t.Fatalf("fallback group=%+v", group)
		}
		check := az4BOLACheck(t, group)
		if check.Decision != AuthorizationAllow || check.RelationState != "EFFECTIVE_SHARED_WITH" {
			t.Fatalf("previous shared check=%+v", check)
		}
		if previous.Models[0].RequiredRelations[0] != "SHARED_WITH" || previous.Models[0].RequiredRelations[1] != "OWNER" {
			t.Fatalf("previous model was mutated: %+v", previous.Models[0].RequiredRelations)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})

	t.Run("watermark regression rejects shared fallback", func(t *testing.T) {
		previous := newAZ4AuthorizationConfig()
		previous.Schema = AuthzSnapshotSchemaV2
		previous.RevocationWatermark = &RevocationWatermark{ManualSeq: 4}
		current := CloneAuthorizationConfig(previous)
		current.Stale = true
		current.RevocationWatermark = &RevocationWatermark{ManualSeq: 5}
		current.PreviousValid = &previous
		group, ctx := evalAZ4Authorization(t, current, az4VerifiedJWT("user-shared"), "/orders/7")
		if group == nil || len(group.Checks) != 1 || group.Checks[0].Decision != AuthorizationUnknown || group.Checks[0].ReasonCode != "AUTHZ-POLICY-002" {
			t.Fatalf("regressed fallback group=%+v", group)
		}
		v3AssertNeverBlocked(t, group, ctx)
	})
}

func TestCloneAuthorizationConfigDeepCopiesSlices(t *testing.T) {
	original := newAZ4AuthorizationConfig()
	original.RoleBaselines = []VerifiedRoleBaseline{{Role: "reader"}}
	original.ConflictedObjects = []ConflictedObject{{ObjectType: "ORDER"}}
	original.RelationIndex = BuildAuthorizationRelationIndex(original.Relations)
	cloned := CloneAuthorizationConfig(original)
	cloned.Models[0].Identifiers[0].Name = "changed"
	cloned.Models[0].RequiredRelations[0] = "CHANGED"
	cloned.Relations[0].PrincipalID = "changed"
	cloned.RoleBaselines[0].Role = "changed"
	cloned.ObjectRefHMACKey[0] ^= 0xff
	cloned.ConflictedObjects[0].ObjectType = "CHANGED"
	for _, relations := range cloned.RelationIndex {
		relations[0].PrincipalID = "changed"
	}
	if original.Models[0].Identifiers[0].Name != "id" || original.Models[0].RequiredRelations[0] != "OWNER" ||
		original.Relations[0].PrincipalID != "user-owner" || original.RoleBaselines[0].Role != "reader" ||
		original.ObjectRefHMACKey[0] != 'a' || original.ConflictedObjects[0].ObjectType != "ORDER" {
		t.Fatalf("clone shares source slices: %+v", original)
	}
	for _, relations := range original.RelationIndex {
		for _, relation := range relations {
			if relation.PrincipalID == "changed" {
				t.Fatalf("clone shares relation index slices: %+v", original.RelationIndex)
			}
		}
	}
}
