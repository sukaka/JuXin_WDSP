package detectors

import (
	"net/http"
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
