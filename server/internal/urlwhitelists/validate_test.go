package urlwhitelists

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateInput(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	past := now.Add(-time.Minute)
	appID := uuid.New()
	evtID := uuid.New()

	t.Run("valid global exact permanent", func(t *testing.T) {
		in := CreateInput{
			Name:         "健康检查放行",
			ScopeType:    ScopeGlobal,
			MatchType:    MatchExact,
			URIPattern:   "/healthz",
			Methods:      []string{"get", "HEAD", "GET"},
			Priority:     50,
			ValidityType: ValidityPermanent,
		}
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(in.Methods) != 2 || in.Methods[0] != "GET" || in.Methods[1] != "HEAD" {
			t.Fatalf("methods not normalized: %+v", in.Methods)
		}
		if in.SourceType != SourceManual {
			t.Fatalf("source_type=%s", in.SourceType)
		}
	})

	t.Run("valid application prefix temporary from security event", func(t *testing.T) {
		in := CreateInput{
			Name:           "回调前缀白名单",
			ScopeType:      ScopeApplication,
			ApplicationID:  &appID,
			MatchType:      MatchPrefix,
			URIPattern:     "/api/webhook/",
			ValidityType:   ValidityTemporary,
			EffectiveUntil: &future,
			SourceType:     SourceSecurityEvent,
			SourceEventID:  &evtID,
		}
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if in.URIPattern != "/api/webhook/" {
			t.Fatalf("trailing slash lost: %q", in.URIPattern)
		}
	})

	t.Run("valid regex", func(t *testing.T) {
		in := CreateInput{
			Name:         "正则放行",
			ScopeType:    ScopeGlobal,
			MatchType:    MatchRegex,
			URIPattern:   `^/api/v[12]/public/[a-z0-9_-]+$`,
			ValidityType: ValidityPermanent,
		}
		if err := ValidateInput(&in, now); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	badCases := []struct {
		name string
		in   CreateInput
	}{
		{"empty name", CreateInput{ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a"}},
		{"global with app_id", CreateInput{Name: "x", ScopeType: ScopeGlobal, ApplicationID: &appID, MatchType: MatchExact, URIPattern: "/a"}},
		{"app without app_id", CreateInput{Name: "x", ScopeType: ScopeApplication, MatchType: MatchExact, URIPattern: "/a"}},
		{"exact without slash", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "api/a"}},
		{"exact with query", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/api?a=1"}},
		{"exact with dotdot", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/api/../admin"}},
		{"invalid regex", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchRegex, URIPattern: "[invalid"}},
		{"invalid method", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", Methods: []string{"TRACE"}}},
		{"temporary missing until", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", ValidityType: ValidityTemporary}},
		{"temporary past until", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", ValidityType: ValidityTemporary, EffectiveUntil: &past}},
		{"permanent with until", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", ValidityType: ValidityPermanent, EffectiveUntil: &future}},
		{"manual with source_event_id", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", SourceType: SourceManual, SourceEventID: &evtID}},
		{"security_event missing source_event_id", CreateInput{Name: "x", ScopeType: ScopeGlobal, MatchType: MatchExact, URIPattern: "/a", SourceType: SourceSecurityEvent}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			if err := ValidateInput(&in, now); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestValidateStatusTransition(t *testing.T) {
	if err := ValidateStatusTransition(StatusDisabled, StatusActive); err != nil {
		t.Fatalf("DISABLED->ACTIVE should succeed: %v", err)
	}
	if err := ValidateStatusTransition(StatusExpired, StatusActive); err == nil {
		t.Fatal("EXPIRED->ACTIVE should fail")
	}
	if err := ValidateStatusTransition(StatusDraft, StatusDisabled); err == nil {
		t.Fatal("DRAFT->DISABLED should fail")
	}
}
