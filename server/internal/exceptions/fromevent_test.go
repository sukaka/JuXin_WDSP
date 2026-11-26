package exceptions

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func TestFilterEventRuleIDs(t *testing.T) {
	t.Run("excludes anomaly blocking evaluation rules and sorts deduplicated detection rules", func(t *testing.T) {
		got, err := FilterEventRuleIDs([]int{949110, 943120, 942100, 943120, 959100, 980170, 0, -1}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0] != 942100 || got[1] != 943120 {
			t.Fatalf("got %v, want [942100 943120]", got)
		}
	})

	t.Run("only blocking eval rules yields empty list so draft becomes NEEDS_REVIEW", func(t *testing.T) {
		got, err := FilterEventRuleIDs([]int{949110, 949111, 9000102}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})

	t.Run("allows narrowing to trusted subset", func(t *testing.T) {
		got, err := FilterEventRuleIDs([]int{942100, 943120, 949110}, []int{943120, 943120})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != 943120 {
			t.Fatalf("got %v, want [943120]", got)
		}
	})

	t.Run("rejects forged rule id or blocking eval rule id selected by client", func(t *testing.T) {
		if _, err := FilterEventRuleIDs([]int{943120, 949110}, []int{949110}); err == nil {
			t.Fatal("selecting blocking eval rule 949110 must be rejected")
		}
		if _, err := FilterEventRuleIDs([]int{943120, 949110}, []int{941100}); err == nil {
			t.Fatal("selecting unmatched rule 941100 must be rejected")
		}
	})
}

func TestBuildFromEventExceptionDefaultsAndOptions(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	appID := uuid.New()
	evtID := uuid.New()
	userID := uuid.New()

	t.Run("zero options preserve P0-04 safe defaults (30m temp + single client IP + DRAFT)", func(t *testing.T) {
		exc, err := buildFromEventException(CreateFromEventInput{
			EventID:       evtID,
			ApplicationID: &appID,
			Method:        "post",
			Path:          "/admin-api/customer/messages/heartbeat?sessionId=masked&role=visitor",
			ClientIP:      "123.121.181.151",
			Domain:        "www.jxdr.cn",
			AttackType:    "SESSION_FIXATION",
			RuleIDs:       []int{943120},
			CreatedBy:     userID,
		}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exc.Status != "DRAFT" || !exc.IsTemporary {
			t.Fatalf("status=%s is_temp=%v, want DRAFT/true", exc.Status, exc.IsTemporary)
		}
		if exc.URIExact != "/admin-api/customer/messages/heartbeat" {
			t.Errorf("uri_exact=%q, want query stripped", exc.URIExact)
		}
		if len(exc.Methods) != 1 || exc.Methods[0] != "POST" {
			t.Errorf("methods=%v, want [POST]", exc.Methods)
		}
		if len(exc.SourceIPs) != 1 || exc.SourceIPs[0] != "123.121.181.151" {
			t.Errorf("source_ips=%v, want [123.121.181.151]", exc.SourceIPs)
		}
		if exc.EffectiveUntil == nil || exc.EffectiveUntil.Sub(now) != 30*time.Minute {
			t.Errorf("effective_until=%v, want +30m", exc.EffectiveUntil)
		}
	})

	t.Run("custom options allow all visitors + custom duration and still pass ValidateForEnable", func(t *testing.T) {
		exc, err := buildFromEventException(CreateFromEventInput{
			EventID:          evtID,
			ApplicationID:    &appID,
			Method:           "POST",
			Path:             "/admin-api/customer/messages/heartbeat",
			ClientIP:         "123.121.181.151",
			Domain:           "www.jxdr.cn",
			RuleIDs:          []int{943120},
			CreatedBy:        userID,
			Name:             "官网客服心跳误报豁免",
			Reason:           "企业微信内嵌浏览器无 Referer 触发 943120 误报",
			RestrictSourceIP: boolPtr(false),
			IsTemporary:      boolPtr(true),
			DurationMinutes:  intPtr(1440),
		}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(exc.SourceIPs) != 0 {
			t.Errorf("source_ips=%v, want empty when restrict_source_ip=false", exc.SourceIPs)
		}
		if exc.EffectiveUntil == nil || exc.EffectiveUntil.Sub(now) != 24*time.Hour {
			t.Errorf("effective_until=%v, want +24h", exc.EffectiveUntil)
		}
		if exc.Name != "官网客服心跳误报豁免" || exc.Reason != "企业微信内嵌浏览器无 Referer 触发 943120 误报" {
			t.Errorf("unexpected name/reason: %q / %q", exc.Name, exc.Reason)
		}
		if exc.IsBroad() {
			t.Error("scoped exception should not be broad")
		}
		if err := ValidateInput(exc); err != nil {
			t.Fatalf("ValidateInput failed: %v", err)
		}
		if _, verrs := ValidateForEnable(context.Background(), exc, p0Hooks()); verrs != nil {
			t.Fatalf("ValidateForEnable failed: %v", verrs)
		}
	})

	t.Run("permanent exception clears effective_until", func(t *testing.T) {
		exc, err := buildFromEventException(CreateFromEventInput{
			EventID:          evtID,
			ApplicationID:    &appID,
			Method:           "POST",
			Path:             "/admin-api/customer/messages/heartbeat",
			Domain:           "www.jxdr.cn",
			RuleIDs:          []int{943120},
			CreatedBy:        userID,
			RestrictSourceIP: boolPtr(false),
			IsTemporary:      boolPtr(false),
		}, now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if exc.IsTemporary || exc.EffectiveUntil != nil {
			t.Errorf("permanent exception got is_temp=%v until=%v", exc.IsTemporary, exc.EffectiveUntil)
		}
	})

	t.Run("rejects invalid duration and overlong fields", func(t *testing.T) {
		_, err := buildFromEventException(CreateFromEventInput{
			EventID:         evtID,
			CreatedBy:       userID,
			DurationMinutes: intPtr(0),
		}, now)
		if err == nil {
			t.Fatal("duration_minutes=0 must fail")
		}
		_, err = buildFromEventException(CreateFromEventInput{
			EventID:         evtID,
			CreatedBy:       userID,
			DurationMinutes: intPtr(maxEventDraftDurationMinutes + 1),
		}, now)
		if err == nil {
			t.Fatal("duration_minutes above 365 days must fail")
		}
		_, err = buildFromEventException(CreateFromEventInput{
			EventID:   evtID,
			CreatedBy: userID,
			Name:      strings.Repeat("a", 129),
		}, now)
		if err == nil {
			t.Fatal("overlong name must fail")
		}
		_, err = buildFromEventException(CreateFromEventInput{
			EventID:   evtID,
			CreatedBy: userID,
			Reason:    strings.Repeat("测", 501),
		}, now)
		if err == nil {
			t.Fatal("overlong reason must fail")
		}
	})
}
