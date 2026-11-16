package jiuzhang_guard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestServeNextObjectEnumerationObservesAndRedacts(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.IdentitySalt = "unit-test-salt"
	g.behaviorStores = &detectors.StoreOverrides{ObjectEnumeration: detectors.NewMemoryObjectEnumerationStore(100, nil)}
	originCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		originCalls++
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/v1/cases/%d", 7300+i), nil)
		req.Header.Set("Authorization", "Bearer unit-test-credential-0123456789")
		req.Header.Set("X-Request-Id", fmt.Sprintf("enum-%d", i))
		verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "verified-subject-fingerprint"}
		*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
		rr := httptest.NewRecorder()
		if err := g.serveNext(rr, req, next); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if rr.Code != http.StatusNoContent {
			t.Fatalf("request %d changed origin status: %d", i, rr.Code)
		}
	}
	if originCalls != 8 {
		t.Fatalf("OBSERVE requests must all reach origin: %d", originCalls)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 8 {
		t.Fatalf("want 8 API events, got %d", len(records))
	}
	var matches int
	for _, record := range records {
		if record.FinalAction == "BLOCK" {
			t.Fatalf("enumeration signal must not block: %+v", record)
		}
		for _, detail := range record.Details {
			if detail.RuleID != "resource.object_enumeration" {
				continue
			}
			matches++
			if detail.Category != "OBSERVE" || !strings.HasPrefix(detail.Evidence["object_ref"], "objref:") || detail.Evidence["distinct_objects"] != "8" {
				t.Fatalf("unexpected event detail: %+v", detail)
			}
			for _, value := range detail.Evidence {
				if strings.Contains(value, "730") {
					t.Fatalf("raw object identifier leaked: %+v", detail.Evidence)
				}
			}
		}
	}
	if matches != 1 {
		t.Fatalf("want one alert in a tracking window, got %d", matches)
	}
}

func TestServeNextObjectEnumerationIgnoresSingleObjectAndList(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.IdentitySalt = "unit-test-salt"
	g.behaviorStores = &detectors.StoreOverrides{ObjectEnumeration: detectors.NewMemoryObjectEnumerationStore(100, nil)}
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	for i := 0; i < 20; i++ {
		target := "/v1/cases/8100"
		if i%2 == 1 {
			target = fmt.Sprintf("/v1/cases?page=%d&page_size=50", i+1)
		}
		req := httptest.NewRequest(http.MethodGet, target, nil)
		verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "normal-subject-fingerprint"}
		*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
		if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
			t.Fatal(err)
		}
	}
	for _, record := range readAPIRecords(t, logPath) {
		for _, detail := range record.Details {
			if detail.RuleID == "resource.object_enumeration" {
				t.Fatalf("single-object and list traffic must not alert: %+v", detail)
			}
		}
	}
}
