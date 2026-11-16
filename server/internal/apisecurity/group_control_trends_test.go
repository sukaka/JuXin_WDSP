package apisecurity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const sharedDeviceTrendPath = "/api/v1/api-security/group-control/trends"

func TestSharedDeviceTrendQueryAndBuckets(t *testing.T) {
	repository := &fakeGroupControlRepository{trendItems: []SharedDeviceTrendPoint{{
		Bucket: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), GroupCount: 2, SignalCount: 3, EventCount: 9,
	}}}
	applicationID := uuid.NewString()
	device := strings.Repeat("a", 32)
	path := sharedDeviceTrendPath + "?start=2026-11-12T00:00:00Z&end=2026-11-15T00:00:00Z" +
		"&application_id=" + applicationID + "&device_fingerprint=" + device + "&min_accounts=4"
	rr := httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK || repository.trendCalls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, repository.trendCalls, rr.Body.String())
	}
	if repository.trendFilter.Bucket != "day" || repository.trendFilter.MinAccounts != 4 ||
		repository.trendFilter.ApplicationID != applicationID || repository.trendFilter.DeviceFingerprint != device {
		t.Fatalf("trend filter=%+v", repository.trendFilter)
	}
	for _, fragment := range []string{`"bucket":"day"`, `"group_count":2`, `"signal_count":3`, `"data_scope":"NOTABLE_SECURITY_EVENTS"`} {
		if !strings.Contains(rr.Body.String(), fragment) {
			t.Fatalf("trend response missing %s: %s", fragment, rr.Body.String())
		}
	}

	repository = &fakeGroupControlRepository{}
	path = sharedDeviceTrendPath + "?start=2026-11-14T00:00:00Z&end=2026-11-15T00:00:00Z"
	rr = httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK || repository.trendFilter.Bucket != "hour" {
		t.Fatalf("default hourly bucket status=%d filter=%+v", rr.Code, repository.trendFilter)
	}

	repository = &fakeGroupControlRepository{}
	rr = httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, sharedDeviceTrendPath+"?bucket=week", nil))
	if rr.Code != http.StatusBadRequest || repository.trendCalls != 0 {
		t.Fatalf("invalid bucket status=%d calls=%d", rr.Code, repository.trendCalls)
	}
}

func TestSharedDeviceTrendPermissionsAndErrors(t *testing.T) {
	h := NewHandler(nil, nil)
	noAuth := http.NewServeMux()
	RegisterRoutes(noAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := httptest.NewRecorder()
	noAuth.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceTrendPath, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	newGroupControlMux(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceTrendPath, nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	newGroupControlMux(nil, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceTrendPath, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable reader status=%d", rr.Code)
	}

	repository := &fakeGroupControlRepository{err: errors.New("read failed")}
	rr = httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceTrendPath, nil))
	if rr.Code != http.StatusInternalServerError || repository.trendCalls != 1 {
		t.Fatalf("repository error status=%d calls=%d", rr.Code, repository.trendCalls)
	}
}

func TestSharedDeviceTrendStoreRejectsInvalidFilters(t *testing.T) {
	valid := SharedDeviceTrendFilter{SharedDeviceFilter: SharedDeviceFilter{
		Start:       time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		MinAccounts: 3,
	}, Bucket: "hour"}
	for _, mutate := range []func(*SharedDeviceTrendFilter){
		func(f *SharedDeviceTrendFilter) { f.Start = f.End },
		func(f *SharedDeviceTrendFilter) { f.MinAccounts = 1 },
		func(f *SharedDeviceTrendFilter) { f.Bucket = "week" },
		func(f *SharedDeviceTrendFilter) { f.ApplicationID = "invalid" },
		func(f *SharedDeviceTrendFilter) { f.DeviceFingerprint = "plaintext" },
	} {
		filter := valid
		mutate(&filter)
		if _, err := (&Store{}).SharedDeviceTrend(context.Background(), filter); err == nil {
			t.Fatalf("invalid trend filter accepted: %+v", filter)
		}
	}
}
