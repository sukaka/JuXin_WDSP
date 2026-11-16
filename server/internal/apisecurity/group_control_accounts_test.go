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

const sharedDeviceAccountsPath = "/api/v1/api-security/group-control/shared-devices/accounts"

func TestSharedDeviceAccountsRequireScopedQuery(t *testing.T) {
	applicationID := uuid.NewString()
	device := strings.Repeat("a", 32)
	repository := &fakeGroupControlRepository{
		accountItems: []SharedDeviceAccount{{
			PrincipalRef: strings.Repeat("b", 32), EventCount: 7, SignalCount: 1, EndpointCount: 2,
			FirstSeenAt: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC),
		}},
		accountTotal: 3,
	}
	mux := newGroupControlMux(repository, "api_runtime.read")
	path := sharedDeviceAccountsPath + "?start=2026-11-14T00:00:00Z&end=2026-11-15T00:00:00Z" +
		"&application_id=" + applicationID + "&device_fingerprint=" + device + "&page=2&page_size=1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if repository.accountCalls != 1 || repository.accountFilter.ApplicationID != applicationID ||
		repository.accountFilter.DeviceFingerprint != device || repository.accountFilter.Page != 2 || repository.accountFilter.PageSize != 1 {
		t.Fatalf("account filter=%+v calls=%d", repository.accountFilter, repository.accountCalls)
	}
	if !strings.Contains(rr.Body.String(), `"principal_ref":"`+strings.Repeat("b", 32)+`"`) ||
		!strings.Contains(rr.Body.String(), `"data_scope":"NOTABLE_SECURITY_EVENTS"`) {
		t.Fatalf("account response=%s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "verified_principal_id") {
		t.Fatalf("raw JWT field name leaked in response: %s", rr.Body.String())
	}

	for _, path := range []string{
		sharedDeviceAccountsPath,
		sharedDeviceAccountsPath + "?application_id=" + applicationID,
		sharedDeviceAccountsPath + "?device_fingerprint=" + device,
		sharedDeviceAccountsPath + "?application_id=invalid&device_fingerprint=" + device,
		sharedDeviceAccountsPath + "?application_id=" + applicationID + "&device_fingerprint=plaintext",
	} {
		repository := &fakeGroupControlRepository{}
		rr := httptest.NewRecorder()
		newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusBadRequest || repository.accountCalls != 0 {
			t.Fatalf("unscoped path=%s status=%d calls=%d", path, rr.Code, repository.accountCalls)
		}
	}
}

func TestSharedDeviceAccountsPermissionsAndErrors(t *testing.T) {
	h := NewHandler(nil, nil)
	noAuth := http.NewServeMux()
	RegisterRoutes(noAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := httptest.NewRecorder()
	noAuth.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceAccountsPath, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	newGroupControlMux(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceAccountsPath, nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rr.Code)
	}
	validQuery := "?application_id=" + uuid.NewString() + "&device_fingerprint=" + strings.Repeat("a", 32)
	rr = httptest.NewRecorder()
	newGroupControlMux(nil, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceAccountsPath+validQuery, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable reader status=%d", rr.Code)
	}

	repository := &fakeGroupControlRepository{err: errors.New("read failed")}
	rr = httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, sharedDeviceAccountsPath+validQuery, nil))
	if rr.Code != http.StatusInternalServerError || repository.accountCalls != 1 {
		t.Fatalf("repository error status=%d calls=%d", rr.Code, repository.accountCalls)
	}
}

func TestSharedDeviceAccountStoreRejectsInvalidScope(t *testing.T) {
	valid := SharedDeviceFilter{
		Start:         time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		End:           time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		ApplicationID: uuid.NewString(), DeviceFingerprint: strings.Repeat("a", 32), Page: 1, PageSize: 20,
	}
	for _, mutate := range []func(*SharedDeviceFilter){
		func(f *SharedDeviceFilter) { f.ApplicationID = "" },
		func(f *SharedDeviceFilter) { f.DeviceFingerprint = "" },
		func(f *SharedDeviceFilter) { f.Start = f.End },
		func(f *SharedDeviceFilter) { f.Page = 1000001 },
		func(f *SharedDeviceFilter) { f.PageSize = 101 },
	} {
		filter := valid
		mutate(&filter)
		if _, _, err := (&Store{}).ListSharedDeviceAccounts(context.Background(), filter); err == nil {
			t.Fatalf("invalid account scope accepted: %+v", filter)
		}
	}
}
