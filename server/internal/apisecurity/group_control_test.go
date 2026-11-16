package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeGroupControlRepository struct {
	filter        SharedDeviceFilter
	calls         int
	items         []SharedDeviceGroup
	total         int64
	accountFilter SharedDeviceFilter
	accountCalls  int
	accountItems  []SharedDeviceAccount
	accountTotal  int64
	trendFilter   SharedDeviceTrendFilter
	trendCalls    int
	trendItems    []SharedDeviceTrendPoint
	err           error
}

func (f *fakeGroupControlRepository) ListSharedDevices(_ context.Context, filter SharedDeviceFilter) ([]SharedDeviceGroup, int64, error) {
	f.calls++
	f.filter = filter
	return f.items, f.total, f.err
}

func (f *fakeGroupControlRepository) ListSharedDeviceAccounts(_ context.Context, filter SharedDeviceFilter) ([]SharedDeviceAccount, int64, error) {
	f.accountCalls++
	f.accountFilter = filter
	return f.accountItems, f.accountTotal, f.err
}

func (f *fakeGroupControlRepository) SharedDeviceTrend(_ context.Context, filter SharedDeviceTrendFilter) ([]SharedDeviceTrendPoint, error) {
	f.trendCalls++
	f.trendFilter = filter
	return f.trendItems, f.err
}

func newGroupControlMux(repository GroupControlRepository, permissions ...string) *http.ServeMux {
	h := NewHandler(nil, nil).SetGroupControlRepository(repository)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectRiskPrincipal(permissions...), h)
	return mux
}

func TestSharedDeviceGroupsQueryAndResponse(t *testing.T) {
	applicationID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	repository := &fakeGroupControlRepository{
		items: []SharedDeviceGroup{{
			ApplicationID: applicationID, ApplicationName: "示例应用", DeviceFingerprint: strings.Repeat("a", 32),
			DistinctAccounts: 3, EventCount: 12, SignalCount: 2, EndpointCount: 4, GatewayNodeCount: 2,
			FirstSeenAt: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 11, 14, 2, 0, 0, 0, time.UTC),
		}},
		total: 3,
	}
	mux := newGroupControlMux(repository, "api_runtime.read")
	path := "/api/v1/api-security/group-control/shared-devices?start=2026-11-14T00:00:00Z&end=2026-11-15T00:00:00Z" +
		"&application_id=" + applicationID.String() + "&device_fingerprint=" + strings.Repeat("a", 32) +
		"&min_accounts=2&page=2&page_size=1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if repository.calls != 1 || repository.filter.MinAccounts != 2 || repository.filter.Page != 2 || repository.filter.PageSize != 1 {
		t.Fatalf("query filter=%+v calls=%d", repository.filter, repository.calls)
	}
	if repository.filter.ApplicationID != applicationID.String() || repository.filter.DeviceFingerprint != strings.Repeat("a", 32) {
		t.Fatalf("query scope not forwarded: %+v", repository.filter)
	}
	var envelope struct {
		Data struct {
			Items     []SharedDeviceGroup `json:"items"`
			Total     int64               `json:"total"`
			Page      int                 `json:"page"`
			PageSize  int                 `json:"page_size"`
			Partial   bool                `json:"partial"`
			DataScope string              `json:"data_scope"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Total != 3 || envelope.Data.Page != 2 || envelope.Data.PageSize != 1 ||
		len(envelope.Data.Items) != 1 || envelope.Data.Items[0].DistinctAccounts != 3 ||
		!envelope.Data.Partial || envelope.Data.DataScope != "NOTABLE_SECURITY_EVENTS" {
		t.Fatalf("response=%s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "verified_principal_id") {
		t.Fatalf("principal identifier leaked in aggregate response: %s", rr.Body.String())
	}
}

func TestSharedDeviceGroupsDefaults(t *testing.T) {
	now := time.Date(2026, 11, 15, 8, 0, 0, 0, time.UTC)
	filter, err := parseSharedDeviceFilter(httptest.NewRequest(http.MethodGet, "/shared-devices", nil), now)
	if err != nil {
		t.Fatal(err)
	}
	if !filter.Start.Equal(now.Add(-24*time.Hour)) || !filter.End.Equal(now) ||
		filter.MinAccounts != 3 || filter.Page != 1 || filter.PageSize != 20 {
		t.Fatalf("defaults=%+v", filter)
	}
}

func TestSharedDeviceGroupsRejectInvalidFilters(t *testing.T) {
	for _, query := range []string{
		"start=not-a-time", "end=not-a-time",
		"start=2026-11-15T00:00:00Z&end=2026-11-14T00:00:00Z",
		"start=2026-10-01T00:00:00Z&end=2026-11-15T00:00:00Z",
		"application_id=orders-prod", "device_fingerprint=shared-laptop",
		"device_fingerprint=" + strings.Repeat("A", 32),
		"min_accounts=1", "min_accounts=1001", "min_accounts=many",
		"page=0", "page=1000001", "page_size=0", "page_size=101", "page_size=all",
	} {
		repository := &fakeGroupControlRepository{}
		mux := newGroupControlMux(repository, "api_runtime.read")
		path := "/api/v1/api-security/group-control/shared-devices?" + query
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q status=%d body=%s", query, rr.Code, rr.Body.String())
		}
		if repository.calls != 0 {
			t.Fatalf("invalid query %q reached repository", query)
		}
	}
}

func TestSharedDeviceGroupsPermissionsAndAvailability(t *testing.T) {
	const path = "/api/v1/api-security/group-control/shared-devices"
	h := NewHandler(nil, nil)
	noAuth := http.NewServeMux()
	RegisterRoutes(noAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := httptest.NewRecorder()
	noAuth.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", rr.Code)
	}

	rr = httptest.NewRecorder()
	newGroupControlMux(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	newGroupControlMux(nil, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable reader status=%d body=%s", rr.Code, rr.Body.String())
	}

	repository := &fakeGroupControlRepository{err: errors.New("read failed")}
	rr = httptest.NewRecorder()
	newGroupControlMux(repository, "api_runtime.read").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusInternalServerError || repository.calls != 1 {
		t.Fatalf("repository error status=%d calls=%d", rr.Code, repository.calls)
	}
}

func TestSharedDeviceStoreRejectsInvalidFiltersBeforeDatabase(t *testing.T) {
	store := &Store{}
	valid := SharedDeviceFilter{
		Start:       time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC),
		End:         time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		MinAccounts: 3, Page: 1, PageSize: 20,
	}
	for _, mutate := range []func(*SharedDeviceFilter){
		func(f *SharedDeviceFilter) { f.Start = f.End },
		func(f *SharedDeviceFilter) { f.MinAccounts = 1 },
		func(f *SharedDeviceFilter) { f.PageSize = 101 },
		func(f *SharedDeviceFilter) { f.ApplicationID = "invalid" },
		func(f *SharedDeviceFilter) { f.DeviceFingerprint = "plaintext" },
	} {
		filter := valid
		mutate(&filter)
		if _, _, err := store.ListSharedDevices(context.Background(), filter); err == nil {
			t.Fatalf("invalid filter accepted: %+v", filter)
		}
	}
}
