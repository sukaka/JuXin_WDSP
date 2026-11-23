package reports

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// TestCanAccessReportFile 报告文件归属边界回归（审查 MED-15）：Preview 与 Download
// 共用同一校验，非创建者且无 reports.download_audit 权限不得读取报告文件内容。
func TestCanAccessReportFile(t *testing.T) {
	ownerID := uuid.New()
	otherID := uuid.New()
	auditReader := &authz.Principal{UserID: otherID, PermsSet: map[string]bool{"reports.download_audit": true}}
	plainUser := &authz.Principal{UserID: otherID, PermsSet: map[string]bool{"reports.download": true}}

	cases := []struct {
		name string
		job  *Job
		p    *authz.Principal
		want bool
	}{
		{"创建者本人", &Job{RequestedBy: &ownerID}, &authz.Principal{UserID: ownerID}, true},
		{"非创建者无审计权限", &Job{RequestedBy: &ownerID}, plainUser, false},
		{"非创建者有 download_audit", &Job{RequestedBy: &ownerID}, auditReader, true},
		{"定时计划报告（无创建者）普通用户", &Job{RequestedBy: nil}, plainUser, false},
		{"定时计划报告（无创建者）审计权限", &Job{RequestedBy: nil}, auditReader, true},
	}
	for _, c := range cases {
		if got := canAccessReportFile(c.job, c.p); got != c.want {
			t.Errorf("%s: canAccessReportFile = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestDeleteReportRoutePermissions 验证 DELETE /api/v1/reports/{id} 路由层放行
// reports.delete_own 与 reports.delete_all 任一权限，缺两者拒绝 403，未认证拒绝 401（B5-06）。
func TestDeleteReportRoutePermissions(t *testing.T) {
	h := NewHandler(nil, nil, nil, nil, "")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, func(next http.Handler) http.Handler { return next })

	cases := []struct {
		name       string
		principal  *authz.Principal
		wantStatus int
	}{
		{
			name:       "unauthenticated",
			principal:  nil,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "no delete permissions",
			principal:  &authz.Principal{UserID: uuid.New(), PermsSet: map[string]bool{"reports.read": true}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "delete_own only reaches handler",
			principal:  &authz.Principal{UserID: uuid.New(), PermsSet: map[string]bool{"reports.delete_own": true}},
			wantStatus: http.StatusBadRequest, // invalid UUID proves middleware passed and h.Delete ran
		},
		{
			name:       "delete_all only reaches handler",
			principal:  &authz.Principal{UserID: uuid.New(), PermsSet: map[string]bool{"reports.delete_all": true}},
			wantStatus: http.StatusBadRequest, // invalid UUID proves middleware passed and h.Delete ran
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/reports/not-a-uuid", nil)
			if tc.principal != nil {
				req = req.WithContext(authz.WithPrincipal(req.Context(), tc.principal))
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestArchiveItemJSONContract 验证 ArchiveItem 序列化包含 file_format/file_hash/file_size 与 archive_id（B5-02）。
func TestArchiveItemJSONContract(t *testing.T) {
	item := ArchiveItem{
		ArchiveID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ReportJobID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		ReportNo:    "JZ-202611-0001",
		ReportType:  TypeMonthly,
		Status:      StatusSuccess,
		FileFormat:  FormatPDF,
		FileHash:    "abcd1234",
		FileSize:    4096,
		ArchivedAt:  time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC),
		Note:        "月度归档",
		ArchivedBy:  "sec_admin",
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal ArchiveItem: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal ArchiveItem: %v", err)
	}
	for _, key := range []string{
		"archive_id", "report_job_id", "report_no", "report_type", "status",
		"file_format", "file_hash", "file_size", "archived_at", "note", "archived_by",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("ArchiveItem JSON missing key %q: %s", key, string(raw))
		}
	}
	if got["file_format"] != "pdf" || got["file_hash"] != "abcd1234" || got["file_size"] != float64(4096) {
		t.Fatalf("unexpected file fields: %v", got)
	}
}
