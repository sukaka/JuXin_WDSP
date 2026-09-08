package reports

import (
	"testing"

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
