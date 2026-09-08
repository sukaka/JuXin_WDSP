// list_findings_test.go 风险发现列表（ListFindings）过滤参数词表校验测试：
// finding_type/severity/status 非法值明确 400（修复前静默返回空列表）；
// 词表函数单测（httptest 不依赖数据库：校验失败在存取层之前返回，nil store 安全）。
package apisecurity

import (
	"net/http"
	"strings"
	"testing"
)

// TestListFindingsFilterValidation 三过滤参数非法值 → 400；
// 词表口径：status 七态（迁移 000042 CHECK）、severity 五档（迁移 000018 注释词表）、
// finding_type 开放词表的形态校验（大写字母/数字/下划线，1-64字符）。
func TestListFindingsFilterValidation(t *testing.T) {
	h := NewHandler(nil, nil)
	mux := newRiskTestMux(h) // 注入 api_risk.read/api_risk.handle；本路由需 api_runtime.read

	// 无 api_runtime.read 权限 → 403（权限校验先于参数校验）
	if rr := doRiskJSON(t, mux, http.MethodGet, "/api/v1/api-security/findings?severity=HIGH", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("no api_runtime.read perm status=%d, want 403", rr.Code)
	}

	muxOK := http.NewServeMux()
	RegisterRoutes(muxOK, injectRiskPrincipal("api_runtime.read"), h)

	cases := map[string]string{
		"finding_type 小写":     "/api/v1/api-security/findings?finding_type=shadow",
		"finding_type 含空格":    "/api/v1/api-security/findings?finding_type=SHADOW%20TYPE",
		"finding_type 含符号":    "/api/v1/api-security/findings?finding_type=SHADOW%27",
		"finding_type 超长":     "/api/v1/api-security/findings?finding_type=" + strings.Repeat("A", 65),
		"severity 词表外":        "/api/v1/api-security/findings?severity=SEVERE",
		"severity 前端展示词 NONE": "/api/v1/api-security/findings?severity=NONE",
		"status 旧四态 OPEN":     "/api/v1/api-security/findings?status=OPEN",
		"status 旧四态 ACK":      "/api/v1/api-security/findings?status=ACKNOWLEDGED",
		"status 词表外":          "/api/v1/api-security/findings?status=PENDING",
	}
	for name, url := range cases {
		if rr := doRiskJSON(t, muxOK, http.MethodGet, url, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400, body=%s", name, rr.Code, rr.Body.String())
		}
	}
}

// TestIsValidRiskFindingType finding_type 形态校验（开放词表不做封闭枚举）。
func TestIsValidRiskFindingType(t *testing.T) {
	valid := []string{
		"SHADOW", "ZOMBIE", "DEPRECATED", "BOLA", "BFLA", "SCHEMA_DEVIATION", "SENSITIVE_LEAK", // 任务书词表
		"BOLA_UNAUTHENTICATED_OBJECT_ACCESS",                                    // 生产方语义覆盖表生成值
		"SCHEMA_PARAM_LENGTH", "BEHAVIOR_BURST", "AUTHENTICATION", "API_SCHEMA", // 机械映射/检测器兜底
		"WAF_12345", "UNKNOWN", // 数字规则号加前缀与 UNKNOWN 兜底
		strings.Repeat("A", 64), // 长度上限
	}
	for _, s := range valid {
		if !IsValidRiskFindingType(s) {
			t.Errorf("IsValidRiskFindingType(%q)=false, want true", s)
		}
	}
	invalid := []string{
		"", strings.Repeat("A", 65), // 空与超长
		"shadow", "Shadow", // 小写/混合大小写
		"SHADOW TYPE", "SHADOW-TYPE", "SHADOW.TYPE", // 空格/连字符/点（入库前已归一化为下划线）
		"SHADOW'; DROP TABLE", "影子", // 注入与非法字符
	}
	for _, s := range invalid {
		if IsValidRiskFindingType(s) {
			t.Errorf("IsValidRiskFindingType(%q)=true, want false", s)
		}
	}
}

// TestIsValidRiskSeverity 严重度五档词表（函数本身大小写敏感；调用方先 ToUpper 归一化）。
func TestIsValidRiskSeverity(t *testing.T) {
	for _, s := range []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if !IsValidRiskSeverity(s) {
			t.Errorf("IsValidRiskSeverity(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"", "NONE", "SEVERE", "high", "1"} {
		if IsValidRiskSeverity(s) {
			t.Errorf("IsValidRiskSeverity(%q)=true, want false", s)
		}
	}
}
