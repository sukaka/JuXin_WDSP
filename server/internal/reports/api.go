package reports

import "time"

// API 域报告类型（P1-06）。report_jobs.report_type 为 VARCHAR(10) 纯文本列
// （无 CHECK 约束，词表由本包代码保证），四个类型均在 10 字符以内，零新表接入。
const (
	TypeAPIAsset = "API_ASSET" // API 资产周报
	TypeAPIRisk  = "API_RISK"  // API 风险周报
	TypeAPIWeak  = "API_WEAK"  // API 弱点整改报告
	TypeAPISens  = "API_SENS"  // API 敏感数据报告
)

// apiReportTypeNames API 报告类型 → 中文报告名（封面/标题用）。
var apiReportTypeNames = map[string]string{
	TypeAPIAsset: "API资产周报",
	TypeAPIRisk:  "API风险周报",
	TypeAPIWeak:  "API弱点整改报告",
	TypeAPISens:  "API敏感数据报告",
}

// IsAPIReportType 判断是否为 API 域报告类型。
func IsAPIReportType(t string) bool {
	_, ok := apiReportTypeNames[t]
	return ok
}

// APIReportTypeName 返回 API 报告类型中文名（未知类型原样返回）。
func APIReportTypeName(t string) string {
	if n, ok := apiReportTypeNames[t]; ok {
		return n
	}
	return t
}

// assetStatusNames 资产状态 → 中文名（asset_status 词表见迁移 000045 注释）。
var assetStatusNames = map[string]string{
	"DISCOVERED": "已发现",
	"CONFIRMED":  "已确认",
	"IGNORED":    "已忽略",
	"DEPRECATED": "已下线",
	"ZOMBIE":     "僵尸",
}

// AssetStatusName 返回资产状态中文名（未知状态原样返回）。
func AssetStatusName(s string) string {
	if n, ok := assetStatusNames[s]; ok {
		return n
	}
	return s
}

// findingStatusNames 运行时发现状态 → 中文名（api_runtime_findings.status 七态词表见 000042 CHECK）。
var findingStatusNames = map[string]string{
	"NEW":            "新建",
	"CONFIRMED":      "已确认",
	"IN_PROGRESS":    "处置中",
	"FALSE_POSITIVE": "误报",
	"IGNORED":        "已忽略",
	"RESOLVED":       "已解决",
	"ARCHIVED":       "已归档",
}

// FindingStatusName 返回发现状态中文名（未知状态原样返回）。
func FindingStatusName(s string) string {
	if n, ok := findingStatusNames[s]; ok {
		return n
	}
	return s
}

// weaknessStatusNames 弱点状态 → 中文名（api_weaknesses.status CHECK 词表见 000039）。
var weaknessStatusNames = map[string]string{
	"NEW":        "新建",
	"CONFIRMED":  "已确认",
	"TO_FIX":     "待整改",
	"FIXED":      "已整改",
	"REPRODUCED": "复现",
	"IGNORED":    "已忽略",
	"ARCHIVED":   "已归档",
}

// WeaknessStatusName 返回弱点状态中文名（未知状态原样返回）。
func WeaknessStatusName(s string) string {
	if n, ok := weaknessStatusNames[s]; ok {
		return n
	}
	return s
}

// weaknessOpenStatuses 弱点「未闭环」状态（超期未修统计口径）。
var weaknessOpenStatuses = []string{"NEW", "CONFIRMED", "TO_FIX", "REPRODUCED"}

// findingOpenStatuses 运行时发现「未关闭」状态（七态词表见 000042；其余四态为关闭态）。
var findingOpenStatuses = []string{"NEW", "CONFIRMED", "IN_PROGRESS"}

// findingClosedStatuses 运行时发现「已关闭」状态（关闭数统计口径）。
var findingClosedStatuses = []string{"RESOLVED", "FALSE_POSITIVE", "IGNORED", "ARCHIVED"}

// sensitiveDataTypeNames 敏感数据类型标签 → 中文名（词表见迁移 000040 种子）。
var sensitiveDataTypeNames = map[string]string{
	"phone":      "手机号码",
	"email":      "电子邮箱",
	"id_card":    "身份证号",
	"bank_card":  "银行卡号",
	"password":   "密码口令",
	"token":      "访问令牌",
	"jwt":        "JWT令牌",
	"credential": "身份凭证",
}

// SensitiveDataTypeName 返回敏感数据类型中文名（未知类型原样返回）。
func SensitiveDataTypeName(t string) string {
	if n, ok := sensitiveDataTypeNames[t]; ok {
		return n
	}
	return t
}

// ---------- API 报告数据（统计与清单摘要，均为聚合数据，不含未脱敏载荷） ----------

// APIReportData API 域报告数据载体：按报告类型填充对应小节（其余为 nil）。
type APIReportData struct {
	ReportType      string    `json:"report_type"`
	PageOrientation string    `json:"page_orientation"` // P 竖向 / L 横向（PDF/Word）
	RangeStart      time.Time `json:"range_start"`
	RangeEnd        time.Time `json:"range_end"`
	GeneratedAt     time.Time `json:"generated_at"`

	Asset     *APIAssetReport     `json:"asset,omitempty"`     // API_ASSET
	Risk      *APIRiskReport      `json:"risk,omitempty"`      // API_RISK
	Weakness  *APIWeaknessReport  `json:"weakness,omitempty"`  // API_WEAK
	Sensitive *APISensitiveReport `json:"sensitive,omitempty"` // API_SENS

	// 全量资产清单（任务开启 include_api_assets 时采集；未开启为 nil）
	AssetList      []APIAssetListItem `json:"asset_list,omitempty"`
	AssetListTotal int64              `json:"asset_list_total"`

	// 结论和建议（确定性模板规则）
	Conclusions []string `json:"conclusions"`
	Suggestions []string `json:"suggestions"`
}

// APIAssetListItem 全量 API 资产清单条目（含用途与影子/僵尸标记）。
type APIAssetListItem struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Purpose  string `json:"purpose"` // 用途分类（PURPOSE 维度中文名，未分类为空）
	Status   string `json:"status"`  // 资产状态（asset_status 词表）
	IsShadow bool   `json:"is_shadow"`
	IsZombie bool   `json:"is_zombie"`
	Hits     int64  `json:"hits"`
}

// FlagLabel 影子/僵尸标记展示文本。
func (it APIAssetListItem) FlagLabel() string {
	switch {
	case it.IsShadow && it.IsZombie:
		return "影子、僵尸"
	case it.IsShadow:
		return "影子API"
	case it.IsZombie:
		return "僵尸API"
	}
	return "-"
}

// APIEndpointDigest 端点清单摘要条目。
type APIEndpointDigest struct {
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    string    `json:"status"`
	Hits      int64     `json:"hits"`
	FirstSeen time.Time `json:"first_seen_at"`
	LastSeen  time.Time `json:"last_seen_at"`
}

// APIAssetReport API 资产周报数据。
type APIAssetReport struct {
	TotalEndpoints int64 `json:"total_endpoints"` // 端点总数（is_api）
	NewEndpoints   int64 `json:"new_endpoints"`   // 报告期内新发现（first_seen_at 落入区间）
	Confirmed      int64 `json:"confirmed"`       // 已确认端点数（确认率 = Confirmed/Total）
	Zombie         int64 `json:"zombie"`          // 僵尸端点数（asset_status=ZOMBIE）
	Deprecated     int64 `json:"deprecated"`      // 已下线端点数
	ShadowOpen     int64 `json:"shadow_open"`     // 当前未关闭的 Shadow 发现（NEW/CONFIRMED/IN_PROGRESS）

	StatusDist []KV                `json:"status_dist"` // 资产状态分布
	NewList    []APIEndpointDigest `json:"new_list"`    // 新增端点清单摘要（最近20条）
	ShadowList []APIEndpointDigest `json:"shadow_list"` // Shadow 端点清单（按发现数排序，前20）
}

// APIRiskEndpoint 风险端点 Top 条目。
type APIRiskEndpoint struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Findings int64  `json:"findings"`
	High     int64  `json:"high"` // 其中高危及以上（HIGH/CRITICAL）
}

// APIRiskSubject 风险主体 Top 条目（subject_id 为指纹，不落明文，展示截断）。
type APIRiskSubject struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Findings    int64  `json:"findings"`
}

// APIRiskReport API 风险周报数据。
type APIRiskReport struct {
	NewFindings    int64 `json:"new_findings"`    // 报告期内新增发现
	ClosedFindings int64 `json:"closed_findings"` // 报告期内关闭（RESOLVED/FALSE_POSITIVE）
	OpenFindings   int64 `json:"open_findings"`   // 当前未关闭（NEW/CONFIRMED/IN_PROGRESS）

	TypeDist     []KV              `json:"type_dist"`     // 新增发现的类型分布
	SeverityDist []KV              `json:"severity_dist"` // 新增发现的严重度分布
	TopEndpoints []APIRiskEndpoint `json:"top_endpoints"` // 风险端点 Top10
	TopSubjects  []APIRiskSubject  `json:"top_subjects"`  // 风险主体 Top10
}

// APIWeaknessItem 超期未修弱点清单条目。
type APIWeaknessItem struct {
	Name     string     `json:"name"`
	Code     string     `json:"code"`
	Severity string     `json:"severity"`
	Status   string     `json:"status"`
	Owner    string     `json:"owner"`
	DueDate  *time.Time `json:"due_date"`
}

// APIRetestItem 复测记录条目（api_weakness_actions，只增不改）。
type APIRetestItem struct {
	WeaknessName string    `json:"weakness_name"`
	Action       string    `json:"action"` // RETEST_PASS / RETEST_FAIL
	Actor        string    `json:"actor"`
	CreatedAt    time.Time `json:"created_at"`
}

// APIWeaknessReport API 弱点整改报告数据。
type APIWeaknessReport struct {
	NewInRange   int64 `json:"new_in_range"`   // 报告期内新派生弱点（first_seen 落入区间）
	FixedInRange int64 `json:"fixed_in_range"` // 报告期内完成整改（fixed_at 落入区间）
	OverdueOpen  int64 `json:"overdue_open"`   // 超期未修（due_date 已过且状态未闭环）
	RetestPass   int64 `json:"retest_pass"`    // 报告期内复测通过次数
	RetestFail   int64 `json:"retest_fail"`    // 报告期内复测失败次数

	StatusDist   []KV              `json:"status_dist"`   // 弱点状态分布（全量）
	SeverityDist []KV              `json:"severity_dist"` // 未闭环弱点严重度分布
	OverdueList  []APIWeaknessItem `json:"overdue_list"`  // 超期未修清单（按期限升序，前20）
	RetestList   []APIRetestItem   `json:"retest_list"`   // 最近复测记录（前10）
}

// APISensitiveEndpoint 涉敏端点 Top 条目。
type APISensitiveEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Fields int64  `json:"fields"` // 敏感字段数
	Types  int64  `json:"types"`  // 涉及数据类型数
}

// APISensitiveReport API 敏感数据报告数据。
type APISensitiveReport struct {
	TotalFields int64 `json:"total_fields"` // 敏感字段总数
	NewInRange  int64 `json:"new_in_range"` // 报告期内新识别（first_seen 落入区间）

	TypeDist     []KV                   `json:"type_dist"`     // 数据类型分布
	TopEndpoints []APISensitiveEndpoint `json:"top_endpoints"` // 涉敏端点 Top10
	DailyNew     []Point                `json:"daily_new"`     // 报告期内按天新增趋势
}
