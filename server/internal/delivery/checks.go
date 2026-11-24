// checks.go 交付检查项注册表（≥20 项）。
package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// RunContext 检查执行上下文（依赖注入，单测可替换）。
type RunContext struct {
	Ctx       context.Context
	DB        *pgxpool.Pool
	Health    *runtimehealth.Store
	Audits    *audits.Service
	Settings  *settings.Service
	Cfg       *config.Config
	DataDir   string
	RepoRoot  string
	CachePing func(ctx context.Context) error
	// HTTPStatus 探测本机 HTTP 状态码（默认 httpGetStatus；测试可注入）。
	HTTPStatus func(url string) (int, error)
	// EnvGet 读环境变量（默认 os.Getenv；测试可注入）。
	EnvGet func(key string) string
	Now    time.Time
}

func (rc *RunContext) env(key string) string {
	if rc.EnvGet != nil {
		return rc.EnvGet(key)
	}
	return os.Getenv(key)
}

func (rc *RunContext) now() time.Time {
	if rc.Now.IsZero() {
		return time.Now().UTC()
	}
	return rc.Now
}

// requiredComponents 交付时必须 UP 的组件。
var requiredComponents = []string{
	runtimehealth.ComponentGateway,
	runtimehealth.ComponentAPI,
	runtimehealth.ComponentPostgres,
	runtimehealth.ComponentValkey,
	runtimehealth.ComponentEventCollector,
}

// requiredDocs 交付必备文档（相对 RepoRoot）。
var requiredDocs = []string{
	"docs/PRODUCT_REQUIREMENTS.md",
	"docs/ARCHITECTURE.md",
	"docs/DATABASE_DESIGN.md",
	"docs/API_DESIGN.md",
	"docs/SECURITY_DESIGN.md",
	"docs/DEPLOYMENT.md",
	"docs/TEST_PLAN.md",
	"docs/OPEN_SOURCE_COMPLIANCE.md",
}

// 已知弱口令占位值（不得作为交付环境密码）。
var placeholderPasswords = map[string]bool{
	"password": true, "123456": true, "changeme": true, "change_me": true,
	"jiuzhang": true, "admin": true, "root": true, "test": true,
}

// Registry 返回交付检查项注册表（固定顺序）。
func Registry() []Check {
	return []Check{
		{Key: "components_up", Name: "核心组件全部运行正常", Category: CategoryRuntime, Critical: true, Run: checkComponentsUp},
		{Key: "https_config", Name: "管理平台 HTTPS 强制配置", Category: CategorySecurity, Critical: true, Run: checkHTTPSConfig},
		{Key: "three_role_accounts", Name: "三权分立账号齐备", Category: CategoryAccount, Critical: true, Run: checkThreeRoleAccounts},
		{Key: "password_policy", Name: "密码策略合规（最小长度≥12）", Category: CategorySecurity, Critical: true, Run: checkPasswordPolicy},
		{Key: "caddy_admin_socket", Name: "Caddy Admin 未暴露 TCP（Unix Socket）", Category: CategorySecurity, Critical: true, Run: checkCaddyAdminSocket},
		{Key: "postgres_bind", Name: "PostgreSQL 未公网暴露", Category: CategorySecurity, Critical: true, Run: checkPostgresBind},
		{Key: "valkey_bind", Name: "Valkey 未公网暴露", Category: CategorySecurity, Critical: true, Run: checkValkeyBind},
		{Key: "config_version_exists", Name: "当前网关配置版本存在", Category: CategoryProtection, Critical: true, Run: checkConfigVersionExists},
		{Key: "waf_detection", Name: "WAF 检测能力可用（CRS 规则）", Category: CategoryProtection, Critical: true, Run: checkWAFDetection},
		{Key: "access_control_available", Name: "黑白名单/CC 策略接口可用", Category: CategoryProtection, Critical: false, Run: checkAccessControlAvailable},
		{Key: "event_collector_lag", Name: "事件采集滞后 <60s", Category: CategoryRuntime, Critical: false, Run: checkEventCollectorLag},
		{Key: "report_generation", Name: "报告生成能力可用", Category: CategoryProtection, Critical: false, Run: checkReportGeneration},
		{Key: "backup_available", Name: "最近已验证备份 <7天", Category: CategoryRuntime, Critical: true, Run: checkBackupAvailable},
		{Key: "restore_drill", Name: "恢复演练记录存在", Category: CategoryQuality, Critical: false, Run: checkRestoreDrill},
		{Key: "audit_chain", Name: "审计哈希链完整", Category: CategoryCompliance, Critical: true, Run: checkAuditChain},
		{Key: "third_party_notices", Name: "THIRD_PARTY_NOTICES.md 存在且非空", Category: CategoryCompliance, Critical: false, Run: checkThirdPartyNotices},
		{Key: "sbom_exists", Name: "SBOM 文件存在（docs/SBOM.spdx.json）", Category: CategoryCompliance, Critical: false, Run: checkSBOMExists},
		{Key: "docs_present", Name: "交付关键文档齐备", Category: CategoryCompliance, Critical: false, Run: checkDocsPresent},
		{Key: "vulnerability_scan", Name: "漏洞扫描无未修复高危发现", Category: CategorySecurity, Critical: true, Run: checkVulnerabilityScan},
		{Key: "no_default_password", Name: "无默认/硬编码初始口令", Category: CategorySecurity, Critical: false, Run: checkNoDefaultPassword},
		{Key: "no_debug_endpoints", Name: "无调试接口暴露（/debug/pprof）", Category: CategorySecurity, Critical: true, Run: checkNoDebugEndpoints},
		{Key: "no_placeholder_secrets", Name: "无占位口令/Mock 标记配置", Category: CategoryQuality, Critical: false, Run: checkNoPlaceholderSecrets},
		{Key: "test_reports", Name: "阶段测试报告存在", Category: CategoryQuality, Critical: false, Run: checkTestReports},
	}
}

// checkComponentsUp 组件全 UP（最新健康快照）。
func checkComponentsUp(rc *RunContext) ItemResult {
	c := findCheck("components_up")
	snaps, err := rc.Health.LatestAll(rc.Ctx)
	if err != nil {
		return c.failErr("读取健康快照失败", err)
	}
	byComp := map[string]runtimehealth.Snapshot{}
	for _, s := range snaps {
		byComp[s.Component] = s
	}
	var down, missing []string
	details := map[string]interface{}{}
	for _, comp := range requiredComponents {
		s, ok := byComp[comp]
		if !ok {
			missing = append(missing, comp)
			continue
		}
		details[comp] = s.Status
		if s.Status != runtimehealth.StatusUp {
			down = append(down, comp+"("+s.Status+")")
		}
	}
	if len(down) > 0 {
		return c.fail("组件未全部 UP："+strings.Join(down, "、"), details)
	}
	if len(missing) > 0 {
		return c.warn("缺少组件快照："+strings.Join(missing, "、"), details)
	}
	return c.pass("全部核心组件 UP", details)
}

// checkHTTPSConfig 生产环境必须启用 CookieSecure（仅 HTTPS 下发）。
func checkHTTPSConfig(rc *RunContext) ItemResult {
	c := findCheck("https_config")
	if rc.Cfg.Env == "prod" && !rc.Cfg.Security.CookieSecure {
		return c.fail("生产环境 COOKIE_SECURE 必须为 true（管理平台强制 HTTPS）", nil)
	}
	if rc.Cfg.Env == "prod" {
		return c.pass("生产环境已启用安全 Cookie（HTTPS）", nil)
	}
	return c.pass(fmt.Sprintf("当前环境 %s，生产部署时须启用 COOKIE_SECURE", rc.Cfg.Env), nil)
}

// checkThreeRoleAccounts 三权账号：系统/运维/审计管理员角色各至少一名启用用户。
func checkThreeRoleAccounts(rc *RunContext) ItemResult {
	c := findCheck("three_role_accounts")
	rows, err := rc.DB.Query(rc.Ctx, `
SELECT r.code, count(DISTINCT u.id)
FROM roles r
LEFT JOIN user_roles ur ON ur.role_id = r.id
LEFT JOIN users u ON u.id = ur.user_id AND u.status = 'ACTIVE' AND u.deleted_at IS NULL
WHERE r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')
GROUP BY r.code`)
	if err != nil {
		return c.failErr("查询三权账号失败", err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var code string
		var n int
		if err := rows.Scan(&code, &n); err != nil {
			return c.failErr("查询三权账号失败", err)
		}
		counts[code] = n
	}
	var missing []string
	for _, role := range []string{"SYSTEM_ADMIN", "SECURITY_ADMIN", "AUDIT_ADMIN"} {
		if counts[role] == 0 {
			missing = append(missing, role)
		}
	}
	details := map[string]interface{}{"counts": counts}
	if len(missing) > 0 {
		return c.fail("以下角色无启用账号："+strings.Join(missing, "、"), details)
	}
	return c.pass("三权账号齐备且分属三角色", details)
}

// checkPasswordPolicy 密码最小长度 ≥12。
func checkPasswordPolicy(rc *RunContext) ItemResult {
	c := findCheck("password_policy")
	policy := rc.Settings.PasswordPolicy(rc.Ctx)
	details := map[string]interface{}{"min_length": policy.MinLength}
	if policy.MinLength < 12 {
		return c.fail(fmt.Sprintf("密码最小长度 %d，低于合规要求 12", policy.MinLength), details)
	}
	return c.pass(fmt.Sprintf("密码最小长度 %d", policy.MinLength), details)
}

// checkCaddyAdminSocket Caddy Admin 走 Unix Socket（socket 文件存在，未暴露 TCP）。
func checkCaddyAdminSocket(rc *RunContext) ItemResult {
	c := findCheck("caddy_admin_socket")
	sock := rc.Cfg.Gateway.AdminSocket
	details := map[string]interface{}{"socket": sock}
	info, err := os.Stat(sock)
	if err != nil {
		return c.fail("Caddy Admin Socket 不存在："+sock, details)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return c.fail("Caddy Admin 路径不是 Unix Socket："+sock, details)
	}
	return c.pass("Caddy Admin 使用 Unix Socket", details)
}

// checkPostgresBind PostgreSQL 监听地址非公网。
func checkPostgresBind(rc *RunContext) ItemResult {
	c := findCheck("postgres_bind")
	return checkBindAddress(c, "PostgreSQL", rc.Cfg.DB.Host)
}

// checkValkeyBind Valkey 监听地址非公网。
func checkValkeyBind(rc *RunContext) ItemResult {
	c := findCheck("valkey_bind")
	return checkBindAddress(c, "Valkey", rc.Cfg.Cache.Host)
}

// checkBindAddress host 为回环地址或内部主机名 → PASS；私网地址 → PASS（提示）；公网地址 → FAIL。
func checkBindAddress(c Check, component, host string) ItemResult {
	details := map[string]interface{}{"host": host}
	ip := net.ParseIP(host)
	if ip == nil {
		// 主机名（如 docker 服务名）：内部网络解析，视为未公网暴露
		return c.pass(component+" 使用内部主机名 "+host, details)
	}
	if ip.IsLoopback() {
		return c.pass(component+" 绑定回环地址 "+host, details)
	}
	if ip.IsPrivate() {
		return c.pass(component+" 绑定私网地址 "+host, details)
	}
	return c.fail(component+" 绑定到公网地址 "+host+"，存在暴露风险", details)
}

// checkConfigVersionExists 存在当前网关配置版本。
func checkConfigVersionExists(rc *RunContext) ItemResult {
	c := findCheck("config_version_exists")
	var exists bool
	err := rc.DB.QueryRow(rc.Ctx, `SELECT EXISTS(SELECT 1 FROM gateway_config_versions)`).Scan(&exists)
	if err != nil {
		return c.failErr("查询配置版本失败", err)
	}
	if !exists {
		return c.fail("尚未发布任何网关配置版本", nil)
	}
	return c.pass("网关配置版本存在", nil)
}

// checkWAFDetection CRS 规则目录存在且含规则文件。
func checkWAFDetection(rc *RunContext) ItemResult {
	c := findCheck("waf_detection")
	dir := rc.Cfg.WAF.CRSDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return c.fail("CRS 规则目录不可读："+dir, nil)
	}
	confCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".conf") {
			confCount++
		}
	}
	details := map[string]interface{}{"crs_dir": dir, "rule_files": confCount, "crs_version": rc.Cfg.WAF.CRSVersion}
	if confCount == 0 {
		return c.fail("CRS 目录无规则文件（*.conf）", details)
	}
	return c.pass(fmt.Sprintf("CRS %s 规则文件 %d 个", rc.Cfg.WAF.CRSVersion, confCount), details)
}

// checkAccessControlAvailable 黑白名单/CC 策略数据表可查询。
func checkAccessControlAvailable(rc *RunContext) ItemResult {
	c := findCheck("access_control_available")
	var rules, policies int64
	if err := rc.DB.QueryRow(rc.Ctx, `SELECT count(*) FROM ip_access_rules`).Scan(&rules); err != nil {
		return c.failErr("查询黑白名单失败", err)
	}
	if err := rc.DB.QueryRow(rc.Ctx, `SELECT count(*) FROM rate_limit_policies`).Scan(&policies); err != nil {
		return c.failErr("查询CC策略失败", err)
	}
	return c.pass(fmt.Sprintf("黑白名单 %d 条，CC 策略 %d 条", rules, policies),
		map[string]interface{}{"access_rules": rules, "rate_limit_policies": policies})
}

// checkEventCollectorLag 事件采集器滞后 <60s。
func checkEventCollectorLag(rc *RunContext) ItemResult {
	c := findCheck("event_collector_lag")
	snap, err := rc.Health.LatestByComponent(rc.Ctx, runtimehealth.ComponentEventCollector)
	if err != nil {
		return c.failErr("读取事件采集器快照失败", err)
	}
	if snap == nil {
		return c.warn("暂无事件采集器快照", nil)
	}
	lag := metricFloat(snap.Metrics, runtimehealth.MetricMaxLagSeconds)
	details := map[string]interface{}{"status": snap.Status, "max_lag_seconds": lag}
	if snap.Status == runtimehealth.StatusUp && lag < 60 {
		return c.pass(fmt.Sprintf("采集滞后 %.0f 秒", lag), details)
	}
	return c.warn(fmt.Sprintf("采集器状态 %s，滞后 %.0f 秒", snap.Status, lag), details)
}

// checkReportGeneration 最近 7 天有成功报告，或存在可用模板（可立即生成）。
func checkReportGeneration(rc *RunContext) ItemResult {
	c := findCheck("report_generation")
	var recent int64
	if err := rc.DB.QueryRow(rc.Ctx, `
SELECT count(*) FROM report_jobs
WHERE status = 'SUCCESS' AND finished_at > now() - interval '7 days'`).Scan(&recent); err != nil {
		return c.failErr("查询报告任务失败", err)
	}
	if recent > 0 {
		return c.pass(fmt.Sprintf("最近 7 天成功报告 %d 份", recent), nil)
	}
	var templates int64
	if err := rc.DB.QueryRow(rc.Ctx, `
SELECT count(*) FROM report_templates WHERE deleted_at IS NULL`).Scan(&templates); err != nil {
		return c.failErr("查询报告模板失败", err)
	}
	if templates > 0 {
		return c.warn("最近 7 天无成功报告，模板可用（建议交付前试生成一份）", nil)
	}
	return c.fail("无可用报告模板，报告生成能力未就绪", nil)
}

// checkBackupAvailable 最近已验证备份 <7天。
func checkBackupAvailable(rc *RunContext) ItemResult {
	c := findCheck("backup_available")
	var last *time.Time
	err := rc.DB.QueryRow(rc.Ctx, `
SELECT max(finished_at) FROM backup_jobs WHERE status = 'SUCCESS' AND verified`).Scan(&last)
	if err != nil {
		return c.failErr("查询备份失败", err)
	}
	if last == nil {
		return c.fail("无已验证的备份", nil)
	}
	age := rc.now().Sub(*last)
	details := map[string]interface{}{"last_backup_at": last.UTC().Format(time.RFC3339)}
	if age > 7*24*time.Hour {
		return c.fail(fmt.Sprintf("最近已验证备份已过期 %.1f 天", age.Hours()/24), details)
	}
	return c.pass(fmt.Sprintf("最近已验证备份 %.1f 小时前", age.Hours()), details)
}

// checkRestoreDrill 存在成功的恢复演练记录。
func checkRestoreDrill(rc *RunContext) ItemResult {
	c := findCheck("restore_drill")
	var n int64
	err := rc.DB.QueryRow(rc.Ctx, `SELECT count(*) FROM restore_jobs WHERE status = 'SUCCESS'`).Scan(&n)
	if err != nil {
		return c.failErr("查询恢复演练失败", err)
	}
	if n == 0 {
		return c.warn("无恢复演练成功记录，建议交付前完成一次恢复演练", nil)
	}
	return c.pass(fmt.Sprintf("恢复演练成功记录 %d 条", n), nil)
}

// checkAuditChain 审计哈希链校验通过。
func checkAuditChain(rc *RunContext) ItemResult {
	c := findCheck("audit_chain")
	mismatches, ids, err := rc.Audits.VerifyChain(rc.Ctx, 100000)
	if err != nil {
		return c.failErr("审计哈希链校验执行失败", err)
	}
	if mismatches > 0 {
		return c.fail(fmt.Sprintf("审计哈希链存在 %d 条不一致记录", mismatches),
			map[string]interface{}{"mismatch_ids": ids})
	}
	return c.pass("审计哈希链完整", nil)
}

// checkThirdPartyNotices THIRD_PARTY_NOTICES.md 存在且非空。
func checkThirdPartyNotices(rc *RunContext) ItemResult {
	c := findCheck("third_party_notices")
	return checkFileNonEmpty(c, filepath.Join(rc.RepoRoot, "THIRD_PARTY_NOTICES.md"))
}

// checkSBOMExists docs/SBOM.spdx.json 存在且为合法 JSON。
func checkSBOMExists(rc *RunContext) ItemResult {
	c := findCheck("sbom_exists")
	p := filepath.Join(rc.RepoRoot, "docs", "SBOM.spdx.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return c.fail("SBOM 文件不存在："+p, nil)
	}
	if len(b) == 0 || !json.Valid(b) {
		return c.fail("SBOM 文件为空或非法 JSON", nil)
	}
	return c.pass("SBOM 文件存在且合法", map[string]interface{}{"path": p, "size": len(b)})
}

// checkDocsPresent 交付关键文档齐备。
func checkDocsPresent(rc *RunContext) ItemResult {
	c := findCheck("docs_present")
	var missing []string
	for _, doc := range requiredDocs {
		info, err := os.Stat(filepath.Join(rc.RepoRoot, doc))
		if err != nil || info.Size() == 0 {
			missing = append(missing, doc)
		}
	}
	if len(missing) > 0 {
		return c.warn("缺少文档："+strings.Join(missing, "、"), map[string]interface{}{"missing": missing})
	}
	return c.pass(fmt.Sprintf("关键文档 %d 项齐备", len(requiredDocs)), nil)
}

// checkVulnerabilityScan 漏洞扫描闭环（§十六「高危漏洞扫描」）：
//  1. 扫描能力存在：scripts/generate-sbom.sh 与 scripts/license-audit.sh 存在、非空且可执行；
//  2. 扫描输入齐备：docs/SBOM.spdx.json 存在且为合法 JSON；
//  3. 无未修复高危：docs/VULN_KNOWN_HIGH.md 登记表中无未修复条目（约定："- [ ]" 行 = 未修复）；
//     登记表缺失或超过 90 天未更新 → WARNING（扫描结论不可信，须重新扫描建档）。
func checkVulnerabilityScan(rc *RunContext) ItemResult {
	c := findCheck("vulnerability_scan")
	var broken []string
	for _, s := range []string{"generate-sbom.sh", "license-audit.sh"} {
		p := filepath.Join(rc.RepoRoot, "scripts", s)
		info, err := os.Stat(p)
		if err != nil || info.Size() == 0 {
			broken = append(broken, s+"(缺失)")
			continue
		}
		if info.Mode()&0o111 == 0 {
			broken = append(broken, s+"(不可执行)")
		}
	}
	if len(broken) > 0 {
		return c.fail("漏洞扫描能力不可用："+strings.Join(broken, "、"),
			map[string]interface{}{"broken_scripts": broken})
	}
	sbom := filepath.Join(rc.RepoRoot, "docs", "SBOM.spdx.json")
	if b, err := os.ReadFile(sbom); err != nil || len(b) == 0 || !json.Valid(b) {
		return c.fail("SBOM 缺失或非法，漏洞扫描输入不齐备："+sbom, nil)
	}
	reg := filepath.Join(rc.RepoRoot, "docs", "VULN_KNOWN_HIGH.md")
	info, err := os.Stat(reg)
	if err != nil {
		return c.warn("无高危漏洞发现登记表（docs/VULN_KNOWN_HIGH.md），交付前须执行漏洞扫描并建档登记结果", nil)
	}
	b, err := os.ReadFile(reg)
	if err != nil {
		return c.failErr("读取高危漏洞登记表失败", err)
	}
	unresolved := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "- [ ]") {
			unresolved++
		}
	}
	details := map[string]interface{}{"register": reg, "unresolved_findings": unresolved}
	if unresolved > 0 {
		return c.fail(fmt.Sprintf("存在 %d 条未修复高危漏洞发现，须修复并复扫后方可交付", unresolved), details)
	}
	if age := rc.now().Sub(info.ModTime()); age > 90*24*time.Hour {
		return c.warn(fmt.Sprintf("高危漏洞登记表已 %.0f 天未更新，交付前须重新扫描并刷新登记", age.Hours()/24), details)
	}
	return c.pass("扫描能力齐备，高危漏洞登记无未修复发现", details)
}

// checkNoDefaultPassword 初始管理员口令环境变量不应在交付环境中长期注入（初始口令仅首次使用）。
func checkNoDefaultPassword(rc *RunContext) ItemResult {
	c := findCheck("no_default_password")
	var injected []string
	for _, key := range []string{
		"INITIAL_ADMIN_PASSWORD",
		"INITIAL_OPER_ADMIN_PASSWORD",
		"INITIAL_AUDIT_ADMIN_PASSWORD",
	} {
		if strings.TrimSpace(rc.env(key)) != "" {
			injected = append(injected, key)
		}
	}
	if len(injected) > 0 {
		return c.warn(strings.Join(injected, "、")+" 仍在环境中注入，初始化完成后应移除相关变量",
			map[string]interface{}{"env_vars": injected})
	}
	return c.pass("初始管理员口令未硬编码注入", nil)
}

// checkNoDebugEndpoints /debug/pprof 未注册（本机回环探测应 404）。
func checkNoDebugEndpoints(rc *RunContext) ItemResult {
	c := findCheck("no_debug_endpoints")
	if rc.HTTPStatus == nil {
		return c.na("无 HTTP 探测能力，跳过")
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/", rc.Cfg.HTTP.Port)
	code, err := rc.HTTPStatus(url)
	if err != nil {
		return c.warn("无法探测调试接口："+err.Error(), nil)
	}
	if code == 200 {
		return c.fail("/debug/pprof 已暴露（HTTP 200），生产环境禁止注册调试接口", nil)
	}
	return c.pass(fmt.Sprintf("/debug/pprof 返回 %d，未暴露", code), nil)
}

// checkNoPlaceholderSecrets 关键口令环境变量不得为已知占位值。
func checkNoPlaceholderSecrets(rc *RunContext) ItemResult {
	c := findCheck("no_placeholder_secrets")
	var weak []string
	for _, key := range []string{"POSTGRES_PASSWORD", "VALKEY_PASSWORD", "JIUZHANG_MASTER_KEY"} {
		v := strings.ToLower(strings.TrimSpace(rc.env(key)))
		if v == "" {
			weak = append(weak, key+"(未设置)")
			continue
		}
		if placeholderPasswords[v] {
			weak = append(weak, key+"(占位口令)")
		}
	}
	if len(weak) > 0 {
		return c.fail("存在未设置或占位口令："+strings.Join(weak, "、"), nil)
	}
	return c.pass("关键口令均已设置且非占位值", nil)
}

// checkTestReports docs/STAGE*_TEST_REPORT.md 至少存在一份。
func checkTestReports(rc *RunContext) ItemResult {
	c := findCheck("test_reports")
	matches, err := filepath.Glob(filepath.Join(rc.RepoRoot, "docs", "STAGE*_TEST_REPORT.md"))
	if err != nil || len(matches) == 0 {
		return c.warn("未找到阶段测试报告（docs/STAGE*_TEST_REPORT.md）", nil)
	}
	return c.pass(fmt.Sprintf("阶段测试报告 %d 份", len(matches)),
		map[string]interface{}{"reports": filepathBase(matches)})
}

// ---------- 辅助 ----------

func checkFileNonEmpty(c Check, path string) ItemResult {
	info, err := os.Stat(path)
	if err != nil {
		return c.fail("文件不存在："+path, nil)
	}
	if info.Size() == 0 {
		return c.fail("文件为空："+path, nil)
	}
	return c.pass("文件存在且非空", map[string]interface{}{"path": path, "size": info.Size()})
}

func metricFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case int64:
			return float64(n)
		}
	}
	return 0
}

func filepathBase(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

// findCheck 按 key 取检查项定义（供 Run 内构造结果）。
func findCheck(key string) Check {
	for _, c := range Registry() {
		if c.Key == key {
			return c
		}
	}
	return Check{Key: key}
}
