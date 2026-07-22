// tables.go 备份表清单、分组与依赖拓扑。
package backups

import (
	"fmt"
	"sort"
)

// 表分组（决定备份/恢复范围）
const (
	GroupDatabase    = "DATABASE"    // 账号/应用拓扑
	GroupCertificate = "CERTIFICATE" // 证书（含加密私钥字段）
	GroupConfig      = "CONFIG"      // 策略与配置
	GroupAudit       = "AUDIT"       // 审计归档（仅导出，永不恢复）
)

// AuditExportLimit 审计表归档导出行数上限（最近 N 行）。
const AuditExportLimit = 1000000

// TableDef 描述一张可备份表。
type TableDef struct {
	Name  string // 物理表名
	Group string
	// RecentLimit >0 时仅导出最近 N 行（按 OrderBy 倒序），用于审计归档。
	RecentLimit int
	OrderBy     string
}

// Tables 备份范围全量表清单（声明顺序即默认恢复顺序的次序基准）。
// 依赖关系见 tableDeps，恢复顺序由 RestoreOrder 拓扑计算得出。
var Tables = []TableDef{
	{Name: "roles", Group: GroupDatabase},
	{Name: "permissions", Group: GroupDatabase},
	{Name: "users", Group: GroupDatabase},
	{Name: "user_roles", Group: GroupDatabase},
	{Name: "role_permissions", Group: GroupDatabase},
	{Name: "system_settings", Group: GroupConfig},
	{Name: "protection_policies", Group: GroupConfig},
	{Name: "applications", Group: GroupDatabase},
	{Name: "application_domains", Group: GroupDatabase},
	{Name: "upstreams", Group: GroupDatabase},
	{Name: "certificates", Group: GroupCertificate},
	{Name: "rule_overrides", Group: GroupConfig},
	{Name: "custom_rules", Group: GroupConfig},
	{Name: "exception_policies", Group: GroupConfig},
	{Name: "trusted_proxies", Group: GroupConfig},
	{Name: "protected_addresses", Group: GroupConfig},
	{Name: "ip_access_rules", Group: GroupConfig},
	{Name: "rate_limit_policies", Group: GroupConfig},
	{Name: "temporary_blocks", Group: GroupConfig},
	{Name: "report_templates", Group: GroupConfig},
	{Name: "operation_audits", Group: GroupAudit, RecentLimit: AuditExportLimit, OrderBy: "occurred_at"},
}

// tableDeps 硬外键依赖：child → parents（恢复时 parent 先于 child）。
// 仅登记备份范围内表之间的依赖；范围外的引用（如 application_policies）
// 在恢复时通过 session_replication_role 临时关闭触发器处理，见 restores 包。
var tableDeps = map[string][]string{
	"user_roles":          {"users", "roles"},
	"role_permissions":    {"roles", "permissions"},
	"application_domains": {"applications"},
	"upstreams":           {"applications"},
	"exception_policies":  {"protection_policies"},
	"ip_access_rules":     {"applications"},
	"rate_limit_policies": {"applications"},
	"temporary_blocks":    {"applications"},
}

// tableRank 声明顺序索引。
var tableRank = func() map[string]int {
	m := make(map[string]int, len(Tables))
	for i, t := range Tables {
		m[t.Name] = i
	}
	return m
}()

// TableByName 查询表定义。
func TableByName(name string) (TableDef, bool) {
	for _, t := range Tables {
		if t.Name == name {
			return t, true
		}
	}
	return TableDef{}, false
}

// IsBackupTable 判断是否为备份范围内的表。
func IsBackupTable(name string) bool {
	_, ok := TableByName(name)
	return ok
}

// TablesForBackup 返回指定备份类型应导出的表（保持声明顺序）。
// FULL：全部表（含审计归档段）；CONFIG_ONLY：排除审计归档段。
func TablesForBackup(backupType string) []TableDef {
	var out []TableDef
	for _, t := range Tables {
		if backupType == TypeConfigOnly && t.Group == GroupAudit {
			continue
		}
		out = append(out, t)
	}
	return out
}

// TablesForGroups 返回属于指定分组的表名（声明顺序）。
func TablesForGroups(groups ...string) []string {
	want := map[string]bool{}
	for _, g := range groups {
		want[g] = true
	}
	var out []string
	for _, t := range Tables {
		if want[t.Group] {
			out = append(out, t.Name)
		}
	}
	return out
}

// RestoreOrder 计算给定表集合的恢复顺序（parent → child，拓扑排序）。
// 同层按 Tables 声明顺序，保证结果确定性；存在环时返回错误。
func RestoreOrder(tables []string) ([]string, error) {
	return topoSort(tables, tableDeps, tableRank)
}

// topoSort Kahn 算法（确定次序）。
func topoSort(nodes []string, deps map[string][]string, rank map[string]int) ([]string, error) {
	inSet := map[string]bool{}
	for _, n := range nodes {
		inSet[n] = true
	}
	indegree := map[string]int{}
	children := map[string][]string{}
	for _, n := range nodes {
		indegree[n] = 0
	}
	for _, n := range nodes {
		for _, p := range deps[n] {
			if !inSet[p] {
				continue // 依赖的表不在本次范围内，忽略
			}
			indegree[n]++
			children[p] = append(children[p], n)
		}
	}
	// 就绪队列按声明顺序排序
	var ready []string
	for _, n := range nodes {
		if indegree[n] == 0 {
			ready = append(ready, n)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return rank[ready[i]] < rank[ready[j]] })

	var out []string
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		out = append(out, n)
		var promoted []string
		for _, c := range children[n] {
			indegree[c]--
			if indegree[c] == 0 {
				promoted = append(promoted, c)
			}
		}
		if len(promoted) > 0 {
			ready = append(ready, promoted...)
			sort.Slice(ready, func(i, j int) bool { return rank[ready[i]] < rank[ready[j]] })
		}
	}
	if len(out) != len(nodes) {
		return nil, fmt.Errorf("table dependency cycle detected among %v", nodes)
	}
	return out, nil
}
