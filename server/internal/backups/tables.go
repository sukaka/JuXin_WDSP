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
	GroupLearning    = "LEARNING"    // 可恢复的学习状态与模型中间态
	GroupFact        = "FACT"        // 可恢复的事实快照与资产状态
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
	{Name: "waf_rule_packs", Group: GroupConfig},
	{Name: "waf_rule_pack_jobs", Group: GroupAudit},
	{Name: "waf_rule_pack_node_states", Group: GroupAudit},
	{Name: "trusted_proxies", Group: GroupConfig},
	{Name: "protected_addresses", Group: GroupConfig},
	{Name: "ip_access_rules", Group: GroupConfig},
	{Name: "geoip_slot_configs", Group: GroupConfig},
	{Name: "threat_intel_feeds", Group: GroupConfig},
	{Name: "geoip_sync_runs", Group: GroupAudit},
	{Name: "threat_intel_sync_runs", Group: GroupAudit},
	{Name: "rate_limit_policies", Group: GroupConfig},
	{Name: "temporary_blocks", Group: GroupConfig},
	{Name: "report_templates", Group: GroupConfig},
	// WDSP policy and runtime state. These tables are exported together so a
	// restore cannot leave a gateway with a mixed policy/model graph.
	{Name: "application_policies", Group: GroupConfig},
	{Name: "jwt_trust_policies", Group: GroupConfig},
	{Name: "jwt_trust_policy_versions", Group: GroupConfig},
	{Name: "bot_policies", Group: GroupConfig},
	{Name: "bot_policy_versions", Group: GroupConfig},
	{Name: "ai_crawler_directories", Group: GroupConfig},
	{Name: "ai_crawl_policies", Group: GroupConfig},
	{Name: "ai_crawl_policy_versions", Group: GroupConfig},
	{Name: "client_side_policies", Group: GroupConfig},
	{Name: "client_side_policy_versions", Group: GroupConfig},
	{Name: "client_script_inventory", Group: GroupConfig},
	{Name: "client_side_violations", Group: GroupAudit},
	{Name: "api_a2a_policies", Group: GroupConfig},
	{Name: "api_a2a_policy_versions", Group: GroupConfig},
	{Name: "api_a2a_agents", Group: GroupConfig},
	{Name: "api_a2a_events", Group: GroupAudit},
	{Name: "semantic_guard_policies", Group: GroupConfig},
	{Name: "semantic_guard_policy_versions", Group: GroupConfig},
	{Name: "wasm_plugins", Group: GroupConfig},
	{Name: "wasm_plugin_versions", Group: GroupConfig},
	{Name: "api_endpoints", Group: GroupConfig},
	{Name: "api_endpoint_aliases", Group: GroupConfig},
	{Name: "api_endpoint_path_segments", Group: GroupConfig},
	{Name: "api_assets", Group: GroupConfig},
	{Name: "api_model_versions", Group: GroupConfig},
	{Name: "api_request_schemas", Group: GroupConfig},
	{Name: "api_response_schemas", Group: GroupConfig},
	{Name: "api_masking_rules", Group: GroupConfig},
	{Name: "api_sensitive_data_types", Group: GroupConfig},
	{Name: "api_file_compliance_rules", Group: GroupConfig},
	{Name: "api_grpc_descriptors", Group: GroupConfig},
	{Name: "api_runtime_policies", Group: GroupConfig},
	{Name: "api_object_models", Group: GroupConfig},
	{Name: "api_object_relations", Group: GroupConfig},
	{Name: "api_role_baselines", Group: GroupConfig},
	{Name: "api_object_ownership", Group: GroupConfig},
	{Name: "api_field_permissions", Group: GroupConfig},
	{Name: "api_flow_baselines", Group: GroupConfig},
	{Name: "api_flow_baseline_steps", Group: GroupConfig},
	{Name: "api_revoked_credentials", Group: GroupConfig},
	{Name: "api_gateway_nodes", Group: GroupConfig},
	{Name: "api_scan_targets", Group: GroupConfig},
	{Name: "api_scan_authorizations", Group: GroupConfig},
	{Name: "api_ai_schedules", Group: GroupConfig},
	{Name: "api_parameter_models", Group: GroupLearning},
	{Name: "api_parameter_statistics", Group: GroupLearning},
	{Name: "api_parameter_relations", Group: GroupLearning},
	{Name: "api_parameter_value_obs", Group: GroupLearning},
	{Name: "api_learning_jobs", Group: GroupLearning},
	{Name: "api_learning_samples", Group: GroupLearning},
	{Name: "api_classifications", Group: GroupLearning},
	{Name: "api_classification_dimensions", Group: GroupLearning},
	{Name: "api_custom_taxonomies", Group: GroupLearning},
	{Name: "api_identity_profiles", Group: GroupLearning},
	{Name: "api_behavior_profiles", Group: GroupLearning},
	{Name: "api_call_edges", Group: GroupLearning},
	{Name: "api_model_reviews", Group: GroupAudit},
	{Name: "api_model_diffs", Group: GroupAudit},
	{Name: "api_import_specs", Group: GroupConfig},
	{Name: "api_spec_diffs", Group: GroupAudit},
	{Name: "api_runtime_events", Group: GroupAudit},
	{Name: "api_runtime_findings", Group: GroupAudit},
	{Name: "api_schema_violations", Group: GroupAudit},
	{Name: "api_lifecycle_events", Group: GroupAudit},
	{Name: "api_authorization_decisions", Group: GroupAudit},
	{Name: "api_authz_candidate_event_receipts", Group: GroupAudit},
	{Name: "api_scan_jobs", Group: GroupAudit},
	{Name: "api_scan_findings", Group: GroupAudit},
	{Name: "api_ai_schedule_runs", Group: GroupAudit},
	{Name: "api_cross_border_events", Group: GroupAudit},
	{Name: "api_weakness_actions", Group: GroupAudit},
	{Name: "api_endpoint_traffic_buckets", Group: GroupFact},
	{Name: "api_weaknesses", Group: GroupFact},
	{Name: "api_file_assets", Group: GroupFact},
	{Name: "api_cross_border_state", Group: GroupFact},
	{Name: "api_llm_observations", Group: GroupFact},
	{Name: "api_object_relation_candidates", Group: GroupLearning},
	{Name: "api_authz_migration_state", Group: GroupLearning},
	{Name: "api_sensitive_fields", Group: GroupFact},
	{Name: "operation_audits", Group: GroupAudit, RecentLimit: AuditExportLimit, OrderBy: "occurred_at"},
}

// tableDeps 硬外键依赖：child → parents（恢复时 parent 先于 child）。
// 仅登记备份范围内表之间的依赖；范围外的引用（如 application_policies）
// 在恢复时通过 session_replication_role 临时关闭触发器处理，见 restores 包。
var tableDeps = map[string][]string{
	"user_roles":                         {"users", "roles"},
	"role_permissions":                   {"roles", "permissions"},
	"application_domains":                {"applications", "protection_policies"},
	"upstreams":                          {"applications"},
	"exception_policies":                 {"protection_policies"},
	"waf_rule_packs":                     {"users"},
	"waf_rule_pack_jobs":                 {"waf_rule_packs", "users"},
	"waf_rule_pack_node_states":          {"waf_rule_pack_jobs"},
	"ip_access_rules":                    {"applications"},
	"rate_limit_policies":                {"applications"},
	"temporary_blocks":                   {"applications"},
	"application_policies":               {"applications", "protection_policies"},
	"jwt_trust_policy_versions":          {"jwt_trust_policies"},
	"bot_policy_versions":                {"bot_policies"},
	"ai_crawl_policies":                  {"applications"},
	"ai_crawl_policy_versions":           {"ai_crawl_policies"},
	"client_side_policies":               {"applications"},
	"client_side_policy_versions":        {"client_side_policies"},
	"client_script_inventory":            {"applications"},
	"client_side_violations":             {"applications"},
	"api_a2a_policies":                   {"applications"},
	"api_a2a_policy_versions":            {"api_a2a_policies"},
	"api_a2a_agents":                     {"applications"},
	"api_a2a_events":                     {"applications"},
	"semantic_guard_policies":            {"applications"},
	"semantic_guard_policy_versions":     {"semantic_guard_policies"},
	"wasm_plugins":                       {"applications"},
	"wasm_plugin_versions":               {"wasm_plugins"},
	"api_endpoints":                      {"applications"},
	"api_endpoint_aliases":               {"api_endpoints"},
	"api_endpoint_path_segments":         {"api_endpoints"},
	"api_model_versions":                 {"api_endpoints"},
	"api_assets":                         {"api_endpoints"},
	"api_parameter_models":               {"api_model_versions"},
	"api_parameter_statistics":           {"api_parameter_models"},
	"api_parameter_relations":            {"api_model_versions", "api_parameter_models"},
	"api_request_schemas":                {"api_model_versions"},
	"api_response_schemas":               {"api_model_versions"},
	"api_masking_rules":                  {"applications"},
	"api_runtime_policies":               {"api_endpoints", "api_model_versions"},
	"api_runtime_events":                 {"api_endpoints", "api_runtime_policies"},
	"api_runtime_findings":               {"api_endpoints", "api_runtime_events"},
	"api_schema_violations":              {"api_endpoints", "api_model_versions", "api_runtime_events"},
	"api_object_models":                  {"api_endpoints", "api_model_versions"},
	"api_object_relations":               {"applications"},
	"api_authorization_decisions":        {"applications", "api_endpoints", "api_object_relations"},
	"api_role_baselines":                 {"api_endpoints"},
	"api_object_ownership":               {"api_endpoints"},
	"api_field_permissions":              {"api_endpoints"},
	"api_flow_baseline_steps":            {"api_flow_baselines", "api_endpoints"},
	"api_learning_jobs":                  {"api_endpoints"},
	"api_learning_samples":               {"api_endpoints"},
	"api_classification_dimensions":      {"api_endpoints"},
	"api_identity_profiles":              {"api_endpoints"},
	"api_behavior_profiles":              {"api_endpoints"},
	"api_call_edges":                     {"api_endpoints"},
	"api_sensitive_fields":               {"api_endpoints"},
	"api_lifecycle_events":               {"api_endpoints"},
	"api_model_reviews":                  {"api_model_versions"},
	"api_model_diffs":                    {"api_model_versions"},
	"api_spec_diffs":                     {"api_import_specs"},
	"api_parameter_value_obs":            {"api_parameter_models"},
	"api_endpoint_traffic_buckets":       {"api_endpoints"},
	"api_weaknesses":                     {"api_endpoints"},
	"api_weakness_actions":               {"api_weaknesses"},
	"api_scan_targets":                   {"applications"},
	"api_scan_authorizations":            {"api_scan_targets", "users"},
	"api_scan_jobs":                      {"api_scan_targets", "api_scan_authorizations"},
	"api_scan_findings":                  {"api_scan_jobs", "api_weaknesses"},
	"api_file_assets":                    {"api_endpoints"},
	"api_ai_schedule_runs":               {"api_ai_schedules"},
	"api_authz_candidate_event_receipts": {"api_runtime_events"},
	"api_object_relation_candidates":     {"applications", "api_endpoints"},
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
